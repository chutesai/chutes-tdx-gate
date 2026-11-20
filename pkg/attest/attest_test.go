package attest

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/chutesai/chutes-tdx-gate/internal/fakequote"
)

func TestReportDataRule(t *testing.T) {
	var nonce [32]byte
	_, _ = rand.Read(nonce[:])
	pk := make([]byte, PublicKeySize)
	_, _ = rand.Read(pk)
	h := sha512.New()
	h.Write([]byte("chutes-tdx-endpoint-attest-v1"))
	h.Write([]byte{0})
	h.Write(nonce[:])
	h.Write(pk)
	got := ReportData(nonce, pk)
	if string(got[:]) != string(h.Sum(nil)) {
		t.Fatal("REPORTDATA rule")
	}
}

func TestCheckQuote(t *testing.T) {
	var rd [64]byte
	_, _ = rand.Read(rd[:])
	q := fakequote.Quote(rd)
	if err := CheckQuote(q, rd); err != nil {
		t.Fatal(err)
	}
	var other [64]byte
	if CheckQuote(q, other) == nil {
		t.Fatal("a quote over other REPORTDATA passed")
	}
	v5 := append([]byte(nil), q...)
	v5[0] = 5
	if CheckQuote(v5, rd) == nil {
		t.Fatal("a v5 quote passed")
	}
	sgx := append([]byte(nil), q...)
	sgx[4] = 0
	if CheckQuote(sgx, rd) == nil {
		t.Fatal("a non-TDX quote passed")
	}
	if CheckQuote(append(q, make([]byte, MaxQuoteBytes)...), rd) == nil {
		t.Fatal("an oversized quote passed")
	}
}

// fakeConfigfs emulates configfs-tsm: mkdir creates provider and generation; a write to inblob
// bumps generation and makes outblob; interleave adds extra writers.
type fakeConfigfs struct {
	mu         sync.Mutex
	provider   string
	files      map[string][]byte
	dirs       map[string]bool
	interleave int // extra generation bumps between the inblob write and the second read
	inblobs    [][]byte
	removed    int
}

func (f *fakeConfigfs) Mkdir(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dirs[path] {
		return errors.New("exists")
	}
	f.dirs[path] = true
	f.files[filepath.Join(path, "provider")] = []byte(f.provider + "\n")
	f.files[filepath.Join(path, "generation")] = []byte("0\n")
	return nil
}

func (f *fakeConfigfs) ReadFile(path string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasSuffix(path, "/generation") && f.interleave > 0 && f.files[filepath.Join(filepath.Dir(path), "outblob")] != nil {
		g, _ := strconv.Atoi(strings.TrimSpace(string(f.files[path])))
		f.files[path] = []byte(strconv.Itoa(g+1) + "\n")
		f.interleave--
	}
	raw, ok := f.files[path]
	if !ok {
		return nil, errors.New("no such file")
	}
	return append([]byte(nil), raw...), nil
}

func (f *fakeConfigfs) WriteOnce(path string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if filepath.Base(path) != "inblob" {
		return errors.New("only inblob is writable")
	}
	f.inblobs = append(f.inblobs, append([]byte(nil), data...))
	dir := filepath.Dir(path)
	g, _ := strconv.Atoi(strings.TrimSpace(string(f.files[filepath.Join(dir, "generation")])))
	f.files[filepath.Join(dir, "generation")] = []byte(strconv.Itoa(g+1) + "\n")
	var rd [64]byte
	copy(rd[:], data)
	f.files[filepath.Join(dir, "outblob")] = fakequote.Quote(rd)
	return nil
}

func (f *fakeConfigfs) Remove(path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.dirs, path)
	f.removed++
	return nil
}

func newFake(provider string) *fakeConfigfs {
	return &fakeConfigfs{provider: provider, files: map[string][]byte{}, dirs: map[string]bool{}}
}

func TestConfigfsTsm(t *testing.T) {
	var rd [64]byte
	_, _ = rand.Read(rd[:])
	fs := newFake("tdx_guest")
	tsm := &ConfigfsTsm{Dir: "/sys/kernel/config/tsm/report", fs: fs}
	q, err := tsm.Quote(rd)
	if err != nil || CheckQuote(q, rd) != nil {
		t.Fatalf("quote: %v", err)
	}
	if len(fs.inblobs) != 1 || string(fs.inblobs[0]) != string(rd[:]) || fs.removed != 1 || len(fs.dirs) != 0 {
		t.Fatal("inblob or rmdir")
	}

	// Another writer once: retried, and the retry passes.
	fs = newFake("tdx_guest")
	fs.interleave = 1
	tsm = &ConfigfsTsm{Dir: "/x", fs: fs}
	if _, err := tsm.Quote(rd); err != nil {
		t.Fatalf("one interleaved writer: %v", err)
	}
	// Twice: busy.
	fs = newFake("tdx_guest")
	fs.interleave = 2
	tsm = &ConfigfsTsm{Dir: "/x", fs: fs}
	if _, err := tsm.Quote(rd); !errors.Is(err, ErrBusy) {
		t.Fatalf("two interleaved writers: %v", err)
	}
	if fs.removed != 2 {
		t.Fatalf("entries left behind: %d removed", fs.removed)
	}

	// Another provider (an SEV-SNP guest, say) is refused.
	fs = newFake("sev_guest")
	tsm = &ConfigfsTsm{Dir: "/x", fs: fs}
	if _, err := tsm.Quote(rd); err == nil || len(fs.inblobs) != 0 {
		t.Fatal("a provider other than tdx_guest was used")
	}
}

func TestParseNonceQuery(t *testing.T) {
	good := "nonce=" + strings.Repeat("0a", 32)
	if _, err := ParseNonceQuery(good); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"", "nonce=", good + "&", "&" + good, good + "0", strings.ToUpper(good), "nonce=" + strings.Repeat("%30", 64), "NONCE=" + strings.Repeat("0a", 32), "nonce=" + strings.Repeat("0g", 32)} {
		if _, err := ParseNonceQuery(q); err == nil {
			t.Fatalf("%q admitted", q)
		}
	}
}
