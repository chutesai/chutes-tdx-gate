package attest

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// ErrBusy means another writer changed the report entry while the quote was made, twice.
var ErrBusy = errors.New("attest: configfs-tsm busy")

// ConfigfsTsm makes TDX quotes through the kernel's configfs-tsm interface
// (Documentation/ABI/testing/configfs-tsm-report), one at a time.
type ConfigfsTsm struct {
	// Dir is the report directory, normally /sys/kernel/config/tsm/report.
	Dir string
	mu  sync.Mutex
	fs  fileOps
}

// fileOps are the four file operations the quote needs; tests substitute a configfs emulation.
type fileOps interface {
	Mkdir(path string) error
	ReadFile(path string) ([]byte, error)
	WriteOnce(path string, data []byte) error
	Remove(path string) error
}

type osOps struct{}

func (osOps) Mkdir(path string) error              { return os.Mkdir(path, 0o700) }
func (osOps) ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }
func (osOps) Remove(path string) error             { return os.Remove(path) }

// WriteOnce writes data in one write to an existing attribute file: the inblob, the only file the
// gate ever writes.
func (osOps) WriteOnce(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n != len(data) {
		err = errors.New("attest: short inblob write")
	}
	return err
}

func (t *ConfigfsTsm) ops() fileOps {
	if t.fs == nil {
		return osOps{}
	}
	return t.fs
}

func (t *ConfigfsTsm) readTrim(path string) (string, error) {
	raw, err := t.ops().ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func (t *ConfigfsTsm) readGeneration(entry string) (uint64, error) {
	text, err := t.readTrim(filepath.Join(entry, "generation"))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(text, 10, 64)
}

// once makes one quote in a fresh entry: mkdir; provider must be tdx_guest; generation; inblob;
// outblob; generation again, which must be the first plus one (errGeneration otherwise); rmdir.
func (t *ConfigfsTsm) once(reportData [64]byte) ([]byte, error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, err
	}
	entry := filepath.Join(t.Dir, "tdx-gate-"+hex.EncodeToString(suffix[:]))
	fs := t.ops()
	if err := fs.Mkdir(entry); err != nil {
		return nil, err
	}
	defer fs.Remove(entry)
	provider, err := t.readTrim(filepath.Join(entry, "provider"))
	if err != nil {
		return nil, err
	}
	if provider != "tdx_guest" {
		return nil, fmt.Errorf("attest: configfs-tsm provider is %q, not tdx_guest", provider)
	}
	first, err := t.readGeneration(entry)
	if err != nil {
		return nil, err
	}
	if err := fs.WriteOnce(filepath.Join(entry, "inblob"), reportData[:]); err != nil {
		return nil, err
	}
	quote, err := fs.ReadFile(filepath.Join(entry, "outblob"))
	if err != nil {
		return nil, err
	}
	second, err := t.readGeneration(entry)
	if err != nil {
		return nil, err
	}
	if second != first+1 {
		return nil, errGeneration
	}
	return quote, nil
}

var errGeneration = errors.New("attest: configfs-tsm generation moved")

// Quote returns a quote over reportData, serialized; a generation that moved is retried once,
// then ErrBusy.
func (t *ConfigfsTsm) Quote(reportData [64]byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	quote, err := t.once(reportData)
	if errors.Is(err, errGeneration) {
		quote, err = t.once(reportData)
		if errors.Is(err, errGeneration) {
			return nil, ErrBusy
		}
	}
	return quote, err
}
