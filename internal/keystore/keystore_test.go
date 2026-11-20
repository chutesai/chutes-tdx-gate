//go:build linux

package keystore

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// fakeSystemd is a NOTIFY_SOCKET that keeps the descriptors it is sent, as PID 1's store does.
func fakeSystemd(t *testing.T) (*net.UnixConn, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notify")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, path
}

func receive(t *testing.T, conn *net.UnixConn) (string, []int) {
	t.Helper()
	buf, oob := make([]byte, 256), make([]byte, 256)
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		t.Fatal(err)
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) != 1 {
		t.Fatalf("control messages: %v %d", err, len(msgs))
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n]), fds
}

func seed() []byte {
	s := make([]byte, SeedSize)
	for i := range s {
		s[i] = byte(i * 7)
	}
	return s
}

// stored runs Store against a fake systemd and returns the mark Store kept and the two stored
// descriptors as the next start would get them.
func stored(t *testing.T) (*Mark, []passed) {
	t.Helper()
	conn, path := fakeSystemd(t)
	t.Setenv("NOTIFY_SOCKET", path)
	mark, err := Store(seed())
	if err != nil || mark == nil {
		t.Fatalf("stored %v: %v", mark, err)
	}
	var list []passed
	for _, name := range []string{MarkName, Name} { // the mark first
		state, fds := receive(t, conn)
		if state != "FDSTORE=1\nFDNAME="+name || len(fds) != 1 {
			t.Fatalf("%q %v", state, fds)
		}
		list = append(list, passed{fds[0], name})
	}
	return mark, list
}

// The first start stores the seed in a sealed memfd named tdx-gate-key and the mark, NoMark, in a
// fixed-size memfd named tdx-gate-mark; the next start gets the same seed and the current mark.
func TestStoreThenRestore(t *testing.T) {
	mark, list := stored(t)
	// The key's memfd refuses any change.
	if _, err := unix.Write(list[1].fd, []byte{1}); err == nil {
		t.Fatal("the stored key accepted a write")
	}
	if v, err := mark.Load(); err != nil || v != NoMark {
		t.Fatalf("a new mark is %d: %v", v, err)
	}
	if err := mark.Set(1795000000123); err != nil {
		t.Fatal(err)
	}
	// The mark keeps its size.
	if _, err := unix.Pwrite(list[0].fd, make([]byte, 16), 0); err == nil {
		t.Fatal("the stored mark grew")
	}
	r, err := restore(list)
	if err != nil || r == nil || !bytes.Equal(r.Seed, seed()) {
		t.Fatalf("restored %+v: %v", r, err)
	}
	if v, err := r.Mark.Load(); err != nil || v != 1795000000123 {
		t.Fatalf("the restored mark is %d: %v", v, err)
	}
	// The restored mark is the stored one: a write through it is what the next start reads.
	if err := r.Mark.Set(-5); err != nil {
		t.Fatal(err)
	}
	if v, _ := mark.Load(); v != -5 {
		t.Fatalf("the mark's writes are not shared: %d", v)
	}
}

func TestNoSystemdStoresNothing(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if mark, err := Store(seed()); mark != nil || err != nil {
		t.Fatalf("stored %v: %v", mark, err)
	}
}

func markFD(t *testing.T, size int, seals int) int {
	t.Helper()
	fd, err := unix.MemfdCreate("m", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = unix.Write(fd, make([]byte, size))
	if seals != 0 {
		_, _ = unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals)
	}
	return fd
}

// A key that is not a sealed 64-byte memfd is refused, and so is a key without a valid mark (the
// gate then fails to start rather than serve without its replay bound).
func TestRestoreRefuses(t *testing.T) {
	keyFD := func(data []byte, seals int) int {
		fd, _ := unix.MemfdCreate("k", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
		_, _ = unix.Write(fd, data)
		if seals != 0 {
			_, _ = unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals)
		}
		return fd
	}
	good := func() int { return markFD(t, MarkSize, markSeals) }
	for name, list := range map[string][]passed{
		"an unsealed key":   {{keyFD(seed(), 0), Name}, {good(), MarkName}},
		"a 32-byte key":     {{keyFD(seed()[:32], keySeals), Name}, {good(), MarkName}},
		"a 128-byte key":    {{keyFD(bytes.Repeat(seed(), 2), keySeals), Name}, {good(), MarkName}},
		"no mark":           {{keyFD(seed(), keySeals), Name}},
		"a 16-byte mark":    {{keyFD(seed(), keySeals), Name}, {markFD(t, 16, markSeals), MarkName}},
		"a mark that grows": {{keyFD(seed(), keySeals), Name}, {markFD(t, MarkSize, unix.F_SEAL_SEAL|unix.F_SEAL_SHRINK), MarkName}},
		"an unsealed mark":  {{keyFD(seed(), keySeals), Name}, {markFD(t, MarkSize, 0), MarkName}},
	} {
		if r, err := restore(list); err == nil || r != nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// Without the key there is nothing to restore (a mark alone is dropped).
func TestRestoreIgnoresOtherNames(t *testing.T) {
	fd, err := memfd(Name, seed(), keySeals)
	if err != nil {
		t.Fatal(err)
	}
	r, err := restore([]passed{{fd, "other"}, {markFD(t, MarkSize, markSeals), MarkName}})
	if err != nil || r != nil {
		t.Fatalf("%v %v", r, err)
	}
}

func TestMarkEncoding(t *testing.T) {
	fd := markFD(t, MarkSize, markSeals)
	m := &Mark{fd: fd}
	for _, v := range []int64{NoMark, -1, 0, 1795000000000, 1<<63 - 1} {
		if err := m.Set(v); err != nil {
			t.Fatal(err)
		}
		var raw [MarkSize]byte
		_, _ = unix.Pread(fd, raw[:], 0)
		if got, _ := m.Load(); got != v || int64(binary.LittleEndian.Uint64(raw[:])) != v {
			t.Fatalf("%d read back as %d", v, got)
		}
	}
}

// LISTEN_FDS counts only for the process LISTEN_PID names.
func TestListenFDs(t *testing.T) {
	pid := os.Getpid()
	env := map[string]string{"LISTEN_PID": strconv.Itoa(pid), "LISTEN_FDS": "2", "LISTEN_FDNAMES": "a:" + Name}
	got := listenFDs(func(k string) string { return env[k] }, pid)
	if len(got) != 2 || got[0] != (passed{3, "a"}) || got[1] != (passed{4, Name}) {
		t.Fatalf("%v", got)
	}
	if listenFDs(func(k string) string { return env[k] }, pid+1) != nil {
		t.Fatal("another process's descriptors were taken")
	}
	env["LISTEN_FDS"] = "x"
	if listenFDs(func(k string) string { return env[k] }, pid) != nil {
		t.Fatal("a malformed LISTEN_FDS was accepted")
	}
	if !strings.Contains(Name, "tdx-gate") || !strings.Contains(MarkName, "tdx-gate") {
		t.Fatal("name")
	}
}
