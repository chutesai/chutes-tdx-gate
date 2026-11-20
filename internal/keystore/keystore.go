//go:build linux

// Package keystore keeps the gate's per-boot key, and the highest request timestamp it admitted,
// across a restart of the gate within one boot.
//
// The spec requires one ML-KEM-768 key pair per boot (spec section 4.1). The unit restarts
// the gate when it fails (Restart=on-failure, an out-of-memory kill included); a new key at that
// point would break the binding the validator recorded and get the VM replaced. So the key's
// 64-byte seed is put, once, in a sealed memfd that the gate hands to systemd's file descriptor
// store (FileDescriptorStoreMax=2, NotifyAccess=main); systemd passes it back to the next start
// of the unit (LISTEN_FDS). It stays in memory: no file is written, nothing survives the boot, and
// the seals forbid any change to its bytes.
//
// Beside it sits the mark: an 8-byte memfd (fixed size, writable) holding the highest ts the gate
// admitted, written before each admission that raises it. A restarted gate refuses every ts at or
// below the mark, so a nonce the previous process admitted can never be admitted again, whatever
// the clock did in between.
package keystore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Name is the stored key's name (FDNAME).
const Name = "tdx-gate-key"

// MarkName is the stored mark's name (FDNAME).
const MarkName = "tdx-gate-mark"

// SeedSize is the key's seed: ML-KEM-768's d || z.
const SeedSize = 64

// MarkSize is the mark: one int64, little-endian.
const MarkSize = 8

// NoMark is the mark before anything was admitted.
const NoMark = math.MinInt64

const (
	keySeals  = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	markSeals = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW
)

// Mark is the stored high-water mark of admitted timestamps.
type Mark struct{ fd int }

// Load reads the mark.
func (m *Mark) Load() (int64, error) {
	var buf [MarkSize]byte
	if n, err := unix.Pread(m.fd, buf[:], 0); err != nil || n != MarkSize {
		return 0, errors.New("keystore: the stored mark cannot be read")
	}
	return int64(binary.LittleEndian.Uint64(buf[:])), nil
}

// Set writes the mark (before the admission it covers).
func (m *Mark) Set(ts int64) error {
	var buf [MarkSize]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(ts))
	if n, err := unix.Pwrite(m.fd, buf[:], 0); err != nil || n != MarkSize {
		return errors.New("keystore: the mark cannot be written")
	}
	return nil
}

// Restored is what systemd handed back to this start.
type Restored struct {
	Seed []byte
	Mark *Mark
}

type passed struct {
	fd   int
	name string
}

// Restore returns the seed and the mark systemd passed back to this start, or nil when there is no
// seed (the first start of the boot, or no systemd). A seed without a valid mark is an error. Every
// other descriptor is closed and LISTEN_* unset.
func Restore() (*Restored, error) {
	list := listenFDs(os.Getenv, os.Getpid())
	for _, k := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		_ = os.Unsetenv(k)
	}
	return restore(list)
}

// listenFDs reads sd_listen_fds' variables: only for this process.
func listenFDs(getenv func(string) string, pid int) []passed {
	if getenv("LISTEN_PID") != strconv.Itoa(pid) {
		return nil
	}
	n, err := strconv.Atoi(getenv("LISTEN_FDS"))
	if err != nil || n < 1 || n > 64 {
		return nil
	}
	names := strings.Split(getenv("LISTEN_FDNAMES"), ":")
	list := make([]passed, n)
	for i := range list {
		list[i].fd = 3 + i
		if i < len(names) {
			list[i].name = names[i]
		}
	}
	return list
}

// restore reads the seed from the descriptor named Name (a memfd of exactly SeedSize bytes, sealed
// against any change) and keeps the one named MarkName (MarkSize bytes, sealed against any change
// of size, writable). Every other passed descriptor is closed.
func restore(list []passed) (*Restored, error) {
	keyFD, markFD := -1, -1
	for _, p := range list {
		switch {
		case p.name == Name && keyFD < 0:
			keyFD = p.fd
		case p.name == MarkName && markFD < 0:
			markFD = p.fd
		default:
			_ = unix.Close(p.fd)
		}
	}
	if keyFD < 0 {
		if markFD >= 0 {
			_ = unix.Close(markFD)
		}
		return nil, nil
	}
	seed, err := readSealed(keyFD)
	_ = unix.Close(keyFD)
	if err == nil && markFD < 0 {
		err = errors.New("keystore: the stored key has no mark")
	}
	if err == nil {
		err = checkMark(markFD)
	}
	if err != nil {
		if markFD >= 0 {
			_ = unix.Close(markFD)
		}
		return nil, err
	}
	return &Restored{Seed: seed, Mark: &Mark{fd: markFD}}, nil
}

func readSealed(fd int) ([]byte, error) {
	got, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil || got&keySeals != keySeals {
		return nil, errors.New("keystore: the stored key is not a sealed memfd")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Size != SeedSize {
		return nil, errors.New("keystore: the stored key is not 64 bytes")
	}
	seed := make([]byte, SeedSize)
	if n, err := unix.Pread(fd, seed, 0); err != nil || n != SeedSize {
		return nil, errors.New("keystore: the stored key cannot be read")
	}
	return seed, nil
}

func checkMark(fd int) error {
	got, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if err != nil || got&markSeals != markSeals {
		return errors.New("keystore: the stored mark is not a fixed-size memfd")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Size != MarkSize {
		return errors.New("keystore: the stored mark is not 8 bytes")
	}
	return nil
}

// Store hands the mark (NoMark) and then the seed, each in its memfd, to systemd's file descriptor
// store, and returns the mark to keep current. Without NOTIFY_SOCKET (not started by systemd) it
// stores nothing and returns nil: a restart then makes a new key.
func Store(seed []byte) (*Mark, error) {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil, nil
	}
	if len(seed) != SeedSize {
		return nil, errors.New("keystore: a seed is 64 bytes")
	}
	var initial [MarkSize]byte
	noMark := int64(NoMark)
	binary.LittleEndian.PutUint64(initial[:], uint64(noMark))
	markFD, err := memfd(MarkName, initial[:], markSeals)
	if err != nil {
		return nil, err
	}
	// The mark first: a store holding the key always holds its mark.
	if err := notifyWithFD(socket, "FDSTORE=1\nFDNAME="+MarkName, markFD); err != nil {
		_ = unix.Close(markFD)
		return nil, err
	}
	keyFD, err := memfd(Name, seed, keySeals)
	if err != nil {
		_ = unix.Close(markFD)
		return nil, err
	}
	defer unix.Close(keyFD)
	if err := notifyWithFD(socket, "FDSTORE=1\nFDNAME="+Name, keyFD); err != nil {
		_ = unix.Close(markFD)
		return nil, err
	}
	return &Mark{fd: markFD}, nil
}

// memfd is the one place a stored memfd is filled: data into anonymous memory, then sealed.
func memfd(name string, data []byte, seals int) (int, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return -1, fmt.Errorf("keystore: memfd_create: %w", err)
	}
	if n, err := unix.Write(fd, data); err != nil || n != len(data) {
		_ = unix.Close(fd)
		return -1, errors.New("keystore: writing the memfd failed")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS, seals); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("keystore: sealing the memfd: %w", err)
	}
	return fd, nil
}

// notifyWithFD sends one sd_notify message with fd attached (SCM_RIGHTS) from an unbound datagram
// socket. An address starting with @ is in the abstract namespace.
func notifyWithFD(socket, state string, fd int) error {
	s, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("keystore: socket: %w", err)
	}
	defer unix.Close(s)
	if err := unix.Sendmsg(s, []byte(state), unix.UnixRights(fd), &unix.SockaddrUnix{Name: socket}, 0); err != nil {
		return fmt.Errorf("keystore: sd_notify: %w", err)
	}
	return nil
}
