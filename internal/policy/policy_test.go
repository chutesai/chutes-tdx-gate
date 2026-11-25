package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var root = filepath.Join("..", "..")

// The gate writes exactly one file, configfs-tsm's inblob in pkg/attest/tsm.go, and in
// internal/keystore two memfds of anonymous memory: the key's seed once into a sealed one and the
// high-water mark of admitted timestamps into a fixed-size one (memfd_create, the one write that
// fills each, the mark's pwrite, and the sd_notify message that hands a descriptor, not its
// content, to systemd). Any other write call site (the ML-KEM key written to disk, say) fails this
// test.
func TestOnlyTheInblobIsWritten(t *testing.T) {
	writes := regexp.MustCompile(`os\.(WriteFile|Create|CreateTemp|OpenFile|MkdirTemp|Symlink|Link|Rename|Chmod|Truncate)\(|ioutil\.WriteFile|\.WriteString\(.*os\.|syscall\.(Open|Write|Creat|Pwrite)|unix\.(Open|Write|Pwrite|Creat|MemfdCreate|Sendmsg|Mmap)\(`)
	allowed := map[string]int{filepath.Join("pkg", "attest", "tsm.go"): 1, filepath.Join("internal", "keystore", "keystore.go"): 4}
	found := map[string]int{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if info.IsDir() && (rel == "vendor" || rel == "out" || rel == "python" || rel == "crosstest" || rel == "mutants" || strings.HasPrefix(rel, ".")) && rel != "." {
			return filepath.SkipDir
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if n := len(writes.FindAll(raw, -1)); n > 0 {
			found[rel] = n
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for file, n := range found {
		if allowed[file] != n {
			t.Errorf("%s: %d file-write call site(s); only the inblob write in pkg/attest/tsm.go is allowed", file, n)
		}
	}
	if found[filepath.Join("pkg", "attest", "tsm.go")] != 1 {
		t.Error("the inblob write was not found where expected")
	}
}

// The key never leaves the process: the gate exposes no way to read its decapsulation key.
func TestNoKeyExport(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(root, "pkg", "e2ev2", "crypto.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "dk.Bytes()") {
		t.Error("pkg/e2ev2 reads the decapsulation key's seed")
	}
}

func TestUnitHardening(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(root, "deploy", "systemd", "tdx-gate.service"))
	if err != nil {
		t.Fatal(err)
	}
	unit := string(raw)
	for _, line := range []string{
		"LimitCORE=0", "NoNewPrivileges=yes", "CapabilityBoundingSet=\n", "ProtectSystem=strict",
		"ReadWritePaths=/sys/kernel/config/tsm/report\n", "MemoryDenyWriteExecute=yes",
		"ExecStart=/usr/local/bin/tdx-gate serve --config /etc/tdx-gate/config.json --memory-budget 536870912\n",
		// Restarted on failure with the same key (the fd store), bounded in memory.
		"Restart=on-failure\n", "NotifyAccess=main\n", "FileDescriptorStoreMax=2\n", "MemoryMax=1G\n", "MemorySwapMax=0\n",
	} {
		if !strings.Contains(unit, line) {
			t.Errorf("the unit lacks %q", strings.TrimSpace(line))
		}
	}
	for _, bad := range []string{"--test-identity", "PrivateTmp=", "Restart=always"} {
		if strings.Contains(unit, bad) {
			t.Errorf("the unit has %q", bad)
		}
	}
}
