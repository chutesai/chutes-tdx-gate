package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/chutesai/chutes-tdx-gate/pkg/gate"
)

func TestIdentityFlags(t *testing.T) {
	static := &gate.Config{IdentitySource: "static"}
	metadata := &gate.Config{IdentitySource: "gce-metadata"}
	if checkIdentityFlags(static, false) == nil {
		t.Fatal("a static identity served without --test-identity")
	}
	if checkIdentityFlags(metadata, true) == nil {
		t.Fatal("--test-identity accepted with the metadata identity")
	}
	if err := checkIdentityFlags(metadata, false); (err != nil) != faketsmBuild {
		t.Fatalf("metadata identity without --test-identity: %v", err)
	}
	if err := checkIdentityFlags(static, true); err != nil {
		t.Fatal(err)
	}
}

// The memory budget must hold one request at the configured limits.
func TestCheckBudget(t *testing.T) {
	cfg := &gate.Config{Limits: gate.Limits{MaxRequestBytes: 8454144, MaxPlaintextBytes: 64 << 20, MaxAnswerBytes: 16 << 20}}
	if checkBudget(cfg, 512<<20) != nil {
		t.Fatal("the unit's 512 MiB was refused")
	}
	if checkBudget(cfg, 64<<20) == nil {
		t.Fatal("a budget smaller than one request was accepted")
	}
}

// reportdata prints the rule's value for the vectors' cases.
func TestReportdataCommand(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "spec", "vectors", "reportdata.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []struct {
			NonceHex      string `json:"nonce_hex"`
			PublicKey     string `json:"public_key"`
			ReportDataHex string `json:"report_data_hex"`
		} `json:"cases"`
		Keys map[string]struct {
			PublicKey string `json:"public_key_b64"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for i, c := range v.Cases {
		path := filepath.Join(dir, "pk")
		data := []byte(v.Keys[c.PublicKey].PublicKey)
		if i%2 == 1 {
			data, _ = base64.StdEncoding.DecodeString(v.Keys[c.PublicKey].PublicKey)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		out := captureStdout(t, func() error { return reportdata([]string{"--nonce", c.NonceHex, "--public-key-file", path}) })
		if out != c.ReportDataHex+"\n" {
			t.Fatalf("case %d: %q", i, out)
		}
	}
}

func captureStdout(t *testing.T, f func() error) string {
	t.Helper()
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	err := f()
	w.Close()
	os.Stdout = old
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	return string(buf[:n])
}
