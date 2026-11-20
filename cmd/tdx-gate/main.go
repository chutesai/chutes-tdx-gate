// Command tdx-gate serves an endpoint VM's /attest, health pass-through and E2E v2 routes in front
// of a plaintext application on loopback (spec/SPEC.md).
//
//	tdx-gate serve --config PATH [--memory-budget BYTES] [--test-identity]
//	tdx-gate check-config --config PATH
//	tdx-gate reportdata --nonce HEX --public-key-file PATH
//	tdx-gate selftest --vectors DIR
//	tdx-gate version
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/chutesai/chutes-tdx-gate/internal/keystore"
	"github.com/chutesai/chutes-tdx-gate/pkg/attest"
	"github.com/chutesai/chutes-tdx-gate/pkg/conformance"
	"github.com/chutesai/chutes-tdx-gate/pkg/e2ev2"
	"github.com/chutesai/chutes-tdx-gate/pkg/gate"
)

// Version is the release; the commit is not embedded so that a build from a source archive gives
// the same bytes as one from git (compare the binary's sha256 with the release notes instead).
const Version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "check-config":
		err = checkConfig(os.Args[2:])
	case "reportdata":
		err = reportdata(os.Args[2:])
	case "selftest":
		err = selftest(os.Args[2:])
	case "version":
		err = version()
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tdx-gate:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tdx-gate serve --config PATH [--memory-budget BYTES] | check-config --config PATH | reportdata --nonce HEX --public-key-file PATH | selftest --vectors DIR | version")
	os.Exit(2)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("config", "", "configuration file (chutes.tdx-gate-config.v1)")
	budget := fs.Int64("memory-budget", e2ev2.DefaultBudget, "bytes all in-flight requests may hold together; over it they are refused e2e_v2_busy")
	testIdentity := fs.Bool("test-identity", false, "accept a static identity (tests only; never in an image)")
	_ = fs.Parse(args)
	cfg, err := gate.LoadConfig(*path)
	if err != nil {
		return err
	}
	if err := checkIdentityFlags(cfg, *testIdentity); err != nil {
		return err
	}
	if err := checkBudget(cfg, *budget); err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	key, mark, restored, err := perBootKey(logger)
	if err != nil {
		return err
	}
	g := gate.New(cfg, key, quoter(cfg), gate.WithLogger(logger), gate.WithBudget(*budget))
	if mark != nil {
		floor, err := keepMark(g, mark, restored, time.Now().UnixMilli())
		if err != nil {
			return err
		}
		if restored {
			logger.Info("the per-boot key outlived a restart of the gate; requests stamped at or before the floor are refused stale",
				"floor_ms", floor)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if cfg.IdentitySource == "gce-metadata" {
		go g.LoadIdentity(ctx, gate.NewMetadata(gate.MetadataBase))
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           g.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          nil,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	logger.Info("serving", "listen", cfg.Listen, "routes", len(cfg.Routes), "version", Version)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}

// marker is the stored high-water mark of admitted timestamps (keystore.Mark).
type marker interface {
	Load() (int64, error)
	Set(int64) error
}

// keepMark wires the stored mark into g: every admission that raises it writes it first, and after
// a restart (the previous process's admitted nonces gone) every ts at or below it, or before now
// plus the future window, is refused. It returns that floor (meaningful when restored).
func keepMark(g *gate.Gate, mark marker, restored bool, nowMS int64) (int64, error) {
	high, err := mark.Load()
	if err != nil {
		return 0, err
	}
	g.PersistAdmitted(mark.Set, high)
	if !restored {
		return 0, nil
	}
	return g.RestoredAt(nowMS, high), nil
}

// checkBudget refuses a memory budget that cannot hold one request at the configured limits.
func checkBudget(cfg *gate.Config, budget int64) error {
	if minimum := gate.MinBudget(cfg.Limits); budget < minimum {
		return fmt.Errorf("--memory-budget %d cannot hold one request at the configured limits (%d bytes)", budget, minimum)
	}
	return nil
}

// perBootKey is the boot's ML-KEM key and its high-water mark: the ones systemd's file descriptor
// store handed back after a restart of the gate, or a new key (its seed and a new mark handed to
// the store, under systemd; no mark otherwise).
func perBootKey(logger *slog.Logger) (*e2ev2.Key, *keystore.Mark, bool, error) {
	back, err := keystore.Restore()
	if err != nil {
		return nil, nil, false, err
	}
	var seed []byte
	var mark *keystore.Mark
	if back != nil {
		seed, mark = back.Seed, back.Mark
	} else {
		seed = make([]byte, keystore.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, nil, false, err
		}
	}
	defer clear(seed)
	key, err := e2ev2.KeyFromSeed(seed)
	if err != nil {
		return nil, nil, false, err
	}
	if back == nil {
		if mark, err = keystore.Store(seed); err != nil {
			// Serving on: a restart would then make a new key, and the validator replaces the VM.
			logger.Error("the key is not in systemd's file descriptor store", "error", err.Error())
		} else if mark == nil {
			logger.Info("not started by systemd: a restart of the gate makes a new key")
		}
	}
	return key, mark, back != nil, nil
}

// checkIdentityFlags: a static identity is accepted only with --test-identity (never in an image),
// and a faketsm test build serves only with it.
func checkIdentityFlags(cfg *gate.Config, testIdentity bool) error {
	if cfg.IdentitySource == "static" && !testIdentity {
		return errors.New("a static identity needs serve --test-identity (tests only)")
	}
	if cfg.IdentitySource != "static" && testIdentity {
		return errors.New("--test-identity needs a static identity in the configuration")
	}
	return testBuildGuard(testIdentity)
}

func checkConfig(args []string) error {
	fs := flag.NewFlagSet("check-config", flag.ExitOnError)
	path := fs.String("config", "", "configuration file")
	_ = fs.Parse(args)
	cfg, err := gate.LoadConfig(*path)
	if err != nil {
		return err
	}
	fmt.Printf("ok: listen %s, %d route(s), health %s, identity %s\n", cfg.Listen, len(cfg.Routes), cfg.HealthPath, cfg.IdentitySource)
	return nil
}

func reportdata(args []string) error {
	fs := flag.NewFlagSet("reportdata", flag.ExitOnError)
	nonceHex := fs.String("nonce", "", "the 32-byte nonce, 64 lower-case hex characters")
	keyPath := fs.String("public-key-file", "", "the ML-KEM-768 public key: 1184 raw bytes or its base64")
	_ = fs.Parse(args)
	nonce, err := attest.ParseNonceQuery("nonce=" + *nonceHex)
	if err != nil {
		return errors.New("--nonce must be 64 lower-case hex characters")
	}
	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		return err
	}
	if len(raw) != attest.PublicKeySize {
		raw, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(raw) != attest.PublicKeySize {
			return errors.New("--public-key-file must hold 1184 bytes or their base64")
		}
	}
	rd := attest.ReportData(nonce, raw)
	fmt.Println(hex.EncodeToString(rd[:]))
	return nil
}

func selftest(args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ExitOnError)
	dir := fs.String("vectors", "spec/vectors", "the vectors directory")
	_ = fs.Parse(args)
	results, err := conformance.Run(*dir)
	if err != nil {
		return err
	}
	failed := 0
	for _, r := range results {
		fmt.Printf("%-18s %4d passed, %d failed\n", r.Group, r.Passed, len(r.Failures))
		for _, f := range r.Failures {
			fmt.Println("  FAIL:", f)
		}
		failed += len(r.Failures)
	}
	if failed > 0 {
		return fmt.Errorf("%d vector check(s) failed", failed)
	}
	fmt.Println("all vectors pass")
	return nil
}

func version() error {
	exe, err := os.Executable()
	sum := "unknown"
	if err == nil {
		if raw, err := os.ReadFile(exe); err == nil {
			h := sha256.Sum256(raw)
			sum = hex.EncodeToString(h[:])
		}
	}
	fmt.Printf("tdx-gate %s (%s %s/%s%s)\nbinary sha256 %s\ncommit not embedded: compare the sha256 with the release notes\n",
		Version, runtime.Version(), runtime.GOOS, runtime.GOARCH, buildNote, sum)
	return nil
}
