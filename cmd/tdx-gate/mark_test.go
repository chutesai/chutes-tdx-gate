package main

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chutesai/chutes-tdx-gate/internal/fakequote"
	"github.com/chutesai/chutes-tdx-gate/pkg/e2ev2"
	"github.com/chutesai/chutes-tdx-gate/pkg/gate"
)

type fakeMark struct {
	value int64
	sets  []int64
}

func (m *fakeMark) Load() (int64, error) { return m.value, nil }
func (m *fakeMark) Set(v int64) error    { m.value = v; m.sets = append(m.sets, v); return nil }

const (
	endpoint = "6b1c0e7e-4d0b-4f2a-9a57-1f3d2c8b9e40"
	instance = "5813945712345678901"
)

func markGate(t *testing.T, key *e2ev2.Key, now time.Time) (*gate.Gate, *httptest.Server) {
	t.Helper()
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) }))
	t.Cleanup(app.Close)
	cfg := &gate.Config{Listen: "0.0.0.0:8080", AppBase: app.URL, AppHealthPath: "/health", AppTimeoutS: 5, HealthPath: "/health",
		Routes:         []e2ev2.Route{{Path: "/v1/compress", AppPath: "/v1/compress"}},
		IdentitySource: "static", StaticEndpointID: endpoint, StaticInstanceID: instance,
		Limits:       gate.Limits{MaxRequestBytes: 8454144, MaxPlaintextBytes: 64 << 20, MaxAnswerBytes: 1 << 20, MaxInflight: 8, ReplayCacheEntries: 65536},
		TsmReportDir: "/sys/kernel/config/tsm/report"}
	g := gate.New(cfg, key, &fakequote.Quoter{}, gate.WithClock(func() time.Time { return now }))
	srv := httptest.NewServer(g.Handler())
	t.Cleanup(srv.Close)
	return g, srv
}

func sealed(t *testing.T, key *e2ev2.Key, ts int64) []byte {
	t.Helper()
	seed := make([]byte, 64)
	_, _ = rand.Read(seed)
	dk, _ := mlkem.NewDecapsulationKey768(seed)
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	env, _ := json.Marshal(map[string]any{"v": 2, "endpoint_id": endpoint, "instance_id": instance, "path": "/v1/compress",
		"stream": false, "nonce": base64.RawURLEncoding.EncodeToString(nonce), "ts": ts,
		"e2e_response_pk": base64.StdEncoding.EncodeToString(dk.EncapsulationKey().Bytes()), "body": map[string]any{}})
	blob, err := e2ev2.SealRequest(key.PublicKey(), env)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func post(t *testing.T, srv *httptest.Server, blob []byte) int {
	t.Helper()
	resp, err := http.Post(srv.URL+"/v1/compress", "application/octet-stream", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// serve's wiring of the stored mark: the first start persists each admission that raises the mark;
// a restarted start (clock stepped back) refuses the previous process's request and serves above
// the mark.
func TestKeepMark(t *testing.T) {
	key, _ := e2ev2.GenerateKey()
	t0 := time.UnixMilli(1795000000000)
	mark := &fakeMark{value: math.MinInt64}
	g, srv := markGate(t, key, t0)
	if _, err := keepMark(g, mark, false, t0.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	old := sealed(t, key, t0.UnixMilli()+50_000)
	if status := post(t, srv, old); status != 201 {
		t.Fatalf("status %d", status)
	}
	if mark.value != t0.UnixMilli()+50_000 || len(mark.sets) != 1 {
		t.Fatalf("mark %d, sets %v", mark.value, mark.sets)
	}
	// Restart 20 s earlier by the clock, then the clock reaches t0 again.
	g2, srv2 := markGate(t, key, t0)
	floor, err := keepMark(g2, mark, true, t0.UnixMilli()-20_000)
	if err != nil || floor != t0.UnixMilli()+50_000 {
		t.Fatalf("floor %d: %v", floor, err)
	}
	if status := post(t, srv2, old); status != 400 {
		t.Fatalf("the previous process's request was served again: %d", status)
	}
	if status := post(t, srv2, sealed(t, key, t0.UnixMilli()+50_001)); status != 201 {
		t.Fatalf("status %d", status)
	}
	if mark.value != t0.UnixMilli()+50_001 {
		t.Fatalf("mark %d", mark.value)
	}
	// A mark that cannot be read stops serve.
	if _, err := keepMark(g2, badMark{}, true, 0); err == nil {
		t.Fatal("an unreadable mark was accepted")
	}
}

type badMark struct{}

func (badMark) Load() (int64, error) { return 0, errors.New("no") }
func (badMark) Set(int64) error      { return nil }
