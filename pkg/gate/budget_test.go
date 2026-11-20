package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chutesai/chutes-tdx-gate/pkg/e2ev2"
)

// rawEnvelope is env with its body replaced by raw JSON bytes (a body too large to build as a map).
func rawEnvelope(t *testing.T, env map[string]any, body []byte) []byte {
	t.Helper()
	env["body"] = map[string]any{}
	head, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.LastIndex(head, []byte(`"body":{}`))
	out := make([]byte, 0, len(head)+len(body))
	out = append(append(append(out, head[:i+len(`"body":`)]...), body...), head[i+len(`"body":{}`):]...)
	return out
}

func (f *fixture) sealRaw(t *testing.T, path string, body []byte) *request {
	t.Helper()
	env, seed := f.envelope(path, false, nil)
	raw := rawEnvelope(t, env, body)
	blob, err := e2ev2.SealRequest(f.g.PublicKey(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return &request{envelope: env, seed: seed, blob: blob}
}

// zeros is a body of n bytes: {"x":[0,0,...]}, a gzip bomb of about a million values per 2 MiB.
func zeros(n int) []byte {
	head, tail := `{"x":[`, `0]}`
	body := make([]byte, 0, n)
	body = append(body, head...)
	body = append(body, bytes.Repeat([]byte("0,"), (n-len(head)-len(tail))/2)...)
	return append(body, tail...)
}

// bigString is a body of about n bytes: {"s":"xxx..."}.
func bigString(n int) []byte {
	return []byte(`{"s":"` + strings.Repeat("x", n-8) + `"}`)
}

func newBudgetFixture(t *testing.T, app http.Handler, budget int64) *fixture {
	t.Helper()
	f := newFixture(t, app, nil)
	f.g = New(f.g.cfg, f.g.key, f.quoter, WithClock(func() time.Time { return f.now }), WithBudget(budget))
	f.srv.Close()
	f.srv = httptest.NewServer(f.g.Handler())
	t.Cleanup(f.srv.Close)
	return f
}

func allocated() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.TotalAlloc
}

// A 64 MiB-plaintext request (a 64 KiB gzip bomb of zeros) is refused, the gate holding at most
// its budget: the plaintext is reserved from the gzip trailer before it is inflated, and the
// parse stops at a million values without building any.
func TestGzipBombWithinBudget(t *testing.T) {
	f := newBudgetFixture(t, echoApp(), e2ev2.DefaultBudget)
	r := f.sealRaw(t, "/v1/compress", zeros(64<<20-4096))
	if len(r.blob) > 1<<20 {
		t.Fatalf("the bomb is %d bytes", len(r.blob))
	}
	runtime.GC()
	before := allocated()
	expectRefusal(t, f.post(t, "/v1/compress", r.blob, nil), 400, "e2e_v2_malformed")
	used := allocated() - before
	b := f.g.Budget()
	if b.Peak() > b.Max() || b.Peak() < 64<<20-4096 || b.Used() != 0 {
		t.Fatalf("peak %d, used %d, budget %d", b.Peak(), b.Used(), b.Max())
	}
	if used > uint64(b.Peak())+16<<20 {
		t.Fatalf("the request allocated %d bytes, the budget held %d", used, b.Peak())
	}
}

// A plaintext one byte over max_plaintext_bytes is refused from its gzip trailer: nothing is
// inflated or reserved for it.
func TestPlaintextOverLimitNotInflated(t *testing.T) {
	f := newBudgetFixture(t, echoApp(), e2ev2.DefaultBudget)
	env, seed := f.envelope("/v1/compress", false, nil)
	raw := rawEnvelope(t, env, []byte(`{}`))
	raw = append(raw[:len(raw)-1], []byte(`,"pad":"`+strings.Repeat("x", 64<<20-len(raw)-8)+`"}`)...)
	if len(raw) != 64<<20+1 {
		t.Fatalf("%d", len(raw))
	}
	blob, _ := e2ev2.SealRequest(f.g.PublicKey(), raw)
	expectRefusal(t, f.post(t, "/v1/compress", blob, nil), 400, "e2e_v2_malformed")
	if peak := f.g.Budget().Peak(); peak > 2<<20 {
		t.Fatalf("the refused plaintext reserved %d bytes", peak)
	}
	_ = seed
}

// A request that needs more than the whole budget could never be admitted: e2e_v2_malformed,
// before it is inflated.
func TestBudgetNeverFits(t *testing.T) {
	f := newBudgetFixture(t, echoApp(), 32<<20)
	expectRefusal(t, f.post(t, "/v1/compress", f.sealRaw(t, "/v1/compress", bigString(60<<20)).blob, nil), 400, "e2e_v2_malformed")
	if b := f.g.Budget(); b.Peak() > 1<<20 || b.Used() != 0 {
		t.Fatalf("peak %d used %d", b.Peak(), b.Used())
	}
}

// The default budget admits a large legitimate body (one long string) and forwards it whole.
func TestBudgetAdmitsLargeBody(t *testing.T) {
	got := make(chan int, 1)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		got <- int(n)
		w.WriteHeader(200)
	})
	f := newBudgetFixture(t, app, e2ev2.DefaultBudget)
	body := bigString(60 << 20)
	r := f.sealRaw(t, "/v1/compress", body)
	if status, _ := openSealed(t, r, f.post(t, "/v1/compress", r.blob, nil)); status != 200 {
		t.Fatalf("status %d", status)
	}
	if n := <-got; n != len(body) {
		t.Fatalf("the app got %d bytes of %d", n, len(body))
	}
	if b := f.g.Budget(); b.Peak() > b.Max() || b.Used() != 0 {
		t.Fatalf("peak %d used %d", b.Peak(), b.Used())
	}
}

// Requests in flight share the budget: with room for two large ones, a third is busy.
func TestBudgetShared(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 3)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		entered <- struct{}{}
		<-release
		w.WriteHeader(200)
	})
	f := newBudgetFixture(t, app, 100<<20)
	reqs := []*request{f.sealRaw(t, "/v1/compress", bigString(40<<20)), f.sealRaw(t, "/v1/compress", bigString(40<<20))}
	var wg sync.WaitGroup
	for _, r := range reqs {
		wg.Add(1)
		go func(r *request) {
			defer wg.Done()
			resp := f.post(t, "/v1/compress", r.blob, nil)
			readAll(t, resp)
		}(r)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(20 * time.Second):
			close(release)
			t.Fatal("the two requests the budget holds did not reach the application")
		}
	}
	third := f.sealRaw(t, "/v1/compress", bigString(40<<20))
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/v1/compress", bytes.NewReader(third.blob))
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req) // admitted, it would wait for release
	if err != nil {
		close(release)
		t.Fatalf("a request over the budget was not refused at once: %v", err)
	}
	if resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("Retry-After %q", resp.Header.Get("Retry-After"))
	}
	expectRefusal(t, resp, 503, "e2e_v2_busy")
	close(release)
	wg.Wait()
	if b := f.g.Budget(); b.Peak() > 100<<20 || b.Used() != 0 {
		t.Fatalf("peak %d used %d", b.Peak(), b.Used())
	}
}

// What SealAnswer allocates stays within SealCost, which the gate reserves before sealing.
func TestSealCost(t *testing.T) {
	f := newFixture(t, echoApp(), nil)
	env, seed := f.envelope("/v1/compress", false, map[string]any{})
	r := f.seal(t, env, seed)
	opened, ref := e2ev2.Open(f.g.key, r.blob, e2ev2.Params{PresentedPath: "/v1/compress", Method: "POST", Routes: f.g.routes,
		Identity: f.g.Identity(), Cache: e2ev2.NewReplayCache(0), NowMS: f.now.UnixMilli()})
	if ref != nil {
		t.Fatal(ref.Code)
	}
	body := make([]byte, 16<<20)
	for i := range body {
		body[i] = byte(i*7919 + i>>11) // little to compress
	}
	runtime.GC()
	before := allocated()
	blob, err := e2ev2.SealAnswer(opened, 200, body)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 0, len(blob)*4/3+16)
	_ = append(out, blob...)
	if used := allocated() - before; int64(used) > e2ev2.SealCost(len(body)) {
		t.Fatalf("sealing %d bytes allocated %d, SealCost %d", len(body), used, e2ev2.SealCost(len(body)))
	}
}

// The request's body is reserved as it is read: by its Content-Length, or in doubling buffers
// when it is chunked; the opened plaintext too.
func TestRequestBodyCharged(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		f := newBudgetFixture(t, echoApp(), e2ev2.DefaultBudget)
		body := bytes.Repeat([]byte{7}, 4<<20)
		var reader io.Reader = bytes.NewReader(body)
		if chunked {
			reader = io.MultiReader(reader) // no length: sent chunked
		}
		req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/v1/compress", reader)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		expectRefusal(t, resp, 400, "e2e_v2_undecryptable")
		if b := f.g.Budget(); b.Peak() < 2*int64(len(body)) || b.Used() != 0 {
			t.Fatalf("chunked %v: peak %d used %d", chunked, b.Peak(), b.Used())
		}
	}
}

// The application's answer is reserved as it is read, and its sealing before it is sealed.
func TestAnswerCharged(t *testing.T) {
	answer := bytes.Repeat([]byte("a"), 8<<20)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(answer) })
	f := newBudgetFixture(t, app, e2ev2.DefaultBudget)
	f.g.cfg.Limits.MaxAnswerBytes = 16 << 20
	env, seed := f.envelope("/v1/compress", false, map[string]any{})
	r := f.seal(t, env, seed)
	if _, plain := openSealed(t, r, f.post(t, "/v1/compress", r.blob, nil)); len(plain) != len(answer) {
		t.Fatal("answer")
	}
	if b := f.g.Budget(); b.Peak() < int64(len(answer))+e2ev2.SealCost(len(answer)) || b.Used() != 0 {
		t.Fatalf("peak %d used %d", b.Peak(), b.Used())
	}
}

// An envelope with a great many top-level members is refused at its tenth member: nothing is
// built for the rest (the parse would otherwise build a value per member before the closed-key
// check, more than it reserves).
func TestManyTopLevelMembers(t *testing.T) {
	f := newBudgetFixture(t, echoApp(), e2ev2.DefaultBudget)
	env, seed := f.envelope("/v1/compress", false, map[string]any{})
	raw, _ := json.Marshal(env)
	var extra bytes.Buffer
	for i := 0; i < 900_000; i++ {
		fmt.Fprintf(&extra, `,"x%d":0`, i)
	}
	raw = append(append(raw[:len(raw)-1], extra.Bytes()...), '}')
	blob, _ := e2ev2.SealRequest(f.g.PublicKey(), raw)
	_ = seed
	runtime.GC()
	before := allocated()
	expectRefusal(t, f.post(t, "/v1/compress", blob, nil), 400, "e2e_v2_malformed")
	if used, peak := allocated()-before, f.g.Budget().Peak(); used > uint64(peak)+16<<20 {
		t.Fatalf("the request allocated %d bytes, the budget held %d", used, peak)
	}
}

// MinBudget is enough for one request at the example configuration's limits, and far below 512 MiB.
func TestMinBudget(t *testing.T) {
	c, err := ParseConfig([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	if m := MinBudget(c.Limits); m > e2ev2.DefaultBudget/2 || m < c.Limits.MaxPlaintextBytes {
		t.Fatalf("MinBudget %d", m)
	}
}

// An application status that HTTP sends without a body (204, 304) cannot carry a sealed answer:
// e2e_v2_app_failed on every route (spec section 4.3).
func TestBodylessStatusIsAppFailed(t *testing.T) {
	for _, status := range []int{204, 304} {
		app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })
		f := newFixture(t, app, nil)
		env, seed := f.envelope("/v1/compress", false, map[string]any{})
		expectRefusal(t, f.post(t, "/v1/compress", f.seal(t, env, seed).blob, nil), 502, "e2e_v2_app_failed")
		env, seed = f.envelope("/v1/stream", true, map[string]any{"stream": true})
		expectRefusal(t, f.post(t, "/v1/stream", f.seal(t, env, seed).blob, nil), 502, "e2e_v2_app_failed")
	}
}

// After a restart that kept the key, every ts up to the restart plus 60 s is refused stale; a
// request stamped after it is served.
func TestRestartClosesTheWindow(t *testing.T) {
	f := newFixture(t, echoApp(), nil)
	f.g.RestoredAt(f.now.UnixMilli(), math.MinInt64)
	for _, ts := range []int64{f.now.UnixMilli(), f.now.UnixMilli() + 60_000} {
		env, seed := f.envelope("/v1/compress", false, map[string]any{})
		env["ts"] = ts
		want, code := 400, "e2e_v2_stale"
		expectRefusal(t, f.post(t, "/v1/compress", f.seal(t, env, seed).blob, nil), want, code)
	}
	f.now = f.now.Add(61 * time.Second)
	env, seed := f.envelope("/v1/compress", false, map[string]any{})
	r := f.seal(t, env, seed)
	if status, _ := openSealed(t, r, f.post(t, "/v1/compress", r.blob, nil)); status != 201 {
		t.Fatalf("status %d", status)
	}
}

// restarted is the same gate (the same key) after a restart at now, with the stored mark.
func (f *fixture) restarted(t *testing.T, now time.Time, mark int64, persist func(int64) error) {
	t.Helper()
	f.now = now
	f.g = New(f.g.cfg, f.g.key, f.quoter, WithClock(func() time.Time { return f.now }))
	f.g.PersistAdmitted(persist, mark)
	f.g.RestoredAt(now.UnixMilli(), mark)
	f.srv.Close()
	f.srv = httptest.NewServer(f.g.Handler())
	t.Cleanup(f.srv.Close)
}

// The highest admitted ts is persisted before the admission, and a restarted gate refuses every ts
// at or below it, even after the clock stepped backward across the restart: a request the
// previous process admitted cannot be replayed.
func TestRestartMarkSurvivesClockStep(t *testing.T) {
	f := newFixture(t, echoApp(), nil)
	stored := int64(math.MinInt64)
	persist := func(ts int64) error { stored = ts; return nil }
	f.g.PersistAdmitted(persist, stored)
	t0 := f.now
	// The previous process admits a request stamped 50 s ahead of its clock.
	env, seed := f.envelope("/v1/compress", false, map[string]any{})
	env["ts"] = t0.UnixMilli() + 50_000
	old := f.seal(t, env, seed)
	if status, _ := openSealed(t, old, f.post(t, "/v1/compress", old.blob, nil)); status != 201 {
		t.Fatalf("status %d", status)
	}
	if stored != t0.UnixMilli()+50_000 {
		t.Fatalf("the mark is %d", stored)
	}
	// An older ts admitted later does not lower the mark.
	env2, seed2 := f.envelope("/v1/compress", false, map[string]any{})
	env2["ts"] = t0.UnixMilli() - 1_000
	r2 := f.seal(t, env2, seed2)
	openSealed(t, r2, f.post(t, "/v1/compress", r2.blob, nil))
	if stored != t0.UnixMilli()+50_000 {
		t.Fatalf("the mark went down to %d", stored)
	}
	// The gate restarts after the clock stepped back 20 s; then the clock runs on to t0. Without the
	// mark the floor would be t0 + 40 s and the old request admissible again.
	f.restarted(t, t0.Add(-20*time.Second), stored, persist)
	f.now = t0
	expectRefusal(t, f.post(t, "/v1/compress", old.blob, nil), 400, "e2e_v2_stale")
	// A new request above the mark is served.
	env3, seed3 := f.envelope("/v1/compress", false, map[string]any{})
	env3["ts"] = t0.UnixMilli() + 50_001
	r3 := f.seal(t, env3, seed3)
	if status, _ := openSealed(t, r3, f.post(t, "/v1/compress", r3.blob, nil)); status != 201 {
		t.Fatalf("status %d", status)
	}
	if stored != t0.UnixMilli()+50_001 {
		t.Fatalf("the mark is %d", stored)
	}
}

// A mark that cannot be written refuses the request busy, before the application and with its
// nonce unused.
func TestMarkWriteFailureIsBusy(t *testing.T) {
	calls := 0
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(201) })
	f := newFixture(t, app, nil)
	fail := true
	f.g.PersistAdmitted(func(int64) error {
		if fail {
			return errors.New("no")
		}
		return nil
	}, math.MinInt64)
	env, seed := f.envelope("/v1/compress", false, map[string]any{})
	r := f.seal(t, env, seed)
	resp := f.post(t, "/v1/compress", r.blob, nil)
	expectRefusal(t, resp, 503, "e2e_v2_busy")
	if calls != 0 {
		t.Fatal("the application ran")
	}
	fail = false
	if status, _ := openSealed(t, r, f.post(t, "/v1/compress", r.blob, nil)); status != 201 {
		t.Fatalf("the nonce was consumed by the refused request: %d", status)
	}
}

// Busy is answered only before the application runs: a stream's buffers are
// reserved with the request, and an answer the budget cannot hold after the application ran is
// e2e_v2_answer_too_large.
func TestBusyOnlyBeforeTheApplication(t *testing.T) {
	calls := 0
	big := bytes.Repeat([]byte("a"), 3<<20)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(200)
		_, _ = w.Write(big)
	})
	// The budget held by others: refused busy, the application not called.
	f := newBudgetFixture(t, app, 64<<20)
	other := f.g.Budget().Lease()
	other.Charge(64<<20 - 100<<10)
	env, seed := f.envelope("/v1/stream", true, map[string]any{"stream": true})
	expectRefusal(t, f.post(t, "/v1/stream", f.seal(t, env, seed).blob, nil), 503, "e2e_v2_busy")
	if calls != 0 {
		t.Fatal("the application ran before busy")
	}
	other.Release()
	// Room for the request but not for sealing the answer: the application ran, so 502.
	f2 := newBudgetFixture(t, app, 8<<20)
	f2.g.cfg.Limits.MaxAnswerBytes = 16 << 20
	env, seed = f2.envelope("/v1/compress", false, map[string]any{})
	expectRefusal(t, f2.post(t, "/v1/compress", f2.seal(t, env, seed).blob, nil), 502, "e2e_v2_answer_too_large")
	if calls != 1 {
		t.Fatalf("the application ran %d times", calls)
	}
}
