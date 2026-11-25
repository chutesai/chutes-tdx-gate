package gate

import (
	"bufio"
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chutesai/chutes-tdx-gate/internal/fakequote"
	"github.com/chutesai/chutes-tdx-gate/pkg/e2ev2"
)

const (
	testEndpoint = "6b1c0e7e-4d0b-4f2a-9a57-1f3d2c8b9e40"
	testInstance = "5813945712345678901"
)

type fixture struct {
	g      *Gate
	srv    *httptest.Server
	quoter *fakequote.Quoter
	app    *httptest.Server
	now    time.Time
}

func testConfig(appBase string) *Config {
	return &Config{
		Listen:        "0.0.0.0:8080",
		AppBase:       appBase,
		AppHealthPath: "/health",
		AppTimeoutS:   5,
		HealthPath:    "/health",
		Routes: []e2ev2.Route{
			{Path: "/v1/compress", Stream: false, AppPath: "/v1/compress"},
			{Path: "/v1/stream", Stream: true, AppPath: "/v1/stream"},
			{Path: "/v1/echo", Stream: false, AppPath: "/app/echo"},
		},
		IdentitySource:   "static",
		StaticEndpointID: testEndpoint,
		StaticInstanceID: testInstance,
		Limits:           Limits{MaxRequestBytes: 8454144, MaxPlaintextBytes: 64 << 20, MaxAnswerBytes: 1 << 20, MaxInflight: 8, ReplayCacheEntries: 65536},
		TsmReportDir:     "/sys/kernel/config/tsm/report",
	}
}

func newFixture(t *testing.T, app http.Handler, edit func(*Config)) *fixture {
	t.Helper()
	f := &fixture{quoter: &fakequote.Quoter{}, now: time.UnixMilli(1795000000000)}
	if app == nil {
		app = http.NotFoundHandler()
	}
	f.app = httptest.NewServer(app)
	t.Cleanup(f.app.Close)
	cfg := testConfig(f.app.URL)
	if edit != nil {
		edit(cfg)
	}
	key, err := e2ev2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	f.g = New(cfg, key, f.quoter, WithClock(func() time.Time { return f.now }))
	f.srv = httptest.NewServer(f.g.Handler())
	t.Cleanup(f.srv.Close)
	return f
}

type request struct {
	envelope map[string]any
	seed     []byte // the response key's seed
	blob     []byte
}

func freshNonce() string {
	var raw [32]byte
	_, _ = rand.Read(raw[:])
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func (f *fixture) envelope(path string, stream bool, body map[string]any) (map[string]any, []byte) {
	seed := make([]byte, 64)
	_, _ = rand.Read(seed)
	dk, _ := mlkem.NewDecapsulationKey768(seed)
	return map[string]any{
		"v": 2, "endpoint_id": testEndpoint, "instance_id": testInstance, "path": path, "stream": stream,
		"nonce": freshNonce(), "ts": f.now.UnixMilli(),
		"e2e_response_pk": base64.StdEncoding.EncodeToString(dk.EncapsulationKey().Bytes()), "body": body,
	}, seed
}

func (f *fixture) seal(t *testing.T, env map[string]any, seed []byte) *request {
	t.Helper()
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := e2ev2.SealRequest(f.g.PublicKey(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return &request{envelope: env, seed: seed, blob: blob}
}

func (f *fixture) post(t *testing.T, path string, blob []byte, header http.Header) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+path, bytes.NewReader(blob))
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readAll(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func refusalBody(code string) string { return `{"detail":{"code":"` + code + `"}}` }

func expectRefusal(t *testing.T, resp *http.Response, status int, code string) {
	t.Helper()
	body := readAll(t, resp)
	if resp.StatusCode != status || string(body) != refusalBody(code) {
		t.Fatalf("got %d %s, want %d %s", resp.StatusCode, body, status, code)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("refusal content type %q", ct)
	}
	if ra := resp.Header.Get("Retry-After"); (ra != "") != (code == "e2e_v2_busy") {
		t.Fatalf("Retry-After %q with %s", ra, code)
	}
}

func openSealed(t *testing.T, r *request, resp *http.Response) (int, []byte) {
	t.Helper()
	body := readAll(t, resp)
	var wire map[string]string
	if err := json.Unmarshal(body, &wire); err != nil || len(wire) != 1 {
		t.Fatalf("not a sealed answer: %d %s", resp.StatusCode, body)
	}
	if string(body) != `{"e2e":"`+wire["e2e"]+`"}` || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("sealed answer not in its exact form: %s", body)
	}
	secret, err := e2ev2.NewResponseSecret(r.seed, sha256.Sum256(r.blob))
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := base64.StdEncoding.DecodeString(wire["e2e"])
	status, plain, err := secret.OpenAnswer(blob)
	if err != nil {
		t.Fatal(err)
	}
	if status != resp.StatusCode {
		t.Fatalf("presented %d, sealed %d", resp.StatusCode, status)
	}
	return status, plain
}

func echoApp() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(200)
		case "/v1/compress", "/app/echo":
			raw, _ := io.ReadAll(r.Body)
			w.Header().Set("X-App-Secret", "must-not-pass")
			w.Header().Set("Set-Cookie", "a=b")
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(201)
			_, _ = w.Write(append([]byte("echo:"), raw...))
		case "/v1/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			for i := 0; i < 3; i++ {
				fmt.Fprintf(w, "data: {\"i\":%d}\n\n", i)
				w.(http.Flusher).Flush()
			}
		default:
			w.WriteHeader(404)
		}
	})
}

func TestSealedAnswer(t *testing.T) {
	f := newFixture(t, echoApp(), nil)
	env, seed := f.envelope("/v1/echo", false, map[string]any{"messages": []any{"hi"}})
	r := f.seal(t, env, seed)
	resp := f.post(t, "/v1/echo", r.blob, nil)
	status, plain := openSealed(t, r, resp)
	if status != 201 || string(plain) != `echo:{"messages":["hi"]}` {
		t.Fatalf("got %d %q", status, plain)
	}
	// No application header passes: only the gate's Content-Type (and the server's Date and length).
	for name := range resp.Header {
		switch name {
		case "Content-Type", "Content-Length", "Date":
		default:
			t.Fatalf("application or extra header passed: %s", name)
		}
	}
	// The same blob again is a replay.
	expectRefusal(t, f.post(t, "/v1/echo", r.blob, nil), 409, "e2e_v2_replayed")
}

// The gate forwards to the application exactly POST with Host, Content-Type and Content-Length,
// and the body bytes of envelope.body as sent.
func TestApplicationRequestBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		var head strings.Builder
		length := 0
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			head.WriteString(line)
			if strings.HasPrefix(strings.ToLower(line), "content-length:") {
				fmt.Sscanf(strings.TrimSpace(line[len("content-length:"):]), "%d", &length)
			}
			if line == "\r\n" {
				break
			}
		}
		body := make([]byte, length)
		_, _ = io.ReadFull(br, body)
		got <- head.String() + string(body)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"))
	}()
	f := newFixture(t, nil, func(c *Config) { c.AppBase = "http://" + ln.Addr().String() })
	env, seed := f.envelope("/v1/compress", false, map[string]any{"z": 1, "a": "ü"})
	raw := []byte(`{"v":2,"endpoint_id":"` + testEndpoint + `","instance_id":"` + testInstance +
		`","path":"/v1/compress","stream":false,"nonce":"` + env["nonce"].(string) + `","ts":` +
		fmt.Sprint(f.now.UnixMilli()) + `,"e2e_response_pk":"` + env["e2e_response_pk"].(string) +
		`","body":{"z":1,  "a":"ü"}}`)
	blob, _ := e2ev2.SealRequest(f.g.PublicKey(), raw)
	resp := f.post(t, "/v1/compress", blob, http.Header{"X-Chutes-Caller": {"someone"}, "Authorization": {"x"}})
	openSealed(t, &request{seed: seed, blob: blob}, resp)
	wire := <-got
	addr := ln.Addr().String()
	sent := `{"z":1,  "a":"ü"}`
	want := "POST /v1/compress HTTP/1.1\r\nHost: " + addr + "\r\nContent-Length: " + fmt.Sprint(len(sent)) + "\r\nContent-Type: application/json\r\n\r\n" + sent
	if wire != want {
		t.Fatalf("application request:\n%q\nwant\n%q", wire, want)
	}
}

func TestStream(t *testing.T) {
	f := newFixture(t, echoApp(), nil)
	env, seed := f.envelope("/v1/stream", true, map[string]any{"stream": true})
	r := f.seal(t, env, seed)
	resp := f.post(t, "/v1/stream", r.blob, nil)
	data, err := readStream(r, resp)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "data: {\"i\":0}\n\ndata: {\"i\":1}\n\ndata: {\"i\":2}\n\n" {
		t.Fatalf("stream data %q", data)
	}
}

func readStream(r *request, resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		return nil, fmt.Errorf("not a stream: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	secret, _ := e2ev2.NewResponseSecret(r.seed, sha256.Sum256(r.blob))
	var opener *e2ev2.StreamOpener
	var data []byte
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "data: ") {
			return nil, fmt.Errorf("not an event line: %q", line)
		}
		var ev map[string]string
		if err := json.Unmarshal([]byte(line[6:]), &ev); err != nil || len(ev) != 1 {
			return nil, fmt.Errorf("bad event %q", line)
		}
		if init, ok := ev["e2e_init"]; ok {
			var err error
			if opener, err = secret.OpenStream(init); err != nil {
				return nil, err
			}
			continue
		}
		if opener == nil {
			return nil, fmt.Errorf("chunk before e2e_init")
		}
		p, err := opener.Chunk(ev["e2e"], resp.StatusCode)
		if err != nil {
			return nil, err
		}
		data = append(data, p...)
	}
	if opener == nil {
		return nil, fmt.Errorf("no e2e_init")
	}
	return data, opener.Finish()
}

// An application that fails mid-stream gets no sealed end: the caller refuses the stream.
func TestStreamNoEndAfterApplicationFailure(t *testing.T) {
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler) // the connection is cut without a clean end
	})
	f := newFixture(t, app, nil)
	env, seed := f.envelope("/v1/stream", true, map[string]any{"stream": true})
	r := f.seal(t, env, seed)
	_, err := readStream(r, f.post(t, "/v1/stream", r.blob, nil))
	if err == nil || !strings.Contains(err.Error(), "cut short") {
		t.Fatalf("a cut stream was not refused: %v", err)
	}
}

func TestStreamRouteErrorIsSealed(t *testing.T) {
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(418)
		_, _ = w.Write([]byte(`{"error":"teapot"}`))
	})
	f := newFixture(t, app, nil)
	env, seed := f.envelope("/v1/stream", true, map[string]any{"stream": true})
	r := f.seal(t, env, seed)
	status, plain := openSealed(t, r, f.post(t, "/v1/stream", r.blob, nil))
	if status != 418 || string(plain) != `{"error":"teapot"}` {
		t.Fatalf("got %d %s", status, plain)
	}
}

func TestApplicationFailures(t *testing.T) {
	big := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), (1<<20)+1))
	})
	f := newFixture(t, big, nil)
	env, seed := f.envelope("/v1/compress", false, map[string]any{})
	expectRefusal(t, f.post(t, "/v1/compress", f.seal(t, env, seed).blob, nil), 502, "e2e_v2_answer_too_large")

	down := newFixture(t, nil, nil)
	down.app.Close()
	env, seed = down.envelope("/v1/compress", false, map[string]any{})
	expectRefusal(t, down.post(t, "/v1/compress", down.seal(t, env, seed).blob, nil), 502, "e2e_v2_app_failed")
}

// Each check of spec section 4.3, through HTTP, in order.
func TestChecks(t *testing.T) {
	f := newFixture(t, echoApp(), nil)
	cases := []struct {
		name   string
		edit   func(map[string]any)
		path   string
		method string
		status int
		code   string
	}{
		{"endpoint", func(e map[string]any) { e["endpoint_id"] = "00000000-0000-4000-8000-000000000000" }, "/v1/compress", "POST", 403, "e2e_v2_wrong_endpoint"},
		{"instance", func(e map[string]any) { e["instance_id"] = "1" }, "/v1/compress", "POST", 403, "e2e_v2_wrong_instance"},
		{"method", nil, "/v1/compress", "PUT", 405, "e2e_v2_method"},
		{"path", nil, "/v1/stream", "POST", 403, "e2e_v2_wrong_path"},
		{"route", func(e map[string]any) { e["path"] = "/v1/other" }, "/v1/other", "POST", 404, "e2e_v2_route_not_served"},
		{"route stream flag", func(e map[string]any) { e["stream"] = true }, "/v1/compress", "POST", 404, "e2e_v2_route_not_served"},
		{"stream", func(e map[string]any) { e["body"] = map[string]any{"stream": true} }, "/v1/compress", "POST", 400, "e2e_v2_stream_mismatch"},
		{"stream not boolean", func(e map[string]any) { e["body"] = map[string]any{"stream": 0} }, "/v1/compress", "POST", 400, "e2e_v2_stream_mismatch"},
		{"stream route without body.stream", func(e map[string]any) { e["path"] = "/v1/stream"; e["stream"] = true }, "/v1/stream", "POST", 400, "e2e_v2_stream_mismatch"},
		{"stale", func(e map[string]any) { e["ts"] = f.now.UnixMilli() - 120001 }, "/v1/compress", "POST", 400, "e2e_v2_stale"},
		{"future", func(e map[string]any) { e["ts"] = f.now.UnixMilli() + 60001 }, "/v1/compress", "POST", 400, "e2e_v2_from_the_future"},
		{"non-printable id", func(e map[string]any) { e["endpoint_id"] = testEndpoint + "​" }, "/v1/compress", "POST", 400, "e2e_v2_malformed"},
		{"version", func(e map[string]any) { e["v"] = 2.5 }, "/v1/compress", "POST", 400, "e2e_v2_malformed"},
	}
	for _, c := range cases {
		env, seed := f.envelope("/v1/compress", false, map[string]any{})
		if c.edit != nil {
			c.edit(env)
		}
		r := f.seal(t, env, seed)
		req, _ := http.NewRequest(c.method, f.srv.URL+c.path, bytes.NewReader(r.blob))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(c.name, func(t *testing.T) { expectRefusal(t, resp, c.status, c.code) })
	}
}

// The nonce is consumed last: a request refused by any earlier check leaves its nonce unused.
func TestNonceConsumedLast(t *testing.T) {
	f := newFixture(t, echoApp(), nil)
	env, seed := f.envelope("/v1/compress", false, map[string]any{})
	env["path"] = "/v1/other"
	expectRefusal(t, f.post(t, "/v1/other", f.seal(t, env, seed).blob, nil), 404, "e2e_v2_route_not_served")
	env2, seed2 := f.envelope("/v1/compress", false, map[string]any{})
	env2["nonce"] = env["nonce"]
	r2 := f.seal(t, env2, seed2)
	if status, _ := openSealed(t, r2, f.post(t, "/v1/compress", r2.blob, nil)); status != 201 {
		t.Fatalf("the nonce of a refused request was consumed: %d", status)
	}
}

func TestReplayBusy(t *testing.T) {
	f := newFixture(t, echoApp(), func(c *Config) { c.Limits.ReplayCacheEntries = 1 })
	env, seed := f.envelope("/v1/compress", false, map[string]any{})
	r := f.seal(t, env, seed)
	openSealed(t, r, f.post(t, "/v1/compress", r.blob, nil))
	env, seed = f.envelope("/v1/compress", false, map[string]any{})
	resp := f.post(t, "/v1/compress", f.seal(t, env, seed).blob, nil)
	if resp.Header.Get("Retry-After") != "120" {
		t.Fatalf("Retry-After %q", resp.Header.Get("Retry-After"))
	}
	expectRefusal(t, resp, 503, "e2e_v2_busy")
}

func TestInflightBusy(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(200)
	})
	f := newFixture(t, app, func(c *Config) { c.Limits.MaxInflight = 1 })
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	env, seed := f.envelope("/v1/compress", false, map[string]any{})
	r := f.seal(t, env, seed)
	done := make(chan *http.Response, 1)
	go func() { done <- f.post(t, "/v1/compress", r.blob, nil) }()
	<-entered
	env2, seed2 := f.envelope("/v1/compress", false, map[string]any{})
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/v1/compress", bytes.NewReader(f.seal(t, env2, seed2).blob))
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("a request over max_inflight was not refused at once: %v", err)
	}
	expectRefusal(t, resp, 503, "e2e_v2_busy")
	close(release)
	openSealed(t, r, <-done)
}

func TestRequestTooLarge(t *testing.T) {
	f := newFixture(t, echoApp(), func(c *Config) { c.Limits.MaxRequestBytes = 2000 })
	expectRefusal(t, f.post(t, "/v1/compress", make([]byte, 2001), nil), 400, "e2e_v2_malformed")
}

// The identity is the configured one, never a request header's.
func TestIdentityNotFromRequest(t *testing.T) {
	f := newFixture(t, echoApp(), func(c *Config) { c.IdentitySource = "gce-metadata" })
	env, seed := f.envelope("/v1/compress", false, map[string]any{})
	hdr := http.Header{
		"X-Chutes-Endpoint-Id": {testEndpoint}, "X-Instance-Id": {testInstance}, "Metadata-Flavor": {"Google"},
		"Chutes-Endpoint-Id": {testEndpoint}, "X-Endpoint-Id": {testEndpoint},
	}
	expectRefusal(t, f.post(t, "/v1/compress", f.seal(t, env, seed).blob, hdr), 503, "e2e_v2_identity_unknown")
	f.g.SetIdentity("00000000-0000-4000-8000-000000000001", testInstance)
	env, seed = f.envelope("/v1/compress", false, map[string]any{})
	expectRefusal(t, f.post(t, "/v1/compress", f.seal(t, env, seed).blob, hdr), 403, "e2e_v2_wrong_endpoint")
	hr, _ := http.Get(f.srv.URL + "/health")
	readAll(t, hr)
	f.g.identity.Store(&e2ev2.Identity{})
	hr, _ = http.Get(f.srv.URL + "/health")
	if readAll(t, hr); hr.StatusCode != 503 {
		t.Fatalf("health %d while the identity is unknown", hr.StatusCode)
	}
}

func TestAttest(t *testing.T) {
	f := newFixture(t, echoApp(), func(c *Config) { c.IdentitySource = "gce-metadata" })
	var nonce [32]byte
	_, _ = rand.Read(nonce[:])
	resp, err := http.Get(f.srv.URL + "/attest?nonce=" + hex.EncodeToString(nonce[:]))
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	pk := f.g.PublicKey()
	h := sha512.New()
	h.Write([]byte("chutes-tdx-endpoint-attest-v1\x00"))
	h.Write(nonce[:])
	h.Write(pk)
	var want [64]byte
	copy(want[:], h.Sum(nil))
	quote := fakequote.Quote(want)
	wantBody := `{"quote":"` + base64.StdEncoding.EncodeToString(quote) + `","public_key":"` + base64.StdEncoding.EncodeToString(pk) + `"}`
	if resp.StatusCode != 200 || string(body) != wantBody || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("attest %d %s", resp.StatusCode, body)
	}
	if f.quoter.Count() != 1 || f.quoter.Seen[0] != want {
		t.Fatal("the quote was not made over the REPORTDATA rule")
	}
	for _, q := range []string{"", "nonce=" + strings.ToUpper(hex.EncodeToString(nonce[:])), "nonce=" + hex.EncodeToString(nonce[:]) + "&x=1",
		"nonce=" + hex.EncodeToString(nonce[:31]), "report_data=" + hex.EncodeToString(want[:]),
		"nonce=" + hex.EncodeToString(nonce[:]) + "&nonce=" + hex.EncodeToString(nonce[:])} {
		resp, _ := http.Get(f.srv.URL + "/attest?" + q)
		if b := readAll(t, resp); resp.StatusCode != 400 || string(b) != `{"detail":{"code":"attest_bad_nonce"}}` {
			t.Fatalf("query %q: %d %s", q, resp.StatusCode, b)
		}
	}
	resp, _ = http.Post(f.srv.URL+"/attest?nonce="+hex.EncodeToString(nonce[:]), "application/json", strings.NewReader(hex.EncodeToString(want[:])))
	if readAll(t, resp); resp.StatusCode != 405 {
		t.Fatalf("POST /attest: %d", resp.StatusCode)
	}
	if f.quoter.Count() != 1 {
		t.Fatal("a refused /attest made a quote")
	}
}

// No route but /attest makes a quote, whatever it is sent.
func TestOnlyAttestQuotes(t *testing.T) {
	f := newFixture(t, echoApp(), nil)
	var rd [64]byte
	_, _ = rand.Read(rd[:])
	for _, p := range []string{"/attest/", "/attest2", "/v1/compress", "/v1/stream", "/v1/echo", "/health", "/quote", "/report", "/"} {
		for _, m := range []string{"GET", "POST"} {
			req, _ := http.NewRequest(m, f.srv.URL+p+"?nonce="+hex.EncodeToString(rd[:32])+"&report_data="+hex.EncodeToString(rd[:]), bytes.NewReader(rd[:]))
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				readAll(t, resp)
			}
		}
	}
	if f.quoter.Count() != 0 {
		t.Fatalf("%d quote(s) made outside /attest", f.quoter.Count())
	}
}

func TestHealth(t *testing.T) {
	var mu sync.Mutex
	status, delay := 200, time.Duration(0)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		s, d := status, delay
		mu.Unlock()
		time.Sleep(d)
		w.WriteHeader(s)
		_, _ = w.Write(bytes.Repeat([]byte("x"), 5000))
	})
	f := newFixture(t, app, nil)
	old := HealthAppTimeout
	HealthAppTimeout = 300 * time.Millisecond
	defer func() { HealthAppTimeout = old }()
	check := func(want int) {
		t.Helper()
		resp, err := http.Get(f.srv.URL + "/health")
		if err != nil {
			t.Fatal(err)
		}
		if b := readAll(t, resp); resp.StatusCode != want || len(b) != 0 {
			t.Fatalf("health %d %q, want %d", resp.StatusCode, b, want)
		}
	}
	check(200)
	for _, s := range []int{204, 299} {
		mu.Lock()
		status = s
		mu.Unlock()
		check(200)
	}
	for _, s := range []int{301, 404, 500, 503} {
		mu.Lock()
		status = s
		mu.Unlock()
		check(503)
	}
	mu.Lock()
	status, delay = 200, 600*time.Millisecond
	mu.Unlock()
	check(503)
	resp, _ := http.Post(f.srv.URL+"/health", "", nil)
	if readAll(t, resp); resp.StatusCode != 405 {
		t.Fatalf("POST /health %d", resp.StatusCode)
	}
}

func TestMetadataIdentity(t *testing.T) {
	answer := map[string]string{
		"/computeMetadata/v1/instance/attributes/chutes-endpoint-id": testEndpoint,
		"/computeMetadata/v1/instance/id":                            testInstance,
	}
	flavor := "Google"
	md := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			w.WriteHeader(403)
			return
		}
		v, ok := answer[r.URL.Path]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Metadata-Flavor", flavor)
		_, _ = io.WriteString(w, v)
	}))
	defer md.Close()
	m := NewMetadata(md.URL + "/computeMetadata/v1/")
	e, i, err := m.Identity(t.Context())
	if err != nil || e != testEndpoint || i != testInstance {
		t.Fatalf("identity %q %q %v", e, i, err)
	}
	flavor = ""
	if _, _, err := m.Identity(t.Context()); err == nil {
		t.Fatal("an answer without Metadata-Flavor: Google was accepted")
	}
	flavor = "Google"
	answer["/computeMetadata/v1/instance/id"] = "0123"
	if _, _, err := m.Identity(t.Context()); err == nil {
		t.Fatal("a malformed instance id was accepted")
	}
}
