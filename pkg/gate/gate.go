// Package gate is tdx-gate's HTTP server (spec sections 4.1, 4.3, 4.4): /attest, the health
// pass-through, and every other path as an E2E v2 route, forwarded in plaintext to the
// application on loopback.
//
// It logs no body, no envelope field and no decrypted byte: only the route (a configured one),
// the status and the refusal code.
package gate

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/chutesai/chutes-tdx-gate/pkg/attest"
	"github.com/chutesai/chutes-tdx-gate/pkg/e2ev2"
)

// HealthAppTimeout is how long the application's health URL has to answer 2xx.
var HealthAppTimeout = 4 * time.Second

// Gate serves one endpoint instance.
type Gate struct {
	cfg      *Config
	key      *e2ev2.Key
	routes   e2ev2.Routes
	cache    *e2ev2.ReplayCache
	quoter   attest.Quoter
	identity atomic.Pointer[e2ev2.Identity]
	sem      chan struct{}
	budget   *e2ev2.Budget
	app      *http.Client
	log      *slog.Logger
	now      func() time.Time
}

// Option adjusts a Gate (tests).
type Option func(*Gate)

// WithClock replaces the clock.
func WithClock(now func() time.Time) Option { return func(g *Gate) { g.now = now } }

// WithLogger replaces the logger.
func WithLogger(l *slog.Logger) Option { return func(g *Gate) { g.log = l } }

// WithBudget sets the in-flight memory budget in bytes (default e2ev2.DefaultBudget).
func WithBudget(bytes int64) Option { return func(g *Gate) { g.budget = e2ev2.NewBudget(bytes) } }

// MinBudget is the smallest budget that admits one request at the limits: its body (read in
// doubling buffers), the opened plaintext, the inflated envelope, and the largest answer read and
// sealed. A document whose parse keeps more (a very large number of keys) can still be busy.
func MinBudget(l Limits) int64 {
	return StreamReserve + 3*(l.MaxRequestBytes+1) + l.MaxPlaintextBytes + 1 + 2*(l.MaxAnswerBytes+1) + e2ev2.SealCost(int(l.MaxAnswerBytes))
}

// StreamReserve is what a stream answer holds: a read buffer, a sealed chunk and its event.
const StreamReserve = 4*e2ev2.MaxChunkData + 64<<10

// New builds a gate for cfg with the per-boot key and a quote source. The identity starts
// unknown unless cfg names a static one.
func New(cfg *Config, key *e2ev2.Key, quoter attest.Quoter, opts ...Option) *Gate {
	g := &Gate{
		cfg:    cfg,
		key:    key,
		routes: e2ev2.NewRoutes(cfg.Routes),
		cache:  e2ev2.NewReplayCache(cfg.Limits.ReplayCacheEntries),
		quoter: quoter,
		sem:    make(chan struct{}, cfg.Limits.MaxInflight),
		budget: e2ev2.NewBudget(e2ev2.DefaultBudget),
		log:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
		now:    time.Now,
	}
	g.app = &http.Client{
		Transport: &http.Transport{
			Proxy:               nil, // never a proxy, whatever the environment says
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			DisableCompression:  true, // no Accept-Encoding added: the application gets exactly three headers
			MaxIdleConnsPerHost: 64,
			IdleConnTimeout:     90 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	g.identity.Store(&e2ev2.Identity{})
	if cfg.IdentitySource == "static" {
		g.SetIdentity(cfg.StaticEndpointID, cfg.StaticInstanceID)
	}
	for _, o := range opts {
		o(g)
	}
	return g
}

// SetIdentity records the endpoint and instance this gate serves.
func (g *Gate) SetIdentity(endpointID, instanceID string) {
	g.identity.Store(&e2ev2.Identity{EndpointID: endpointID, InstanceID: instanceID, Known: true})
}

// Identity is the current identity.
func (g *Gate) Identity() e2ev2.Identity { return *g.identity.Load() }

// PublicKey is the gate's ML-KEM encapsulation key.
func (g *Gate) PublicKey() []byte { return g.key.PublicKey() }

// Budget is the gate's in-flight memory budget.
func (g *Gate) Budget() *e2ev2.Budget { return g.budget }

// RestoredAt tells the replay cache that the key outlived a restart of the gate at nowMS, the
// previous process having admitted no ts above mark: every ts at or below mark, or at or below
// nowMS plus the future window, is refused stale. The mark makes this hold whatever the clock did
// across the restart; it returns the floor.
func (g *Gate) RestoredAt(nowMS, mark int64) int64 {
	floor := max(mark, nowMS+e2ev2.MaxFutureMS)
	g.cache.RaiseFloor(floor)
	return floor
}

// PersistAdmitted makes every admission that raises the highest admitted ts (above mark) call
// persist with it first (the stored high-water mark); a failed persist refuses the request busy.
func (g *Gate) PersistAdmitted(persist func(int64) error, mark int64) { g.cache.Persist(persist, mark) }

// Handler is the gate's HTTP handler. It does not use http.ServeMux, which would redirect
// unclean paths: every path but /attest and the health path is an E2E route.
func (g *Gate) Handler() http.Handler {
	at := &attest.Handler{
		PublicKey: g.key.PublicKey(),
		Quoter:    g.quoter,
		Logf: func(status int, code string) {
			g.log.Info("attest", "status", status, "code", code)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/attest":
			at.ServeHTTP(w, r)
		case g.cfg.HealthPath:
			g.serveHealth(w, r)
		default:
			g.serveE2E(w, r)
		}
	})
}

func (g *Gate) serveHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	status := http.StatusServiceUnavailable
	// Healthy only once the gate knows its identity (it can serve) and the application answers
	// 2xx within 4 s.
	if g.Identity().Known && g.appHealthy(r.Context()) {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	g.log.Info("health", "status", status)
}

func (g *Gate) appHealthy(parent context.Context) bool {
	ctx, cancel := context.WithTimeout(parent, HealthAppTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.cfg.AppBase+g.cfg.AppHealthPath, nil)
	if err != nil {
		return false
	}
	req.Header["User-Agent"] = []string{""}
	resp, err := g.app.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode >= 200 && resp.StatusCode <= 299
}

func (g *Gate) refuse(w http.ResponseWriter, ref *e2ev2.Refusal, route string) {
	w.Header().Set("Content-Type", "application/json")
	if ref.Code == "e2e_v2_busy" {
		w.Header().Set("Retry-After", strconv.Itoa(ref.RetryAfter))
	}
	w.WriteHeader(ref.Status)
	_, _ = w.Write(ref.Body())
	g.log.Info("e2e", "route", route, "status", ref.Status, "code", ref.Code)
}

func (g *Gate) serveE2E(w http.ResponseWriter, r *http.Request) {
	select {
	case g.sem <- struct{}{}:
		defer func() { <-g.sem }()
	default:
		g.refuse(w, e2ev2.Busy(1), "-")
		return
	}
	lease := g.budget.Lease()
	defer lease.Release()
	// A stream's buffers, reserved for every request before its nonce is used: busy is answered
	// only before the application sees anything (a caller can resend a busy request).
	if !lease.Charge(StreamReserve) {
		g.refuse(w, lease.Refusal(), "-")
		return
	}
	if r.ContentLength > g.cfg.Limits.MaxRequestBytes {
		g.refuse(w, e2ev2.NewRefusal("e2e_v2_malformed"), "-")
		return
	}
	blob, over, busy, err := readCharged(r.Body, g.cfg.Limits.MaxRequestBytes, r.ContentLength, lease)
	if busy {
		g.refuse(w, lease.Refusal(), "-")
		return
	}
	if err != nil || over {
		g.refuse(w, e2ev2.NewRefusal("e2e_v2_malformed"), "-")
		return
	}
	opened, ref := e2ev2.Open(g.key, blob, e2ev2.Params{
		PresentedPath: r.URL.Path,
		Method:        r.Method,
		Routes:        g.routes,
		Identity:      g.Identity(),
		Cache:         g.cache,
		NowMS:         g.now().UnixMilli(),
		MaxPlaintext:  g.cfg.Limits.MaxPlaintextBytes,
		Lease:         lease,
	})
	if ref != nil {
		g.refuse(w, ref, "-")
		return
	}
	g.forward(w, r, opened, lease)
}

// readCharged reads at most limit bytes, reserving every buffer from lease before allocating it
// (hint, a Content-Length or -1, sizes the first). over: more than limit bytes; busy: the budget
// could not hold the next buffer.
func readCharged(r io.Reader, limit, hint int64, lease *e2ev2.Lease) (data []byte, over, busy bool, err error) {
	size := int64(64 << 10)
	if hint >= 0 {
		size = hint + 1 // one more byte finds the end without growing
	}
	size = min(size, limit+1)
	if !lease.Charge(size) {
		return nil, false, true, nil
	}
	buf := make([]byte, 0, size)
	for {
		if len(buf) == cap(buf) {
			if int64(len(buf)) > limit {
				return nil, true, false, nil
			}
			next := min(2*int64(cap(buf)), limit+1)
			if !lease.Charge(next) {
				return nil, false, true, nil
			}
			buf = append(make([]byte, 0, next), buf...)
		}
		n, rerr := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return nil, false, false, rerr
		}
	}
	if int64(len(buf)) > limit {
		return nil, true, false, nil
	}
	return buf, false, false, nil
}

// appRequest sends the opened body to the application: POST with only Host, Content-Type and
// Content-Length; nothing added (no identity, no stream options).
func (g *Gate) appRequest(ctx context.Context, opened *e2ev2.Opened) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.cfg.AppBase+opened.Route.AppPath, bytes.NewReader(opened.Body))
	if err != nil {
		return nil, err
	}
	req.Header = http.Header{
		"Content-Type": {"application/json"},
		"User-Agent":   {""}, // an explicit empty User-Agent sends none
	}
	req.ContentLength = int64(len(opened.Body))
	return g.app.Do(req)
}

// sealable reports whether the application's status can be answered: 200..599 except the ones
// HTTP sends without a body (204, 304), which could not carry a sealed answer (spec section 4.3:
// e2e_v2_app_failed, on every route).
func sealable(status int) bool {
	return status >= 200 && status <= 599 && status != http.StatusNoContent && status != http.StatusNotModified
}

func (g *Gate) forward(w http.ResponseWriter, r *http.Request, opened *e2ev2.Opened, lease *e2ev2.Lease) {
	route := opened.Route.Path
	timeout := time.Duration(g.cfg.AppTimeoutS) * time.Second
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	// The application has timeout_s to answer, and (a stream) at most timeout_s between reads.
	idle := time.AfterFunc(timeout, cancel)
	defer idle.Stop()
	resp, err := g.appRequest(ctx, opened)
	if err != nil {
		g.refuse(w, e2ev2.NewRefusal("e2e_v2_app_failed"), route)
		return
	}
	defer resp.Body.Close()
	if !sealable(resp.StatusCode) {
		g.refuse(w, e2ev2.NewRefusal("e2e_v2_app_failed"), route)
		return
	}
	if opened.Stream && resp.StatusCode <= 299 {
		g.stream(w, resp, opened, idle, timeout) // its buffers were reserved with the request
		return
	}
	// The application has run: an answer the budget cannot hold now is never busy (a caller can
	// resend a busy request, and the application would run twice) but too large for the gate.
	body, over, busy, err := readCharged(resp.Body, g.cfg.Limits.MaxAnswerBytes, resp.ContentLength, lease)
	switch {
	case busy:
		g.refuse(w, e2ev2.NewRefusal("e2e_v2_answer_too_large"), route)
		return
	case err != nil:
		g.refuse(w, e2ev2.NewRefusal("e2e_v2_app_failed"), route)
		return
	case over:
		g.refuse(w, e2ev2.NewRefusal("e2e_v2_answer_too_large"), route)
		return
	}
	if !lease.Charge(e2ev2.SealCost(len(body))) {
		g.refuse(w, e2ev2.NewRefusal("e2e_v2_answer_too_large"), route)
		return
	}
	blob, err := e2ev2.SealAnswer(opened, resp.StatusCode, body)
	if err != nil {
		g.refuse(w, e2ev2.NewRefusal("e2e_v2_app_failed"), route)
		return
	}
	out := make([]byte, 0, base64.StdEncoding.EncodedLen(len(blob))+16)
	out = append(out, `{"e2e":"`...)
	out = base64.StdEncoding.AppendEncode(out, blob)
	out = append(out, `"}`...)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(out)
	g.log.Info("e2e", "route", route, "status", resp.StatusCode)
}

func sseEvent(field string, raw []byte) []byte {
	out := make([]byte, 0, len(raw)*4/3+32)
	out = append(out, `data: {"`...)
	out = append(out, field...)
	out = append(out, `":"`...)
	out = base64.StdEncoding.AppendEncode(out, raw)
	out = append(out, "\"}\n\n"...)
	return out
}

// stream answers a stream route's 2xx: e2e_init, the sealed head, one sealed data chunk per read
// (at most 64 KiB), and the sealed end only after the application's body ended normally.
func (g *Gate) stream(w http.ResponseWriter, resp *http.Response, opened *e2ev2.Opened, idle *time.Timer, timeout time.Duration) {
	route := opened.Route.Path
	sealer, err := e2ev2.NewStreamSealer(opened)
	if err != nil {
		g.refuse(w, e2ev2.NewRefusal("e2e_v2_app_failed"), route)
		return
	}
	head, err := sealer.Head(resp.StatusCode)
	if err != nil {
		g.refuse(w, e2ev2.NewRefusal("e2e_v2_app_failed"), route)
		return
	}
	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	write := func(event []byte) bool {
		if _, err := w.Write(event); err != nil {
			return false
		}
		if flusher != nil {
			flusher.Flush()
		}
		return true
	}
	if !write(sseEvent("e2e_init", sealer.Init())) || !write(sseEvent("e2e", head)) {
		return
	}
	buf := make([]byte, e2ev2.MaxChunkData)
	for {
		n, err := resp.Body.Read(buf)
		idle.Reset(timeout)
		if n > 0 {
			chunk, serr := sealer.Data(buf[:n])
			if serr != nil || !write(sseEvent("e2e", chunk)) {
				return
			}
		}
		if errors.Is(err, io.EOF) {
			end, serr := sealer.End()
			if serr == nil && write(sseEvent("e2e", end)) {
				g.log.Info("e2e", "route", route, "status", http.StatusOK)
			}
			return
		}
		if err != nil {
			// The application failed mid-stream: no sealed end, so the caller refuses the stream.
			g.log.Info("e2e", "route", route, "status", http.StatusOK, "code", "stream_cut")
			return
		}
	}
}
