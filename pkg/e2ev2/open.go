package e2ev2

import (
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/chutesai/chutes-tdx-gate/pkg/sjson"
)

// DefaultMaxPlaintext is the largest decompressed envelope (64 MiB).
const DefaultMaxPlaintext = 64 * 1024 * 1024

// The envelope's parse limits, checked while parsing (beyond the spec's rules, the gate's own
// bounds; a document over one is e2e_v2_malformed): at most MaxNodes values, keys of at most
// MaxKeyBytes, top-level strings of at most MaxEnvelopeString bytes. Only the envelope's own
// members are built; the body is checked as strictly and forwarded as its raw bytes.
const (
	MaxNodes          = 1 << 20
	MaxKeyBytes       = 1 << 16
	MaxEnvelopeString = 1 << 16
)

// Identity is the endpoint and instance this gate serves; Known is false until both were read
// from the instance metadata.
type Identity struct {
	EndpointID string
	InstanceID string
	Known      bool
}

// Route is one declared route: its public path, whether it streams, and the application path.
type Route struct {
	Path    string
	Stream  bool
	AppPath string
}

// Routes maps (path, stream) to the route.
type Routes map[routeKey]Route

type routeKey struct {
	path   string
	stream bool
}

// NewRoutes builds the route table.
func NewRoutes(list []Route) Routes {
	out := Routes{}
	for _, r := range list {
		out[routeKey{r.Path, r.Stream}] = r
	}
	return out
}

func (rs Routes) lookup(path string, stream bool) (Route, bool) {
	r, ok := rs[routeKey{path, stream}]
	return r, ok
}

// Opened is an admitted request: the application body (the envelope's body bytes as sent), the
// route, and what sealing its answer needs.
type Opened struct {
	Body        []byte
	Path        string
	Stream      bool
	Route       Route
	Nonce       string
	responseKey *mlkem.EncapsulationKey768
	digest      [32]byte
}

// ResponseKey is the caller's one-time response key (1184 bytes).
func (o *Opened) ResponseKey() []byte { return o.responseKey.Bytes() }

// Params are one request's inputs besides the blob.
type Params struct {
	PresentedPath string
	Method        string
	Routes        Routes
	Identity      Identity
	Cache         *ReplayCache
	NowMS         int64
	MaxPlaintext  int64
	// Lease is the request's share of the gate's memory budget: the plaintext, the inflated
	// envelope and the parse's key sets are reserved before they are allocated (nil: no budget).
	Lease *Lease
}

var envelopeKeys = []string{"v", "endpoint_id", "instance_id", "path", "stream", "nonce", "ts", "e2e_response_pk", "body"}

// printable is Python's str.isprintable() for one code point: not in Cc, Cf, Cs, Co, Cn, Zl, Zp,
// or Zs other than U+0020.
func printable(r rune) bool {
	if r == ' ' {
		return true
	}
	if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Cs, unicode.Co, unicode.Zl, unicode.Zp, unicode.Zs) {
		return false
	}
	// Cn: a code point assigned to no category.
	return unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S)
}

// text is a JSON string of 1..256 code points, each printable.
func text(v *sjson.Value) (string, bool) {
	if v == nil || v.Kind != sjson.String {
		return "", false
	}
	n := utf8.RuneCountInString(v.Str)
	if n < 1 || n > 256 {
		return "", false
	}
	for _, r := range v.Str {
		if !printable(r) {
			return "", false
		}
	}
	return v.Str, true
}

func nonceOK(s string) bool {
	if len(s) != 43 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// stdBase64 decodes standard base64 with padding, refusing any byte outside its alphabet (Go's
// decoder would skip CR and LF).
func stdBase64(s string) ([]byte, bool) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=') {
			return nil, false
		}
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	return raw, err == nil
}

// tsValue is the envelope's ts: an integer literal in [-2^63, 2^64-1] (the SDK runtime's orjson
// reads any other integer literal as a float, which is not a ts); one above int64 is saturated,
// which decides "from the future" exactly as its own value would.
func tsValue(v *sjson.Value) (int64, bool) {
	if !v.IsInteger() {
		return 0, false
	}
	ts, err := strconv.ParseInt(v.Num, 10, 64)
	if err != nil {
		if _, uerr := strconv.ParseUint(v.Num, 10, 64); uerr != nil {
			return 0, false
		}
		return math.MaxInt64, true
	}
	return ts, true
}

type envelope struct {
	endpointID, instanceID, path, nonce string
	stream                              bool
	ts                                  int64
	responseKey                         *mlkem.EncapsulationKey768
	body                                *sjson.Value
}

func parseEnvelope(plain []byte, lease *Lease) (*envelope, *Refusal) {
	malformed := refusal("e2e_v2_malformed")
	v, err := sjson.ParseWith(plain, sjson.Limits{
		MaxDepth: sjson.MaxDepth, MaxNodes: MaxNodes, MaxKeyBytes: MaxKeyBytes, MaxStringBytes: MaxEnvelopeString,
		MaxMembers: len(envelopeKeys), Build: 1, Charge: lease.Charge,
	})
	if errors.Is(err, sjson.ErrBusy) {
		return nil, lease.Refusal()
	}
	if err != nil || !v.HasExactly(envelopeKeys...) {
		return nil, malformed
	}
	if ver := v.Get("v"); ver.Kind != sjson.Number || ver.Num != "2" {
		return nil, malformed
	}
	var env envelope
	var ok bool
	if env.endpointID, ok = text(v.Get("endpoint_id")); !ok {
		return nil, malformed
	}
	if env.instanceID, ok = text(v.Get("instance_id")); !ok {
		return nil, malformed
	}
	if env.path, ok = text(v.Get("path")); !ok || !strings.HasPrefix(env.path, "/") {
		return nil, malformed
	}
	if s := v.Get("stream"); s.Kind != sjson.Bool {
		return nil, malformed
	} else {
		env.stream = s.Bool
	}
	if n := v.Get("nonce"); n.Kind != sjson.String || !nonceOK(n.Str) {
		return nil, malformed
	} else {
		env.nonce = n.Str
	}
	if env.ts, ok = tsValue(v.Get("ts")); !ok {
		return nil, malformed
	}
	pk := v.Get("e2e_response_pk")
	if pk.Kind != sjson.String {
		return nil, malformed
	}
	raw, ok := stdBase64(pk.Str)
	if !ok || len(raw) != PublicKeySize {
		return nil, malformed
	}
	// An encapsulation key that fails FIPS 203's modulus check could never be sealed to.
	if env.responseKey, err = mlkem.NewEncapsulationKey768(raw); err != nil {
		return nil, malformed
	}
	if env.body = v.Get("body"); env.body.Kind != sjson.Object {
		return nil, malformed
	}
	return &env, nil
}

// Open opens, checks and admits one request blob, in the spec's order: open; gunzip and the
// closed envelope; identity known; endpoint_id; instance_id; method POST; presented path = bound
// path; (path, POST, stream) served; body.stream; ts not stale; not in the future; nonce not
// admitted; cache not full; then the nonce is admitted (consumed last).
//
// Memory: the opened plaintext, the inflated envelope (its size from the gzip trailer) and the
// parse are each reserved from p.Lease before they are allocated; a reservation the budget cannot
// hold now is e2e_v2_busy, one it could never hold e2e_v2_malformed, before the nonce is touched.
func Open(key *Key, blob []byte, p Params) (*Opened, *Refusal) {
	if !p.Lease.Charge(int64(len(blob))) {
		return nil, p.Lease.Refusal()
	}
	plain, err := open(key, blob)
	if err != nil {
		return nil, refusal("e2e_v2_undecryptable")
	}
	limit := p.MaxPlaintext
	if limit <= 0 {
		limit = DefaultMaxPlaintext
	}
	inflated, ref := gunzip(plain, limit, p.Lease)
	if ref != nil {
		return nil, ref
	}
	env, ref := parseEnvelope(inflated, p.Lease)
	if ref != nil {
		return nil, ref
	}
	if !p.Identity.Known {
		return nil, refusal("e2e_v2_identity_unknown")
	}
	if env.endpointID != p.Identity.EndpointID {
		return nil, refusal("e2e_v2_wrong_endpoint")
	}
	if env.instanceID != p.Identity.InstanceID {
		return nil, refusal("e2e_v2_wrong_instance")
	}
	if strings.ToUpper(p.Method) != "POST" {
		return nil, refusal("e2e_v2_method")
	}
	if p.PresentedPath != env.path {
		return nil, refusal("e2e_v2_wrong_path")
	}
	route, ok := p.Routes.lookup(env.path, env.stream)
	if !ok {
		return nil, refusal("e2e_v2_route_not_served")
	}
	// body.stream: absent counts as false; present, a JSON boolean equal to the bound stream.
	bodyStream := false
	if s := env.body.Lookup("stream"); s != nil {
		if s.Kind != sjson.Bool {
			return nil, refusal("e2e_v2_stream_mismatch")
		}
		bodyStream = s.Bool
	}
	if bodyStream != env.stream {
		return nil, refusal("e2e_v2_stream_mismatch")
	}
	if ref := p.Cache.Admit(env.nonce, env.ts, p.NowMS); ref != nil {
		return nil, ref
	}
	return &Opened{
		Body:        env.body.Raw,
		Path:        env.path,
		Stream:      env.stream,
		Route:       route,
		Nonce:       env.nonce,
		responseKey: env.responseKey,
		digest:      sha256.Sum256(blob),
	}, nil
}
