// Package conformance runs the spec's test vectors (spec/vectors: reportdata.json,
// e2e_v2.json, health.json) against this gate's code. `tdx-gate selftest --vectors DIR` and the
// Go tests both call Run.
package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/chutesai/chutes-tdx-gate/pkg/attest"
	"github.com/chutesai/chutes-tdx-gate/pkg/e2ev2"
)

// Result counts the checks of one group.
type Result struct {
	Group    string
	Passed   int
	Failures []string
}

func (r *Result) check(ok bool, format string, args ...any) {
	if ok {
		r.Passed++
	} else {
		r.Failures = append(r.Failures, fmt.Sprintf(format, args...))
	}
}

func load(dir, name string, into any) error {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

func b64(s string) []byte {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return raw
}

func unhex(s string) []byte {
	raw, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return raw
}

// VerifySums checks every file named in dir/SHA256SUMS.
func VerifySums(dir string) (*Result, error) {
	res := &Result{Group: "SHA256SUMS"}
	raw, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			res.check(false, "bad line %q", line)
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, fields[1]))
		if err != nil {
			res.check(false, "%s missing", fields[1])
			continue
		}
		sum := sha256.Sum256(data)
		res.check(hex.EncodeToString(sum[:]) == fields[0], "%s sha256 differs", fields[1])
	}
	return res, nil
}

type vmKey struct {
	Label     string `json:"label"`
	Seed      string `json:"seed_d_z_hex"`
	PublicKey string `json:"public_key_b64"`
}

// Reportdata runs reportdata.json.
func Reportdata(dir string) (*Result, error) {
	var v struct {
		RawCases []struct {
			Name          string `json:"name"`
			NonceHex      string `json:"nonce_hex"`
			PublicKey     string `json:"public_key"`
			ReportDataHex string `json:"report_data_hex"`
		} `json:"cases"`
		Wrong []struct {
			Name          string `json:"name"`
			ReportDataHex string `json:"report_data_hex"`
		} `json:"wrong_forms_for_cases_0"`
		Attest struct {
			Request         string                        `json:"request"`
			RefusedQueries  []struct{ Query, Why string } `json:"refused_queries"`
			AnswerShapeKeys map[string]string             `json:"answer_shape"`
		} `json:"attest"`
		Keys map[string]vmKey `json:"keys"`
		Tag  string           `json:"tag_hex"`
	}
	if err := load(dir, "reportdata.json", &v); err != nil {
		return nil, err
	}
	res := &Result{Group: "reportdata.json"}
	res.check(string(unhex(v.Tag)) == attest.Tag, "tag")
	keys := map[string][]byte{}
	for name, k := range v.Keys {
		key, err := e2ev2.KeyFromSeed(unhex(k.Seed))
		if err != nil {
			res.check(false, "key %s from seed: %v", name, err)
			continue
		}
		res.check(bytes.Equal(key.PublicKey(), b64(k.PublicKey)), "key %s: public key from seed", name)
		keys[name] = key.PublicKey()
	}
	for _, c := range v.RawCases {
		var nonce [32]byte
		copy(nonce[:], unhex(c.NonceHex))
		rd := attest.ReportData(nonce, keys[c.PublicKey])
		res.check(hex.EncodeToString(rd[:]) == c.ReportDataHex, "case %s", c.Name)
	}
	if len(v.RawCases) > 0 {
		var nonce [32]byte
		copy(nonce[:], unhex(v.RawCases[0].NonceHex))
		rd := attest.ReportData(nonce, keys[v.RawCases[0].PublicKey])
		for _, w := range v.Wrong {
			res.check(hex.EncodeToString(rd[:]) != w.ReportDataHex, "wrong form %s equals the rule", w.Name)
		}
	}
	// The accepted query, and every refused one.
	_, query, _ := strings.Cut(v.Attest.Request, "?")
	_, err := attest.ParseNonceQuery(query)
	res.check(err == nil, "the vector's request query is refused")
	for _, q := range v.Attest.RefusedQueries {
		_, err := attest.ParseNonceQuery(q.Query)
		res.check(err != nil, "refused query admitted (%s)", q.Why)
	}
	// The answer is exactly compact {"quote","public_key"} in that order.
	quote := []byte{1, 2, 3}
	want := `{"quote":"` + base64.StdEncoding.EncodeToString(quote) + `","public_key":"` + v.Attest.AnswerShapeKeys["public_key"] + `"}`
	res.check(string(attest.Answer(quote, keys["vm-1"])) == want, "answer shape")
	return res, nil
}

type e2eVectors struct {
	Identity struct {
		EndpointID string `json:"endpoint_id"`
		InstanceID string `json:"instance_id"`
	} `json:"identity"`
	Routes []struct {
		Path   string `json:"path"`
		Stream bool   `json:"stream"`
	} `json:"routes"`
	VMKey       vmKey `json:"vm_key"`
	ResponseKey vmKey `json:"response_key"`
	NowMS       int64 `json:"now_ms"`
	Requests    []struct {
		Name          string          `json:"name"`
		Blob          string          `json:"blob_b64"`
		PresentedPath string          `json:"presented_path"`
		Method        string          `json:"method"`
		NowMS         int64           `json:"now_ms"`
		Expect        json.RawMessage `json:"expect"`
		Own           string          `json:"own"`
	} `json:"requests"`
	Answers []struct {
		Name       string          `json:"name"`
		Request    string          `json:"request"`
		WireBody   string          `json:"wire_body"`
		HTTPStatus int             `json:"http_status"`
		Blob       string          `json:"blob_b64"`
		Expect     json.RawMessage `json:"expect"`
	} `json:"answers"`
	Stream struct {
		Request    string `json:"request"`
		HTTPStatus int    `json:"http_status"`
		SSE        string `json:"sse_b64"`
		Expect     struct {
			Data   string `json:"data_b64"`
			Status int    `json:"status"`
		} `json:"expect"`
		Variants []struct {
			Name      string `json:"name"`
			DropChunk *int   `json:"drop_chunk"`
			Swap      []int  `json:"swap"`
			Repeat    *int   `json:"repeat"`
		} `json:"variants"`
	} `json:"stream"`
	RefusalBodies map[string]string `json:"refusal_bodies"`
	RelayPasses   struct {
		Codes []string `json:"codes"`
	} `json:"relay_passes"`
	ReplayCache struct {
		MaxEntries int `json:"max_entries"`
		Sequence   []struct {
			Nonce      string          `json:"nonce"`
			TS         int64           `json:"ts"`
			NowMS      int64           `json:"now_ms"`
			Expect     json.RawMessage `json:"expect"`
			RetryAfter *int            `json:"retry_after"`
		} `json:"sequence"`
	} `json:"replay_cache"`
}

func jsonEqual(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// E2E runs e2e_v2.json: the 34 requests in order against one cache, the answers and the stream
// from the caller's side, the 15 refusal bodies, and the replay cache's bound.
func E2E(dir string) (*Result, error) {
	var v e2eVectors
	if err := load(dir, "e2e_v2.json", &v); err != nil {
		return nil, err
	}
	res := &Result{Group: "e2e_v2.json"}
	key, err := e2ev2.KeyFromSeed(unhex(v.VMKey.Seed))
	if err != nil {
		return nil, err
	}
	res.check(bytes.Equal(key.PublicKey(), b64(v.VMKey.PublicKey)), "vm key from seed")
	var routes []e2ev2.Route
	for _, r := range v.Routes {
		routes = append(routes, e2ev2.Route{Path: r.Path, Stream: r.Stream, AppPath: r.Path})
	}
	table := e2ev2.NewRoutes(routes)
	cache := e2ev2.NewReplayCache(e2ev2.DefaultReplayEntries)
	own := e2ev2.Identity{EndpointID: v.Identity.EndpointID, InstanceID: v.Identity.InstanceID, Known: true}
	blobs := map[string][]byte{}
	for _, c := range v.Requests {
		blob := b64(c.Blob)
		blobs[strings.SplitN(c.Name, " ", 2)[0]] = blob
		id := own
		if c.Own == "unknown" {
			id = e2ev2.Identity{}
		}
		opened, ref := e2ev2.Open(key, blob, e2ev2.Params{
			PresentedPath: c.PresentedPath, Method: c.Method, Routes: table, Identity: id, Cache: cache, NowMS: c.NowMS,
		})
		var expect struct {
			Admit   bool            `json:"admit"`
			Body    json.RawMessage `json:"body"`
			Path    string          `json:"path"`
			Stream  bool            `json:"stream"`
			Nonce   string          `json:"nonce"`
			PKSha   string          `json:"e2e_response_pk_sha256"`
			Refused []any           `json:"refused"`
		}
		if err := json.Unmarshal(c.Expect, &expect); err != nil {
			return nil, err
		}
		if expect.Admit {
			ok := ref == nil
			if ok {
				pk := sha256.Sum256(opened.ResponseKey())
				ok = jsonEqual(opened.Body, expect.Body) && opened.Path == expect.Path && opened.Stream == expect.Stream &&
					opened.Nonce == expect.Nonce && hex.EncodeToString(pk[:]) == expect.PKSha
			}
			res.check(ok, "request %s: expected admit, got %+v", c.Name, ref)
		} else {
			want := fmt.Sprintf("%v %v", expect.Refused[0], expect.Refused[1])
			got := "admitted"
			if ref != nil {
				got = fmt.Sprintf("%d %s", ref.Status, ref.Code)
			}
			res.check(got == want, "request %s: expected %s, got %s", c.Name, want, got)
		}
	}

	// Answers, from the caller's side.
	for _, a := range v.Answers {
		secret, err := e2ev2.NewResponseSecret(unhex(v.ResponseKey.Seed), sha256.Sum256(blobs[a.Request]))
		if err != nil {
			return nil, err
		}
		var expect struct {
			Status  int    `json:"status"`
			Body    string `json:"body_b64"`
			Refused string `json:"refused"`
		}
		_ = json.Unmarshal(a.Expect, &expect)
		status, body, err := secret.OpenAnswer(b64(a.Blob))
		if err == nil && status != a.HTTPStatus {
			err = fmt.Errorf("presented status differs from the sealed one")
		}
		if expect.Refused != "" {
			res.check(err != nil, "answer %s opened", a.Name)
		} else {
			res.check(err == nil && status == expect.Status && base64.StdEncoding.EncodeToString(body) == expect.Body, "answer %s", a.Name)
			if a.WireBody != "" {
				res.check(a.WireBody == `{"e2e":"`+a.Blob+`"}`, "answer %s wire body", a.Name)
			}
		}
	}

	// The stream and its broken variants.
	secret, _ := e2ev2.NewResponseSecret(unhex(v.ResponseKey.Seed), sha256.Sum256(blobs[v.Stream.Request]))
	var init string
	var chunks []string
	for _, line := range strings.Split(string(b64(v.Stream.SSE)), "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var ev map[string]string
		if err := json.Unmarshal([]byte(line[6:]), &ev); err != nil {
			return nil, err
		}
		if s, ok := ev["e2e_init"]; ok {
			init = s
		} else {
			chunks = append(chunks, ev["e2e"])
		}
	}
	run := func(seq []string) ([]byte, error) {
		o, err := secret.OpenStream(init)
		if err != nil {
			return nil, err
		}
		var data []byte
		for _, c := range seq {
			p, err := o.Chunk(c, v.Stream.HTTPStatus)
			if err != nil {
				return nil, err
			}
			data = append(data, p...)
		}
		return data, o.Finish()
	}
	data, err := run(chunks)
	res.check(err == nil && base64.StdEncoding.EncodeToString(data) == v.Stream.Expect.Data, "stream S1")
	for _, variant := range v.Stream.Variants {
		seq := append([]string(nil), chunks...)
		switch {
		case variant.DropChunk != nil:
			seq = append(seq[:*variant.DropChunk], seq[*variant.DropChunk+1:]...)
		case len(variant.Swap) == 2:
			seq[variant.Swap[0]], seq[variant.Swap[1]] = seq[variant.Swap[1]], seq[variant.Swap[0]]
		case variant.Repeat != nil:
			i := *variant.Repeat
			seq = append(seq[:i+1], append([]string{seq[i]}, seq[i+1:]...)...)
		}
		_, err := run(seq)
		res.check(err != nil, "stream variant accepted: %s", variant.Name)
	}

	// The 15 refusal bodies, byte for byte, and nothing else.
	codes := e2ev2.Codes()
	listed := append([]string(nil), v.RelayPasses.Codes...)
	sort.Strings(listed)
	res.check(reflect.DeepEqual(codes, listed) && len(codes) == 15, "the gate's codes are not the vector's 15")
	for code, body := range v.RefusalBodies {
		res.check(e2ev2.StatusOf(code) != 0 && string(e2ev2.NewRefusal(code).Body()) == body, "refusal body %s", code)
	}

	// The replay cache's bound.
	small := e2ev2.NewReplayCache(v.ReplayCache.MaxEntries)
	for i, step := range v.ReplayCache.Sequence {
		nonce := strings.Repeat(step.Nonce, 43)[:43]
		ref := small.Admit(nonce, step.TS, step.NowMS)
		var got any = "admitted"
		if ref != nil {
			got = []any{float64(ref.Status), ref.Code}
		}
		var want any
		_ = json.Unmarshal(step.Expect, &want)
		res.check(reflect.DeepEqual(got, want), "replay step %d: got %v want %v", i, got, want)
		if step.RetryAfter != nil {
			res.check(ref != nil && ref.RetryAfter == *step.RetryAfter, "replay step %d retry_after", i)
		}
	}
	return res, nil
}

// ProbeHealthy is the controller's health rule (spec section 4.4): a status 200..299 with at
// most 4096 body bytes within 5 s; everything else (an event such as a timeout) is unhealthy.
func ProbeHealthy(status int, bodyBytes int, event string) bool {
	return event == "" && status >= 200 && status <= 299 && bodyBytes <= 4096
}

// Health runs health.json's 10 probe outcomes through ProbeHealthy, and checks the gate's own two
// answers (200 with an empty body, 503) are classified as intended.
func Health(dir string) (*Result, error) {
	var v struct {
		Cases []struct {
			Status    *int    `json:"status"`
			Event     *string `json:"event"`
			BodyBytes int     `json:"body_bytes"`
			Expect    string  `json:"expect"`
		} `json:"cases"`
	}
	if err := load(dir, "health.json", &v); err != nil {
		return nil, err
	}
	res := &Result{Group: "health.json"}
	for i, c := range v.Cases {
		status, event := 0, ""
		if c.Status != nil {
			status = *c.Status
		}
		if c.Event != nil {
			event = *c.Event
		}
		want := strings.HasPrefix(c.Expect, "healthy")
		res.check(ProbeHealthy(status, c.BodyBytes, event) == want, "health case %d (%v %v): want %s", i, status, event, c.Expect)
	}
	res.check(ProbeHealthy(200, 0, ""), "the gate's healthy answer")
	res.check(!ProbeHealthy(503, 0, ""), "the gate's unhealthy answer")
	return res, nil
}

// Run runs every group.
func Run(dir string) ([]*Result, error) {
	var out []*Result
	for _, f := range []func(string) (*Result, error){VerifySums, Reportdata, E2E, Health} {
		r, err := f(dir)
		if err != nil {
			return out, err
		}
		out = append(out, r)
	}
	return out, nil
}
