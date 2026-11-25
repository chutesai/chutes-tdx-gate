package e2ev2_test

import (
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chutesai/chutes-tdx-gate/pkg/conformance"
	"github.com/chutesai/chutes-tdx-gate/pkg/e2ev2"
)

const vectors = "../../spec/vectors"

// Every vector in spec/vectors, in Go.
func TestVectors(t *testing.T) {
	results, err := conformance.Run(vectors)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, r := range results {
		total += r.Passed
		for _, f := range r.Failures {
			t.Errorf("%s: %s", r.Group, f)
		}
	}
	if total < 100 {
		t.Fatalf("only %d vector checks ran", total)
	}
}

func envelope(pk []byte, ts int64, nonce string, body string) []byte {
	return []byte(`{"v":2,"endpoint_id":"e","instance_id":"1","path":"/r","stream":false,"nonce":"` + nonce +
		`","ts":` + jsonInt(ts) + `,"e2e_response_pk":"` + base64.StdEncoding.EncodeToString(pk) + `","body":` + body + `}`)
}

func jsonInt(v int64) string { b, _ := json.Marshal(v); return string(b) }

func fixture(t *testing.T) (*e2ev2.Key, []byte, e2ev2.Params) {
	key, err := e2ev2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, 64)
	_, _ = rand.Read(seed)
	dk, _ := mlkem.NewDecapsulationKey768(seed)
	p := e2ev2.Params{
		PresentedPath: "/r", Method: "POST",
		Routes:   e2ev2.NewRoutes([]e2ev2.Route{{Path: "/r", AppPath: "/app"}}),
		Identity: e2ev2.Identity{EndpointID: "e", InstanceID: "1", Known: true},
		Cache:    e2ev2.NewReplayCache(16), NowMS: 1795000000000,
	}
	_ = seed
	return key, dk.EncapsulationKey().Bytes(), p
}

func nonce(i int) string { return strings.Repeat(string(rune('a'+i)), 43) }

func TestEnvelopeRules(t *testing.T) {
	key, pk, p := fixture(t)
	ts := p.NowMS
	cases := map[string]struct {
		env  []byte
		code string
	}{
		"duplicate key":                       {[]byte(strings.Replace(string(envelope(pk, ts, nonce(0), `{}`)), `"v":2,`, `"v":2,"v":2,`, 1)), "e2e_v2_malformed"},
		"duplicate key in body":               {envelope(pk, ts, nonce(1), `{"stream":false,"stream":true}`), "e2e_v2_malformed"},
		"lone surrogate":                      {envelope(pk, ts, nonce(2), `{"a":"\ud800"}`), "e2e_v2_malformed"},
		"NaN in body":                         {envelope(pk, ts, nonce(3), `{"a":NaN}`), "e2e_v2_malformed"},
		"ts 2.0":                              {[]byte(strings.Replace(string(envelope(pk, ts, nonce(4), `{}`)), `"ts":`+jsonInt(ts), `"ts":`+jsonInt(ts)+`.0`, 1)), "e2e_v2_malformed"},
		"ts uint64 max":                       {[]byte(strings.Replace(string(envelope(pk, ts, nonce(5), `{}`)), `"ts":`+jsonInt(ts), `"ts":18446744073709551615`, 1)), "e2e_v2_from_the_future"},
		"ts int64 min":                        {[]byte(strings.Replace(string(envelope(pk, ts, nonce(6), `{}`)), `"ts":`+jsonInt(ts), `"ts":-9223372036854775808`, 1)), "e2e_v2_stale"},
		"ts above uint64":                     {[]byte(strings.Replace(string(envelope(pk, ts, nonce(17), `{}`)), `"ts":`+jsonInt(ts), `"ts":18446744073709551616`, 1)), "e2e_v2_malformed"},
		"ts below int64":                      {[]byte(strings.Replace(string(envelope(pk, ts, nonce(18), `{}`)), `"ts":`+jsonInt(ts), `"ts":-9223372036854775809`, 1)), "e2e_v2_malformed"},
		"body integer beyond 64 bits (valid)": {envelope(pk, ts, nonce(19), `{"n":99999999999999999999999}`), ""},
		"key with a newline":                  {[]byte(strings.Replace(string(envelope(pk, ts, nonce(7), `{}`)), `"e2e_response_pk":"`, `"e2e_response_pk":"\n`, 1)), "e2e_v2_malformed"},
		"key unpadded":                        {[]byte(strings.Replace(string(envelope(pk, ts, nonce(8), `{}`)), `=","body"`, `","body"`, 1)), "e2e_v2_malformed"},
		"nonce 44":                            {envelope(pk, ts, nonce(9)+"a", `{}`), "e2e_v2_malformed"},
		"nonce with +":                        {envelope(pk, ts, "+"+nonce(10)[1:], `{}`), "e2e_v2_malformed"},
		"body array":                          {envelope(pk, ts, nonce(11), `[]`), "e2e_v2_malformed"},
		"v \"2\"":                             {[]byte(strings.Replace(string(envelope(pk, ts, nonce(12), `{}`)), `"v":2`, `"v":"2"`, 1)), "e2e_v2_malformed"},
		"stream null":                         {[]byte(strings.Replace(string(envelope(pk, ts, nonce(13), `{}`)), `"stream":false`, `"stream":null`, 1)), "e2e_v2_malformed"},
		"body.stream \"false\"":               {envelope(pk, ts, nonce(14), `{"stream":"false"}`), "e2e_v2_stream_mismatch"},
		"body.stream null":                    {envelope(pk, ts, nonce(15), `{"stream":null}`), "e2e_v2_stream_mismatch"},
		"body.stream false (fine)":            {envelope(pk, ts, nonce(16), `{"stream":false}`), ""},
	}
	for name, c := range cases {
		blob, err := e2ev2.SealRequest(key.PublicKey(), c.env)
		if err != nil {
			t.Fatal(err)
		}
		_, ref := e2ev2.Open(key, blob, p)
		got := ""
		if ref != nil {
			got = ref.Code
		}
		if got != c.code {
			t.Errorf("%s: got %q want %q", name, got, c.code)
		}
	}
}

// A response key that fails FIPS 203's modulus check is refused before the nonce is used.
func TestResponseKeyModulus(t *testing.T) {
	key, pk, p := fixture(t)
	bad := append([]byte(nil), pk...)
	bad[0], bad[1] = 0xff, 0xff // a coefficient >= q
	blob, _ := e2ev2.SealRequest(key.PublicKey(), envelope(bad, p.NowMS, nonce(0), `{}`))
	if _, ref := e2ev2.Open(key, blob, p); ref == nil || ref.Code != "e2e_v2_malformed" {
		t.Fatalf("got %+v", ref)
	}
	blob, _ = e2ev2.SealRequest(key.PublicKey(), envelope(pk, p.NowMS, nonce(0), `{}`))
	if _, ref := e2ev2.Open(key, blob, p); ref != nil {
		t.Fatalf("the nonce of a refused request was consumed: %+v", ref)
	}
}

func TestGzipRules(t *testing.T) {
	key, pk, p := fixture(t)
	p.MaxPlaintext = 1024
	big := `{"x":"` + strings.Repeat("a", 2000) + `"}`
	blob, _ := e2ev2.SealRequest(key.PublicKey(), envelope(pk, p.NowMS, nonce(0), big))
	if _, ref := e2ev2.Open(key, blob, p); ref == nil || ref.Code != "e2e_v2_malformed" {
		t.Fatalf("over the plaintext limit: %+v", ref)
	}
}

func TestSealRoundTrip(t *testing.T) {
	key, _, p := fixture(t)
	seed := make([]byte, 64)
	_, _ = rand.Read(seed)
	dk, _ := mlkem.NewDecapsulationKey768(seed)
	blob, _ := e2ev2.SealRequest(key.PublicKey(), envelope(dk.EncapsulationKey().Bytes(), p.NowMS, nonce(0), `{"k":1}`))
	o, ref := e2ev2.Open(key, blob, p)
	if ref != nil {
		t.Fatal(ref)
	}
	sealed, err := e2ev2.SealAnswer(o, 418, []byte("body"))
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := e2ev2.NewResponseSecret(seed, sha256.Sum256(blob))
	status, body, err := secret.OpenAnswer(sealed)
	if err != nil || status != 418 || string(body) != "body" {
		t.Fatalf("%d %q %v", status, body, err)
	}
	other, _ := e2ev2.NewResponseSecret(seed, sha256.Sum256([]byte("another request")))
	if _, _, err := other.OpenAnswer(sealed); err == nil {
		t.Fatal("an answer opened for another request")
	}
	if _, err := e2ev2.SealAnswer(o, 199, nil); err == nil {
		t.Fatal("a status below 200 was sealed")
	}
}

func TestRefusalCodesClosed(t *testing.T) {
	if len(e2ev2.Codes()) != 15 {
		t.Fatal("not 15 codes")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("a 16th code was accepted")
		}
	}()
	e2ev2.NewRefusal("e2e_v2_overloaded")
}

func TestReplayFloor(t *testing.T) {
	c := e2ev2.NewReplayCache(4)
	now := int64(1795000000000)
	if r := c.Admit(nonce(0), now, now); r != nil {
		t.Fatal(r)
	}
	// After it leaves the window, anything dated at or below it is stale, even with a clock step back.
	later := now + e2ev2.MaxAgeMS + 1
	if r := c.Admit(nonce(1), later, later); r != nil {
		t.Fatal(r)
	}
	if r := c.Admit(nonce(0), now, now+1000); r == nil || r.Code != "e2e_v2_stale" {
		t.Fatalf("a forgotten request was admitted again after a clock step: %+v", r)
	}
}
