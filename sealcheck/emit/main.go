// Command emit seals answers and one stream with the Go gate's own sealer (pkg/e2ev2: SealAnswer,
// StreamSealer) and prints them as JSON for sealcheck/open.py, which opens them with code that
// shares nothing with the gate (FIPS 203 from spec/vectors/mlkem768.py, HKDF and
// ChaCha20-Poly1305 written out in Python).
//
//	go run ./sealcheck/emit > out/sealed-go.json
package main

import (
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/chutesai/chutes-tdx-gate/pkg/e2ev2"
)

const (
	endpoint = "6b1c0e7e-4d0b-4f2a-9a57-1f3d2c8b9e40"
	instance = "5813945712345678901"
	nowMS    = 1795000000000
)

type answer struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
	Wire   string `json:"wire"`
}

type stream struct {
	RequestBlob string   `json:"request_blob"`
	Status      int      `json:"status"`
	Data        []string `json:"data"`
	SSE         string   `json:"sse"`
}

type output struct {
	Form         string   `json:"form"`
	ResponseSeed string   `json:"response_seed"`
	RequestBlob  string   `json:"request_blob"`
	Answers      []answer `json:"answers"`
	Stream       stream   `json:"stream"`
}

func opened(gate *e2ev2.Key, responseSeed []byte, path string, stream bool) (*e2ev2.Opened, []byte, error) {
	dk, err := mlkem.NewDecapsulationKey768(responseSeed)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	env, _ := json.Marshal(map[string]any{
		"v": 2, "endpoint_id": endpoint, "instance_id": instance, "path": path, "stream": stream,
		"nonce": base64.RawURLEncoding.EncodeToString(nonce), "ts": nowMS,
		"e2e_response_pk": base64.StdEncoding.EncodeToString(dk.EncapsulationKey().Bytes()),
		"body":            map[string]any{"stream": stream},
	})
	blob, err := e2ev2.SealRequest(gate.PublicKey(), env)
	if err != nil {
		return nil, nil, err
	}
	o, ref := e2ev2.Open(gate, blob, e2ev2.Params{
		PresentedPath: path, Method: "POST",
		Routes:   e2ev2.NewRoutes([]e2ev2.Route{{Path: path, Stream: stream, AppPath: path}}),
		Identity: e2ev2.Identity{EndpointID: endpoint, InstanceID: instance, Known: true},
		Cache:    e2ev2.NewReplayCache(0), NowMS: nowMS,
	})
	if ref != nil {
		return nil, nil, fmt.Errorf("the request was refused: %s", ref.Code)
	}
	return o, blob, nil
}

func sse(field string, raw []byte) string {
	return `data: {"` + field + `":"` + base64.StdEncoding.EncodeToString(raw) + "\"}\n\n"
}

func run() error {
	gate, err := e2ev2.GenerateKey()
	if err != nil {
		return err
	}
	seed := make([]byte, 64)
	_, _ = rand.Read(seed)
	out := output{Form: "go", ResponseSeed: hex.EncodeToString(seed)}

	o, blob, err := opened(gate, seed, "/v1/answer", false)
	if err != nil {
		return err
	}
	out.RequestBlob = base64.StdEncoding.EncodeToString(blob)
	big := []byte(strings.Repeat("0123456789abcdef", 6000))
	for _, c := range []struct {
		status int
		body   []byte
	}{{200, nil}, {201, []byte("hello")}, {418, []byte(`{"error":"teapot","é":"😀"}`)}, {599, big}} {
		sealed, err := e2ev2.SealAnswer(o, c.status, c.body)
		if err != nil {
			return err
		}
		out.Answers = append(out.Answers, answer{c.status, base64.StdEncoding.EncodeToString(c.body),
			`{"e2e":"` + base64.StdEncoding.EncodeToString(sealed) + `"}`})
	}

	// The stream answers its own request (bound to that blob): the opener gets that blob too.
	so, sblob, err := opened(gate, seed, "/v1/stream", true)
	if err != nil {
		return err
	}
	sealer, err := e2ev2.NewStreamSealer(so)
	if err != nil {
		return err
	}
	head, err := sealer.Head(200)
	if err != nil {
		return err
	}
	var events strings.Builder
	events.WriteString(sse("e2e_init", sealer.Init()))
	events.WriteString(sse("e2e", head))
	out.Stream.Status = 200
	for _, chunk := range [][]byte{[]byte("data: {\"i\":0}\n\n"), make([]byte, e2ev2.MaxChunkData), []byte("x")} {
		c, err := sealer.Data(chunk)
		if err != nil {
			return err
		}
		events.WriteString(sse("e2e", c))
		out.Stream.Data = append(out.Stream.Data, base64.StdEncoding.EncodeToString(chunk))
	}
	end, err := sealer.End()
	if err != nil {
		return err
	}
	events.WriteString(sse("e2e", end))
	out.Stream.SSE = events.String()
	out.Stream.RequestBlob = base64.StdEncoding.EncodeToString(sblob)
	return json.NewEncoder(os.Stdout).Encode(out)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "emit:", err)
		os.Exit(1)
	}
}
