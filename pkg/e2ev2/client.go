package e2ev2

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/chutesai/chutes-tdx-gate/pkg/sjson"
)

// This file is the caller's side, used by the conformance vectors and the tests (the answer and
// stream vectors are read from the caller's position). The gate itself never calls it.

// SealRequest builds a request blob for the instance key pk from the envelope's plaintext
// (before gzip), and returns the blob and the response decapsulation key to open the answer.
func SealRequest(pk []byte, envelope []byte) ([]byte, error) {
	ek, err := mlkem.NewEncapsulationKey768(pk)
	if err != nil {
		return nil, err
	}
	compressed, err := gz(envelope)
	if err != nil {
		return nil, err
	}
	shared, ct := ek.Encapsulate()
	k, err := deriveKey(shared, ct, InfoRequest)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(k)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append(bytes.Clone(ct), nonce...)
	return aead.Seal(out, nonce, compressed, aadRequest), nil
}

// ResponseSecret opens answers to one request: the response decapsulation key and the request
// blob's digest.
type ResponseSecret struct {
	dk     *mlkem.DecapsulationKey768
	digest [32]byte
}

// NewResponseSecret from a response key seed and the request digest.
func NewResponseSecret(seed []byte, digest [32]byte) (*ResponseSecret, error) {
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, err
	}
	return &ResponseSecret{dk: dk, digest: digest}, nil
}

// ErrNotThisRequest is an answer that does not open as this request's.
var ErrNotThisRequest = errors.New("e2ev2: does not decrypt as this request's")

// OpenAnswer returns the sealed (status, body).
func (s *ResponseSecret) OpenAnswer(blob []byte) (int, []byte, error) {
	if len(blob) < MinBlobSize {
		return 0, nil, ErrNotThisRequest
	}
	ct, nonce, sealed := blob[:CiphertextSize], blob[CiphertextSize:CiphertextSize+NonceSize], blob[CiphertextSize+NonceSize:]
	shared, err := s.dk.Decapsulate(ct)
	if err != nil {
		return 0, nil, ErrNotThisRequest
	}
	k, _ := deriveKey(shared, ct, InfoAnswer)
	aead, _ := chacha20poly1305.New(k)
	compressed, err := aead.Open(nil, nonce, sealed, append(bytes.Clone(aadAnswer), s.digest[:]...))
	if err != nil {
		return 0, nil, ErrNotThisRequest
	}
	plain, ref := gunzip(compressed, 256<<20, nil)
	if ref != nil {
		return 0, nil, errors.New("e2ev2: the answer is not one gzip member")
	}
	end := bytes.IndexByte(plain, '\n')
	if end < 0 || end > 64 {
		return 0, nil, errors.New("e2ev2: no status header")
	}
	status, err := parseStatusHeader(plain[:end])
	if err != nil {
		return 0, nil, err
	}
	return status, plain[end+1:], nil
}

func parseStatusHeader(raw []byte) (int, error) {
	v, err := sjson.Parse(raw)
	if err != nil || !v.HasExactly("v", "status") || v.Get("v").Num != "2" || !v.Get("status").IsInteger() {
		return 0, errors.New("e2ev2: not a v2 status header")
	}
	status, err := strconv.Atoi(v.Get("status").Num)
	if err != nil || status < 100 || status > 599 {
		return 0, errors.New("e2ev2: not a v2 status header")
	}
	return status, nil
}

// StreamOpener opens one stream's chunks in order and refuses a gap, a repeat, a reordering or a
// missing end.
type StreamOpener struct {
	key      []byte
	digest   [32]byte
	expected uint64
	status   int
	ended    bool
}

// OpenStream derives the stream key from the e2e_init ciphertext (base64).
func (s *ResponseSecret) OpenStream(initB64 string) (*StreamOpener, error) {
	ct, err := base64.StdEncoding.DecodeString(initB64)
	if err != nil || len(ct) != CiphertextSize {
		return nil, errors.New("e2ev2: bad e2e_init")
	}
	shared, err := s.dk.Decapsulate(ct)
	if err != nil {
		return nil, err
	}
	k, _ := deriveKey(shared, ct, InfoStream)
	return &StreamOpener{key: k, digest: s.digest}, nil
}

// Chunk opens one e2e chunk (base64) and returns its data payload (nil for head and end).
func (o *StreamOpener) Chunk(chunkB64 string, presented int) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(chunkB64)
	if err != nil || len(raw) < NonceSize+TagSize {
		return nil, errors.New("e2ev2: bad chunk")
	}
	if o.ended {
		return nil, errors.New("e2ev2: data after the end")
	}
	aead, _ := chacha20poly1305.New(o.key)
	plain, err := aead.Open(nil, raw[:NonceSize], raw[NonceSize:], append(bytes.Clone(aadStream), o.digest[:]...))
	if err != nil || len(plain) < 9 {
		return nil, errors.New("e2ev2: chunk does not open")
	}
	kind, seq, payload := plain[0], binary.BigEndian.Uint64(plain[1:9]), plain[9:]
	if seq != o.expected {
		return nil, errors.New("e2ev2: out of order")
	}
	o.expected++
	switch {
	case seq == 0:
		if kind != ChunkHead {
			return nil, errors.New("e2ev2: no head")
		}
		if o.status, err = parseStatusHeader(payload); err != nil || o.status != presented || o.status < 200 || o.status > 299 {
			return nil, errors.New("e2ev2: bad head")
		}
		return nil, nil
	case kind == ChunkHead:
		return nil, errors.New("e2ev2: repeated head")
	case kind == ChunkEnd:
		if len(payload) != 0 {
			return nil, errors.New("e2ev2: end with data")
		}
		o.ended = true
		return nil, nil
	case kind == ChunkData:
		return payload, nil
	}
	return nil, errors.New("e2ev2: unknown chunk kind")
}

// Finish refuses a stream without its head or its end.
func (o *StreamOpener) Finish() error {
	if o.status == 0 || !o.ended {
		return errors.New("e2ev2: cut short")
	}
	return nil
}
