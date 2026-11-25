// Package e2ev2 is the instance (server) side of Chutes E2E v2 (spec section 4.3): it opens a
// request blob, checks its envelope and bindings in the spec's order, admits its nonce, and
// seals the answer or the stream to the caller's one-time response key.
//
// Wire format (identical to the SDK's chutes.entrypoint.cpu_e2e v2):
//
//	request:  mlkem_ct(1088) || nonce(12) || ciphertext || tag(16); key = HKDF-SHA256(shared,
//	          salt = mlkem_ct[:16], info "e2e-req-v2"); ChaCha20-Poly1305 with AAD
//	          "chutes-e2e-v2 request"; plaintext = gzip(the JSON envelope).
//	answer:   the same shape, encapsulated to e2e_response_pk, info "e2e-resp-v2", AAD
//	          "chutes-e2e-v2 answer" || SHA-256(request blob); plaintext = gzip({"v":2,"status":S}\n body).
//	stream:   e2e_init = mlkem_ct (info "e2e-stream-v2"); each chunk nonce(12) || ct || tag(16),
//	          AAD "chutes-e2e-v2 stream" || SHA-256(request blob); plaintext = kind(1) ||
//	          seq(8, big-endian) || payload.
package e2ev2

import (
	"bytes"
	"compress/gzip"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	CiphertextSize = mlkem.CiphertextSize768       // 1088
	PublicKeySize  = mlkem.EncapsulationKeySize768 // 1184
	NonceSize      = chacha20poly1305.NonceSize    // 12
	TagSize        = chacha20poly1305.Overhead     // 16
	MinBlobSize    = CiphertextSize + NonceSize + TagSize

	InfoRequest = "e2e-req-v2"
	InfoAnswer  = "e2e-resp-v2"
	InfoStream  = "e2e-stream-v2"

	ChunkHead = 1
	ChunkData = 2
	ChunkEnd  = 3

	// MaxChunkData is the largest data chunk payload the gate seals.
	MaxChunkData = 65536
)

var (
	aadRequest = []byte("chutes-e2e-v2 request")
	aadAnswer  = []byte("chutes-e2e-v2 answer")
	aadStream  = []byte("chutes-e2e-v2 stream")
)

// Key is the gate's ML-KEM-768 key pair. It lives in memory only: no file holds it (the seed is
// in a sealed memfd in systemd's store, internal/keystore).
type Key struct {
	dk *mlkem.DecapsulationKey768
	pk []byte
}

// GenerateKey makes the per-boot key.
func GenerateKey() (*Key, error) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, err
	}
	return &Key{dk: dk, pk: dk.EncapsulationKey().Bytes()}, nil
}

// KeyFromSeed makes a key from its 64-byte seed d || z (FIPS 203 ML-KEM.KeyGen_internal): the
// gate's per-boot key from a fresh random seed, or the same seed back from systemd's file
// descriptor store after a restart of the gate (internal/keystore); the vectors' keys.
func KeyFromSeed(seed []byte) (*Key, error) {
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, err
	}
	return &Key{dk: dk, pk: dk.EncapsulationKey().Bytes()}, nil
}

// PublicKey is the 1184-byte encapsulation key.
func (k *Key) PublicKey() []byte { return bytes.Clone(k.pk) }

func deriveKey(shared, ct []byte, info string) ([]byte, error) {
	return hkdf.Key(sha256.New, shared, ct[:16], info, 32)
}

func open(key *Key, blob []byte) ([]byte, error) {
	if len(blob) < MinBlobSize {
		return nil, errors.New("short blob")
	}
	ct := blob[:CiphertextSize]
	nonce := blob[CiphertextSize : CiphertextSize+NonceSize]
	sealed := blob[CiphertextSize+NonceSize:]
	shared, err := key.dk.Decapsulate(ct)
	if err != nil {
		return nil, err
	}
	k, err := deriveKey(shared, ct, InfoRequest)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(k)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, sealed, aadRequest)
}

// gunzip inflates exactly one gzip member of at most limit bytes with nothing after it. The size
// is the member's trailer (ISIZE, which the reader checks at the end): it is reserved from lease
// before a byte is inflated, and a member that inflates to more is refused.
func gunzip(data []byte, limit int64, lease *Lease) ([]byte, *Refusal) {
	malformed := refusal("e2e_v2_malformed")
	if len(data) < 18 { // a gzip header and trailer
		return nil, malformed
	}
	size := int64(binary.LittleEndian.Uint32(data[len(data)-4:]))
	if size > limit {
		return nil, malformed
	}
	if !lease.Charge(size + 1) {
		return nil, lease.Refusal()
	}
	src := bytes.NewReader(data)
	zr, err := gzip.NewReader(src)
	if err != nil {
		return nil, malformed
	}
	zr.Multistream(false)
	buf := make([]byte, size+1)
	n, err := io.ReadFull(zr, buf)
	// EOF comes only after the reader checked the CRC and that the member inflated to exactly
	// ISIZE bytes; a full buffer is one byte too many.
	if (err != io.EOF && err != io.ErrUnexpectedEOF) || src.Len() != 0 {
		return nil, malformed
	}
	return buf[:n], nil
}

// SealCost bounds what SealAnswer and its wire encoding allocate for a body of n bytes: the
// plaintext, the gzip member (stored blocks at worst) and the compressor's state, the blob, and
// its base64 (the gate reserves it before sealing).
func SealCost(n int) int64 { return 5*int64(n) + 2<<20 }

func gz(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(len(data) + len(data)/1000 + 1024) // incompressible data: stored blocks, 5 bytes per 64 KiB
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func statusHeader(status int) []byte {
	return []byte(`{"v":2,"status":` + strconv.Itoa(status) + `}`)
}

// SealAnswer seals a non-stream answer (status and body together) to the request's response key,
// bound to the request blob's digest. The status must be 200..599.
func SealAnswer(o *Opened, status int, body []byte) ([]byte, error) {
	if status < 200 || status > 599 {
		return nil, errors.New("status outside 200..599")
	}
	header := statusHeader(status)
	plain := make([]byte, 0, len(header)+1+len(body))
	plain = append(append(append(plain, header...), '\n'), body...)
	compressed, err := gz(plain)
	if err != nil {
		return nil, err
	}
	shared, ct := o.responseKey.Encapsulate()
	k, err := deriveKey(shared, ct, InfoAnswer)
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
	aad := append(bytes.Clone(aadAnswer), o.digest[:]...)
	out := make([]byte, 0, CiphertextSize+NonceSize+len(compressed)+TagSize)
	out = append(out, ct...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, compressed, aad), nil
}

// StreamSealer seals one stream answer: Init (the ML-KEM ciphertext), then Head, Data..., End.
type StreamSealer struct {
	key    []byte
	ct     []byte
	digest [32]byte
	seq    uint64
	ended  bool
}

// NewStreamSealer encapsulates the stream key to the request's response key.
func NewStreamSealer(o *Opened) (*StreamSealer, error) {
	shared, ct := o.responseKey.Encapsulate()
	k, err := deriveKey(shared, ct, InfoStream)
	if err != nil {
		return nil, err
	}
	return &StreamSealer{key: k, ct: ct, digest: o.digest}, nil
}

// Init is the e2e_init value: the ML-KEM ciphertext.
func (s *StreamSealer) Init() []byte { return bytes.Clone(s.ct) }

func (s *StreamSealer) chunk(kind byte, payload []byte) ([]byte, error) {
	if s.ended {
		return nil, errors.New("the stream already ended")
	}
	aead, err := chacha20poly1305.New(s.key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, 9, 9+len(payload))
	plain[0] = kind
	binary.BigEndian.PutUint64(plain[1:9], s.seq)
	plain = append(plain, payload...)
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := append(bytes.Clone(aadStream), s.digest[:]...)
	s.seq++
	return aead.Seal(bytes.Clone(nonce), nonce, plain, aad), nil
}

// Head seals chunk 0, the status header.
func (s *StreamSealer) Head(status int) ([]byte, error) {
	if s.seq != 0 {
		return nil, errors.New("the head is chunk 0")
	}
	return s.chunk(ChunkHead, statusHeader(status))
}

// Data seals one data chunk of at most MaxChunkData bytes.
func (s *StreamSealer) Data(payload []byte) ([]byte, error) {
	if s.seq == 0 {
		return nil, errors.New("data before the head")
	}
	if len(payload) > MaxChunkData {
		return nil, errors.New("data chunk over 65536 bytes")
	}
	return s.chunk(ChunkData, payload)
}

// End seals the end chunk. Call it only after the application's body ended normally.
func (s *StreamSealer) End() ([]byte, error) {
	if s.seq == 0 {
		return nil, errors.New("end before the head")
	}
	out, err := s.chunk(ChunkEnd, nil)
	if err == nil {
		s.ended = true
	}
	return out, err
}
