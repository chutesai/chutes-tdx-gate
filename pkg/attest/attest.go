// Package attest implements the endpoint's /attest route (spec section 4.1): the REPORTDATA
// rule, the nonce query, the answer, and TDX quote generation through configfs-tsm.
//
// Domain separation: this package is the only code in the gate that computes REPORTDATA, and it
// computes it only as ReportData(nonce, the gate's own public key). No route returns a quote over
// caller-chosen REPORTDATA.
package attest

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
)

// Tag is the REPORTDATA domain tag of the /attest route.
const Tag = "chutes-tdx-endpoint-attest-v1"

// PublicKeySize is the ML-KEM-768 encapsulation key size.
const PublicKeySize = 1184

// MaxQuoteBytes is the largest quote the route returns.
const MaxQuoteBytes = 32768

// ReportData is SHA-512(Tag || 0x00 || nonce (32 bytes) || publicKey (1184 bytes)).
func ReportData(nonce [32]byte, publicKey []byte) [64]byte {
	h := sha512.New()
	h.Write([]byte(Tag))
	h.Write([]byte{0})
	h.Write(nonce[:])
	h.Write(publicKey)
	var out [64]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ErrBadNonce is a query other than exactly nonce=<64 lower-case hex>.
var ErrBadNonce = errors.New("attest: bad nonce query")

// ParseNonceQuery accepts exactly one query parameter, nonce, as 64 lower-case hex characters,
// written literally (no percent-encoding, no other parameter, no repetition).
func ParseNonceQuery(rawQuery string) ([32]byte, error) {
	var nonce [32]byte
	const prefix = "nonce="
	if len(rawQuery) != len(prefix)+64 || rawQuery[:len(prefix)] != prefix {
		return nonce, ErrBadNonce
	}
	text := rawQuery[len(prefix):]
	for i := 0; i < len(text); i++ {
		c := text[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nonce, ErrBadNonce
		}
	}
	if _, err := hex.Decode(nonce[:], []byte(text)); err != nil {
		return nonce, ErrBadNonce
	}
	return nonce, nil
}

// CheckQuote checks that raw is a TDX quote v4 (version 4, TEE type 0x81) of at most
// MaxQuoteBytes whose REPORTDATA is want.
func CheckQuote(raw []byte, want [64]byte) error {
	if len(raw) < 632 || len(raw) > MaxQuoteBytes {
		return errors.New("attest: quote size")
	}
	if binary.LittleEndian.Uint16(raw[0:2]) != 4 || binary.LittleEndian.Uint32(raw[4:8]) != 0x81 {
		return errors.New("attest: not a TDX quote v4")
	}
	if string(raw[568:632]) != string(want[:]) {
		return errors.New("attest: quote REPORTDATA differs")
	}
	return nil
}

// Answer is the exact /attest body: compact {"quote": B64, "public_key": B64}, keys in that order.
func Answer(quote, publicKey []byte) []byte {
	out := []byte(`{"quote":"`)
	out = append(out, base64.StdEncoding.EncodeToString(quote)...)
	out = append(out, `","public_key":"`...)
	out = append(out, base64.StdEncoding.EncodeToString(publicKey)...)
	out = append(out, `"}`...)
	return out
}

// Quoter produces a TDX quote over 64 REPORTDATA bytes.
type Quoter interface {
	Quote(reportData [64]byte) ([]byte, error)
}

// Refusal bodies of the route.
var (
	bodyBadNonce    = []byte(`{"detail":{"code":"attest_bad_nonce"}}`)
	bodyBusy        = []byte(`{"detail":{"code":"attest_busy"}}`)
	bodyUnavailable = []byte(`{"detail":{"code":"attest_unavailable"}}`)
)

// Handler serves GET /attest?nonce=<64 hex> for the key publicKey.
type Handler struct {
	PublicKey []byte
	Quoter    Quoter
	// Logf records the outcome only (status and code), never a request byte.
	Logf func(status int, code string)
}

func (h *Handler) log(status int, code string) {
	if h.Logf != nil {
		h.Logf(status, code)
	}
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		h.log(http.StatusMethodNotAllowed, "attest_method")
		return
	}
	nonce, err := ParseNonceQuery(r.URL.RawQuery)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, bodyBadNonce)
		h.log(http.StatusBadRequest, "attest_bad_nonce")
		return
	}
	rd := ReportData(nonce, h.PublicKey)
	quote, err := h.Quoter.Quote(rd)
	if err == nil {
		err = CheckQuote(quote, rd)
	}
	switch {
	case errors.Is(err, ErrBusy):
		writeJSON(w, http.StatusServiceUnavailable, bodyBusy)
		h.log(http.StatusServiceUnavailable, "attest_busy")
		return
	case err != nil:
		writeJSON(w, http.StatusServiceUnavailable, bodyUnavailable)
		h.log(http.StatusServiceUnavailable, "attest_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, Answer(quote, h.PublicKey))
	h.log(http.StatusOK, "")
}
