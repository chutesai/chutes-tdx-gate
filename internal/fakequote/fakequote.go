// Package fakequote makes UNSIGNED synthetic TDX v4 quotes (the vectors' quote.json layout) that
// carry a given REPORTDATA. Tests and the faketsm test build only: no verifier accepts them.
package fakequote

import (
	"encoding/binary"
	"sync"
)

// Quote is a 640-byte v4 quote: a 48-byte header (version 4, attestation key type 2, TEE type
// 0x81), a 584-byte TD body with reportData at absolute offset 568, and an empty signature.
func Quote(reportData [64]byte) []byte {
	q := make([]byte, 640)
	binary.LittleEndian.PutUint16(q[0:2], 4)
	binary.LittleEndian.PutUint16(q[2:4], 2)
	binary.LittleEndian.PutUint32(q[4:8], 0x81)
	copy(q[568:632], reportData[:])
	binary.LittleEndian.PutUint32(q[632:636], 4)
	return q
}

// Quoter records every REPORTDATA it was asked for.
type Quoter struct {
	mu   sync.Mutex
	Seen [][64]byte
}

// Quote returns Quote(reportData) and records the request.
func (f *Quoter) Quote(reportData [64]byte) ([]byte, error) {
	f.mu.Lock()
	f.Seen = append(f.Seen, reportData)
	f.mu.Unlock()
	return Quote(reportData), nil
}

// Count is the number of quotes made.
func (f *Quoter) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.Seen)
}
