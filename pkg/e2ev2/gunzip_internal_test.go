package e2ev2

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Exactly one gzip member with nothing after it, whatever the last four bytes claim: a second
// member of the same size (whose trailer names the first's size) and trailing bytes that end in a
// plausible size are refused; a trailer that understates the content is refused.
func TestGunzipOneMember(t *testing.T) {
	plain := []byte(`{"v":2}`)
	member, err := gz(plain)
	if err != nil {
		t.Fatal(err)
	}
	if got, ref := gunzip(member, 1024, nil); ref != nil || !bytes.Equal(got, plain) {
		t.Fatalf("one member: %v", ref)
	}
	var size [4]byte
	binary.LittleEndian.PutUint32(size[:], uint32(len(plain)))
	for name, data := range map[string][]byte{
		"two members":                    append(append([]byte(nil), member...), member...),
		"trailing bytes ending in ISIZE": append(append(append([]byte(nil), member...), 0, 0, 0, 0), size[:]...),
	} {
		if _, ref := gunzip(data, 1024, nil); ref == nil || ref.Code != "e2e_v2_malformed" {
			t.Errorf("%s accepted", name)
		}
	}
	short := append([]byte(nil), member...)
	binary.LittleEndian.PutUint32(short[len(short)-4:], uint32(len(plain)-1))
	if _, ref := gunzip(short, 1024, nil); ref == nil {
		t.Error("a trailer that understates the content was accepted")
	}
}
