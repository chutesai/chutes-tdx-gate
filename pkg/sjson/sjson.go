// Package sjson is a strict RFC 8259 JSON parser for untrusted input.
//
// It refuses what lenient parsers let through and what would let two parsers disagree about one
// document: invalid UTF-8, a byte-order mark, a duplicate object key (compared after unescaping),
// an escaped lone surrogate, NaN and Infinity (they are not JSON), a number whose magnitude
// overflows a float64, and trailing bytes. Every value keeps its raw bytes, so a caller can forward
// a sub-document exactly as it was received.
//
// Limits bound the work and the memory of one parse, checked while parsing: the nesting depth,
// the number of values, the length of an object key and of a built string, the members of a built
// object, and the levels that are built at all. Below the built levels a value is checked as
// strictly but kept only as its kind and raw bytes, so a large document costs its own bytes plus
// one key set per open object, which Limits.Charge accounts for before it is allocated.
package sjson

import (
	"errors"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// MaxDepth is the deepest nesting of arrays and objects accepted.
const MaxDepth = 512

// Default limits of Parse.
const (
	DefaultMaxNodes    = 1 << 20 // values in one document
	DefaultMaxKeyBytes = 1 << 16 // one object key, decoded
)

// Kind is a JSON value's type.
type Kind int

const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

// Member is one object member, in document order.
type Member struct {
	Key   string
	Value *Value
}

// Value is a parsed JSON value. A value below Limits.Build levels has only Kind and Raw.
type Value struct {
	Kind    Kind
	Bool    bool
	Num     string // the number's text, as written
	Str     string // the decoded string
	Items   []*Value
	Members []Member
	Raw     []byte // the value's bytes in the input (no surrounding whitespace)
	Built   bool   // Bool, Num, Str, Items and Members are filled
}

// Get returns the member named key of a built object, or nil.
func (v *Value) Get(key string) *Value {
	if v == nil || v.Kind != Object {
		return nil
	}
	for _, m := range v.Members {
		if m.Key == key {
			return m.Value
		}
	}
	return nil
}

// Keys returns a built object's keys in document order.
func (v *Value) Keys() []string {
	out := make([]string, 0, len(v.Members))
	for _, m := range v.Members {
		out = append(out, m.Key)
	}
	return out
}

// HasExactly reports whether v is a built object whose keys are exactly keys (any order).
func (v *Value) HasExactly(keys ...string) bool {
	if v == nil || v.Kind != Object || !v.Built || len(v.Members) != len(keys) {
		return false
	}
	for _, k := range keys {
		if v.Get(k) == nil {
			return false
		}
	}
	return true
}

// IsInteger reports whether v is a JSON number written without a fraction or an exponent.
func (v *Value) IsInteger() bool {
	if v == nil || v.Kind != Number {
		return false
	}
	for i := 0; i < len(v.Raw); i++ {
		if c := v.Raw[i]; c == '.' || c == 'e' || c == 'E' {
			return false
		}
	}
	return true
}

// Lookup returns the member named key of an object that Parse already accepted (built or not),
// built as one level, or nil when the object has no such member. It allocates only the decoded
// keys it compares that hold an escape.
func (v *Value) Lookup(key string) *Value {
	if v == nil || v.Kind != Object {
		return nil
	}
	if v.Built {
		return v.Get(key)
	}
	// The object was checked by Parse: no limit applies again, and nothing below its member is built.
	p := &parser{data: v.Raw, lim: Limits{MaxDepth: -1, MaxNodes: -1, MaxKeyBytes: -1, MaxStringBytes: -1, MaxMembers: -1, Build: 1}}
	p.pos++ // {
	for {
		p.space()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil // '}' of an empty object, or the end
		}
		k, err := p.str(true)
		if err != nil {
			return nil
		}
		p.space()
		p.pos++ // :
		p.space()
		if k == key {
			member, err := p.value(1)
			if err != nil {
				return nil
			}
			return member
		}
		if _, err := p.value(2); err != nil { // skipped: depth 2 is below Build
			return nil
		}
		p.space()
		if p.pos >= len(p.data) || p.data[p.pos] != ',' {
			return nil
		}
		p.pos++
	}
}

// Limits bound one parse. A negative value means no limit.
type Limits struct {
	MaxDepth       int // nesting of arrays and objects
	MaxNodes       int // values in the document
	MaxKeyBytes    int // one object key, decoded
	MaxStringBytes int // one built string, decoded
	MaxMembers     int // members of one built object
	// Build is the number of levels built as Values: 1 builds the top-level value and its
	// members' scalars (a member that is an array or object keeps Kind and Raw only); a negative
	// value builds everything.
	Build int
	// Charge, when set, is called before the parse keeps n more bytes (an object's key set);
	// false stops the parse with ErrBusy.
	Charge func(n int64) bool
}

// DefaultLimits are Parse's: depth MaxDepth, DefaultMaxNodes values, keys of DefaultMaxKeyBytes,
// every level built.
func DefaultLimits() Limits {
	return Limits{MaxDepth: MaxDepth, MaxNodes: DefaultMaxNodes, MaxKeyBytes: DefaultMaxKeyBytes, MaxStringBytes: -1, MaxMembers: -1, Build: -1}
}

// KeyCost is what Charge is asked for one key of an object's key set, besides the key's bytes:
// the map's slot, its growth and the string's rounding (measured at under 120 bytes a key for
// Go 1.27's maps, small and large). It is never given back during the parse.
const KeyCost = 128

// keyCharge is one key's charge: its bytes and an eighth (a large allocation rounds up to its
// size class, at most an eighth more), plus KeyCost.
func keyCharge(n int) int64 { return int64(n) + int64(n)/8 + KeyCost }

var (
	// ErrInvalid is returned for every refused document, a limit included.
	ErrInvalid = errors.New("sjson: invalid JSON")
	// ErrBusy is returned when Limits.Charge refused memory.
	ErrBusy = errors.New("sjson: memory budget exhausted")
)

type parser struct {
	data    []byte
	pos     int
	lim     Limits
	nodes   int
	scratch []byte // the key being decoded
}

// Parse parses one JSON document with DefaultLimits.
func Parse(data []byte) (*Value, error) { return ParseWith(data, DefaultLimits()) }

// ParseWith parses one JSON document, refusing anything the package comment lists and anything
// over lim.
func ParseWith(data []byte, lim Limits) (*Value, error) {
	if !utf8.Valid(data) {
		return nil, ErrInvalid
	}
	p := &parser{data: data, lim: lim}
	p.space()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.pos != len(p.data) {
		return nil, ErrInvalid
	}
	return v, nil
}

func over(n, limit int) bool { return limit >= 0 && n > limit }

// building reports whether a value at depth (the number of containers around it) is built (a
// container's Value then exists; its members are built when it is at a lower depth than Build).
func (p *parser) building(depth int) bool { return p.lim.Build < 0 || depth <= p.lim.Build }

func (p *parser) space() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

// value parses one value at depth (the number of containers around it). A value below the built
// levels is checked without allocating and returns nil.
func (p *parser) value(depth int) (*Value, error) {
	if p.pos >= len(p.data) {
		return nil, ErrInvalid
	}
	p.nodes++
	if over(p.nodes, p.lim.MaxNodes) {
		return nil, ErrInvalid
	}
	if !p.building(depth) {
		return nil, p.skip(depth)
	}
	start := p.pos
	v := &Value{Built: true}
	var err error
	switch c := p.data[p.pos]; {
	case c == '{':
		v.Kind, v.Built = Object, p.building(depth+1)
		v.Members, err = p.object(depth+1, v.Built)
	case c == '[':
		v.Kind, v.Built = Array, p.building(depth+1)
		v.Items, err = p.array(depth+1, v.Built)
	case c == '"':
		v.Kind = String
		v.Str, err = p.str(true)
	case c == 't':
		v.Kind, v.Bool = Bool, true
		err = p.literal("true")
	case c == 'f':
		v.Kind = Bool
		err = p.literal("false")
	case c == 'n':
		v.Kind = Null
		err = p.literal("null")
	case c == '-' || (c >= '0' && c <= '9'):
		v.Kind = Number
		if err = p.number(); err == nil {
			v.Num = string(p.data[start:p.pos])
		}
	default:
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	v.Raw = p.data[start:p.pos]
	return v, nil
}

// skip checks one value without building it.
func (p *parser) skip(depth int) error {
	var err error
	switch c := p.data[p.pos]; {
	case c == '{':
		_, err = p.object(depth+1, false)
	case c == '[':
		_, err = p.array(depth+1, false)
	case c == '"':
		_, err = p.str(false)
	case c == 't':
		err = p.literal("true")
	case c == 'f':
		err = p.literal("false")
	case c == 'n':
		err = p.literal("null")
	case c == '-' || (c >= '0' && c <= '9'):
		err = p.number()
	default:
		err = ErrInvalid
	}
	return err
}

func (p *parser) literal(word string) error {
	if len(p.data)-p.pos < len(word) || string(p.data[p.pos:p.pos+len(word)]) != word {
		return ErrInvalid
	}
	p.pos += len(word)
	return nil
}

// object parses an object's members; with build, it returns them (at most MaxMembers).
func (p *parser) object(depth int, build bool) ([]Member, error) {
	if over(depth, p.lim.MaxDepth) {
		return nil, ErrInvalid
	}
	p.pos++ // {
	var members []Member
	seen := map[string]struct{}{}
	p.space()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return members, nil
	}
	for {
		p.space()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return nil, ErrInvalid
		}
		keyStart := p.pos
		if err := p.skipString(p.lim.MaxKeyBytes); err != nil {
			return nil, err
		}
		if p.lim.Charge != nil && !p.lim.Charge(keyCharge(p.pos-keyStart)) {
			return nil, ErrBusy
		}
		p.pos = keyStart
		var err error
		if p.scratch, err = p.scanString(p.scratch[:0], true, p.lim.MaxKeyBytes); err != nil {
			return nil, err
		}
		key := string(p.scratch)
		if _, dup := seen[key]; dup {
			return nil, ErrInvalid
		}
		seen[key] = struct{}{}
		p.space()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return nil, ErrInvalid
		}
		p.pos++
		p.space()
		member, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		if build {
			if over(len(members)+1, p.lim.MaxMembers) {
				return nil, ErrInvalid
			}
			members = append(members, Member{Key: key, Value: member})
		}
		p.space()
		if p.pos >= len(p.data) {
			return nil, ErrInvalid
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return members, nil
		default:
			return nil, ErrInvalid
		}
	}
}

// array parses an array's items; with build, it returns them.
func (p *parser) array(depth int, build bool) ([]*Value, error) {
	if over(depth, p.lim.MaxDepth) {
		return nil, ErrInvalid
	}
	p.pos++ // [
	var items []*Value
	p.space()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return items, nil
	}
	for {
		p.space()
		item, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		if build {
			items = append(items, item)
		}
		p.space()
		if p.pos >= len(p.data) {
			return nil, ErrInvalid
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return items, nil
		default:
			return nil, ErrInvalid
		}
	}
}

func hexval(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func (p *parser) hex4() (rune, error) {
	if len(p.data)-p.pos < 4 {
		return 0, ErrInvalid
	}
	var r rune
	for i := 0; i < 4; i++ {
		h := hexval(p.data[p.pos+i])
		if h < 0 {
			return 0, ErrInvalid
		}
		r = r<<4 | rune(h)
	}
	p.pos += 4
	return r, nil
}

// skipString checks one string and moves past it without allocating; its decoded length must
// not exceed limit (negative: no limit).
func (p *parser) skipString(limit int) error {
	_, err := p.scanString(nil, false, limit)
	return err
}

// str decodes one string when build is set (MaxStringBytes applies), else checks it in place.
func (p *parser) str(build bool) (string, error) {
	if !build {
		_, err := p.scanString(nil, false, -1)
		return "", err
	}
	out, err := p.scanString(nil, true, p.lim.MaxStringBytes)
	return string(out), err
}

// scanString checks the string at p.pos (its opening quote) and, with keep, appends its decoded
// bytes to out. Its decoded length must not exceed limit (negative: no limit).
func (p *parser) scanString(out []byte, keep bool, limit int) ([]byte, error) {
	p.pos++ // opening quote
	n := 0
	for {
		// A run of plain bytes.
		run := p.pos
		for run < len(p.data) {
			if c := p.data[run]; c == '"' || c == '\\' || c < 0x20 {
				break
			}
			run++
		}
		n += run - p.pos
		if over(n, limit) {
			return nil, ErrInvalid
		}
		if keep {
			out = append(out, p.data[p.pos:run]...)
		}
		p.pos = run
		if p.pos >= len(p.data) || p.data[p.pos] < 0x20 {
			return nil, ErrInvalid
		}
		if p.data[p.pos] == '"' {
			p.pos++
			return out, nil
		}
		p.pos++ // backslash
		if p.pos >= len(p.data) {
			return nil, ErrInvalid
		}
		e := p.data[p.pos]
		p.pos++
		var buf [4]byte
		dec := buf[:1]
		switch e {
		case '"', '\\', '/':
			buf[0] = e
		case 'b':
			buf[0] = '\b'
		case 'f':
			buf[0] = '\f'
		case 'n':
			buf[0] = '\n'
		case 'r':
			buf[0] = '\r'
		case 't':
			buf[0] = '\t'
		case 'u':
			r, err := p.hex4()
			if err != nil {
				return nil, err
			}
			if utf16.IsSurrogate(r) {
				// Only a high surrogate followed by an escaped low surrogate is a character.
				if r >= 0xDC00 || len(p.data)-p.pos < 6 || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
					return nil, ErrInvalid
				}
				p.pos += 2
				low, err := p.hex4()
				if err != nil {
					return nil, err
				}
				if low < 0xDC00 || low > 0xDFFF {
					return nil, ErrInvalid
				}
				r = utf16.DecodeRune(r, low)
			}
			dec = buf[:utf8.EncodeRune(buf[:], r)]
		default:
			return nil, ErrInvalid
		}
		n += len(dec)
		if over(n, limit) {
			return nil, ErrInvalid
		}
		if keep {
			out = append(out, dec...)
		}
	}
}

func (p *parser) digits() int {
	n := 0
	for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
		p.pos++
		n++
	}
	return n
}

// number checks one number. Only one that could overflow a float64 (an exponent, or more than
// 308 integer digits) is converted.
func (p *parser) number() error {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	if p.pos >= len(p.data) {
		return ErrInvalid
	}
	intDigits := 1
	if p.data[p.pos] == '0' {
		p.pos++
	} else if intDigits = p.digits(); intDigits == 0 {
		return ErrInvalid
	}
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		p.pos++
		if p.digits() == 0 {
			return ErrInvalid
		}
	}
	exponent := false
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		exponent = true
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if p.digits() == 0 {
			return ErrInvalid
		}
	}
	if !exponent && intDigits <= 308 {
		return nil
	}
	// A number that overflows a float64 would become Infinity in other parsers (Python reads 1e400
	// as inf and cannot write it back as JSON): refuse it rather than disagree.
	f, err := strconv.ParseFloat(string(p.data[start:p.pos]), 64)
	if err != nil {
		var ne *strconv.NumError
		if !errors.As(err, &ne) || ne.Err != strconv.ErrRange || f > 1 || f < -1 { // overflow, not underflow to zero
			return ErrInvalid
		}
	}
	return nil
}
