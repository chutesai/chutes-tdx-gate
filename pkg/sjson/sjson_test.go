package sjson

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccepts(t *testing.T) {
	for _, doc := range []string{
		`{}`, `[]`, `{"a":1,"b":[true,false,null],"c":"é😀","d":-0.5e+10}`, ` {"a" : "b"} `,
		`18446744073709551616`, `-9223372036854775809`, `123456789012345678901234567890`, `1e30`, `1e-400`, `"\/"`,
	} {
		if _, err := Parse([]byte(doc)); err != nil {
			t.Fatalf("%s refused: %v", doc, err)
		}
	}
	v, _ := Parse([]byte(`{"x": {"y" : [1, 2]}, "z":"q"}`))
	if string(v.Get("x").Raw) != `{"y" : [1, 2]}` || v.Get("z").Str != "q" {
		t.Fatal("raw spans")
	}
}

func TestRefuses(t *testing.T) {
	for _, doc := range []string{
		``, `{"a":1,"a":2}`, `{"a":{"b":1,"b":1}}`, `{"a":1,"a":2}`, `NaN`, `[Infinity]`, `[-Infinity]`, `1e400`, `-1e400`,
		"\xef\xbb\xbf{}", "{\"a\":\"\xff\"}", `"\ud800"`, `"\udc00"`, `"\ud800A"`, `{"a":1}x`, `{"a":1,}`, `[1,]`, `01`,
		`1.`, `.5`, `+1`, `"a` + "\x01" + `"`, `'a'`, `{a:1}`, `"\x"`, `tru`, strings.Repeat("[", MaxDepth+1) + strings.Repeat("]", MaxDepth+1),
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Fatalf("%q accepted", doc)
		}
	}
	if _, err := Parse([]byte(strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth))); err != nil {
		t.Fatal("depth MaxDepth refused")
	}
}

func TestInteger(t *testing.T) {
	for doc, want := range map[string]bool{`2`: true, `-0`: true, `2.0`: false, `2e0`: false, `"2"`: false} {
		v, err := Parse([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		if v.IsInteger() != want {
			t.Fatalf("%s IsInteger %v", doc, !want)
		}
	}
}

func envelopeLimits(charge func(int64) bool) Limits {
	return Limits{MaxDepth: MaxDepth, MaxNodes: 100, MaxKeyBytes: 8, MaxStringBytes: 16, MaxMembers: 4, Build: 1, Charge: charge}
}

// The number cases both forms' readers must decide alike (spec/strict_json/numbers.json, which the
// Python library's tests read too): each document alone, and below the built level.
func TestNumberVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "spec", "strict_json", "numbers.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []struct {
			Name   string `json:"name"`
			Doc    string `json:"doc"`
			Expect string `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) != 60 {
		t.Fatalf("%d cases", len(v.Cases))
	}
	for _, c := range v.Cases {
		if c.Expect != "accept" && c.Expect != "refuse" {
			t.Fatalf("%s: expect %q", c.Name, c.Expect)
		}
		_, alone := Parse([]byte(c.Doc))
		_, below := ParseWith([]byte(`{"b":[`+c.Doc+`]}`), envelopeLimits(nil))
		if want := c.Expect == "accept"; (alone == nil) != want || (below == nil) != want {
			t.Errorf("%s: expect %s; alone: %v; below the built level: %v", c.Name, c.Expect, alone, below)
		}
	}
}

// Only the top level is built; below it a value keeps its kind and raw bytes, and Lookup finds a
// member of an unbuilt object.
func TestBuildLevels(t *testing.T) {
	v, err := ParseWith([]byte(`{"a":1,"b":{"stream":true,"c":[1,{"d":2}]},"s":"x"}`), envelopeLimits(nil))
	if err != nil {
		t.Fatal(err)
	}
	b := v.Get("b")
	if v.Get("a").Num != "1" || v.Get("s").Str != "x" || b.Kind != Object || b.Built || b.Members != nil {
		t.Fatalf("%+v", b)
	}
	if string(b.Raw) != `{"stream":true,"c":[1,{"d":2}]}` {
		t.Fatal("raw")
	}
	if s := b.Lookup("stream"); s == nil || s.Kind != Bool || !s.Bool {
		t.Fatal("Lookup stream")
	}
	if c := b.Lookup("c"); c == nil || c.Kind != Array || c.Built || string(c.Raw) != `[1,{"d":2}]` {
		t.Fatal("Lookup c")
	}
	if b.Lookup("x") != nil || b.Lookup("d") != nil {
		t.Fatal("Lookup found a member that is not there")
	}
	esc, _ := Parse([]byte(`{"o":{"stream":false}}`))
	if s := esc.Get("o").Lookup("stream"); s == nil || s.Bool {
		t.Fatal("Lookup compares decoded keys")
	}
}

// Every limit is checked while parsing, built level or not.
func TestLimits(t *testing.T) {
	lim := envelopeLimits(nil)
	for name, doc := range map[string]string{
		"nodes":             `{"b":[` + strings.Repeat("0,", 99) + `0]}`,
		"key below":         `{"b":{"123456789":1}}`,
		"key at top":        `{"123456789":1}`,
		"built string":      `{"s":"12345678901234567"}`,
		"members":           `{"a":1,"b":2,"c":3,"d":4,"e":5}`,
		"duplicate below":   `{"b":{"x":{"k":1,"k":2}}}`,
		"surrogate below":   `{"b":["\ud800"]}`,
		"overflow below":    `{"b":[1e400]}`,
		"long int overflow": `{"b":[` + strings.Repeat("9", 400) + `]}`,
	} {
		if _, err := ParseWith([]byte(doc), lim); err != ErrInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	deep := lim
	deep.MaxNodes = -1
	if _, err := ParseWith([]byte(`{"b":`+strings.Repeat("[", MaxDepth)+strings.Repeat("]", MaxDepth)+`}`), deep); err != ErrInvalid {
		t.Errorf("depth below the built level: %v", err)
	}
	if _, err := ParseWith([]byte(`{"b":`+strings.Repeat("[", MaxDepth-1)+strings.Repeat("]", MaxDepth-1)+`}`), deep); err != nil {
		t.Errorf("depth at the limit: %v", err)
	}
	for name, doc := range map[string]string{
		"string below the built level": `{"b":["` + strings.Repeat("x", 100) + `"]}`,
		"nodes at the limit":           `{"b":[` + strings.Repeat("0,", 97) + `0]}`,
		"long int":                     `{"b":[` + strings.Repeat("9", 300) + `]}`,
	} {
		if _, err := ParseWith([]byte(doc), lim); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The key sets are charged before they are kept; a refused charge stops the parse with ErrBusy.
func TestCharge(t *testing.T) {
	var charged int64
	_, err := ParseWith([]byte(`{"a":{"xy":1,"z":2}}`), envelopeLimits(func(n int64) bool { charged += n; return true }))
	if err != nil || charged != (3+KeyCost)+(4+KeyCost)+(3+KeyCost) {
		t.Fatalf("charged %d: %v", charged, err)
	}
	// A long key is charged its bytes and an eighth (its allocation's size class), plus KeyCost.
	charged = 0
	long := `{"` + strings.Repeat("k", 60000) + `":1}`
	lim := envelopeLimits(func(n int64) bool { charged += n; return true })
	lim.MaxKeyBytes = 1 << 16
	if _, err := ParseWith([]byte(long), lim); err != nil || charged != 60002+60002/8+KeyCost {
		t.Fatalf("charged %d: %v", charged, err)
	}
	refuse := func(int64) bool { return false }
	if _, err := ParseWith([]byte(`{"a":1}`), envelopeLimits(refuse)); err != ErrBusy {
		t.Fatalf("%v", err)
	}
}

// Below the built levels nothing is allocated per value: a million zeros cost a few allocations.
func TestNoAllocationBelowBuild(t *testing.T) {
	doc := []byte(`{"b":[` + strings.Repeat("0,", 1<<20-3) + `0]}`)
	lim := Limits{MaxDepth: MaxDepth, MaxNodes: 1 << 20, MaxKeyBytes: 1 << 16, MaxStringBytes: 1 << 16, MaxMembers: 9, Build: 1}
	allocs := testing.AllocsPerRun(1, func() {
		if _, err := ParseWith(doc, lim); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 16 {
		t.Fatalf("%v allocations", allocs)
	}
}
