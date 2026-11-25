package e2ev2_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/chutesai/chutes-tdx-gate/pkg/e2ev2"
)

// TestDifferentialCorpus runs crosstest/differential.py's corpus (DIFF_CORPUS=path) through the Go
// gate: its result must equal the Python library's on every request (the library was itself
// compared with the SDK runtime when the corpus was made).
func TestDifferentialCorpus(t *testing.T) {
	path := os.Getenv("DIFF_CORPUS")
	if path == "" {
		t.Skip("DIFF_CORPUS not set (make crosstest makes the corpus)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Seed     string    `json:"seed_d_z_hex"`
		Identity [2]string `json:"identity"`
		Routes   []struct {
			Path   string `json:"path"`
			Stream bool   `json:"stream"`
		} `json:"routes"`
		Cases []struct {
			I             int      `json:"i"`
			Tags          []string `json:"tags"`
			Blob          string   `json:"blob_b64"`
			PresentedPath string   `json:"presented_path"`
			Method        string   `json:"method"`
			Own           string   `json:"own"`
			NowMS         int64    `json:"now_ms"`
			Lib           string   `json:"lib"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(corpus.Seed)
	key, err := e2ev2.KeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	var routes []e2ev2.Route
	for _, r := range corpus.Routes {
		routes = append(routes, e2ev2.Route{Path: r.Path, Stream: r.Stream, AppPath: r.Path})
	}
	table := e2ev2.NewRoutes(routes)
	cache := e2ev2.NewReplayCache(e2ev2.DefaultReplayEntries)
	agree := 0
	for _, c := range corpus.Cases {
		blob, _ := base64.StdEncoding.DecodeString(c.Blob)
		id := e2ev2.Identity{EndpointID: corpus.Identity[0], InstanceID: corpus.Identity[1], Known: true}
		if c.Own == "unknown" {
			id = e2ev2.Identity{}
		}
		_, ref := e2ev2.Open(key, blob, e2ev2.Params{PresentedPath: c.PresentedPath, Method: c.Method, Routes: table,
			Identity: id, Cache: cache, NowMS: c.NowMS})
		got := "admitted"
		if ref != nil {
			got = ref.Code
		}
		if got != c.Lib {
			t.Errorf("case %d %v: Go %s, Python library %s", c.I, c.Tags, got, c.Lib)
			continue
		}
		agree++
	}
	t.Logf("%d/%d requests: the Go gate equals the Python library", agree, len(corpus.Cases))
}
