package gate

import (
	"strings"
	"testing"
)

const example = `{"schema": "chutes.tdx-gate-config.v1",
 "listen": "0.0.0.0:8080",
 "app": {"base": "http://127.0.0.1:9000", "health_path": "/health", "timeout_s": 600},
 "health_path": "/health",
 "routes": [{"path": "/v1/compress", "stream": false, "app_path": "/v1/compress"}],
 "identity": {"source": "gce-metadata"},
 "limits": {"max_request_bytes": 8454144, "max_plaintext_bytes": 67108864, "max_answer_bytes": 16777216,
            "max_inflight": 64, "replay_cache_entries": 65536},
 "tsm_report_dir": "/sys/kernel/config/tsm/report"}`

func TestContractExampleConfig(t *testing.T) {
	c, err := ParseConfig([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "0.0.0.0:8080" || len(c.Routes) != 1 || c.IdentitySource != "gce-metadata" || c.Limits.ReplayCacheEntries != 65536 {
		t.Fatalf("%+v", c)
	}
}

func TestConfigRefusals(t *testing.T) {
	for name, edit := range map[string][2]string{
		"another port":         {`"0.0.0.0:8080"`, `"0.0.0.0:8081"`},
		"a name to listen on":  {`"0.0.0.0:8080"`, `"localhost:8080"`},
		"app not loopback":     {`http://127.0.0.1:9000`, `http://10.0.0.1:9000`},
		"app by name":          {`http://127.0.0.1:9000`, `http://localhost:9000`},
		"app https":            {`http://127.0.0.1:9000`, `https://127.0.0.1:9000`},
		"app with a path":      {`http://127.0.0.1:9000`, `http://127.0.0.1:9000/x`},
		"app with a slash":     {`http://127.0.0.1:9000`, `http://127.0.0.1:9000/`},
		"app with a ?":         {`http://127.0.0.1:9000`, `http://127.0.0.1:9000?`},
		"app on 8080":          {`http://127.0.0.1:9000`, `http://127.0.0.1:8080`},
		"health is /attest":    {`"health_path": "/health",` + "\n" + ` "routes"`, `"health_path": "/attest",` + "\n" + ` "routes"`},
		"route is /attest":     {`{"path": "/v1/compress", "stream"`, `{"path": "/attest", "stream"`},
		"route is health":      {`{"path": "/v1/compress", "stream"`, `{"path": "/health", "stream"`},
		"route grammar":        {`{"path": "/v1/compress", "stream"`, `{"path": "/V1/compress", "stream"`},
		"stream not boolean":   {`"stream": false`, `"stream": 0`},
		"unknown key":          {`"tsm_report_dir"`, `"extra": 1, "tsm_report_dir"`},
		"duplicate key":        {`"listen": "0.0.0.0:8080",`, `"listen": "0.0.0.0:8080", "listen": "0.0.0.0:8080",`},
		"static without ids":   {`{"source": "gce-metadata"}`, `{"source": "static"}`},
		"another identity":     {`{"source": "gce-metadata"}`, `{"source": "header"}`},
		"schema":               {`chutes.tdx-gate-config.v1`, `chutes.tdx-gate-config.v2`},
		"relative tsm dir":     {`"/sys/kernel/config/tsm/report"`, `"sys/kernel/config/tsm/report"`},
		"replay cache 0":       {`"replay_cache_entries": 65536`, `"replay_cache_entries": 0`},
		"timeout as a float":   {`"timeout_s": 600`, `"timeout_s": 600.0`},
		"extra app key":        {`"timeout_s": 600}`, `"timeout_s": 600, "headers": {}}`},
		"extra route key":      {`"app_path": "/v1/compress"}`, `"app_path": "/v1/compress", "x": 1}`},
		"metadata with ids":    {`{"source": "gce-metadata"}`, `{"source": "gce-metadata", "endpoint_id": "x"}`},
		"plaintext over 64MiB": {`"max_plaintext_bytes": 67108864`, `"max_plaintext_bytes": 67108865`},
	} {
		doc := strings.Replace(example, edit[0], edit[1], 1)
		if doc == example {
			t.Fatalf("%s: the edit did not apply", name)
		}
		if _, err := ParseConfig([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestStaticIdentityConfig(t *testing.T) {
	doc := strings.Replace(example, `{"source": "gce-metadata"}`,
		`{"source": "static", "endpoint_id": "6b1c0e7e-4d0b-4f2a-9a57-1f3d2c8b9e40", "instance_id": "5813945712345678901"}`, 1)
	c, err := ParseConfig([]byte(doc))
	if err != nil || c.IdentitySource != "static" {
		t.Fatal(err)
	}
	g := New(c, nil, nil)
	if id := g.Identity(); !id.Known || id.InstanceID != "5813945712345678901" {
		t.Fatal("the static identity was not set")
	}
}
