package gate

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/chutesai/chutes-tdx-gate/pkg/e2ev2"
	"github.com/chutesai/chutes-tdx-gate/pkg/sjson"
)

// ConfigSchema is the configuration's schema name.
const ConfigSchema = "chutes.tdx-gate-config.v1"

// ServicePort is the one port every VM endpoint serves on.
const ServicePort = 8080

var routePattern = regexp.MustCompile(`^(/[a-z][a-z0-9_-]*)+$`)

// ValidRoute is Chutes' route grammar: ^(/[a-z][a-z0-9_-]*)+$, at most 200 characters.
func ValidRoute(p string) bool { return len(p) <= 200 && routePattern.MatchString(p) }

// Limits bound the gate's work per request.
type Limits struct {
	MaxRequestBytes    int64
	MaxPlaintextBytes  int64
	MaxAnswerBytes     int64
	MaxInflight        int
	ReplayCacheEntries int
}

// Config is chutes.tdx-gate-config.v1.
type Config struct {
	Listen        string
	AppBase       string // http://<loopback IP>:<port>, no path
	AppHealthPath string
	AppTimeoutS   int
	HealthPath    string
	Routes        []e2ev2.Route
	// IdentitySource is "gce-metadata", or "static" (accepted only with serve --test-identity).
	IdentitySource   string
	StaticEndpointID string
	StaticInstanceID string
	Limits           Limits
	TsmReportDir     string
}

func closed(v *sjson.Value, name string, keys ...string) error {
	if !v.HasExactly(keys...) {
		return fmt.Errorf("%s must be an object with exactly the keys %v", name, keys)
	}
	return nil
}

func str(v *sjson.Value, name string) (string, error) {
	if v == nil || v.Kind != sjson.String {
		return "", fmt.Errorf("%s must be a string", name)
	}
	return v.Str, nil
}

func integer(v *sjson.Value, name string, lo, hi int64) (int64, error) {
	if !v.IsInteger() {
		return 0, fmt.Errorf("%s must be an integer", name)
	}
	n, err := strconv.ParseInt(v.Num, 10, 64)
	if err != nil || n < lo || n > hi {
		return 0, fmt.Errorf("%s must be an integer in %d..%d", name, lo, hi)
	}
	return n, nil
}

// LoadConfig reads and checks a configuration file.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(raw)
}

// ParseConfig parses and checks the closed configuration document.
func ParseConfig(raw []byte) (*Config, error) {
	v, err := sjson.Parse(raw)
	if err != nil {
		return nil, errors.New("config: not strict JSON (duplicate key, invalid UTF-8 or syntax)")
	}
	if err := closed(v, "config", "schema", "listen", "app", "health_path", "routes", "identity", "limits", "tsm_report_dir"); err != nil {
		return nil, err
	}
	c := &Config{}
	if s, err := str(v.Get("schema"), "schema"); err != nil || s != ConfigSchema {
		return nil, fmt.Errorf("config: schema must be %s", ConfigSchema)
	}
	if c.Listen, err = str(v.Get("listen"), "listen"); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || port != strconv.Itoa(ServicePort) {
		return nil, fmt.Errorf("config: listen must be <address>:%d", ServicePort)
	}
	if host != "" {
		if _, err := netip.ParseAddr(host); err != nil {
			return nil, errors.New("config: listen's address must be an IP literal")
		}
	}

	app := v.Get("app")
	if err := closed(app, "app", "base", "health_path", "timeout_s"); err != nil {
		return nil, err
	}
	if c.AppBase, err = str(app.Get("base"), "app.base"); err != nil {
		return nil, err
	}
	if err := checkAppBase(c.AppBase); err != nil {
		return nil, err
	}
	if c.AppHealthPath, err = str(app.Get("health_path"), "app.health_path"); err != nil || !ValidRoute(c.AppHealthPath) {
		return nil, errors.New("config: app.health_path must be a route path (^(/[a-z][a-z0-9_-]*)+$)")
	}
	timeout, err := integer(app.Get("timeout_s"), "app.timeout_s", 1, 3600)
	if err != nil {
		return nil, err
	}
	c.AppTimeoutS = int(timeout)

	if c.HealthPath, err = str(v.Get("health_path"), "health_path"); err != nil || !ValidRoute(c.HealthPath) || c.HealthPath == "/attest" {
		return nil, errors.New("config: health_path must be a route path other than /attest")
	}

	routes := v.Get("routes")
	if routes == nil || routes.Kind != sjson.Array || len(routes.Items) < 1 || len(routes.Items) > 64 {
		return nil, errors.New("config: routes must be a list of 1..64 routes")
	}
	seen := map[string]bool{}
	for i, item := range routes.Items {
		name := fmt.Sprintf("routes[%d]", i)
		if err := closed(item, name, "path", "stream", "app_path"); err != nil {
			return nil, err
		}
		var r e2ev2.Route
		if r.Path, err = str(item.Get("path"), name+".path"); err != nil || !ValidRoute(r.Path) {
			return nil, fmt.Errorf("config: %s.path must be a route path", name)
		}
		if r.Path == "/attest" || r.Path == c.HealthPath {
			return nil, fmt.Errorf("config: %s.path must differ from /attest and the health path", name)
		}
		if seen[r.Path] {
			return nil, fmt.Errorf("config: %s.path is declared twice", name)
		}
		seen[r.Path] = true
		if s := item.Get("stream"); s.Kind != sjson.Bool {
			return nil, fmt.Errorf("config: %s.stream must be a boolean", name)
		} else {
			r.Stream = s.Bool
		}
		if r.AppPath, err = str(item.Get("app_path"), name+".app_path"); err != nil || !ValidRoute(r.AppPath) {
			return nil, fmt.Errorf("config: %s.app_path must be a route path", name)
		}
		c.Routes = append(c.Routes, r)
	}

	identity := v.Get("identity")
	if identity == nil || identity.Kind != sjson.Object {
		return nil, errors.New("config: identity must be an object")
	}
	if c.IdentitySource, err = str(identity.Get("source"), "identity.source"); err != nil {
		return nil, err
	}
	switch c.IdentitySource {
	case "gce-metadata":
		if err := closed(identity, "identity", "source"); err != nil {
			return nil, err
		}
	case "static":
		if err := closed(identity, "identity", "source", "endpoint_id", "instance_id"); err != nil {
			return nil, err
		}
		if c.StaticEndpointID, err = str(identity.Get("endpoint_id"), "identity.endpoint_id"); err != nil || !ValidEndpointID(c.StaticEndpointID) {
			return nil, errors.New("config: identity.endpoint_id must be a lower-case UUID")
		}
		if c.StaticInstanceID, err = str(identity.Get("instance_id"), "identity.instance_id"); err != nil || !ValidInstanceID(c.StaticInstanceID) {
			return nil, errors.New("config: identity.instance_id must be a GCE instance id")
		}
	default:
		return nil, errors.New("config: identity.source must be gce-metadata (or static for tests)")
	}

	limits := v.Get("limits")
	if err := closed(limits, "limits", "max_request_bytes", "max_plaintext_bytes", "max_answer_bytes", "max_inflight", "replay_cache_entries"); err != nil {
		return nil, err
	}
	if c.Limits.MaxRequestBytes, err = integer(limits.Get("max_request_bytes"), "limits.max_request_bytes", int64(e2ev2.MinBlobSize), 64<<20); err != nil {
		return nil, err
	}
	if c.Limits.MaxPlaintextBytes, err = integer(limits.Get("max_plaintext_bytes"), "limits.max_plaintext_bytes", 1024, 64<<20); err != nil {
		return nil, err
	}
	if c.Limits.MaxAnswerBytes, err = integer(limits.Get("max_answer_bytes"), "limits.max_answer_bytes", 1024, 256<<20); err != nil {
		return nil, err
	}
	n, err := integer(limits.Get("max_inflight"), "limits.max_inflight", 1, 4096)
	if err != nil {
		return nil, err
	}
	c.Limits.MaxInflight = int(n)
	if n, err = integer(limits.Get("replay_cache_entries"), "limits.replay_cache_entries", 1, 1<<20); err != nil {
		return nil, err
	}
	c.Limits.ReplayCacheEntries = int(n)

	if c.TsmReportDir, err = str(v.Get("tsm_report_dir"), "tsm_report_dir"); err != nil || !filepath.IsAbs(c.TsmReportDir) || filepath.Clean(c.TsmReportDir) != c.TsmReportDir {
		return nil, errors.New("config: tsm_report_dir must be a clean absolute path")
	}
	return c, nil
}

// checkAppBase admits only http://<loopback IP literal>:<port> with nothing else.
func checkAppBase(base string) error {
	u, err := url.Parse(base)
	bad := errors.New("config: app.base must be http://<loopback IP>:<port> (127.0.0.0/8 or [::1]) with no path, not even /")
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Path != "" || u.ForceQuery {
		return bad
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil || !addr.IsLoopback() || u.Port() == "" {
		return bad
	}
	if p, err := strconv.Atoi(u.Port()); err != nil || p < 1 || p > 65535 || p == ServicePort {
		return bad
	}
	return nil
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var gceIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

// ValidEndpointID: an endpoint id is a lower-case UUID.
func ValidEndpointID(s string) bool { return uuidPattern.MatchString(s) }

// ValidInstanceID: a GCE instance id, decimal, below 2^64.
func ValidInstanceID(s string) bool {
	if !gceIDPattern.MatchString(s) {
		return false
	}
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}
