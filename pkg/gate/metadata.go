package gate

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// MetadataBase is the GCE metadata server (metadata.google.internal does not resolve in the VM).
const MetadataBase = "http://169.254.169.254/computeMetadata/v1/"

// Metadata reads the instance's identity from the GCE metadata server: the attribute
// chutes-endpoint-id and instance/id. It never reads the identity from a request.
type Metadata struct {
	Base   string
	client *http.Client
}

// NewMetadata returns a reader for base (MetadataBase in an image).
func NewMetadata(base string) *Metadata {
	return &Metadata{
		Base: base,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				Proxy:             nil,
				DialContext:       (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
				DisableKeepAlives: true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (m *Metadata) get(ctx context.Context, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.Base+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := m.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Metadata-Flavor") != "Google" {
		return "", errors.New("metadata: not a 200 from the metadata server")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1025))
	if err != nil || len(raw) > 1024 {
		return "", errors.New("metadata: answer too long")
	}
	return strings.TrimSpace(string(raw)), nil
}

// Identity reads both values once; both must be well formed.
func (m *Metadata) Identity(ctx context.Context) (endpointID, instanceID string, err error) {
	if endpointID, err = m.get(ctx, "instance/attributes/chutes-endpoint-id"); err != nil {
		return "", "", err
	}
	if instanceID, err = m.get(ctx, "instance/id"); err != nil {
		return "", "", err
	}
	if !ValidEndpointID(endpointID) || !ValidInstanceID(instanceID) {
		return "", "", errors.New("metadata: malformed endpoint or instance id")
	}
	return endpointID, instanceID, nil
}

// LoadIdentity retries every 1 s, doubling to 30 s, until the metadata server answers, then sets
// the gate's identity. Until then every E2E route answers 503 e2e_v2_identity_unknown.
func (g *Gate) LoadIdentity(ctx context.Context, m *Metadata) {
	delay := time.Second
	for {
		endpointID, instanceID, err := m.Identity(ctx)
		if err == nil {
			g.SetIdentity(endpointID, instanceID)
			g.log.Info("identity", "known", true)
			return
		}
		g.log.Warn("identity", "known", false, "retry_s", int(delay/time.Second))
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, 30*time.Second)
	}
}
