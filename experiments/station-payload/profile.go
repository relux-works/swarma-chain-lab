package payload

import (
	"net/url"
	"strings"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind"
)

const DialectMessages = "messages"
const DialectResponses = "responses"

// ModelSelection mirrors the public deploy pairing record. Endpoint and leaf
// pin come from the decoded bootstrap at runtime, never from a delivery.
type ModelSelection struct {
	Dialect    string `json:"dialect"`
	Model      string `json:"model"`
	MaxTokens  uint64 `json:"max_tokens"`
	Endpoint   string `json:"model_endpoint"`
	CertSHA256 string `json:"model_cert_sha256"`
}

// CheckModelPair reads values only. It never opens credential paths named by the
// public proxy config, starts a registry or contacts an endpoint. The operator
// must provision this exact public config together with the proxy configuration.
func CheckModelPair(p ModelSelection, c proxy.FileConfig) error {
	m, ok := c.Models[p.Model]
	if !ok || p.Model == "" || p.MaxTokens == 0 || m.ContextTokens == 0 || p.MaxTokens > m.ContextTokens || p.Endpoint != c.Endpoint.URL || p.CertSHA256 != c.Endpoint.CertSHA256 {
		return ErrConfig
	}
	want := DialectMessages
	if profile, ok := c.ModelProfiles[p.Model]; ok {
		u, e := url.Parse(profile.Upstream)
		if profile.Profile != proxy.OpenAIResponsesProfile || e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" || !strings.HasSuffix(u.Path, "/v1/responses") {
			return ErrConfig
		}
		want = DialectResponses
	}
	if p.Dialect != want {
		return ErrConfig
	}
	return nil
}

// NewPinned is the deployment-qualified v2 entry point. Legacy New remains for
// existing Messages fixtures only; deploy validation requires this pinned mode.
func NewPinned(raw []byte, o Options, dialect string, config proxy.FileConfig) (*Client, error) {
	b, e := gatewaybind.DecodeBootstrap(raw)
	if e != nil {
		return nil, ErrBootstrap
	}
	if b.V != 2 {
		return nil, ErrConfig
	}
	if e = CheckModelPair(ModelSelection{dialect, o.Model, o.MaxTokens, b.ModelEndpoint, b.ModelCertSHA256}, config); e != nil {
		return nil, e
	}
	c, e := New(raw, o)
	if e != nil {
		return nil, e
	}
	c.responses = dialect == DialectResponses
	return c, nil
}
