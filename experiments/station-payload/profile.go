package payload

import (
	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/modelprofile"
	"github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind"
)

const DialectMessages = modelprofile.DialectMessages
const DialectResponses = modelprofile.DialectResponses

// ModelSelection mirrors the public deploy pairing record. Endpoint and leaf
// pin come from the decoded bootstrap at runtime, never from a delivery.
type ModelSelection = modelprofile.TypedProfile

// CheckModelPair reads values only. It never opens credential paths named by the
// public proxy config, starts a registry or contacts an endpoint. The operator
// must provision this exact public config together with the proxy configuration.
func CheckModelPair(p ModelSelection, c proxy.FileConfig) error {
	if modelprofile.CheckModelPair(p, c) != nil {
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
	if e = CheckModelPair(ModelSelection{Dialect: dialect, Model: o.Model, MaxTokens: o.MaxTokens, Endpoint: b.ModelEndpoint, CertSHA256: b.ModelCertSHA256}, config); e != nil {
		return nil, e
	}
	c, e := New(raw, o)
	if e != nil {
		return nil, e
	}
	c.responses = dialect == DialectResponses
	return c, nil
}
