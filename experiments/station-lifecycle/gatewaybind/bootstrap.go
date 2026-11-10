package gatewaybind

import (
	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap/codec"
	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
)

// PayloadBootstrap preserves the credential-bearing compatibility API. The
// shared codec owns its sole wire schema; root callers use the public projection.
type PayloadBootstrap = codec.Bootstrap[lifecycle.Secret, proxy.Secret]

func EncodeBootstrap(b PayloadBootstrap) (lifecycle.Secret, error) { return codec.Encode(b) }
func DecodeBootstrap(raw []byte) (PayloadBootstrap, error) {
	return codec.Decode[lifecycle.Secret, proxy.Secret](raw)
}
