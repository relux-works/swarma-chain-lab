package gatewaybind

import (
	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap/codec"
	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
)

// PayloadBootstrap preserves the credential-bearing compatibility API. The
// shared codec owns its sole wire schema; root callers use the public projection.
type PayloadBootstrap = codec.Bootstrap[lifecycle.Secret, proxy.Secret]

// NewChannelSecret and NewModelBearer retain the compatibility credential types
// behind opaque storage. Reveal only at an explicit credential use boundary.
func NewChannelSecret(secret lifecycle.Secret) codec.Secret[lifecycle.Secret] {
	return codec.NewSecret(secret)
}
func NewModelBearer(bearer proxy.Secret) codec.Secret[proxy.Secret] {
	return codec.NewSecret(bearer)
}

func EncodeBootstrap(b PayloadBootstrap) (lifecycle.Secret, error) { return codec.Encode(b) }
func DecodeBootstrap(raw []byte) (PayloadBootstrap, error) {
	return codec.Decode[lifecycle.Secret, proxy.Secret](raw)
}
