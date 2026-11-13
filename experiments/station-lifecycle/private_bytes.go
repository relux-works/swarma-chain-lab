package lifecycle

import (
	"encoding/json"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap/codec"
)

// PrivateBytes retains private lifecycle bytes without exposing them to fmt or
// automatic encoders. The empty flag preserves the legacy distinction between
// a nil byte slice (JSON null) and a nonnil empty byte slice (JSON ""). It carries
// no credential data; the scalar-pointer holder owns all nonempty bytes.
type PrivateBytes struct {
	value codec.Secret[Secret]
	empty bool
}

// NewPrivateBytes preserves the original byte representation and takes a copy.
func NewPrivateBytes(value Secret) PrivateBytes {
	return PrivateBytes{value: codec.NewSecret(value), empty: value != nil && len(value) == 0}
}

// Reveal returns isolated private bytes only for an explicit private operation.
func (p PrivateBytes) Reveal() Secret {
	if p.empty {
		return Secret{}
	}
	return p.value.Reveal()
}

func (p PrivateBytes) IsZero() bool                 { return p.value.IsZero() }
func (p PrivateBytes) String() string               { return p.value.String() }
func (p PrivateBytes) GoString() string             { return p.value.GoString() }
func (p PrivateBytes) MarshalJSON() ([]byte, error) { return p.value.MarshalJSON() }
func (p PrivateBytes) MarshalText() ([]byte, error) { return p.value.MarshalText() }

func (p *PrivateBytes) UnmarshalJSON(raw []byte) error {
	*p = PrivateBytes{}
	var value Secret
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	*p = NewPrivateBytes(value)
	return nil
}
