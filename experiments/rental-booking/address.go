package booking

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

func refuse(code string) error { return errors.New(code) }
func Hash(b []byte) string     { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// AddressDeriver contains only a pinned public branch. The caller must durably
// reserve each index before exposing its address, including across restarts.
type AddressDeriver struct{ key *hdkeychain.ExtendedKey }

func NewAddressDeriver(publicBranch, pin string) (*AddressDeriver, error) {
	if Hash([]byte(publicBranch)) != pin {
		return nil, refuse("XPUB_PIN")
	}
	k, err := hdkeychain.NewKeyFromString(publicBranch)
	if err != nil || k.IsPrivate() || !k.IsForNet(&chaincfg.RegressionNetParams) {
		return nil, refuse("WATCH_ONLY_REGTEST_KEY")
	}
	return &AddressDeriver{k}, nil
}

func (d *AddressDeriver) Address(index uint32) (address, script string, err error) {
	if index >= hdkeychain.HardenedKeyStart {
		return "", "", refuse("ADDRESS_INDEX")
	}
	child, e := d.key.Derive(index)
	if e != nil {
		return "", "", refuse("ADDRESS_DERIVATION")
	}
	addr, e := child.Address(&chaincfg.RegressionNetParams)
	if e != nil {
		return "", "", refuse("ADDRESS_DERIVATION")
	}
	return addr.EncodeAddress(), "76a914" + hex.EncodeToString(addr.ScriptAddress()) + "88ac", nil
}
