// Package paymentchain observes booking fees on explicitly pinned nodes.
// It does not sign, spend, reserve execution authority or mutate a node.
package paymentchain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

func refuse(code string) error { return errors.New(code) }
func Hash(b []byte) string     { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func canonical(v any) []byte {
	b, e := json.Marshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
func hexSize(s string, n int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == n && hex.EncodeToString(b) == s
}

// Profiles are closed. A copied or user-decoded profile must match one of these
// exact values before it can authorize a quote, address or RPC observation.
type Profile struct {
	Coin      string `json:"coin"`
	Network   string `json:"network"`
	Genesis   string `json:"genesis"`
	HRP       string `json:"hrp"`
	MaxAtoms  int64  `json:"max_atoms"`
	DustAtoms int64  `json:"dust_atoms"`
}

const NamecoinMainGenesis = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"

// ForCoin preserves the original regtest-only selector. Mainnet callers must
// supply both the network and its genesis through ForNetwork.
func ForCoin(coin string) (Profile, error) {
	p := Profile{Coin: coin, Network: "regtest", Genesis: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206", MaxAtoms: 21000000 * 100000000}
	switch coin {
	case "btc":
		p.HRP = "bcrt"
		p.DustAtoms = 294
	case "ltc":
		p.HRP = "rltc"
		p.Genesis = "530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9"
		p.MaxAtoms = 84000000 * 100000000
		p.DustAtoms = 2940
	case "nmc":
		p.DustAtoms = 546
	default:
		return Profile{}, refuse("COIN_PROFILE")
	}
	return p, nil
}

func ForNetwork(coin, network, genesis string) (Profile, error) {
	p, err := ForCoin(coin)
	if err != nil {
		return Profile{}, err
	}
	if network == "main" && coin == "nmc" && genesis == NamecoinMainGenesis {
		p.Network, p.Genesis = network, genesis
		return p, nil
	}
	if network != p.Network || genesis != p.Genesis {
		return Profile{}, refuse("COIN_PROFILE")
	}
	return p, nil
}

func (p Profile) Validate() error {
	want, e := ForNetwork(p.Coin, p.Network, p.Genesis)
	if e != nil || p != want {
		return refuse("COIN_PROFILE")
	}
	return nil
}
func (p Profile) validScript(s string) bool {
	if p.Coin == "nmc" {
		return len(s) == 50 && strings.HasPrefix(s, "76a914") && strings.HasSuffix(s, "88ac") && hexSize(s, 25)
	}
	return len(s) == 44 && strings.HasPrefix(s, "0014") && hexSize(s, 22)
}
func (p Profile) params() chaincfg.Params {
	v := chaincfg.RegressionNetParams
	if p.Network == "main" {
		v = chaincfg.MainNetParams
		v.PubKeyHashAddrID, v.ScriptHashAddrID, v.PrivateKeyID = 52, 13, 180
	}
	v.Bech32HRPSegwit = p.HRP
	return v
}

// AddressDeriver holds only a pinned public branch. The caller must atomically
// reserve the per-coin index with its global booking interval before exposure.
type AddressDeriver struct {
	profile Profile
	key     *hdkeychain.ExtendedKey
}

func NewAddressDeriver(p Profile, branch, pin string) (*AddressDeriver, error) {
	if p.Validate() != nil {
		return nil, refuse("COIN_PROFILE")
	}
	if !hexSize(pin, 32) || Hash([]byte(branch)) != pin {
		return nil, refuse("XPUB_PIN")
	}
	k, e := hdkeychain.NewKeyFromString(branch)
	params := p.params()
	if e != nil || k.IsPrivate() || !k.IsForNet(&params) {
		if p.Network == "main" {
			return nil, refuse("WATCH_ONLY_MAIN_KEY")
		}
		return nil, refuse("WATCH_ONLY_REGTEST_KEY")
	}
	return &AddressDeriver{p, k}, nil
}
func (d *AddressDeriver) Address(index uint32) (address, script string, err error) {
	if d == nil || d.key == nil || index >= hdkeychain.HardenedKeyStart {
		return "", "", refuse("ADDRESS_INDEX")
	}
	child, e := d.key.Derive(index)
	if e != nil {
		return "", "", refuse("ADDRESS_DERIVATION")
	}
	key, e := child.ECPubKey()
	if e != nil {
		return "", "", refuse("ADDRESS_DERIVATION")
	}
	h := btcutil.Hash160(key.SerializeCompressed())
	params := d.profile.params()
	if d.profile.Coin == "nmc" {
		a, e := btcutil.NewAddressPubKeyHash(h, &params)
		if e != nil {
			return "", "", e
		}
		address = a.EncodeAddress()
	} else {
		a, e := btcutil.NewAddressWitnessPubKeyHash(h, &params)
		if e != nil {
			return "", "", e
		}
		address = a.EncodeAddress()
	}
	script, err = d.profile.Script(address)
	return
}

// Script accepts exactly the profile's payment address family and canonical
// spelling. Alternate networks, case variants, witness versions and P2SH refuse.
func (p Profile) Script(address string) (string, error) {
	if p.Validate() != nil {
		return "", refuse("COIN_PROFILE")
	}
	if p.Coin == "nmc" {
		params := p.params()
		a, e := btcutil.DecodeAddress(address, &params)
		if e != nil {
			return "", refuse("PAYMENT_ADDRESS")
		}
		h, ok := a.(*btcutil.AddressPubKeyHash)
		if !ok || !h.IsForNet(&params) || h.EncodeAddress() != address {
			return "", refuse("PAYMENT_ADDRESS")
		}
		return "76a914" + hex.EncodeToString(h.ScriptAddress()) + "88ac", nil
	}
	if address != strings.ToLower(address) || len(address) > 90 {
		return "", refuse("PAYMENT_ADDRESS")
	}
	hrp, data, e := bech32.Decode(address)
	if e != nil || hrp != p.HRP || len(data) != 33 || data[0] != 0 {
		return "", refuse("PAYMENT_ADDRESS")
	}
	program, e := bech32.ConvertBits(data[1:], 5, 8, false)
	if e != nil || len(program) != 20 {
		return "", refuse("PAYMENT_ADDRESS")
	}
	params := p.params()
	a, e := btcutil.NewAddressWitnessPubKeyHash(program, &params)
	if e != nil || a.EncodeAddress() != address {
		return "", refuse("PAYMENT_ADDRESS")
	}
	return "0014" + hex.EncodeToString(program), nil
}

// Terms is the signed v2 payment object. NMC execution budget is a separate
// contract field and is never interpreted as an amount in this coin.
type Terms struct {
	Coin              string `json:"coin"`
	Network           string `json:"network"`
	Genesis           string `json:"genesis"`
	PriceUSDCents     int64  `json:"price_usd_cents"`
	USDMicrosPerCoin  int64  `json:"usd_micros_per_coin"`
	RateAsOf          int64  `json:"rate_as_of"`
	MaxRateAgeSeconds int64  `json:"max_rate_age_seconds"`
	AmountAtoms       int64  `json:"amount_atoms"`
	Address           string `json:"address"`
	MinConfirmations  int64  `json:"min_confirmations"`
}

func Quote(p Profile, cents, micros, asOf, maxAge, now int64) (int64, error) {
	if p.Validate() != nil {
		return 0, refuse("COIN_PROFILE")
	}
	if cents <= 0 || micros <= 0 || asOf <= 0 || maxAge <= 0 || now < asOf || now-asOf > maxAge {
		return 0, refuse("QUOTE_RATE")
	}
	n := new(big.Int).Mul(big.NewInt(cents), big.NewInt(1000000000000))
	n.Add(n, big.NewInt(micros-1)).Quo(n, big.NewInt(micros))
	if !n.IsInt64() || n.Int64() < p.DustAtoms || n.Int64() > p.MaxAtoms {
		return 0, refuse("QUOTE_AMOUNT")
	}
	return n.Int64(), nil
}

// ValidateAt binds the signed quote to its hold-creation time and trusted policy.
// A later admission does not expire a quote frozen within a valid hold.
func (t Terms) ValidateAt(holdCreated, maxAge, minConfirmations int64) error {
	p, e := ForNetwork(t.Coin, t.Network, t.Genesis)
	if e != nil || t.Network != p.Network || t.Genesis != p.Genesis {
		return refuse("PAYMENT_PROFILE")
	}
	if maxAge <= 0 || t.MaxRateAgeSeconds > maxAge || minConfirmations < 1 || minConfirmations > 2016 || t.MinConfirmations < minConfirmations || t.MinConfirmations > 2016 {
		return refuse("PAYMENT_POLICY")
	}
	amount, e := Quote(p, t.PriceUSDCents, t.USDMicrosPerCoin, t.RateAsOf, t.MaxRateAgeSeconds, holdCreated)
	if e != nil {
		return e
	}
	if amount != t.AmountAtoms {
		return refuse("PAYMENT_QUOTE")
	}
	_, e = p.Script(t.Address)
	return e
}
