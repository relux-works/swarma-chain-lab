package paymentchain

import (
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

// Main admission is explicitly NMC-only and genesis-bound. This checks local
// derivation and quote validation, not a live mainnet payment or node.
func TestExplicitNamecoinMainProfile(t *testing.T) {
	p, err := ForNetwork("nmc", "main", NamecoinMainGenesis)
	if err != nil || p.Validate() != nil {
		t.Fatal(p, err)
	}
	seed := make([]byte, 32)
	seed[0] = 19
	master, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := master.Neuter()
	d, err := NewAddressDeriver(p, pub.String(), Hash([]byte(pub.String())))
	if err != nil {
		t.Fatal(err)
	}
	address, script, err := d.Address(0)
	if err != nil || !p.validScript(script) {
		t.Fatal(address, script, err)
	}
	params := chaincfg.MainNetParams
	params.PubKeyHashAddrID = 52
	a, err := btcutil.DecodeAddress(address, &params)
	if err != nil || !a.IsForNet(&params) {
		t.Fatal("NMC main address version", err)
	}
	amount, err := Quote(p, 1000, 10000000, 100, 60, 100)
	if err != nil {
		t.Fatal(err)
	}
	terms := Terms{"nmc", "main", NamecoinMainGenesis, 1000, 10000000, 100, 60, amount, address, 1}
	if err = terms.ValidateAt(100, 60, 1); err != nil {
		t.Fatal(err)
	}
	reg, _ := ForCoin("nmc")
	if _, err = reg.Script(address); err == nil || err.Error() != "PAYMENT_ADDRESS" {
		t.Fatal("main address crossed into regtest", err)
	}
	regMaster, _ := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	regPub, _ := regMaster.Neuter()
	regDeriver, _ := NewAddressDeriver(reg, regPub.String(), Hash([]byte(regPub.String())))
	regAddress, _, _ := regDeriver.Address(0)
	if _, err = p.Script(regAddress); err == nil || err.Error() != "PAYMENT_ADDRESS" {
		t.Fatal("regtest address crossed into main", err)
	}
	for _, key := range []string{regPub.String(), master.String()} {
		if _, err = NewAddressDeriver(p, key, Hash([]byte(key))); err == nil || err.Error() != "WATCH_ONLY_MAIN_KEY" {
			t.Fatal("wrong-network/private key accepted", err)
		}
	}
	for _, c := range []struct{ coin, network, genesis string }{
		{"btc", "main", NamecoinMainGenesis},
		{"ltc", "main", NamecoinMainGenesis},
		{"nmc", "main", reg.Genesis},
		{"nmc", "regtest", NamecoinMainGenesis},
		{"nmc", "test", NamecoinMainGenesis},
		{"nmc", "", ""},
	} {
		if _, err = ForNetwork(c.coin, c.network, c.genesis); err == nil || err.Error() != "COIN_PROFILE" {
			t.Fatal("unsupported profile accepted", c, err)
		}
	}
	terms.Genesis = reg.Genesis
	if err = terms.ValidateAt(100, 60, 1); err == nil || err.Error() != "PAYMENT_PROFILE" {
		t.Fatal("mismatched signed genesis accepted", err)
	}
}
