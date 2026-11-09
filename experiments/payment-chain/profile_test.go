package paymentchain

import (
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"strings"
	"testing"
)

// These controls prove closed regtest profiles, address-family/network binding,
// public-only derivation and frozen integer quote boundaries, not node admission.
func TestProfiles(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 7
	master, e := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	if e != nil {
		t.Fatal(e)
	}
	pub, _ := master.Neuter()
	for _, coin := range []string{"btc", "ltc", "nmc"} {
		t.Run(coin, func(t *testing.T) {
			p, _ := ForCoin(coin)
			d, e := NewAddressDeriver(p, pub.String(), Hash([]byte(pub.String())))
			if e != nil {
				t.Fatal(e)
			}
			addr, script, e := d.Address(0)
			if e != nil {
				t.Fatal(e)
			}
			got, e := p.Script(addr)
			if e != nil || got != script {
				t.Fatal("valid derived address", e)
			}
			if _, _, e = d.Address(hdkeychain.HardenedKeyStart); e == nil || e.Error() != "ADDRESS_INDEX" {
				t.Fatal("hardened accepted")
			}
			if _, e = NewAddressDeriver(p, master.String(), Hash([]byte(master.String()))); e == nil || e.Error() != "WATCH_ONLY_REGTEST_KEY" {
				t.Fatal("private accepted")
			}
			if _, e = NewAddressDeriver(p, pub.String(), strings.Repeat("0", 64)); e == nil || e.Error() != "XPUB_PIN" {
				t.Fatal("wrong pin accepted")
			}
			main := chaincfg.MainNetParams
			if coin == "ltc" {
				main.Bech32HRPSegwit = "ltc"
			}
			var wrong string
			if coin == "nmc" {
				main.PubKeyHashAddrID = 52
				a, _ := btcutil.NewAddressPubKeyHash(make([]byte, 20), &main)
				wrong = a.EncodeAddress()
			} else {
				a, _ := btcutil.NewAddressWitnessPubKeyHash(make([]byte, 20), &main)
				wrong = a.EncodeAddress()
			}
			if _, e = p.Script(wrong); e == nil || e.Error() != "PAYMENT_ADDRESS" {
				t.Fatal("mainnet address accepted")
			}
			changed := p
			changed.Network = "main"
			if _, e = changed.Script(addr); e == nil || e.Error() != "COIN_PROFILE" {
				t.Fatal("open profile")
			}
			q, e := Quote(p, 1, 300000000, 100, 60, 100)
			if e != nil || q != 3334 {
				t.Fatal("ceil quote", q, e)
			}
			terms := Terms{coin, p.Network, p.Genesis, 1, 300000000, 100, 60, q, addr, 2}
			if e = terms.ValidateAt(160, 60, 2); e != nil {
				t.Fatal("age boundary", e)
			}
			if e = terms.ValidateAt(161, 60, 2); e == nil || e.Error() != "QUOTE_RATE" {
				t.Fatal("stale quote accepted")
			}
			if e = terms.ValidateAt(99, 60, 2); e == nil || e.Error() != "QUOTE_RATE" {
				t.Fatal("future rate accepted")
			}
			if e = terms.ValidateAt(100, 60, 3); e == nil || e.Error() != "PAYMENT_POLICY" {
				t.Fatal("weak confirmations accepted")
			}
			terms.AmountAtoms++
			if e = terms.ValidateAt(100, 60, 2); e == nil || e.Error() != "PAYMENT_QUOTE" {
				t.Fatal("quote mismatch accepted")
			}
			if _, e = Quote(p, 1, 1000000000000, 100, 60, 100); e == nil || e.Error() != "QUOTE_AMOUNT" {
				t.Fatal("dust quote accepted")
			}
			if _, e = Quote(p, 9223372036854775807, 1, 100, 60, 100); e == nil || e.Error() != "QUOTE_AMOUNT" {
				t.Fatal("overflow accepted")
			}
		})
	}
	if _, e := ForCoin("eth"); e == nil {
		t.Fatal("unknown coin accepted")
	}
}
