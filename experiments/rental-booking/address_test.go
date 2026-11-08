package booking

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
)

func fixtureBranch(t *testing.T) string {
	t.Helper()
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f") // Public BIP32 vector seed; never a real wallet.
	key, e := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := key.Neuter()
	if e != nil {
		t.Fatal(e)
	}
	return pub.String()
}

// These controls prove pin/private/network/index refusals beside a usable public
// derivation. Cryptographic BIP32 vectors are also exercised in upstream tests.
func TestAddressGuards(t *testing.T) {
	branch := fixtureBranch(t)
	d, e := NewAddressDeriver(branch, Hash([]byte(branch)))
	if e != nil {
		t.Fatal(e)
	}
	a, s, e := d.Address(0)
	if e != nil || a == "" || !strings.HasPrefix(s, "76a914") || len(s) != 50 {
		t.Fatalf("address %q %q %v", a, s, e)
	}
	b, _, e := d.Address(1)
	if e != nil || a == b {
		t.Fatal("distinct child addresses required")
	}
	seed := make([]byte, 32)
	seed[0] = 1
	priv, _ := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	main, _ := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	mainPub, _ := main.Neuter()
	for _, tc := range []struct{ name, key, pin, code string }{
		{"wrong_pin", branch, strings.Repeat("0", 64), "XPUB_PIN"},
		{"private", priv.String(), Hash([]byte(priv.String())), "WATCH_ONLY_REGTEST_KEY"},
		{"wrong_network", mainPub.String(), Hash([]byte(mainPub.String())), "WATCH_ONLY_REGTEST_KEY"},
		{"malformed", "not-a-key", Hash([]byte("not-a-key")), "WATCH_ONLY_REGTEST_KEY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, e := NewAddressDeriver(tc.key, tc.pin)
			if e == nil || e.Error() != tc.code {
				t.Fatalf("want %s, got %v", tc.code, e)
			}
			if _, _, e = d.Address(2); e != nil {
				t.Fatal(e)
			}
		})
	}
	if _, _, e = d.Address(hdkeychain.HardenedKeyStart); e == nil || e.Error() != "ADDRESS_INDEX" {
		t.Fatalf("hardened: %v", e)
	}
}
