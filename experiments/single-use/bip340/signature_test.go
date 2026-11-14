package bip340

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// Parsing enforces each unsigned boundary before reduction; both official valid
// controls verify, including s > n/2, so this is not an ECDSA low-S restriction.
func TestParseBIP340Strict(t *testing.T) {
	vectors := []struct{ name, key, hash, sig string }{
		{"valid", "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9", "0000000000000000000000000000000000000000000000000000000000000000", "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"},
		{"valid-high-s", "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"},
	}
	decode := func(s string) []byte {
		t.Helper()
		b, e := hex.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			b := decode(v.sig)
			sig, e := ParseBIP340Strict(b)
			if e != nil {
				t.Fatal(e)
			}
			pk, e := schnorr.ParsePubKey(decode(v.key))
			if e != nil || !sig.Verify(decode(v.hash), pk) || !bytes.Equal(b, sig.Serialize()) {
				t.Fatal("valid vector refused or changed")
			}
			if v.name == "valid-high-s" && new(big.Int).SetBytes(b[32:]).Cmp(new(big.Int).Rsh(btcec.S256().N, 1)) <= 0 {
				t.Fatal("high-s control is not high")
			}
		})
	}
	base := decode(vectors[0].sig)
	n := btcec.S256().N
	p := btcec.S256().P
	cases := []struct {
		name   string
		offset int
		value  *big.Int
		length int
		want   string
	}{
		{"s-equal-n", 32, n, 64, "BIP340: s >= n"},
		{"s-above-n", 32, new(big.Int).Add(n, big.NewInt(1)), 64, "BIP340: s >= n"},
		{"s-max", 32, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)), 64, "BIP340: s >= n"},
		{"r-equal-p", 0, p, 64, "BIP340: r >= p"},
		{"r-above-p", 0, new(big.Int).Add(p, big.NewInt(1)), 64, "BIP340: r >= p"},
		{"length-63", 0, nil, 63, "BIP340: signature must be 64 bytes"},
		{"length-65", 0, nil, 65, "BIP340: signature must be 64 bytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := make([]byte, c.length)
			copy(b, base)
			if c.value != nil {
				c.value.FillBytes(b[c.offset : c.offset+32])
			}
			sig, e := ParseBIP340Strict(b)
			if e == nil || e.Error() != c.want || sig != nil {
				t.Fatalf("want nil signature and %s; got %v, %v", c.want, sig, e)
			}
			if _, e = ParseBIP340Strict(base); e != nil {
				t.Fatal("valid neighbour refused", e)
			}
		})
	}
	// Encoding bounds are not curve or message verification: zero and n-1 may
	// parse, and must still be checked by the caller against the key and message.
	for _, s := range []*big.Int{big.NewInt(0), new(big.Int).Sub(n, big.NewInt(1))} {
		b := bytes.Clone(base)
		s.FillBytes(b[32:])
		if _, e := ParseBIP340Strict(b); e != nil {
			t.Fatal("in-range scalar refused", e)
		}
	}
	// The field value immediately below p is an allowed encoding; this does not claim mathematical validity.
	b := bytes.Clone(base)
	new(big.Int).Sub(p, big.NewInt(1)).FillBytes(b[:32])
	if _, e := ParseBIP340Strict(b); e != nil {
		t.Fatal("in-range r refused", e)
	}

}
