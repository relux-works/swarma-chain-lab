package g1bench

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func validHighSFixture(t *testing.T) ([]byte, map[string]any, []byte) {
	t.Helper()
	var scalar [32]byte
	scalar[31] = 1
	key, _ := btcec.PrivKeyFromBytes(scalar[:])
	defer key.Zero()
	n, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	half := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	for i := 0; i < 64; i++ {
		envelope := []byte(fmt.Sprintf(`{"public_high_s_fixture":%d}`, i))
		co, e := CoSign(key, envelope, schnorr.CustomNonce([32]byte{}))
		if e != nil {
			t.Fatal(e)
		}
		raw, e := hex.DecodeString(co["sig"].(string))
		if e != nil {
			t.Fatal(e)
		}
		scalar := new(big.Int).SetBytes(raw[32:])
		if scalar.Cmp(half) > 0 && scalar.Cmp(n) < 0 {
			if _, e := (BIP340{}).Verify(envelope, co); e != nil {
				t.Fatal("valid high-s signature refused", e)
			}
			return envelope, co, raw
		}
	}
	t.Fatal("bounded deterministic public high-s fixture not found")
	return nil, nil, nil
}

// Proves exact len/r/s wire bounds beside a fully verifying high-s < n control; this is not a low-s policy.
func TestCoSignatureStrictBounds(t *testing.T) {
	envelope, good, raw := validHighSFixture(t)
	p, _ := hex.DecodeString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
	n, _ := hex.DecodeString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	for _, name := range []string{"empty", "short", "long", "r-equals-p", "r-above-p", "s-equals-n", "s-above-n"} {
		t.Run(name, func(t *testing.T) {
			bad := append([]byte{}, raw...)
			switch name {
			case "empty":
				bad = nil
			case "short":
				bad = bad[:63]
			case "long":
				bad = append(bad, 0)
			case "r-equals-p":
				copy(bad[:32], p)
			case "r-above-p":
				copy(bad[:32], bytes.Repeat([]byte{255}, 32))
			case "s-equals-n":
				copy(bad[32:], n)
			case "s-above-n":
				v := new(big.Int).Add(new(big.Int).SetBytes(n), big.NewInt(1))
				copy(bad[32:], v.FillBytes(make([]byte, 32)))
			}
			before := append([]byte{}, bad...)
			if _, e := canonicalSignature(bad); e != ErrInvalid {
				t.Fatal("out-of-range signature parsed", name, e)
			}
			if !bytes.Equal(before, bad) {
				t.Fatal("strict parser changed input")
			}
			if _, e := canonicalSignature(raw); e != nil {
				t.Fatal("valid high-s parser control refused", e)
			}
			if _, e := (BIP340{}).Verify(envelope, good); e != nil {
				t.Fatal("valid high-s verification control refused", e)
			}
		})
	}
}

// Proves a bounded 64-byte (r,s+n) encoding aliases a canonical parser input in btcec but is refused here; the synthetic s=1 pair is format-only, beside a real valid high-s signature.
func TestCoSignatureMalleatedScalar(t *testing.T) {
	envelope, good, raw := validHighSFixture(t)
	n, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	base := append([]byte{}, raw...)
	copy(base[32:], big.NewInt(1).FillBytes(make([]byte, 32)))
	canonical, e := canonicalSignature(base)
	if e != nil || !bytes.Equal(canonical.Serialize(), base) {
		t.Fatal("canonical encoding control refused", e)
	}
	sum := new(big.Int).Add(n, new(big.Int).SetBytes(base[32:]))
	if sum.Cmp(new(big.Int).Lsh(big.NewInt(1), 256)) >= 0 {
		t.Fatal("malleated witness exceeds 64-byte encoding")
	}
	alias := append([]byte{}, base...)
	copy(alias[32:], sum.FillBytes(make([]byte, 32)))
	if len(alias) != 64 || bytes.Equal(alias, base) {
		t.Fatal("invalid alias witness setup")
	}
	normalized, e := schnorr.ParseSignature(alias)
	if e != nil || !bytes.Equal(normalized.Serialize(), base) {
		t.Fatal("pinned parser did not normalize alias witness", e)
	}
	before := append([]byte{}, alias...)
	if _, e := canonicalSignature(alias); e != ErrInvalid {
		t.Fatal("malleated scalar accepted before verification")
	}
	if !bytes.Equal(before, alias) {
		t.Fatal("alias refusal rewrote bytes")
	}
	if _, e := (BIP340{}).Verify(envelope, good); e != nil {
		t.Fatal("valid high-s positive refused", e)
	}
}

// Claim: the exact tag/tag/uint64-BE-length/wire-byte digest matches an independent SHA-256 vector.
func TestCoSignatureDigestVector(t *testing.T) {
	raw := []byte("exact envelope bytes\n")
	digest, err := Digest(raw)
	if err != nil || hex.EncodeToString(digest[:]) != "a9e64098e1290ce7c467094cecf44489515ccda5b53e97d7f85b9bd131a02eec" {
		t.Fatal("Track A framing mismatch", err)
	}
	for _, bad := range [][]byte{nil, bytes.Repeat([]byte{'x'}, maxEnvelope+1)} {
		if _, err := Digest(bad); err != ErrInvalid {
			t.Fatal("digest size bound missing")
		}
	}
}
