package rental

import (
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// These scalars are public deterministic test fixtures, never wallet keys.
func testKey(n byte) (*btcec.PrivateKey, string) {
	b := make([]byte, 32)
	b[31] = n
	k, p := btcec.PrivKeyFromBytes(b)
	return k, hex.EncodeToString(schnorr.SerializePubKey(p))
}
func testCertificate() Certificate {
	_, issuer := testKey(1)
	_, grantee := testKey(2)
	_, agent := testKey(3)
	return Certificate{1, "regtest", su.RegtestGenesis, "id/swarma-station-test", agent, issuer, grantee, strings.Repeat("a", 64), []string{"deliver", "pay"}, 100, 1000, Point{strings.Repeat("b", 64), 0}, 100000}
}
func signTest(t *testing.T, c Certificate, key byte) []byte {
	t.Helper()
	b, e := c.Canonical()
	if e != nil {
		t.Fatal(e)
	}
	h, _ := hex.DecodeString(Hash(b))
	k, _ := testKey(key)
	sig, e := schnorr.Sign(k, h)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(Envelope{c, hex.EncodeToString(sig.Serialize())})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

// Official BIP-340 32-byte-message vectors cover positive/negative signature
// cases for this profile. btcec v2.3.5 rejects the later variable-length-message
// extension (vectors 15-18); certificates always sign a 32-byte SHA256 digest.
func TestOfficialBIP340Vectors(t *testing.T) {
	raw, e := os.ReadFile("testdata/bip340.csv")
	if e != nil {
		t.Fatal(e)
	}
	if Hash(raw) != "34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d" {
		t.Fatal("vector pin")
	}
	rows, e := csv.NewReader(strings.NewReader(string(raw))).ReadAll()
	if e != nil {
		t.Fatal(e)
	}
	for _, row := range rows[1:] {
		t.Run(row[0], func(t *testing.T) {
			kb, _ := hex.DecodeString(row[2])
			m, _ := hex.DecodeString(row[4])
			sb, _ := hex.DecodeString(row[5])
			pk, pe := schnorr.ParsePubKey(kb)
			sig, se := schnorr.ParseSignature(sb)
			valid := pe == nil && se == nil && sig.Verify(m, pk)
			if len(m) != 32 {
				if valid {
					t.Fatal("library unexpectedly accepts out-of-profile message length")
				}
				return
			}
			if valid != (row[6] == "TRUE") {
				t.Fatalf("vector %s: %v", row[0], valid)
			}
		})
	}
}

// Signed bytes have one encoding; field mutations, aliases and foreign
// signatures do not validate. Empty scope is a valid chat-only positive case.
func TestCertificateBoundary(t *testing.T) {
	c := testCertificate()
	raw := signTest(t, c, 1)
	if _, e := ParseEnvelope(raw); e != nil {
		t.Fatal(e)
	}
	changes := map[string]string{
		"newline":   string(raw) + "\n",
		"alias":     strings.Replace(string(raw), `"budget_sat"`, `"Budget_Sat"`, 1),
		"missing":   strings.Replace(string(raw), `"version":1,`, "", 1),
		"extra":     strings.Replace(string(raw), `"version":1,`, `"version":1,"extra":0,`, 1),
		"duplicate": strings.Replace(string(raw), `"version":1,`, `"version":1,"version":1,`, 1),
		"contract":  strings.Replace(string(raw), c.ContractSHA256, strings.Repeat("c", 64), 1),
		"expiry":    strings.Replace(string(raw), `"not_after":1000`, `"not_after":1001`, 1),
		"seal":      strings.Replace(string(raw), c.Seal.TxID, strings.Repeat("d", 64), 1),
		"scope":     strings.Replace(string(raw), `["deliver","pay"]`, `["deliver"]`, 1),
	}
	for name, b := range changes {
		t.Run(name, func(t *testing.T) {
			if _, e := ParseEnvelope([]byte(b)); e == nil {
				t.Fatal("mutated envelope accepted")
			}
		})
	}
	if _, e := ParseEnvelope(signTest(t, c, 4)); e == nil || e.Error() != "ISSUER_SIGNATURE" {
		t.Fatalf("foreign signer: %v", e)
	}
	c.Scope = []string{}
	if _, e := ParseEnvelope(signTest(t, c, 1)); e != nil {
		t.Fatal(e)
	}
	for _, s := range [][]string{nil, {"pay", "deliver"}, {"pay", "pay"}, {"pay.nmc"}} {
		c.Scope = s
		if e := c.Validate(); e == nil || e.Error() != "CERTIFICATE_SCOPE" {
			t.Fatalf("scope %v: %v", s, e)
		}
	}
}
