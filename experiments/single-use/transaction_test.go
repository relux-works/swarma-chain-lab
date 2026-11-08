package singleuse

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func coreFixture(t *testing.T, role string) (*Transaction, Point, string, string) {
	t.Helper()
	b, e := os.ReadFile("testdata/public-script.json")
	if e != nil {
		t.Fatal(e)
	}
	// This fixture also contains non-string policy metadata; project key strings only.
	var fields map[string]json.RawMessage
	if e = json.Unmarshal(b, &fields); e != nil {
		t.Fatal(e)
	}
	var issuer, grantee string
	_ = json.Unmarshal(fields["issuer_key"], &issuer)
	_ = json.Unmarshal(fields["grantee_key"], &grantee)
	b, e = os.ReadFile("testdata/" + role + "-spend.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Raw      string
		SealTxID string `json:"seal_txid"`
		SealVout uint32 `json:"seal_vout"`
		Decoded  struct {
			TxID string `json:"txid"`
		}
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	raw, e := hex.DecodeString(f.Raw)
	if e != nil {
		t.Fatal(e)
	}
	tx, e := DecodeTransaction(raw)
	if e != nil {
		t.Fatal(e)
	}
	if tx.ID() != f.Decoded.TxID || !bytes.Equal(tx.Bytes(), raw) {
		t.Fatal("raw roundtrip/txid differs from Core")
	}
	return tx, Point{f.SealTxID, f.SealVout}, issuer, grantee
}

// Captured genuine Core28 signatures independently establish legacy digest and
// issuer/grantee attribution; changing a signed output must destroy that proof.
func TestCoreSignatureAttribution(t *testing.T) {
	for _, role := range []string{"grantee", "issuer"} {
		t.Run(role, func(t *testing.T) {
			tx, seal, issuer, grantee := coreFixture(t, role)
			got, e := Attribute(tx, seal, issuer, grantee)
			if e != nil || got != role {
				t.Fatal(got, e)
			}
			tx.Outputs[0].Value--
			if _, e = Attribute(tx, seal, issuer, grantee); e == nil {
				t.Fatal("changed output accepted")
			}
		})
	}
}

// The profile requires a distinct pinned key pair, NULLDUMMY, exact redeem
// script and SIGHASH_ALL; malformed cases never acquire signer attribution.
func TestSealProfileRefusals(t *testing.T) {
	for _, mode := range []string{"duplicate-key", "wrong-seal", "dummy", "sighash", "redeem", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			tx, seal, issuer, grantee := coreFixture(t, "grantee")
			switch mode {
			case "duplicate-key":
				issuer = grantee
			case "wrong-seal":
				seal.Vout++
			case "dummy":
				tx.Inputs[0].Script[0] = 0x51
			case "sighash":
				tx.Inputs[0].Script[1+int(tx.Inputs[0].Script[1])] = 0x81
			case "redeem":
				tx.Inputs[0].Script[len(tx.Inputs[0].Script)-1] ^= 1
			case "truncated":
				tx.Inputs[0].Script = tx.Inputs[0].Script[:2]
			}
			if _, e := Attribute(tx, seal, issuer, grantee); e == nil {
				t.Fatal("invalid profile admitted")
			}
		})
	}
}

// Exactly one minimal zero-value OP_RETURN binds the complete request bytes;
// ordinary signed change outputs are permitted by this commitment predicate.
func TestRequestCommitment(t *testing.T) {
	req := []byte("signed-envelope-fixture")
	h, _ := hex.DecodeString(Hash(req))
	script := append([]byte{0x6a, 32}, h...)
	for _, mode := range []string{"valid", "missing", "two", "value", "short", "nonminimal", "trailing", "wrong"} {
		t.Run(mode, func(t *testing.T) {
			tx := &Transaction{Outputs: []Output{{42, []byte{0x51}}, {0, append([]byte(nil), script...)}}}
			switch mode {
			case "missing":
				tx.Outputs = tx.Outputs[:1]
			case "two":
				tx.Outputs = append(tx.Outputs, tx.Outputs[1])
			case "value":
				tx.Outputs[1].Value = 1
			case "short":
				tx.Outputs[1].Script = script[:33]
			case "nonminimal":
				tx.Outputs[1].Script = append([]byte{0x6a, 0x4c, 32}, h...)
			case "trailing":
				tx.Outputs[1].Script = append(tx.Outputs[1].Script, 0)
			case "wrong":
				tx.Outputs[1].Script[2] ^= 1
			}
			e := RequestCommitment(tx, req)
			if (e == nil) != (mode == "valid") {
				t.Fatal(mode, e)
			}
		})
	}
}

// Bounded legacy parsing roundtrips genuine Core bytes and refuses truncation,
// nonminimal lengths, witness markers and trailing bytes without a panic.
func TestRawBounds(t *testing.T) {
	tx, _, _, _ := coreFixture(t, "grantee")
	raw := tx.Bytes()
	samples := [][]byte{nil, raw[:4], raw[:len(raw)-1], append(append([]byte(nil), raw...), 0), append(append([]byte(nil), raw[:4]...), append([]byte{253, 1, 0}, raw[5:]...)...), append(append([]byte(nil), raw[:4]...), append([]byte{0, 1}, raw[5:]...)...)}
	for i, b := range samples {
		if _, e := DecodeTransaction(b); e == nil {
			t.Fatalf("sample %d admitted", i)
		}
	}
}
