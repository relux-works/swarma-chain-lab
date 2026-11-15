package notarycheck

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type vector struct {
	Name           string `json:"name"`
	Claim          string `json:"claim"`
	Expected       string `json:"expected"`
	Parent         string `json:"parent"`
	Child          string `json:"child"`
	ParentContract string `json:"parent_contract"`
	ChildContract  string `json:"child_contract"`
	Request        string `json:"request"`
	Policy         string `json:"policy"`
	NotaryValue    string `json:"notary_value"`
	Statement      string `json:"statement"`
	ParentText     string `json:"parent_text"`
	ChildText      string `json:"child_text"`
	At             int64  `json:"at"`
	Result         struct {
		Attestation string `json:"attestation"`
		Digest      string `json:"digest"`
	} `json:"result"`
	Signature     string `json:"attestation_signature"`
	AttestationID string `json:"attestation_id"`
	AnchorScript  string `json:"anchor_script"`
}

func (v vector) input() Input {
	return Input{[]byte(v.Parent), []byte(v.Child), []byte(v.ParentContract), []byte(v.ChildContract), []byte(v.Request), []byte(v.Policy), []byte(v.NotaryValue), []byte(v.Statement), []byte(v.ParentText), []byte(v.ChildText), v.At}
}

type corpus struct {
	Vectors    []vector `json:"vectors"`
	RowVectors []struct {
		Name     string   `json:"name"`
		Parent   Contract `json:"parent"`
		Child    Contract `json:"child"`
		Expected string   `json:"expected"`
	} `json:"row_vectors"`
}

func readCorpus(t testing.TB) corpus {
	t.Helper()
	raw, e := os.ReadFile("testdata/vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var c corpus
	if e = json.Unmarshal(raw, &c); e != nil {
		t.Fatal(e)
	}
	return c
}

// Each fixture's claim is scoped to exact signed bytes and explicit policy.
// Negative witnesses assert a specific refusal AND no partial candidate output.
// Positives compare independent expected octets, digest, envelope ID and frame.
func TestVectors(t *testing.T) {
	c := readCorpus(t)
	for _, v := range c.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			got, e := Check(v.input())
			code := "ATTEST"
			if e != nil {
				code = e.Error()
			}
			if code != v.Expected {
				t.Fatalf("%s: got %s; want %s", v.Claim, code, v.Expected)
			}
			if e != nil {
				if got.Digest != "" || len(got.Attestation) != 0 {
					t.Fatal("refusal leaked partial output")
				}
				return
			}
			if string(got.Attestation) != v.Result.Attestation || got.Digest != v.Result.Digest {
				t.Fatal("candidate differs from independent fixed fixture")
			}
			again, e := Check(v.input())
			if e != nil || !bytes.Equal(again.Attestation, got.Attestation) || again.Digest != got.Digest {
				t.Fatal("not deterministic")
			}
			signed, id, e := SignedAttestation(got, v.Signature)
			if e != nil || id != v.AttestationID {
				t.Fatalf("signed envelope: %s %v", id, e)
			}
			if hash(signed) != id {
				t.Fatal("envelope ID does not bind exact bytes")
			}
			var pol Policy
			if e = json.Unmarshal([]byte(v.Policy), &pol); e != nil {
				t.Fatal(e)
			}
			frame, e := AnchorScript(id, pol.ChildGrantID, pol.ParentGrantID)
			if e != nil || len(frame) != 72 || hex.EncodeToString(frame) != v.AnchorScript {
				t.Fatal("anchor frame differs")
			}
		})
	}
}

// This isolates the row-cap inequality that D12 makes unreachable with a valid
// nonzero spend child. Passing here does NOT admit any spend delegation.
func TestRowVectors(t *testing.T) {
	for _, v := range readCorpus(t).RowVectors {
		t.Run(v.Name, func(t *testing.T) {
			var pd Delegate
			if e := json.Unmarshal(v.Parent.Delegate, &pd); e != nil {
				t.Fatal(e)
			}
			e := checkRow(v.Parent, pd, v.Child)
			code := "ATTEST"
			if e != nil {
				code = e.Error()
			}
			if code != v.Expected {
				t.Fatalf("got %s; want %s", code, v.Expected)
			}
		})
	}
}

// A candidate's digest and a service signature are inseparable from its exact
// octets. Altered digests, malformed signatures and key substitutions refuse.
func TestSignedAttestationRejectsMismatch(t *testing.T) {
	v := readCorpus(t).Vectors[0]
	good, e := Check(v.input())
	if e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name string
		r    Result
		sig  string
	}{
		{"signature", good, "00" + v.Signature[2:]},
		{"digest", Result{good.Attestation, "00" + good.Digest[2:]}, v.Signature},
		{"octets", Result{append(append([]byte{}, good.Attestation...), '\n'), good.Digest}, v.Signature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, id, e := SignedAttestation(c.r, c.sig)
			if e == nil || e.Error() != "ATTESTATION_SIGNATURE" || b != nil || id != "" {
				t.Fatal("accepted altered candidate/signature")
			}
		})
	}
}

// Bad frame IDs never yield partial script bytes; a nearby valid case is tested
// in every positive bundle above.
func TestAnchorRejectsMalformedID(t *testing.T) {
	for i := 0; i < 3; i++ {
		a := []string{hash([]byte("a")), hash([]byte("c")), hash([]byte("p"))}
		a[i] = ""
		b, e := AnchorScript(a[0], a[1], a[2])
		if e == nil || e.Error() != "ATTESTATION_BINDING" || b != nil {
			t.Fatal("accepted missing ID")
		}
	}
}

// Canonical spelling is lexical at every depth, including unknown members.
// Duplicate nested shape errors belong to rule 9; malformed spellings belong
// to rule 1. These assertions pin the contract reader's refusal precedence.
func TestContractEncodingOrder(t *testing.T) {
	raw := []byte(readCorpus(t).Vectors[0].ParentContract)
	cases := []struct {
		name string
		raw  []byte
		code string
	}{
		{"nested-duplicate", bytes.Replace(raw, []byte(`"cap":0`), []byte(`"cap":0,"cap":0`), 1), "CONTRACT_DELEGATE"},
		{"nested-leading-zero", bytes.Replace(raw, []byte(`"cap":0`), []byte(`"cap":01`), 1), "CONTRACT_ENCODING"},
		{"negative", bytes.Replace(raw, []byte(`"cap":0`), []byte(`"cap":-1`), 1), "CONTRACT_ENCODING"},
		{"overflow", bytes.Replace(raw, []byte(`"cap":0`), []byte(`"cap":9223372036854775808`), 1), "CONTRACT_ENCODING"},
		{"unicode", bytes.Replace(raw, []byte(`"note":""`), []byte(`"note":"\u0061"`), 1), "CONTRACT_ENCODING"},
		{"boolean", bytes.Replace(raw, []byte(`"cap":0`), []byte(`"cap":false`), 1), "CONTRACT_ENCODING"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, e := ParseContract(c.raw)
			if e == nil || e.Error() != c.code {
				t.Fatalf("got %v; want %s", e, c.code)
			}
		})
	}
}

// Untrusted input bounds and lexical failures must refuse rather than panic.
// This is a bounded seed check in ordinary go test, not a fuzzing claim.
func FuzzContract(f *testing.F) {
	for _, b := range [][]byte{nil, []byte("{}"), []byte("[]"), []byte(`{"delegate":null}`), []byte(readCorpus(f).Vectors[0].ParentContract)} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _ = ParseContract(b) })
}

// Contract-only witnesses isolate reader rules from earlier grant checks and
// later child checks. This is required to test D12 without pretending spend
// delegation is admitted by the complete checker.
func TestContractRules(t *testing.T) {
	c := readCorpus(t)
	for _, v := range c.Vectors {
		if len(v.Expected) < 9 || (v.Expected[:9] != "CONTRACT_" && v.Expected != "DELEGATE_NO_NOTARY") {
			continue
		}
		if v.Expected == "CONTRACT_HASH" || v.Expected == "CONTRACT_MISMATCH" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			_, _, pe := ParseContract([]byte(v.ParentContract))
			_, _, ce := ParseContract([]byte(v.ChildContract))
			e := ce
			if pe != nil {
				e = pe
			}
			if e == nil {
				t.Fatalf("got ATTEST; want %s", v.Expected)
			}
			if e.Error() != v.Expected {
				t.Fatalf("got %v; want %s", e, v.Expected)
			}
		})
	}
}
