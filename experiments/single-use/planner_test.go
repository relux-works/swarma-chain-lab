package singleuse

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func exampleSpec(t *testing.T, kind string) PlanSpec {
	_, _, issuer, grantee := coreFixture(t, "grantee")
	_, seal, e := SealScript(issuer, grantee)
	if e != nil {
		t.Fatal(e)
	}
	payment := "76a914" + strings.Repeat("11", 20) + "88ac"
	point := Point{strings.Repeat("22", 32), 0}
	s := PlanSpec{Kind: kind, IssuerKey: issuer, GranteeKey: grantee, ChangeScript: payment, Seal: point, SealValueSat: 1000000, OwnerName: "id/w3-template", OwnerSPKI: "public-fixture-only", OwnerPaymentScript: payment, CertificateHash: strings.Repeat("33", 32)}
	switch kind {
	case "seal":
		s.Inputs = []PlanInput{{point, 2000000, payment, "funding"}}
	case "use":
		s.Inputs = []PlanInput{{point, 1000000, hex.EncodeToString(seal), "seal"}}
	case "anchor":
		spk, _ := hex.DecodeString(payment)
		s.Inputs = []PlanInput{{point, 2000000, hex.EncodeToString(NameUpdateScript(s.OwnerName, "{}", spk)), "name"}}
	}
	return s
}

// All three inert plans conserve integer satoshis and reserve 200 sat/vB at the
// conservative signed-size bound; no transaction hex or network action exists.
func TestOfflinePlans(t *testing.T) {
	for _, kind := range []string{"seal", "anchor", "use"} {
		t.Run(kind, func(t *testing.T) {
			s := exampleSpec(t, kind)
			p, e := MakePlan(s, []byte("signed-request"))
			if e != nil {
				t.Fatal(e)
			}
			var in, out int64
			for _, v := range p.Inputs {
				in += v.ValueSat
			}
			for _, v := range p.Outputs {
				out += v.ValueSat
			}
			if in-out != p.FeeSat || p.FeeSat != int64(p.MaxSignedVBytes)*200 || !p.Offline || p.Network != "main" {
				t.Fatal(p)
			}
		})
	}
}

// Invalid funding roles, duplicated points, insufficient/dust change, missing
// request bytes and malformed keys cannot produce an apparently usable plan.
func TestOfflinePlanRefusals(t *testing.T) {
	for _, mode := range []string{"duplicate", "insufficient", "no-request", "wrong-role", "equal-keys", "wrong-seal", "unknown-kind"} {
		t.Run(mode, func(t *testing.T) {
			s := exampleSpec(t, "use")
			req := []byte("signed-request")
			switch mode {
			case "duplicate":
				s.Inputs = append(s.Inputs, s.Inputs[0])
			case "insufficient":
				s.Inputs[0].ValueSat = 1
				s.SealValueSat = 1
			case "no-request":
				req = nil
			case "wrong-role":
				s.Inputs[0].Role = "funding"
			case "equal-keys":
				s.IssuerKey = s.GranteeKey
			case "wrong-seal":
				s.Seal.Vout++
			case "unknown-kind":
				s.Kind = "broadcast"
			}
			want := map[string]string{"duplicate": "FUNDING_INPUT", "insufficient": "FUNDING_OR_DUST_RESERVE", "no-request": "USE_PLAN", "wrong-role": "LEGACY_FUNDING_ONLY", "equal-keys": "EQUAL_CHAIN_KEYS", "wrong-seal": "PLAN_SEAL_BINDING", "unknown-kind": "PLAN_SEAL_BINDING"}[mode]
			if _, e := MakePlan(s, req); publicError(e) != want {
				t.Fatalf("want %s, got %v", want, e)
			}
		})
	}
}

// The public-input decoder rejects unknown/aliased fields inside arrays too;
// a normal serialized plan remains accepted and its fee bound covers a 65-byte
// legacy funding public key. P2SH name inputs have no declared unlock bound.
func TestPlannerInputBoundary(t *testing.T) {
	s := exampleSpec(t, "anchor")
	raw, _ := json.Marshal(s)
	var decoded PlanSpec
	if e := StrictInput(raw, &decoded); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{
		strings.Replace(string(raw), `"value_sat":2000000`, `"Value_Sat":2000000`, 1),
		strings.Replace(string(raw), `"role":"name"`, `"role":"name","extra":1`, 1),
	} {
		if e := StrictInput([]byte(bad), &decoded); e == nil {
			t.Fatal("nested field accepted")
		}
	}
	p, e := MakePlan(s, nil)
	if e != nil {
		t.Fatal(e)
	}
	tx := Transaction{Version: p.Version, Inputs: []Input{{s.Inputs[0].Point, make([]byte, 140), 0xfffffffe}}}
	for _, out := range p.Outputs {
		b, _ := hex.DecodeString(out.Script)
		tx.Outputs = append(tx.Outputs, Output{out.ValueSat, b})
	}
	if len(tx.Bytes()) != p.MaxSignedVBytes {
		t.Fatal("legacy upper bound")
	}
	s.OwnerPaymentScript = "a914" + strings.Repeat("11", 20) + "87"
	b, _ := hex.DecodeString(s.OwnerPaymentScript)
	s.Inputs[0].Script = hex.EncodeToString(NameUpdateScript(s.OwnerName, "{}", b))
	if _, e = MakePlan(s, nil); publicError(e) != "PLAN_NAME_PREVOUT" {
		t.Fatal(e)
	}
}
