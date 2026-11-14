package wire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func (s vectorSet) composed(t *testing.T, v vector) IssuanceInput {
	t.Helper()
	var ctx struct {
		fixtureContext
		Party string `json:"party_public_key"`
		Grant string `json:"grant"`
	}
	var parts struct {
		Assent     string           `json:"issuer_assent_hex"`
		Consent    string           `json:"consent_event_hex"`
		NameOutput *Outpoint        `json:"name_output"`
		Evidence   *fixtureEvidence `json:"evidence"`
	}
	decode(t, v["context"], &ctx)
	decode(t, v["parts"], &parts)
	ctx.Evidence = parts.Evidence
	facts := s.byID[ctx.Grant]
	if facts == nil {
		t.Fatal("missing stated grant facts")
	}
	assent, err := hex.DecodeString(parts.Assent)
	wantCode(t, err, "")
	consent, err := hex.DecodeString(parts.Consent)
	wantCode(t, err, "")
	return IssuanceInput{
		Grant: &GrantFacts{Mode: ctx.Mode, Genesis: ctx.Genesis, Contract: ctx.Contract,
			ID: facts.str("identifier"), Signature: facts.str("signature"), ContentAddress: facts.str("content_address"),
			IssuerPublicKey: ctx.Issuer, PartyPublicKey: ctx.Party,
			RequestPublicKey: ctx.Request, RecipientName: ctx.Name, RecentBlockHeight: ctx.Recent},
		IssuerAssent:     assent,
		RecipientConsent: consent,
		NameOutput:       parts.NameOutput, Evidence: ctx.context().Evidence, Now: ctx.Now,
		Frame: Frame{Script: v.octets(t, "script_hex"), OpReturnCount: 1},
	}
}

// Every pair of buildable W9.4 steps reports the earlier defect, beside both single defects and a valid control.
func TestV4IssuanceFirstRefusalPairs(t *testing.T) {
	s := loadVectors(t)
	defects := []struct {
		name  string
		code  Code
		apply func(*IssuanceInput)
	}{
		{"mode", IssuanceMode, func(in *IssuanceInput) { in.NameOutput = &Outpoint{TxID: strings.Repeat("0", 64)} }},
		{"assent", AssentParty, func(in *IssuanceInput) { in.Grant.PartyPublicKey = in.Grant.RequestPublicKey }},
		{"consent", ConsentTime, func(in *IssuanceInput) { in.Now = 0 }},
		{"frame", IssuanceFrame, func(in *IssuanceInput) { in.Frame.Value = 1 }},
		{"commitment", IssuanceCommitment, func(in *IssuanceInput) { in.Frame.Script[7] ^= 1 }},
	}
	check := func(t *testing.T, indices []int, want Code) {
		t.Helper()
		in := s.composed(t, s.byID["composed-v-01"])
		for _, i := range indices {
			defects[i].apply(&in)
		}
		before, err := json.Marshal(in)
		wantCode(t, err, "")
		p, err := CheckIssuance(in)
		wantCode(t, err, string(want))
		requireNoObject(t, p, err)
		after, err := json.Marshal(in)
		wantCode(t, err, "")
		equalBytes(t, after, before)
		if want == "" && p == nil {
			t.Fatal("valid control returned no preparation")
		}
	}
	for i := range defects {
		for j := i + 1; j < len(defects); j++ {
			t.Run(defects[i].name+"-before-"+defects[j].name, func(t *testing.T) {
				t.Run("valid-control", func(t *testing.T) { check(t, nil, "") })
				t.Run("earlier-alone", func(t *testing.T) { check(t, []int{i}, defects[i].code) })
				t.Run("later-alone", func(t *testing.T) { check(t, []int{j}, defects[j].code) })
				check(t, []int{i, j}, defects[i].code)
			})
		}
	}
}

// Typed dispatch checks stated inputs; octets, missing facts and reserved schemas never become grants.
func TestV4ComposedDispatchBoundary(t *testing.T) {
	s := loadVectors(t)
	in := s.composed(t, s.byID["composed-v-01"])
	p, err := Read(IssuanceClass, nil, ReadContext{Issuance: &in})
	wantCode(t, err, "")
	baseline := p.(*Preparation).Bytes()
	for _, raw := range [][]byte{{}, []byte(`{}`), s.byID["prim-grant-01"].octets(t, "signed_octets_hex")} {
		o, err := Read(IssuanceClass, raw, ReadContext{Issuance: &in})
		wantCode(t, err, string(WireType))
		if o != nil {
			t.Fatal("raw presentation admitted")
		}
	}
	for _, missing := range []*IssuanceInput{nil, {}} {
		o, err := Read(IssuanceClass, nil, ReadContext{Issuance: missing})
		wantCode(t, err, string(WireType))
		if o != nil {
			t.Fatal("missing facts admitted")
		}
	}
	for _, typ := range []Type{Grant, Invocation, Receipt, SealEndorsement, NotaryAttestation} {
		o, err := ReadSigned([]byte(`{"type":"`+string(typ)+`"}`), typ)
		wantCode(t, err, string(WireType))
		requireNoObject(t, o, err)
	}
	// Returned preparation and caller inputs remain independent after composed dispatch.
	for _, b := range [][]byte{in.IssuerAssent, in.RecipientConsent, in.Frame.Script, baseline} {
		for i := range b {
			b[i] ^= 1
		}
	}
	fresh := s.composed(t, s.byID["composed-v-01"])
	q, err := CheckIssuance(fresh)
	wantCode(t, err, "")
	if bytes.Equal(baseline, q.Bytes()) {
		t.Fatal("mutation control did not change bytes")
	}
	equalBytes(t, p.(*Preparation).Bytes(), q.Bytes())
}

// Trusted issuer seconds bound age inclusively at 72 hours; consumed ids reject re-issue/reuse without mutating records.
func TestV4IssuerConsentDecisions(t *testing.T) {
	s := loadVectors(t)
	v := s.byID["issuer-c-01"]
	ctx, snapshot, consumed := s.issuerContext(t, v)
	b := v.octets(t, "event_hex")
	c, err := ReadConsent(b, ctx)
	wantCode(t, err, "")
	for _, tc := range []struct {
		name string
		now  uint64
		used []string
		want Code
	}{
		{"fresh", c.CreatedAt(), consumed, ""},
		{"72-hours", c.CreatedAt() + MaxConsentAge, consumed, ""},
		{"72-hours-plus-one", c.CreatedAt() + MaxConsentAge + 1, consumed, ConsentAge},
		{"future", c.CreatedAt() - 1, consumed, ConsentTime},
		{"second-grant", ctx.Now, []string{c.ID()}, ConsentConsumed},
		{"reissue", ctx.Now, []string{c.ID()}, ConsentConsumed},
		{"successor", ctx.Now, []string{c.ID()}, ConsentConsumed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			control := ctx
			control.Now = c.CreatedAt() + MaxConsentAge
			wantCode(t, CheckIssuerConditions(b, control, snapshot, nil), "")
			ctx.Now = tc.now
			wantCode(t, CheckIssuerConditions(b, ctx, snapshot, tc.used), string(tc.want))
		})
	}
	// Reconstructing the supplied consumed record models a restart input, not durable storage by this module.
	var restored []string
	raw, err := json.Marshal([]string{c.ID()})
	wantCode(t, err, "")
	decode(t, raw, &restored)
	ctx.Now = c.CreatedAt() + MaxConsentAge
	wantCode(t, CheckIssuerConditions(b, ctx, snapshot, restored), string(ConsentConsumed))
	ctx.Now++
	_, err = ReadConsent(b, ctx)
	wantCode(t, err, "") // Verifiers impose no issuer age limit or global reuse claim (W7.8-W7.9).
	for _, id := range []string{"consent-c-10", "consent-c-11", "consent-c-12", "consent-c-13", "consent-c-14", "consent-c-32", "consent-c-33", "issuer-c-06"} {
		t.Run(id, func(t *testing.T) { s.run(t, s.byID[id]) })
	}
}
