package facade

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// TestJunctionExport drives the pinned CLI with its existing regtest loopback
// node and published test signers. It exports public bytes only; it does not
// sign transactions, broadcast, or assert confirmed Core state.
func TestJunctionExport(t *testing.T) {
	out := os.Getenv("IDENTITY_INTEROP_OUT")
	if !filepath.IsAbs(out) {
		t.Fatal("absolute IDENTITY_INTEROP_OUT required")
	}
	if err := os.MkdirAll(out, 0700); err != nil {
		t.Fatal(err)
	}
	save := func(name string, v any) {
		t.Helper()
		raw, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(out, name), append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	octets := func(name string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(out, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	f := newFlow(t, "regtest", "id/landlord-a", "id/landlord-a-agent")
	n := newGrantTxNode(t, f.node, f.landlord.PublicKey())
	sealReq := GrantSealRequest{GrantSealSchema, "regtest", "id/landlord-a", f.landlord.PublicKey(), 100000, grantTestFunding(t, "0014751e76e8199196d454941c45d1b3a323f1433bd6", 1000000)}
	save("seal-request.json", sealReq)
	e, code := sealCmd(t, n, sealReq)
	mustOK(t, e, code)
	seal := resultAs[GrantSealResult](t, e)
	save("seal-result.json", seal)
	r := regtestRequest([]string{"instruct", "review"}, []string{}, 0)
	r.Seal = seal.Seal
	f.issue(r)
	save("draft-request.json", r)
	save("draft-result.json", f.draft)
	save("consent-result.json", f.consent)
	save("sign-result.json", f.signed)
	raw, _ := base64.StdEncoding.DecodeString(f.signed.SignedGrantB64)
	octets("signed-grant.json", raw)
	contract, _ := base64.StdEncoding.DecodeString(f.signed.ContractB64)
	octets("contract.json", contract)
	n.mu.Lock()
	n.point = seal.Seal
	n.mu.Unlock()
	anchorReq := GrantAnchorRequest{Schema: GrantAnchorSchema, SignedGrantB64: f.signed.SignedGrantB64, ContractB64: f.signed.ContractB64, Funding: grantTestFunding(t, "0014751e76e8199196d454941c45d1b3a323f1433bd6", 500000)}
	save("anchor-request.json", anchorReq)
	e, code = anchorCmd(t, n, anchorReq)
	mustOK(t, e, code)
	anchor := resultAs[GrantAnchorResult](t, e)
	save("anchor-result.json", anchor)
	proof, err := rental.PresentIssuedGrant(raw, anchor.Transaction.UnsignedTxID)
	if err != nil {
		t.Fatal(err)
	}
	octets("presentation.json", proof)
	legacy := landlordValue(f.landlord.PublicKey())
	octets("landlord-legacy.json", []byte(legacy))
	octets("agent-value.json", []byte(agentValue(r.LandlordName)))
	ledgerControl, err := os.ReadFile(f.ledger)
	if err != nil {
		t.Fatal(err)
	}
	outcomes := map[string]any{}
	recordOK := func(name string, e Envelope, code int, detail, value string) {
		t.Helper()
		mustOK(t, e, code)
		if e.Error != nil || e.Result == nil {
			t.Fatal("success envelope has no usable result")
		}
		// OK is the normalized success label; exit comes from the actual dispatch.
		outcomes[name] = map[string]any{"exit": code, "code": "OK", detail: value}
	}
	recordOK("legacy", e, code, "stage", "signed+anchor-plan")
	record := func(name string, e Envelope, code int, want string) {
		t.Helper()
		mustRefuse(t, e, code, want)
		current, err := os.ReadFile(f.ledger)
		if err != nil || !bytes.Equal(current, ledgerControl) {
			t.Fatal("refusal changed seal ledger", err)
		}
		outcomes[name] = map[string]any{"exit": code, "code": e.Error.Code}
		save("issuer-"+name+".json", e)
	}
	for _, tc := range []struct{ name, holders string }{{"holders-empty", "[]"}, {"holders-populated", `["02` + f.landlord.PublicKey() + `"]`}} {
		value := strings.Replace(legacy, `"grant":"`+f.landlord.PublicKey()+`"`, `"grant":"`+f.landlord.PublicKey()+`","holders":`+tc.holders, 1)
		octets("landlord-"+tc.name+".json", []byte(value))
		f.node.set(r.LandlordName, value)
		// Draft refuses before any seal can be consumed; compare with the same
		// legacy request using a fresh unused outpoint (the issued seal is recorded).
		fresh := r
		fresh.Seal = rental.Point{TxID: sealB, Vout: 0}
		e, code = f.draftCmd(fresh)
		record(tc.name, e, code, "LANDLORD_NOT_V3")
		f.node.set(r.LandlordName, legacy)
		e, code = f.draftCmd(fresh)
		mustOK(t, e, code)
	}
	consentReq := GrantConsentRequest{Schema: GrantConsentSchema, Draft: f.draft.Draft, ConsentSig: strings.Repeat("00", 64)}
	e, code = f.consentCmd(consentReq)
	record("wrong-consent", e, code, "CONSENT_SIGNATURE")
	wrong := f.consent.ConsentEvent
	wrong.Pubkey = testsigner_public(t, keyOther)
	e, code = f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: f.draft.Draft, ConsentEvent: &wrong})
	record("wrong-grantee", e, code, "CONSENT_SIGNER")
	tamper := anchorReq
	tamper.ContractB64 = base64.StdEncoding.EncodeToString(append(contract, ' '))
	e, code = anchorCmd(t, n, tamper)
	record("tampered-contract", e, code, "CONTRACT_HASH")
	bad := r
	bad.Schema = "swarma-trust/draft/9"
	e, code = f.draftCmd(bad)
	record("wrong-version", e, code, "BAD_INPUT")
	for _, mode := range []string{"spent", "missing"} {
		n.reset(mode)
		e, code = anchorCmd(t, n, anchorReq)
		record("seal-"+mode, e, code, "SEAL_MISSING_OR_SPENT")
		n.reset("")
		e, code = anchorCmd(t, n, anchorReq)
		mustOK(t, e, code)
	}
	// Refusal bytes preserve all unrelated fields; re-sign the outer grant
	// using the public test signer to isolate inner consent and field checks.
	base := *f.signed.SignedGrant
	for _, tc := range []struct {
		name string
		edit func(*rental.SignedGrant)
	}{
		{"wrong-consent", func(s *rental.SignedGrant) { s.Grant.Consent.ConsentEvent.Sig = strings.Repeat("00", 64) }},
		{"wrong-grantee", func(s *rental.SignedGrant) { s.Grant.GranteeKey = testsigner_public(t, keyOther) }},
		{"wrong-version", func(s *rental.SignedGrant) { s.Grant.Version = 9 }},
		{"wrong-seal", func(s *rental.SignedGrant) { s.Grant.Seal.Vout = 1 }},
	} {
		var changed rental.SignedGrant
		b, _ := json.Marshal(base)
		if err := json.Unmarshal(b, &changed); err != nil {
			t.Fatal(err)
		}
		tc.edit(&changed)
		payload, _ := json.Marshal(changed.Grant)
		changed.Signature = sign(t, f.landlord, sha256Hex(append([]byte("swarma-grant-v3"), payload...)))
		octets(tc.name+".json", mustJSONForJunction(t, rental.GrantPresentation{SignedGrant: changed, Issuance: rental.IssuanceProof{TxID: anchor.Transaction.UnsignedTxID}}))
	}
	var tampered rental.GrantPresentation
	if err := json.Unmarshal(proof, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.SignedGrant.Grant.NotBefore++
	octets("tampered-byte.json", mustJSONForJunction(t, tampered))
	wrongLocator := rental.GrantPresentation{SignedGrant: base, Issuance: rental.IssuanceProof{TxID: seal.Seal.TxID}}
	octets("wrong-locator.json", mustJSONForJunction(t, wrongLocator))

	// Unsupported contract profile: issuer refuses before accepting a consent.
	wrongProfile := []byte(strings.Replace(string(contract), "swarma-trust-contract/1", "swarma-trust-contract/9", 1))
	octets("wrong-profile-contract.json", wrongProfile)
	draftProfile := f.draft.Draft
	draftProfile.ContractB64 = base64.StdEncoding.EncodeToString(wrongProfile)
	draftProfile.ContractSHA256 = sha256Hex(wrongProfile)
	e, code = f.consentCmd(GrantConsentRequest{Schema: GrantConsentSchema, Draft: draftProfile, ConsentSig: strings.Repeat("00", 64)})
	record("wrong-profile", e, code, "CONTRACT_PROFILE")
	// A public-test-signed unsupported profile lets the verifier isolate its
	// contract parser rather than fail at an unrelated outer-signature gate.
	var profileGrant rental.SignedGrant
	json.Unmarshal(raw, &profileGrant)
	g := &profileGrant.Grant
	g.ContractSHA256 = sha256Hex(wrongProfile)
	g.Consent.ContractSHA256 = g.ContractSHA256
	event := g.Consent.ConsentEvent
	event.Tags = [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", g.ContractSHA256}, {"booking", sha256Hex(append(append([]byte{}, wrongProfile...), []byte("booking")...))}, {"privacy", sha256Hex([]byte("swarma-trust-privacy-v1"))}}
	event.ID = consentEventID(event.Pubkey, event.CreatedAt, event.Kind, event.Tags, event.Content)
	event.Sig = sign(t, f.grantee, event.ID)
	g.Consent.ConsentEvent = event
	g.Consent.LandlordSig = sign(t, f.landlord, g.ContractSHA256)
	profileGrant.Signature = sign(t, f.landlord, sha256Hex(append([]byte("swarma-grant-v3"), mustJSONForJunction(t, *g)...)))
	octets("wrong-profile.json", mustJSONForJunction(t, rental.GrantPresentation{SignedGrant: profileGrant, Issuance: rental.IssuanceProof{TxID: anchor.Transaction.UnsignedTxID}}))
	// Wrong seal script is refused by the anchor precheck next to its valid plan.
	n.reset("wrong-key")
	e, code = anchorCmd(t, n, anchorReq)
	record("wrong-seal", e, code, "SEAL_KEY_MISMATCH")
	n.reset("")
	e, code = anchorCmd(t, n, anchorReq)
	mustOK(t, e, code)
	// Issuance has no ambient clock: an already elapsed but internally valid
	// window is accepted. Verifier-time expiry is intentionally asymmetric.
	expired := r
	expired.Seal = rental.Point{TxID: sealB, Vout: 1}
	expired.NotBefore = 100
	expired.NotAfter = 200
	expired.ConsentCreatedAt = 99
	f.prepare(expired)
	e, code = f.signCmd(f.finalRequest())
	mustOK(t, e, code)
	f.signed = resultAs[GrantSignResult](t, e)
	recordOK("expired-window", e, code, "reason", "issuer has no ambient clock")
	expiredRaw, _ := base64.StdEncoding.DecodeString(f.signed.SignedGrantB64)
	octets("expired-signed-grant.json", expiredRaw)
	expiredContract, _ := base64.StdEncoding.DecodeString(f.signed.ContractB64)
	octets("expired-contract.json", expiredContract)
	expiredProof, err := rental.PresentIssuedGrant(expiredRaw, anchor.Transaction.UnsignedTxID)
	if err != nil {
		t.Fatal(err)
	}
	octets("expired-window.json", expiredProof)
	save("issuer-outcomes.json", outcomes)
	assertNoSecrets(t, f.outputs)
}

func mustJSONForJunction(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
