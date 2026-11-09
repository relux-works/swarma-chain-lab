package rental

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Frozen public v3 bytes preserve payload/id/commitment and exact identity
// linkage. Synthetic outpoints make no chain-readiness claim.
func TestGrantFixture(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		b, e := os.ReadFile("testdata/grant-v3/" + name)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	raw := read("signed-grant.json")
	signed, e := ParseSignedGrant(raw)
	if e != nil {
		t.Fatal(e)
	}
	var meta map[string]string
	if e = json.Unmarshal(read("metadata.json"), &meta); e != nil {
		t.Fatal(e)
	}
	payload, e := signed.Grant.Canonical()
	if e != nil || string(payload) != string(read("grant.json")) || Hash(payload) != meta["payload_sha256"] || signed.ID() != meta["grant_id"] {
		t.Fatal("grant fixture digest")
	}
	commit, e := IssuanceCommitment(signed)
	if e != nil || commit != meta["commitment"] {
		t.Fatal("grant fixture commitment")
	}
	presentation, e := ParseGrantPresentation(read("presentation.json"))
	if e != nil || presentation.SignedGrant.ID() != signed.ID() {
		t.Fatal("grant fixture locator")
	}
	a, e := ParseAgentBinding(string(read("agent-value.json")))
	if e != nil || a.Landlord != signed.Grant.LandlordName {
		t.Fatal("grant fixture pointer")
	}
	l, e := ParseLandlordValue(string(read("landlord-value.json")))
	if e != nil || l.Grant != signed.Grant.IssuerKey {
		t.Fatal("grant fixture landlord")
	}
	script, e := GrantSealScript(l.Grant)
	if e != nil || script != meta["seal_script"] {
		t.Fatal("grant fixture seal")
	}
}

func testGrant(t *testing.T) Grant {
	t.Helper()
	c := testDetached()
	e := signedEvent(t, Event{CreatedAt: 99, Kind: 8181, Tags: [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", c.ContractSHA256}, {"booking", Hash([]byte("booking"))}, {"privacy", Hash([]byte("privacy"))}}, Content: ""}, 2)
	return Grant{Version: 3, Network: c.Network, Genesis: c.Genesis, AgentName: c.AgentName, LandlordName: "id/test-landlord", IssuerKey: c.IssuerKey, GranteeKey: c.GranteeKey, ContractSHA256: c.ContractSHA256, Scope: c.Scope, NotBefore: c.NotBefore, NotAfter: c.NotAfter, Seal: c.Seal, Consent: GrantConsent{c.ContractSHA256, e, signature(t, c.ContractSHA256, 1)}}
}
func signGrantTest(t *testing.T, g Grant, key byte) []byte {
	t.Helper()
	b, e := json.Marshal(g)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(SignedGrant{g, signature(t, Hash(append([]byte("swarma-grant-v3"), b...)), key)})
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

// V3 authenticates two distinct signature messages: renter NIP-01 event id
// and landlord contract hash, then the complete grant payload. Every semantic
// mutation is re-signed by the landlord to isolate the consent guard.
func TestGrantConsent(t *testing.T) {
	good := testGrant(t)
	for _, mode := range []string{"event-key", "event-id", "event-signature", "raw-renter-signature", "event-contract", "booking-alias", "landlord-signature", "missing-landlord-signature", "consent-contract", "event-content", "event-kind"} {
		t.Run(mode, func(t *testing.T) {
			g := testGrant(t)
			want := "RENTER_CONSENT_EVENT"
			switch mode {
			case "event-key":
				g.Consent.ConsentEvent = signedEvent(t, g.Consent.ConsentEvent, 4)
			case "event-id":
				g.Consent.ConsentEvent.ID = Hash([]byte("wrong"))
			case "event-signature":
				g.Consent.ConsentEvent.Sig = signature(t, g.Consent.ConsentEvent.ID, 4)
			case "raw-renter-signature":
				g.Consent.ConsentEvent.Sig = signature(t, g.ContractSHA256, 2)
			case "event-contract":
				g.Consent.ConsentEvent.Tags[1][1] = Hash([]byte("wrong"))
				g.Consent.ConsentEvent = signedEvent(t, g.Consent.ConsentEvent, 2)
				want = "RENTER_CONSENT_BINDING"
			case "booking-alias":
				g.Consent.ConsentEvent.Tags[2][0] = "booking_id"
				g.Consent.ConsentEvent = signedEvent(t, g.Consent.ConsentEvent, 2)
				want = "RENTER_CONSENT_BINDING"
			case "landlord-signature":
				g.Consent.LandlordSig = signature(t, g.ContractSHA256, 4)
				want = "LANDLORD_CONSENT_SIGNATURE"
			case "missing-landlord-signature":
				g.Consent.LandlordSig = ""
				want = "LANDLORD_CONSENT_SIGNATURE"
			case "consent-contract":
				g.Consent.ContractSHA256 = Hash([]byte("wrong"))
				want = "CONSENT_CONTRACT"
			case "event-content":
				g.Consent.ConsentEvent.Content = "other"
				g.Consent.ConsentEvent = signedEvent(t, g.Consent.ConsentEvent, 2)
			case "event-kind":
				g.Consent.ConsentEvent.Kind = 8182
				g.Consent.ConsentEvent = signedEvent(t, g.Consent.ConsentEvent, 2)
			}
			if _, e := ParseSignedGrant(signGrantTest(t, g, 1)); e == nil || e.Error() != want {
				t.Fatal("consent guard", want, e)
			}
			if _, e := ParseSignedGrant(signGrantTest(t, good, 1)); e != nil {
				t.Fatal("valid neighbor", e)
			}
		})
	}
}

// The locator is outside the signed id and commitment. Changing it preserves
// signed authority bytes but still requires an independent on-node check.
// Alternate envelope encodings and the v2 wire cannot enter the v3 parser.
func TestGrantWire(t *testing.T) {
	g := testGrant(t)
	raw := signGrantTest(t, g, 1)
	signed, e := ParseSignedGrant(raw)
	if e != nil {
		t.Fatal(e)
	}
	a, e := PresentIssuedGrant(raw, strings.Repeat("c", 64))
	if e != nil {
		t.Fatal(e)
	}
	b, e := PresentIssuedGrant(raw, strings.Repeat("d", 64))
	if e != nil {
		t.Fatal(e)
	}
	pa, e := ParseGrantPresentation(a)
	if e != nil {
		t.Fatal(e)
	}
	pb, e := ParseGrantPresentation(b)
	if e != nil {
		t.Fatal(e)
	}
	if pa.SignedGrant.ID() != Hash(raw) || pb.SignedGrant.ID() != Hash(raw) || Hash(a) == Hash(b) {
		t.Fatal("locator/id separation")
	}
	commit, e := IssuanceCommitment(signed)
	if e != nil {
		t.Fatal(e)
	}
	data := []byte("swarma-issue-v1")
	for _, v := range []string{g.ContractSHA256, g.Consent.ConsentEvent.ID, g.Consent.ConsentEvent.Sig, g.Consent.LandlordSig, Hash(raw)} {
		data = append(data, mustDecodeKey(v)...)
	}
	if Hash(data) != commit {
		t.Fatal("commitment byte profile")
	}
	for _, input := range [][]byte{signDetachedTest(t, testDetached(), 1), append(append([]byte(nil), raw...), 10), []byte(strings.Replace(string(raw), `"version":3`, `"version":3,"extra":0`, 1)), signGrantTest(t, g, 4)} {
		if _, e := ParseSignedGrant(input); e == nil {
			t.Fatal("invalid grant accepted")
		}
		if _, e := ParseSignedGrant(raw); e != nil {
			t.Fatal("valid neighbor", e)
		}
	}
}

// Exact landlord/agent shapes admit their intended identities. Missing,
// aliased, extra and old-v2 fields cannot silently become a new binding.
func TestLandlordNameValues(t *testing.T) {
	_, key := testKey(1)
	_, nostr := testKey(3)
	a, e := AgentBindingValue(AgentBinding{nostr, "id/landlord"})
	if e != nil {
		t.Fatal(e)
	}
	l, e := LandlordValue(LandlordBinding{key})
	if e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{a + " ", strings.Replace(a, `"landlord":`, `"owner":`, 1), strings.Replace(a, `"landlord":"id/landlord"`, `"grant":"`+key+`"`, 1), strings.Replace(a, `"nostr":`, `"extra":0,"nostr":`, 1), `{"swarma":{"agent":{"nostr":"` + nostr + `"}}}`} {
		if _, e := ParseAgentBinding(raw); e == nil {
			t.Fatal("invalid agent binding accepted")
		}
		if _, e := ParseAgentBinding(a); e != nil {
			t.Fatal("valid agent neighbor", e)
		}
	}
	for _, raw := range []string{l + " ", strings.Replace(l, `"grant":`, `"issuer":`, 1), strings.Replace(l, `"grant":`, `"extra":0,"grant":`, 1), `{"swarma":{"landlord":{}}}`} {
		if _, e := ParseLandlordValue(raw); e == nil {
			t.Fatal("invalid landlord value accepted")
		}
		if _, e := ParseLandlordValue(l); e != nil {
			t.Fatal("valid landlord neighbor", e)
		}
	}
}
