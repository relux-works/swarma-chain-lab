package rental

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// sj1Variants preserves the surrounding valid fixture. Invalid duplicate values
// use a different semantic value; reverse order defeats last-key-wins decoders.
func sj1Variants(t *testing.T, raw []byte, key, good, bad string) map[string][]byte {
	t.Helper()
	field := `"` + key + `":` + good
	if !strings.Contains(string(raw), field) {
		t.Fatal("missing mutation target", key)
	}
	escaped := `"\u` + fmt.Sprintf("%04x", key[0]) + key[1:] + `":`
	out := map[string][]byte{}
	for name, value := range map[string]string{
		"left-valid":        field + `,"` + key + `":` + bad,
		"right-valid":       `"` + key + `":` + bad + `,` + field,
		"escaped-duplicate": field + `,` + escaped + bad,
		"escaped-single":    escaped + good,
	} {
		out[name] = []byte(strings.Replace(string(raw), field, value, 1))
	}
	return out
}

// Public signed grant/presentation and K1/N1 parsers reject both duplicate orders
// and escaped spellings. These are pure offline parsers: no chain effects claimed.
func TestSJ1AuthorityParsers(t *testing.T) {
	for _, tc := range []struct {
		name, file, key, good, bad string
		parse                      func([]byte) error
	}{
		{"grant", "signed-grant.json", "version", "3", "2", func(b []byte) error { _, e := ParseSignedGrant(b); return e }},
		{"presentation", "presentation.json", "version", "3", "2", func(b []byte) error { _, e := ParseGrantPresentation(b); return e }},
		{"agent", "agent-value.json", "landlord", `"id/swarma-landlord"`, `"invalid"`, func(b []byte) error { _, e := ParseAgentBinding(string(b)); return e }},
		{"landlord", "landlord-value.json", "grant", "", `"invalid"`, func(b []byte) error { _, e := ParseLandlordValue(string(b)); return e }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, e := os.ReadFile("testdata/grant-v3/" + tc.file)
			if e != nil {
				t.Fatal(e)
			}
			if tc.name == "agent" {
				v, e := ParseAgentBinding(string(raw))
				if e != nil {
					t.Fatal(e)
				}
				tc.good = fmt.Sprintf("%q", v.Landlord)
			}
			if tc.name == "landlord" {
				v, e := ParseLandlordValue(string(raw))
				if e != nil {
					t.Fatal(e)
				}
				tc.good = fmt.Sprintf("%q", v.Grant)
			}
			for name, bad := range sj1Variants(t, raw, tc.key, tc.good, tc.bad) {
				t.Run(name, func(t *testing.T) {
					want := map[string]string{"grant": "CANONICAL_ENCODING", "presentation": "CANONICAL_ENCODING", "agent": "AGENT_BINDING_VALUE", "landlord": "LANDLORD_VALUE"}[tc.name]
					if e := tc.parse(bad); e == nil || e.Error() != want {
						t.Fatal("SJ1 ambiguous authority admitted")
					}
					if e := tc.parse(raw); e != nil {
						t.Fatal("valid neighbor refused", e)
					}
				})
			}
		})
	}
	_, key := testKey(1)
	_, nostr := testKey(3)
	k1, _ := AgentValue(AgentKeys{Nostr: nostr, Grant: key})
	n1, _ := CombinedLandlordValue(LandlordBinding{key}, n1Descriptor(nostr))
	for name, raw := range map[string]string{"K1": k1, "N1": n1} {
		t.Run(name, func(t *testing.T) {
			parse := func(b []byte) error {
				if name == "K1" {
					_, e := ParseAgentValue(string(b))
					return e
				}
				_, _, e := ParseLandlordIdentity(string(b))
				return e
			}
			for _, bad := range sj1Variants(t, []byte(raw), "grant", fmt.Sprintf("%q", key), `"invalid"`) {
				want := map[string]string{"K1": "AGENT_NAME_VALUE", "N1": "LANDLORD_VALUE"}[name]
				if e := parse(bad); e == nil || e.Error() != want {
					t.Fatal("SJ1 ambiguous name admitted")
				}
				if e := parse([]byte(raw)); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}

// The issuer checks JSON both outside and inside the authenticated publication.
// Embedded package mutations are re-signed so a signature failure cannot mask
// the key guard; valid request/publication controls authenticate offline.
func TestSJ1IssuanceKeys(t *testing.T) {
	p, r, pack, pub := paymentV2Fixture(t, "nmc")
	now := pack.HoldCreatedAt + 10
	verify := func(req, event []byte) error { _, _, e := VerifyIssuancePackageV2(p, req, event, now); return e }
	req, event := eventBytes(r), eventBytes(pub)
	for _, bad := range sj1Variants(t, req, "version", "2", "9") {
		if e := verify(bad, event); e == nil {
			t.Fatal("SJ1 ambiguous request admitted")
		}
		if e := verify(req, event); e != nil {
			t.Fatal(e)
		}
	}
	for _, bad := range sj1Variants(t, event, "kind", "8182", "0") {
		if e := verify(req, bad); e == nil {
			t.Fatal("SJ1 ambiguous publication admitted")
		}
		if e := verify(req, event); e != nil {
			t.Fatal(e)
		}
	}
	for _, target := range []struct{ key, good, bad string }{{"version", "1", "9"}, {"budget_sat", fmt.Sprint(pack.Contract.BudgetSat), "-1"}, {"kind", "8181", "0"}} {
		for _, bad := range sj1Variants(t, []byte(pub.Content), target.key, target.good, target.bad) {
			changed := pub
			changed.Content = string(bad)
			changed = signedEvent(t, changed, 2)
			rr := r
			rr.PackageEventID = changed.ID
			if e := verify(eventBytes(rr), eventBytes(changed)); e == nil || e.Error() != "PACKAGE_ENCODING" {
				t.Fatal("package key refusal", e)
			}
			if e := verify(req, event); e != nil {
				t.Fatal(e)
			}
		}
	}
}
