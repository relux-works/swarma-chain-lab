package rental

import (
	"encoding/json"
	"slices"
	"testing"
)

// Re-sign every affected layer, so scope tests exercise the partition contract
// rather than accidentally failing an unrelated signature/digest guard.
func scopePackage(t *testing.T, request, event []byte, allowed, forbidden []string) ([]byte, []byte) {
	t.Helper()
	var req IssuanceRequest
	var pub Event
	var pack Package
	if json.Unmarshal(request, &req) != nil || json.Unmarshal(event, &pub) != nil || json.Unmarshal([]byte(pub.Content), &pack) != nil {
		t.Fatal("scope fixture")
	}
	pack.Contract.Allowed = allowed
	pack.Contract.Forbidden = forbidden
	hash := Hash(eventBytes(pack.Contract))
	req.ContractSHA256 = hash
	req.Scope = allowed
	pack.ProviderSignature = signature(t, hash, 4)
	pack.Consent.Tags[1][1] = hash
	pack.Consent = signedEvent(t, pack.Consent, 2)
	pub.Tags[1][1] = hash
	pub.Tags[3][1] = pack.Consent.ID
	pub.Content = string(eventBytes(pack))
	pub = signedEvent(t, pub, 4)
	req.PackageEventID = pub.ID
	b, _ := json.Marshal(req)
	return b, eventBytes(pub)
}

// names.register is an exact action, not a wildcard. Existing five-action M3
// contracts remain valid and do not grant it; explicit use requires a complete
// six-action partition, with no omitted older action or overlapping grant.
func TestGrantNameScope(t *testing.T) {
	p, _, _, req, event := unitIssue(t)
	if r, _, e := VerifyIssuancePackage(p, req, event, 500); e != nil || slices.Contains(r.Scope, "names.register") {
		t.Fatal("legacy scope neighbor", e)
	}
	allowed := []string{"deliver", "names.register", "pay"}
	forbidden := []string{"publish", "repository.push", "secret.release"}
	a, b := scopePackage(t, req, event, allowed, forbidden)
	if r, _, e := VerifyIssuancePackage(p, a, b, 500); e != nil || !slices.Contains(r.Scope, "names.register") {
		t.Fatal("names.register admission", e)
	}
	g := testGrant(t)
	g.Scope = allowed
	if _, e := ParseSignedGrant(signGrantTest(t, g, 1)); e != nil {
		t.Fatal("names.register grant", e)
	}
	for _, badScope := range [][]string{{"names.*"}, {"name.register"}, {"names.register", "names.register"}, {"pay", "names.register"}} {
		g.Scope = badScope
		if _, e := ParseSignedGrant(signGrantTest(t, g, 1)); e == nil || e.Error() != "GRANT_SCOPE" {
			t.Fatal("scope guard", e)
		}
	}
	for _, badForbidden := range [][]string{{"publish", "repository.push"}, {"names.register", "repository.push", "secret.release"}} {
		x, y := scopePackage(t, req, event, allowed, badForbidden)
		if _, _, e := VerifyIssuancePackage(p, x, y, 500); e == nil || e.Error() != "CONTRACT_SCOPE" {
			t.Fatal("scope partition guard", e)
		}
		if _, _, e := VerifyIssuancePackage(p, a, b, 500); e != nil {
			t.Fatal("scope partition neighbor", e)
		}
	}
}
