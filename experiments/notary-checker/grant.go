package notarycheck

import (
	"bytes"
	"strconv"
)

func eventID(e Event) string {
	return hash(canonical([]any{0, e.Pubkey, e.CreatedAt, e.Kind, e.Tags, e.Content}))
}
func validEvent(e Event, at int64) bool {
	return e.CreatedAt >= 1 && e.CreatedAt <= MaxTime && e.CreatedAt <= at && e.ID == eventID(e) && signature(e.Pubkey, e.ID, e.Sig)
}
func network(n, g string) bool {
	return (n == "main" && g == "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770") || (n == "regtest" && g == "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")
}
func readGrant(raw []byte, at int64) (Presentation, error) {
	var p Presentation
	fail := func(s string) (Presentation, error) { return p, refuse(s) }
	if !decode(raw, &p, 32768) {
		return fail("GRANT_ENCODING")
	}
	g := p.SignedGrant.Grant
	if g.Version != 3 || !network(g.Network, g.Genesis) || !nameRE.MatchString(g.AgentName) || !nameRE.MatchString(g.LandlordName) || g.AgentName == g.LandlordName || (g.GranteeName != "" && !nameRE.MatchString(g.GranteeName)) || !key(g.IssuerKey) || !key(g.GranteeKey) || !ishex(g.ContractSHA256, 64) || !ishex(g.Seal.TxID, 64) || !ishex(p.Issuance.TxID, 64) || !sorted(g.Scope) || !subset(g.Scope, []string{"deliver", "names.register", "pay", "publish", "repository.push", "secret.release"}) || g.NotAfter <= g.NotBefore || g.NotAfter > MaxTime || (g.Budget != nil && *g.Budget > MaxMoney) {
		return fail("GRANT_FIELD")
	}
	if !signature(g.IssuerKey, tagged("swarma-grant-v3", canonical(g)), p.SignedGrant.Signature) {
		return fail("GRANT_SIGNATURE")
	}
	if at < g.NotBefore {
		return fail("GRANT_NOT_YET_VALID")
	}
	if at >= g.NotAfter {
		return fail("GRANT_EXPIRED")
	}
	c := g.Consent
	e := c.ConsentEvent
	if c.ContractSHA256 != g.ContractSHA256 || !validEvent(e, at) || e.CreatedAt >= g.NotAfter || e.Pubkey != g.GranteeKey || e.Kind != 8181 || e.Content != "" || !signature(g.IssuerKey, g.ContractSHA256, c.LandlordSig) {
		return fail("GRANT_CONSENT")
	}
	return p, nil
}
func bind(g Grant, raw []byte) (Contract, Delegate, error) {
	var c Contract
	var d Delegate
	if hash(raw) != g.ContractSHA256 {
		return c, d, refuse("CONTRACT_HASH")
	}
	c, d, e := ParseContract(raw)
	if e != nil {
		return c, d, e
	}
	if c.Network != g.Network || c.LandlordName != g.LandlordName || c.AgentName != g.AgentName || c.GranteeKey != g.GranteeKey || c.NotBefore != g.NotBefore || c.NotAfter != g.NotAfter {
		return c, d, refuse("CONTRACT_MISMATCH")
	}
	scope := []string{}
	if contains(c.Actions, "spend") {
		scope = append(scope, "pay")
	}
	if contains(c.Actions, "land") {
		scope = append(scope, "repository.push")
	}
	if !bytes.Equal(canonical(scope), canonical(g.Scope)) {
		return c, d, refuse("SCOPE_MISMATCH")
	}
	budget := int64(0)
	if g.Budget != nil {
		budget = *g.Budget
	}
	if budget != c.SpendBudget {
		return c, d, refuse("BUDGET_MISMATCH")
	}
	tags := [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", g.ContractSHA256}, {"booking", hash(append(append([]byte{}, raw...), []byte("booking")...))}, {"privacy", hash([]byte("swarma-trust-privacy-v1"))}}
	if !bytes.Equal(canonical(g.Consent.ConsentEvent.Tags), canonical(tags)) {
		return c, d, refuse("CONSENT_TAGS")
	}
	return c, d, nil
}
func request(raw []byte, p Grant, c Contract, parentID, childHash string, at int64) bool {
	var e Event
	if !decode(raw, &e, 16384) || !validEvent(e, MaxTime) || e.Pubkey != p.GranteeKey || e.Kind != 8186 || e.Content != "" || e.CreatedAt < p.NotBefore || e.CreatedAt >= p.NotAfter || len(e.Tags) != 5 || len(e.Tags[4]) != 2 || !ishex(e.Tags[4][1], 64) {
		return false
	}
	want := [][]string{{"t", "swarma-delegation-request-v1"}, {"parent", parentID}, {"contract", childHash}, {"ordinal", strconv.FormatInt(c.Ordinal, 10)}, {"nonce", e.Tags[4][1]}}
	return bytes.Equal(canonical(e.Tags), canonical(want))
}
