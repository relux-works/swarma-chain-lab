package notarycheck

import (
	"bytes"
	"encoding/json"
)

// ParseContract applies LIP-0014 section 3.1 in its specified refusal order.
// Only the fifteen-member profile /2 is supported by this checker.
func ParseContract(raw []byte) (Contract, Delegate, error) {
	var c Contract
	var d Delegate
	fail := func(s string) (Contract, Delegate, error) { return c, d, refuse(s) }
	if !decode(raw, &c, 8192) {
		return fail("CONTRACT_ENCODING")
	} // rule 1
	if c.Profile != "swarma-trust-contract/2" {
		return fail("CONTRACT_PROFILE")
	}
	if (c.Network != "main" && c.Network != "regtest") || !nameRE.MatchString(c.LandlordName) || !nameRE.MatchString(c.AgentName) || c.AgentName == c.LandlordName || !key(c.GranteeKey) || c.NotAfter <= c.NotBefore || c.NotAfter > MaxTime || (c.ScopeTextSHA256 != "" && !ishex(c.ScopeTextSHA256, 64)) {
		return fail("CONTRACT_FIELD")
	}
	if len(c.Actions) == 0 || !sorted(c.Actions) || !subset(c.Actions, []string{"instruct", "land", "review", "spend"}) {
		return fail("CONTRACT_ACTIONS")
	}
	if !sorted(c.Repos) || len(c.Repos) > 16 || ((len(c.Repos) > 0) != contains(c.Actions, "land")) {
		return fail("CONTRACT_REPOS")
	}
	for _, s := range c.Repos {
		if !repository(s) {
			return fail("CONTRACT_REPOS")
		}
	}
	if c.SpendBudget > MaxMoney || ((c.SpendBudget > 0) != contains(c.Actions, "spend")) {
		return fail("CONTRACT_BUDGET")
	}
	if len(c.Note) > 280 {
		return fail("CONTRACT_NOTE")
	}
	if c.Ordinal > 16 || (c.ParentGrantID != "" && !ishex(c.ParentGrantID, 64)) || ((c.ParentGrantID == "") != (c.Ordinal == 0)) {
		return fail("CONTRACT_PARENT")
	}
	// Rule 8 reads depth only when it is the first member with integer value.
	decoder := json.NewDecoder(bytes.NewReader(c.Delegate))
	first, _ := decoder.Token()
	if first == json.Delim('{') {
		member, _ := decoder.Token()
		if member == "depth" {
			var depth int64
			if decoder.Decode(&depth) == nil && c.ParentGrantID != "" && depth != 0 {
				return fail("CONTRACT_PARENT")
			}
		}
	}
	// Rule 9 step 1 judges the delegate header, not its nested row semantics.
	var head struct {
		Depth      int64             `json:"depth"`
		Actions    []json.RawMessage `json:"actions"`
		Budget     int64             `json:"budget"`
		Slots      []json.RawMessage `json:"slots"`
		Notaries   []json.RawMessage `json:"notaries"`
		Checkpoint string            `json:"checkpoint"`
	}
	if !decode(c.Delegate, &head, 8192) {
		return fail("CONTRACT_DELEGATE")
	}
	if head.Depth == 1 && len(head.Notaries) == 0 {
		return fail("DELEGATE_NO_NOTARY")
	}
	if !decode(c.Delegate, &d, 8192) {
		return fail("CONTRACT_DELEGATE")
	}
	if d.Depth == 0 {
		if len(d.Actions) != 0 || d.Budget != 0 || len(d.Slots) != 0 || len(d.Notaries) != 0 || d.Checkpoint != "" {
			return fail("CONTRACT_DELEGATE")
		}
		return c, d, nil
	}
	if d.Depth != 1 || len(d.Actions) == 0 || !sorted(d.Actions) || !subset(d.Actions, c.Actions) || d.Budget > MaxMoney || ((d.Budget > 0) != contains(d.Actions, "spend")) || len(d.Slots) < 1 || len(d.Slots) > 16 || len(d.Notaries) < 1 || len(d.Notaries) > 4 || !ishex(d.Checkpoint, 64) {
		return fail("CONTRACT_DELEGATE")
	}
	for i, n := range d.Notaries {
		if !nameRE.MatchString(n.Name) || !ishex(n.Registration.TxID, 64) || !owner(n.Owner) || (i > 0 && d.Notaries[i-1].Name >= n.Name) {
			return fail("CONTRACT_DELEGATE")
		}
	}
	var total int64
	for _, r := range d.Slots {
		found := false
		for _, n := range d.Notaries {
			if r.Notary == n.Name {
				found = true
			}
		}
		if !nameRE.MatchString(r.Executor) || r.Executor == c.LandlordName || !key(r.Grantee) || r.Cap > MaxMoney || !found {
			return fail("CONTRACT_DELEGATE")
		}
		total += r.Cap // At most 16 * MaxMoney, strictly within int64.
	}
	if total > d.Budget {
		return fail("CONTRACT_DELEGATE")
	}
	// D12 is unconditional for profile /2; there is no spend-profile switch.
	if contains(d.Actions, "spend") {
		return fail("CONTRACT_DELEGATE")
	}
	return c, d, nil
}
