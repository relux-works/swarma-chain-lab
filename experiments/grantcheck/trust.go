package grantcheck

import (
	"encoding/json"

	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck/internal/trustcontract"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// trustTerms judges the contract bytes of a grant under the trust profile.
// The caller has already checked the presentation, its signatures and the
// grant against the configured binding. terms and lookup are what
// Config.Terms returned for the grant's contract_sha256.
//
// It applies LIP-0013 section 2.5 with the reader of both profiles (LIP-0014
// sections 3.1 and 3.2) and maps each refusal to the closed code set:
//
//   - the hash, and every rule that judges the document alone (encoding,
//     profile string, field, actions, repositories, budget, note, parent and
//     delegate): terms_invalid;
//   - every comparison of a valid document with the grant (the common fields,
//     the derived scope, the budget and the consent tags): binding_mismatch.
//
// For profile /2 it then admits a root at depth 0 only. A right of
// re-delegation (depth above 0) and a child (a parent id or an ordinal) are
// valid documents that this checker does not serve: a child needs the
// notary's checks of LIP-0014 section 8, which are not made here. Both
// refuse as terms_invalid.
func trustTerms(g rental.Grant, terms []byte, lookup error) Code {
	// The same pre-hash bound as the pay profile; the profile's own limit of
	// 8192 bytes is rule 1 of the contract and is judged after the hash.
	if lookup != nil || len(terms) == 0 || len(terms) > MaxPresentationBytes {
		return CodeTermsInvalid
	}
	bound, refusal := trustcontract.Bind(terms, trustcontract.Grant{
		Network: g.Network, AgentName: g.AgentName, LandlordName: g.LandlordName, GranteeKey: g.GranteeKey,
		ContractSHA256: g.ContractSHA256, Scope: g.Scope, Budget: g.BudgetSat(),
		NotBefore: g.NotBefore, NotAfter: g.NotAfter, ConsentTags: g.Consent.ConsentEvent.Tags,
	})
	switch refusal {
	case "":
	case "CONTRACT_MISMATCH", "SCOPE_MISMATCH", "BUDGET_MISMATCH", "CONSENT_TAGS":
		return CodeBindingMismatch
	default:
		return CodeTermsInvalid
	}
	if bound.DelegateDepth != 0 {
		return CodeTermsInvalid
	}
	if bound.ParentGrantID != "" || bound.Ordinal != 0 {
		return CodeTermsInvalid
	}
	// G1.0 has no gate that resolves and checks scope text (owner decision).
	if bound.ScopeTextSHA256 != "" {
		return CodeTermsInvalid
	}
	return CodeLive
}

// landlordHolders reports whether a name_show answer carries a landlord
// binding with a member named holders, empty or populated (LIP-0010 section
// 10). It decides nothing else: every other departure from the legacy value
// is left to the kernel's strict reader of the legacy shape.
func landlordHolders(shown json.RawMessage) bool {
	var answer struct {
		Value string `json:"value"`
	}
	if len(shown) > 1<<20 || json.Unmarshal(shown, &answer) != nil {
		return false
	}
	var value struct {
		Swarma struct {
			Landlord map[string]json.RawMessage `json:"landlord"`
		} `json:"swarma"`
	}
	if json.Unmarshal([]byte(answer.Value), &value) != nil {
		return false
	}
	_, present := value.Swarma.Landlord["holders"]
	return present
}
