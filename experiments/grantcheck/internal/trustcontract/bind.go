package trustcontract

import (
	"bytes"
	"encoding/json"
	"slices"
)

// Grant is the projection of a v3 grant that both profiles bind to
// (LIP-0013 section 2.5). Budget is the v3 budget value: an absent budget
// is 0. ConsentTags are the tags of the grant's consent event.
type Grant struct {
	Network        string     `json:"network"`
	AgentName      string     `json:"agent_name"`
	LandlordName   string     `json:"landlord_name"`
	GranteeKey     string     `json:"grantee_key"`
	ContractSHA256 string     `json:"contract_sha256"`
	Scope          []string   `json:"scope"`
	Budget         int64      `json:"budget"`
	NotBefore      int64      `json:"not_before"`
	NotAfter       int64      `json:"not_after"`
	ConsentTags    [][]string `json:"consent_tags"`
}

// Terms is what a valid contract of either profile states. The last four
// members are those of profile /2; for profile /1 they hold the values of a
// root without a right of re-delegation: "", "", 0 and 0.
type Terms struct {
	Profile         string
	Network         string
	LandlordName    string
	AgentName       string
	GranteeKey      string
	Actions         []string
	Repos           []string
	SpendBudget     int64
	NotBefore       int64
	NotAfter        int64
	ScopeTextSHA256 string
	ParentGrantID   string
	Ordinal         int64
	DelegateDepth   int64
}

// membersV1 and membersV2 are the two member sets of LIP-0014 section 3.1,
// in their order.
var membersV1 = []string{"profile", "network", "landlord_name", "agent_name", "grantee_key", "actions", "repos", "spend_budget", "not_before", "not_after", "note"}
var membersV2 = []string{"profile", "network", "landlord_name", "agent_name", "grantee_key", "actions", "repos", "spend_budget", "not_before", "not_after", "scope_text_sha256", "parent_grant_id", "ordinal", "delegate", "note"}

// memberNames returns the member names of a top-level JSON object in the
// order of the bytes, repeated names included. It judges no value.
func memberNames(raw []byte) ([]string, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if first, err := dec.Token(); err != nil || first != json.Delim('{') {
		return nil, false
	}
	names := []string{}
	for dec.More() {
		token, err := dec.Token()
		name, ok := token.(string)
		if err != nil || !ok || len(names) == len(membersV2) {
			return nil, false
		}
		names = append(names, name)
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return nil, false
		}
	}
	return names, true
}

// Parse is the reader of LIP-0014 section 3.1 that supports both profiles.
// The member set of the object selects the rules before any value is judged:
// the eleven members of LIP-0013 select profile /1, the fifteen of LIP-0014
// select profile /2, and any other set or order refuses as CONTRACT_ENCODING.
// The profile string never selects: it is judged by rule 2 of the selected
// rules. Parse returns the first refusal code, or "" for a valid contract.
func Parse(raw []byte) (Terms, string) {
	if len(raw) == 0 || len(raw) > MaxContractBytes {
		return Terms{}, "CONTRACT_ENCODING"
	}
	names, ok := memberNames(raw)
	if ok && slices.Equal(names, membersV1) {
		c, code := ParseV1(raw)
		if code != "" {
			return Terms{}, code
		}
		return Terms{Profile: ProfileV1, Network: c.Network, LandlordName: c.LandlordName, AgentName: c.AgentName, GranteeKey: c.GranteeKey,
			Actions: c.Actions, Repos: c.Repos, SpendBudget: c.SpendBudget, NotBefore: c.NotBefore, NotAfter: c.NotAfter}, ""
	}
	if ok && slices.Equal(names, membersV2) {
		c, d, code := ParseV2(raw)
		if code != "" {
			return Terms{}, code
		}
		return Terms{Profile: ProfileV2, Network: c.Network, LandlordName: c.LandlordName, AgentName: c.AgentName, GranteeKey: c.GranteeKey,
			Actions: c.Actions, Repos: c.Repos, SpendBudget: c.SpendBudget, NotBefore: c.NotBefore, NotAfter: c.NotAfter,
			ScopeTextSHA256: c.ScopeTextSHA256, ParentGrantID: c.ParentGrantID, Ordinal: c.Ordinal, DelegateDepth: d.Depth}, ""
	}
	return Terms{}, "CONTRACT_ENCODING"
}

// Bind applies LIP-0013 section 2.5 in its order, with the substitution of
// LIP-0014 section 3.2 for check 2: the contract bytes against the grant
// fields. It returns the first refusal code, or "" when the contract binds.
// This is the port of Bind in tools/trustcheck/contract.go, extended to the
// reader of both profiles.
func Bind(raw []byte, g Grant) (Terms, string) {
	if sha256Hex(raw) != g.ContractSHA256 {
		return Terms{}, "CONTRACT_HASH"
	}
	t, code := Parse(raw)
	if code != "" {
		return Terms{}, code
	}
	if t.Network != g.Network || t.AgentName != g.AgentName || t.LandlordName != g.LandlordName ||
		t.GranteeKey != g.GranteeKey || t.NotBefore != g.NotBefore || t.NotAfter != g.NotAfter {
		return Terms{}, "CONTRACT_MISMATCH"
	}
	if g.Scope == nil || !slices.Equal(V3Scope(t.Actions), g.Scope) {
		return Terms{}, "SCOPE_MISMATCH"
	}
	if t.SpendBudget != g.Budget {
		return Terms{}, "BUDGET_MISMATCH"
	}
	if !bytes.Equal(compact(ConsentTags(raw)), compact(g.ConsentTags)) {
		return Terms{}, "CONSENT_TAGS"
	}
	return t, ""
}
