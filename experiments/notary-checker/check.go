package notarycheck

import (
	"encoding/hex"
)

// Check validates signed octets and local policy, then returns an UNSIGNED
// candidate and its signing digest. It has no direct I/O, signing keys, clock
// or state; MVP calls NameSource for reads at the explicit statement view.
// The caller still owes all online and durable-record obligations in DESIGN.md.
func Check(in Input) (Result, error) {
	fail := func(s string) (Result, error) { return Result{}, refuse(s) }
	if in.At < 1 || in.At > MaxTime {
		return fail("AT_TIME")
	}
	pp, e := readGrant(in.Parent, in.At)
	if e != nil {
		return Result{}, e
	}
	cp, e := readGrant(in.Child, in.At)
	if e != nil {
		return Result{}, e
	}
	p, c := pp.SignedGrant.Grant, cp.SignedGrant.Grant
	pc, pd, e := bind(p, in.ParentContract)
	if e != nil {
		return Result{}, e
	}
	cc, _, e := bind(c, in.ChildContract)
	if e != nil {
		return Result{}, e
	}
	pid, cid := hash(canonical(pp.SignedGrant)), hash(canonical(cp.SignedGrant))
	if cc.ParentGrantID != pid {
		return fail("PARENT_ID_MISMATCH")
	}
	if pc.ParentGrantID != "" || pid == cid {
		return fail("CHAIN_DEPTH")
	}
	if pd.Depth != 1 {
		return fail("NOT_DELEGABLE")
	}
	if p.Network != c.Network || p.Genesis != c.Genesis || p.LandlordName != c.LandlordName || p.IssuerKey != c.IssuerKey {
		return fail("SUBJECT_MISMATCH")
	}
	if !request(in.Request, p, cc, pid, c.ContractSHA256, in.At) {
		return fail("DELEGATION_REQUEST")
	}
	if e := checkRow(pc, pd, cc); e != nil {
		return Result{}, e
	}
	// Conservative J5 policy: differing hashes require human judgement, forbidden
	// in this unit. Never manufacture the attestation value "within".
	if pc.ScopeTextSHA256 != cc.ScopeTextSHA256 {
		return fail("TEXT_JUDGEMENT_REQUIRED")
	}
	if (pc.ScopeTextSHA256 != "" && hash(in.ParentText) != pc.ScopeTextSHA256) || (cc.ScopeTextSHA256 != "" && hash(in.ChildText) != cc.ScopeTextSHA256) || (pc.ScopeTextSHA256 == "" && len(in.ParentText) > 0) || (cc.ScopeTextSHA256 == "" && len(in.ChildText) > 0) {
		return fail("DELEGATION_BUNDLE")
	}
	var policy Policy
	if !decode(in.Policy, &policy, 8192) || policy.ParentGrantID != pid || policy.ChildGrantID != cid || !owner(policy.IssuerOwner) || !owner(policy.DelegatorOwner) || !owner(policy.NotaryOwner) || !sorted(policy.AgreedBy) {
		return fail("OWNER_EVIDENCE_REQUIRED")
	}
	for _, id := range policy.AgreedBy {
		if !owner(id) {
			return fail("OWNER_EVIDENCE_REQUIRED")
		}
	}
	if policy.Mode != "" && policy.Mode != MVPPairOwnedNotary {
		return fail("POLICY_MODE_UNSUPPORTED")
	}
	if policy.Mode == "" && len(policy.ModeApprovals) != 0 {
		return fail("POLICY_MODE_REQUIRED")
	}
	var designated *Notary
	for i := range pd.Notaries {
		if pd.Notaries[i].Name == policy.NotaryName {
			designated = &pd.Notaries[i]
		}
	}
	if designated == nil {
		return fail("NOTARY_NOT_DESIGNATED")
	}
	if designated.Owner != policy.NotaryOwner {
		return fail("NOTARY_NAME_CHANGED")
	}
	if policy.Mode == MVPPairOwnedNotary {
		if policy.IssuerOwner[2:] == policy.DelegatorOwner[2:] {
			return fail("MVP_MODE_PAIR_REQUIRED")
		}
		if e := modeApproved(policy, in); e != nil {
			return Result{}, e
		}
	}
	if policy.IssuerOwner == policy.DelegatorOwner {
		if policy.NotaryOwner != policy.IssuerOwner {
			return fail("NOTARY_OWNER_RELATION")
		}
	} else {
		if (policy.NotaryOwner == policy.IssuerOwner || policy.NotaryOwner == policy.DelegatorOwner) && policy.Mode != MVPPairOwnedNotary {
			return fail("NOTARY_OWNER_RELATION")
		}
		if !contains(policy.AgreedBy, policy.IssuerOwner) || !contains(policy.AgreedBy, policy.DelegatorOwner) {
			return fail("CROSS_OWNER_CERTIFIER_REQUIRED")
		}
	}
	nk, e := notaryKey(in.NotaryValue)
	if e != nil {
		return Result{}, e
	}
	if nk == p.GranteeKey {
		return fail("NOTARY_IS_DELEGATOR")
	}
	if nk == c.GranteeKey {
		return fail("NOTARY_IS_DELEGATEE")
	}
	if policy.NotaryName == p.AgentName || policy.NotaryName == c.AgentName {
		return fail("NOTARY_IS_EXECUTOR")
	}
	var st Statement
	if !decode(in.Statement, &st, 8192) || !ishex(st.NotarySeal.TxID, 64) || st.NotarySeal.Script == "" || len(st.NotarySeal.Script) > 20000 || len(st.NotarySeal.Script)%2 != 0 || !ishex(st.NotarySeal.Script, len(st.NotarySeal.Script)) || !ishex(st.TipHash, 64) {
		return fail("STATEMENT_FIELD")
	}
	text := "none"
	if pc.ScopeTextSHA256 != "" {
		text = "identical"
	}
	a := Attestation{"swarma-notary-attestation/1", "child-within-parent", p.Network, p.Genesis, p.LandlordName, policy.NotaryName, nk, pid, p.ContractSHA256, cid, c.ContractSHA256, cc.Ordinal, text, "pass", st.NotarySeal, st.TipHeight, st.TipHash, in.At}
	raw := canonical(a)
	if len(raw) > MaxAttestationBytes {
		return fail("ATTESTATION_TOO_LARGE")
	}
	return Result{raw, tagged("swarma-notary-v1", raw)}, nil
}

// SignedAttestation checks a returned service signature and assembles the exact
// compact envelope of LIP-0014 section 6.1. It does not certify chain state.
func SignedAttestation(r Result, sig string) ([]byte, string, error) {
	var a Attestation
	if !decode(r.Attestation, &a, MaxAttestationBytes) || r.Digest != tagged("swarma-notary-v1", r.Attestation) || !signature(a.NotaryKey, r.Digest, sig) {
		return nil, "", refuse("ATTESTATION_SIGNATURE")
	}
	envelope := struct {
		Attestation Attestation `json:"attestation"`
		Signature   string      `json:"signature"`
	}{a, sig}
	b := canonical(envelope)
	return b, hash(b), nil
}

// AnchorScript computes the one 72-byte LIP-0005 action-0x04 frame. This is
// construction only; no chain is read and no transaction is broadcast.
func AnchorScript(attestationID, childID, parentID string) ([]byte, error) {
	if !ishex(attestationID, 64) || !ishex(childID, 64) || !ishex(parentID, 64) {
		return nil, refuse("ATTESTATION_BINDING")
	}
	b := []byte("swarma-attest-v1")
	for _, s := range []string{attestationID, childID, parentID} {
		raw, _ := hex.DecodeString(s)
		b = append(b, raw...)
	}
	commitment, _ := hex.DecodeString(hash(b))
	id, _ := hex.DecodeString(attestationID)
	script := []byte{0x6a, 0x03, 0x53, 0x4c, 0x04, 0x42, 0x01}
	script = append(script, commitment...)
	script = append(script, 0x01)
	script = append(script, id...)
	return script, nil
}

// checkRow is the signed-row comparison of LIP-0014 sections 4/8 and
// LIP-0026 R2. No attestation or local policy can override its verdict.
func checkRow(pc Contract, pd Delegate, cc Contract) error {
	if cc.Ordinal < 1 || cc.Ordinal > int64(len(pd.Slots)) {
		return refuse("CHILD_ORDINAL")
	}
	row := pd.Slots[cc.Ordinal-1]
	if cc.AgentName != row.Executor {
		return refuse("CHILD_AGENT_NOT_ALLOWED")
	}
	if cc.GranteeKey != row.Grantee {
		return refuse("CHILD_GRANTEE_NOT_ALLOWED")
	}
	if !subset(cc.Actions, pd.Actions) {
		return refuse("CHILD_ACTIONS_WIDER")
	}
	if !subset(cc.Repos, pc.Repos) {
		return refuse("CHILD_REPOS_WIDER")
	}
	if cc.SpendBudget > row.Cap {
		return refuse("CHILD_BUDGET_OVER")
	}
	if cc.NotBefore < pc.NotBefore || cc.NotAfter > pc.NotAfter {
		return refuse("CHILD_WINDOW_NOT_NESTED")
	}
	return nil
}
