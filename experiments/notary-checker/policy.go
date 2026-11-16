package notarycheck

// MVPPairOwnedNotary explicitly selects a local MVP deployment exception.
// The absent mode retains the strict specification reading.
const MVPPairOwnedNotary = "mvp-pair-owned-notary"

// modeApproved resolves identities from the chain, never from operator policy.
// Signatures bind the exact policy plus ordered owner/name/registration claims.
func modeApproved(p Policy, in Input) error {
	approvals := p.ModeApprovals
	if in.Names == nil {
		return refuse("MVP_CHAIN_READ_REQUIRED")
	}
	if len(approvals) != 2 || approvals[0].Owner >= approvals[1].Owner {
		return refuse("MVP_MODE_APPROVAL_REQUIRED")
	}
	if approvals[0].Name == approvals[1].Name {
		return refuse("MVP_OWNER_NAME_REUSED")
	}
	if approvals[0].Registration == approvals[1].Registration {
		return refuse("MVP_OWNER_REGISTRATION_REUSED")
	}
	var st Statement
	if !decode(in.Statement, &st, 8192) || st.TipHeight < 0 || !ishex(st.TipHash, 64) {
		return refuse("STATEMENT_FIELD")
	}
	p.ModeApprovals = nil
	identities := make([]struct {
		Owner        string `json:"owner"`
		Name         string `json:"name"`
		Registration Point  `json:"registration"`
	}, 0, 2)
	for _, a := range approvals {
		identities = append(identities, struct {
			Owner        string `json:"owner"`
			Name         string `json:"name"`
			Registration Point  `json:"registration"`
		}{a.Owner, a.Name, a.Registration})
	}
	digest := tagged("swarma-notary-local-policy-v1", append(canonical(p), canonical(identities)...))
	for _, a := range approvals {
		if (a.Owner != p.IssuerOwner && a.Owner != p.DelegatorOwner) || !owner(a.Owner) || !nameRE.MatchString(a.Name) || !ishex(a.Registration.TxID, 64) {
			return refuse("MVP_MODE_APPROVAL_REQUIRED")
		}
		observation, e := in.Names.Lookup(a.Name, st.TipHeight, st.TipHash)
		if e != nil {
			if e == Refusal("MVP_CHAIN_READ_REQUIRED") || e == Refusal("NODE_RPC_FAILURE") || e == Refusal("NODE_TIP_MISMATCH") || e == Refusal("NODE_NETWORK") || e == Refusal("NODE_NAME_UNREGISTERED") || e == Refusal("NODE_NAME_VALUE") || e == Refusal("NODE_NAME_HISTORY") {
				return e
			}
			return refuse("MVP_NAME_UNREADABLE")
		}
		if observation.Height != st.TipHeight || observation.BlockHash != st.TipHash {
			return refuse("MVP_NAME_VIEW_MISMATCH")
		}
		if observation.Registration != a.Registration {
			return refuse("MVP_NAME_REGISTRATION_MISMATCH")
		}
		k, e := grantKey(observation.Value)
		if e != nil {
			return refuse("MVP_NAME_VALUE")
		}
		if !signature(k, digest, a.Signature) {
			return refuse("MVP_MODE_APPROVAL_REQUIRED")
		}
	}
	return nil
}
