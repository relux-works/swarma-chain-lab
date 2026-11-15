package notarycheck

// MVPPairOwnedNotary explicitly selects a local MVP deployment exception.
// The absent mode retains the strict specification reading.
const MVPPairOwnedNotary = "mvp-pair-owned-notary"

// modeApproved authenticates both distinct configured owners over the complete
// canonical policy with only mode_approvals omitted. This binds the mode, both
// recomputed grant IDs, both owner identifiers, notary name/pin and agreed_by.
// It proves signatures under configured keys, not real-world affiliations.
func modeApproved(p Policy) bool {
	approvals := p.ModeApprovals
	if len(approvals) != 2 || approvals[0].Owner >= approvals[1].Owner {
		return false
	}
	p.ModeApprovals = nil
	digest := tagged("swarma-notary-local-policy-v1", canonical(p))
	for _, a := range approvals {
		if (a.Owner != p.IssuerOwner && a.Owner != p.DelegatorOwner) || !owner(a.Owner) || !signature(a.Owner[2:], digest, a.Signature) {
			return false
		}
	}
	return true
}
