package chainview

import "errors"

// CheckRecent checks the recent block first, then the relative height of an
// already established confirmed anchor. Anchor membership is a separate fact
// check (B1.4); a height alone cannot establish it.
func CheckRecent(tipHeight int64, chain map[int64]string, recentHeight *int64, hash string, anchorHeight, k int64) Code {
	if !BlockOnChain(tipHeight, chain, recentHeight, hash) {
		return RecentBlock
	}
	if k < 0 || anchorHeight <= *recentHeight || anchorHeight > tipHeight || anchorHeight-*recentHeight > k {
		return RecentBlockWindow
	}
	return ""
}

// WindowAllows implements LIP-0008 draft 7.1, which assigns no refusal code.
// The height must come from the same observation as the other facts.
func WindowAllows(recentHeight, notBefore, notAfter, tipHeight int64) bool {
	return recentHeight >= 0 && notBefore >= recentHeight && notBefore < notAfter &&
		notBefore <= tipHeight && tipHeight < notAfter
}

// RecentForIssuance selects exactly the tip of the coherent, healthy issuance
// observation (B4.1). It returns no selected tip on refusal. It does not encode
// the grant member that will commit this hash, or make any node reads.
func RecentForIssuance(p Parameters, o Observation, reading Node, comparisons []Node, chain map[int64]string) (Tip, Code, error) {
	if err := p.validate(); err != nil {
		return Tip{}, "", err
	}
	if reading.Tip != o.FirstTip || reading.GenesisHash != o.GenesisHash {
		return Tip{}, "", errors.New("reading node does not describe the stated observation")
	}
	code := first(CheckObservation(p.PinnedGenesis, o), CheckHealth(p.PinnedGenesis, p.LagBlocks, reading, comparisons, chain))
	if code != "" {
		return Tip{}, code, nil
	}
	return o.FirstTip, "", nil
}
