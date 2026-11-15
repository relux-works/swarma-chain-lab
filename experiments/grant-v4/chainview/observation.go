package chainview

// Tip compares a stated active-chain hash and height, without interpreting a
// hash string as proof that the node has validated it.
type Tip struct {
	Height int64  `json:"height"`
	Hash   string `json:"hash"`
}

func (t Tip) valid() bool { return t.Height >= 0 && t.Hash != "" }

// Observation contains endpoint reads, plus any independently established
// intermediate movement. Equal endpoints alone cannot establish a snapshot.
type Observation struct {
	GenesisHash       string
	FirstTip, LastTip Tip
	TipBeforeEffect   *Tip
	MovementObserved  bool
}

func CheckObservation(pinnedGenesis string, o Observation) Code {
	if pinnedGenesis == "" || o.GenesisHash != pinnedGenesis {
		return ObservationChain
	}
	if !o.FirstTip.valid() || !o.LastTip.valid() || o.FirstTip != o.LastTip || o.MovementObserved {
		return ObservationVoid
	}
	if o.TipBeforeEffect != nil && *o.TipBeforeEffect != o.FirstTip {
		return ObservationVoid
	}
	return ""
}

// BlockOnChain requires a known, nonempty hash at a nonnegative height no higher
// than the observed tip. A known orphan is not an active-chain block.
func BlockOnChain(tipHeight int64, chain map[int64]string, height *int64, hash string) bool {
	return height != nil && *height >= 0 && *height <= tipHeight && hash != "" && chain[*height] == hash
}

func FactBelongs(tipHeight int64, chain map[int64]string, height *int64, hash string, holdsTransaction bool) bool {
	return holdsTransaction && BlockOnChain(tipHeight, chain, height, hash)
}
