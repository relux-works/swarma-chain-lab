package notarycheck

// NameObservation is the current value and registration at one explicit chain
// view. A source must fail rather than substitute its latest or cached view.
type NameObservation struct {
	Registration Point  `json:"registration"`
	Value        []byte `json:"-"`
	Height       int64  `json:"height"`
	BlockHash    string `json:"blockhash"`
}

// NameSource supplies chain reads without coupling the checker to node I/O.
// Offline callers must explicitly label their supplied observations as fixtures.
type NameSource interface {
	Lookup(name string, height int64, blockhash string) (NameObservation, error)
}

// NodeNameReader reserves the running adapter for N3. It has no file, fixture or
// caller-observation fallback. N3 must implement node reads and view validation.
type NodeNameReader struct{}

func (*NodeNameReader) Lookup(string, int64, string) (NameObservation, error) {
	return NameObservation{}, refuse("MVP_CHAIN_READ_REQUIRED")
}

// CheckRunning never accepts an injected fixture or operator-supplied source.
// The strict default needs no name source. MVP refuses until N3 wires the node.
func CheckRunning(in Input) (Result, error) {
	if in.Names != nil {
		return Result{}, refuse("MVP_CHAIN_READ_REQUIRED")
	}
	in.Names = &NodeNameReader{}
	return Check(in)
}
