package chainview

// Node contains stated answers from one configured source. Endpoint is only
// descriptive: distinct URLs never establish source independence.
type Node struct {
	SourceLabel          string
	Endpoint             string
	Answers              bool
	GenesisHash          string
	InitialBlockDownload bool
	HeadersAboveTip      int64
	Tip                  Tip
}

func healthy(pin string, lag int64, n Node) bool {
	return pin != "" && lag >= 0 && n.Answers && n.GenesisHash == pin &&
		!n.InitialBlockDownload && n.HeadersAboveTip >= 0 && n.HeadersAboveTip <= lag &&
		n.Tip.valid() && n.SourceLabel != ""
}

// CheckHealth examines all configured comparisons. Even a same-source healthy
// conflict counts; unhealthy nodes neither agree nor conflict.
func CheckHealth(pin string, lag int64, reading Node, comparisons []Node, chain map[int64]string) Code {
	if pin == "" || reading.GenesisHash != pin {
		return ObservationChain
	}
	otherHealthy, otherAgrees, conflict := false, false, false
	for _, n := range comparisons {
		if !healthy(pin, lag, n) {
			continue
		}
		independent := n.SourceLabel != reading.SourceLabel
		otherHealthy = otherHealthy || independent
		member := n.Tip.Height <= reading.Tip.Height && n.Tip.Hash != "" && chain[n.Tip.Height] == n.Tip.Hash
		if !member {
			conflict = true
			continue
		}
		if independent && reading.Tip.Height-n.Tip.Height <= lag {
			otherAgrees = true
		}
	}
	if !healthy(pin, lag, reading) || !otherHealthy {
		return NodeUnhealthy
	}
	if conflict || !otherAgrees {
		return NodeDisagreement
	}
	return ""
}
