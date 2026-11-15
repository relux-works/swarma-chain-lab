package identity

import "errors"

// Liveness is the outcome of O5.1. The zero value is Expired, so a check
// that was never made does not pass as live.
type Liveness int

const (
	// Expired: H >= h + D.
	Expired Liveness = iota
	// Live: H < h + D.
	Live
)

func (l Liveness) String() string {
	if l == Live {
		return "live"
	}
	return "expired"
}

// ErrLiveInput reports stated heights that O5.1 cannot compare: a negative
// height, a depth below one, or a block below the one that holds the output.
var ErrLiveInput = errors.New("identity: heights cannot be compared for a live name")

// CheckLive applies O5.1: a name whose current output is confirmed at height
// confirmedAt is live at the block of height height when
// height < confirmedAt + depth, and expired at height = confirmedAt + depth
// and above. depth is the expiration depth that the consensus rules of the
// chain give for height; it is the caller's, and this module carries no
// production value of it.
func CheckLive(confirmedAt, height, depth int64) (Liveness, error) {
	if confirmedAt < 0 || height < confirmedAt || depth < 1 {
		return Expired, ErrLiveInput
	}
	// height - confirmedAt cannot overflow: both are non-negative.
	if height-confirmedAt < depth {
		return Live, nil
	}
	return Expired, nil
}
