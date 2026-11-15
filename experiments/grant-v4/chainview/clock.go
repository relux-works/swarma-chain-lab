package chainview

import "errors"

// ActionClass is an input from a service's action profile, not a request field.
type ActionClass string

const (
	MoneyOrIrreversible ActionClass = "money or irreversible"
	OtherPrivileged     ActionClass = "other privileged"
)

// Parameters have no production defaults. The vector file supplies test values.
type Parameters struct {
	PinnedGenesis                    string
	SkewSeconds, LagBlocks, KBlocks  int64
	MoneyAgeSeconds, OtherAgeSeconds int64
}

func (p Parameters) validate() error {
	if p.PinnedGenesis == "" || p.SkewSeconds < 0 || p.LagBlocks < 0 || p.KBlocks < 0 ||
		p.MoneyAgeSeconds <= 0 || p.OtherAgeSeconds <= 0 {
		return errors.New("explicit nonnegative bounds and positive age cutoffs required")
	}
	return nil
}

// CheckClock measures max(header age, seen age) after checking rollback and
// skew. Times are nonnegative whole UTC seconds; unknown classes fail closed
// as the first class. A future first sight is inconsistent kept state.
func CheckClock(p Parameters, now, keptMark, headerTime, firstSight int64, class ActionClass) Code {
	if p.validate() != nil || now < 0 || keptMark < 0 || headerTime < 0 || firstSight < 0 ||
		now < keptMark || now < firstSight || (headerTime > now && headerTime-now > p.SkewSeconds) {
		return ObservationClock
	}
	age := max(now-min(now, headerTime), now-firstSight)
	cutoff := p.MoneyAgeSeconds
	if class == OtherPrivileged {
		cutoff = p.OtherAgeSeconds
	}
	if age >= cutoff {
		return TipAge
	}
	return ""
}

// ClockInput is one already read observation and its independently computed
// profile findings. Clock processing never creates node-health facts. Findings
// must be codes of this profile; unrelated grant failures belong to their own
// caller, before it treats the clock result as admission.
type ClockInput struct {
	TipHash         string
	Now, HeaderTime int64
	Class           ActionClass
	Findings        []Code
}

// Clock owns no closure journal. A passing result is only a conditional decision
// on stated facts. Store errors return no passing result.
type Clock struct {
	parameters Parameters
	store      ClockStore
}

func NewClock(p Parameters, store ClockStore) (*Clock, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("clock store required")
	}
	return &Clock{p, store}, nil
}

// Observe durably records a first sight on every coherent pinned observation
// whose clock is at or above the mark, including one refused by health or skew.
// The mark advances for a new sight or a passing decision, not other refusals.
func (c *Clock) Observe(in ClockInput) (Code, error) {
	if in.TipHash == "" || in.Now < 0 || in.HeaderTime < 0 {
		return "", errors.New("invalid stated clock input")
	}
	finding, err := FirstRefusal(in.Findings...)
	if err != nil {
		return "", err
	}
	var result Code
	err = c.store.Transact(func(state *ClockState) error {
		if in.Now < state.KeptMark {
			result = first(finding, ObservationClock)
			return nil
		}
		if finding == ObservationChain || finding == ObservationVoid {
			result = finding
			return nil
		}
		f, known := state.FirstSights[in.TipHash]
		if !known {
			f = in.Now
			state.FirstSights[in.TipHash] = f
			state.KeptMark = max(state.KeptMark, in.Now)
		}
		result = first(finding, CheckClock(c.parameters, in.Now, state.KeptMark, in.HeaderTime, f, in.Class))
		if result == "" {
			state.KeptMark = max(state.KeptMark, in.Now)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return result, nil
}
