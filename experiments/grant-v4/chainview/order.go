// Package chainview evaluates the comparisons proposed by draft LIP-0022 on
// stated facts. It reads no node and grants no authority to perform an effect.
package chainview

import "fmt"

// Code is a single profile refusal. The empty code means these comparisons pass.
type Code string

const (
	ObservationChain  Code = "OBSERVATION_CHAIN"
	ObservationVoid   Code = "OBSERVATION_VOID"
	NodeUnhealthy     Code = "NODE_UNHEALTHY"
	NodeDisagreement  Code = "NODE_DISAGREEMENT"
	ObservationClock  Code = "OBSERVATION_CLOCK"
	TipAge            Code = "TIP_AGE"
	RecentBlock       Code = "RECENT_BLOCK"
	RecentBlockWindow Code = "RECENT_BLOCK_WINDOW"
	Confirmations     Code = "CONFIRMATIONS"
)

var refusalOrder = [...]Code{ObservationChain, ObservationVoid, NodeUnhealthy,
	NodeDisagreement, ObservationClock, TipAge, RecentBlock, RecentBlockWindow, Confirmations}

// FirstRefusal selects one profile finding, irrespective of input order. It is
// not a dispatcher for grant rules: B6.2 leaves those rules at their call sites.
func FirstRefusal(findings ...Code) (Code, error) {
	for _, code := range findings {
		known := code == ""
		for _, candidate := range refusalOrder {
			known = known || code == candidate
		}
		if !known {
			return "", fmt.Errorf("unknown profile finding %q", code)
		}
	}
	for _, candidate := range refusalOrder {
		for _, code := range findings {
			if code == candidate {
				return candidate, nil
			}
		}
	}
	return "", nil
}

func first(findings ...Code) Code {
	code, err := FirstRefusal(findings...)
	if err != nil {
		panic(err)
	} // Only package-defined codes reach this helper.
	return code
}
