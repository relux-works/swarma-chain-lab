package booking

import "fmt"

// ModelCaps is part of the renter-signed contract, not an execution hint.
// DefaultMaxOutputTokens is the disclosed default for a future coding profile.
// The current Responses profile still requires an explicit output limit; no
// operator or client may silently substitute a different value after consent.
type ModelCaps struct {
	InputTokens            uint64 `json:"input_tokens"`
	OutputTokens           uint64 `json:"output_tokens"`
	Requests               uint64 `json:"requests"`
	MaxTokens              uint64 `json:"max_tokens"`
	CostNanoUSD            uint64 `json:"cost_nano_usd"`
	DefaultMaxOutputTokens uint64 `json:"default_max_output_tokens"`
}

func (c ModelCaps) Valid() bool {
	// The NIP-07 browser must display every signed integer without rounding.
	for _, n := range []uint64{c.InputTokens, c.OutputTokens, c.Requests, c.MaxTokens, c.CostNanoUSD, c.DefaultMaxOutputTokens} {
		if n == 0 || n > (1<<53)-1 {
			return false
		}
	}
	return c.DefaultMaxOutputTokens <= c.MaxTokens && c.MaxTokens <= c.OutputTokens
}

func EqualModelCaps(a, b *ModelCaps) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Valid() && b.Valid() && *a == *b
}

func copyModelCaps(c *ModelCaps) *ModelCaps {
	if c == nil {
		return nil
	}
	out := *c
	return &out
}

// Text uses the same exact integers included in ContractV2.Bytes and consent.
func (c ModelCaps) Text() string {
	return fmt.Sprintf("Model limits for this rental: %d requests; %d input tokens; %d output tokens; %d nano-USD total cost ceiling; %d output tokens per request. Declared default output limit: %d tokens. The current Responses profile requires an explicit output limit; defaulting is not enabled.", c.Requests, c.InputTokens, c.OutputTokens, c.CostNanoUSD, c.MaxTokens, c.DefaultMaxOutputTokens)
}
