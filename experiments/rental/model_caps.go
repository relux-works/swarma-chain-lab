package rental

// ModelCaps independently decodes the signed booking extension. Keep the wire
// field order identical to its producer; legacy contracts omit the whole field.
type ModelCaps struct {
	InputTokens            uint64 `json:"input_tokens"`
	OutputTokens           uint64 `json:"output_tokens"`
	Requests               uint64 `json:"requests"`
	MaxTokens              uint64 `json:"max_tokens"`
	CostNanoUSD            uint64 `json:"cost_nano_usd"`
	DefaultMaxOutputTokens uint64 `json:"default_max_output_tokens"`
}

func (c ModelCaps) valid() bool {
	for _, n := range []uint64{c.InputTokens, c.OutputTokens, c.Requests, c.MaxTokens, c.CostNanoUSD, c.DefaultMaxOutputTokens} {
		if n == 0 || n > (1<<53)-1 {
			return false
		}
	}
	return c.DefaultMaxOutputTokens <= c.MaxTokens && c.MaxTokens <= c.OutputTokens
}
