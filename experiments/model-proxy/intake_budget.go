package modelproxy

import "encoding/json"

func (s *Service) ReserveGeneration(body []byte) error {
	var request struct {
		Model     string `json:"model"`
		MaxTokens uint64 `json:"max_tokens"`
	}
	if unique(body) != nil || json.Unmarshal(body, &request) != nil {
		return fail("REQUEST")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.clock(); err != nil {
		return err
	}
	model, allowed := s.cfg.Models[request.Model]
	if !allowed {
		return fail("MODEL")
	}
	if request.MaxTokens == 0 || request.MaxTokens > model.ContextTokens {
		return fail("CAP")
	}
	cost, valid := price(model, Usage{Input: model.ContextTokens, Output: request.MaxTokens})
	next, fits := add(s.state.Daily.Committed, cost)
	if !valid || !fits || next > s.cfg.DailyCostCeilingNanoUSD {
		return fail("DAILY_COST_CEILING")
	}
	s.state.Daily.Committed = next
	return s.save()
}
