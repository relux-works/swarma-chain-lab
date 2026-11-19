package modelproxy

import (
	"encoding/json"
	"strings"
)

func (s *Service) ReserveGeneration(body []byte) error {
	fields, err := object(body)
	if err != nil {
		return fail("REQUEST")
	}
	for key := range fields {
		for _, canonical := range []string{"model", "max_tokens", "stream", "speed", "inference_geo", "tools", "service_tier"} {
			if key != canonical && strings.EqualFold(key, canonical) {
				return fail("REQUEST")
			}
		}
	}
	modelID, validModel := str(fields["model"])
	maxTokens, validTokens := integer(fields["max_tokens"])
	if !validModel || !validTokens {
		return fail("REQUEST")
	}
	if stream, present := fields["stream"]; present && string(stream) != "true" && string(stream) != "false" {
		return fail("REQUEST")
	}
	inputRate, outputRate, validPricing := intakeRates(fields)
	if !validPricing {
		return fail("PRICING")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.clock(); err != nil {
		return err
	}
	model, allowed := s.cfg.Models[modelID]
	if !allowed {
		return fail("MODEL")
	}
	if maxTokens == 0 || maxTokens > model.ContextTokens {
		return fail("CAP")
	}
	input, validInput := mul(model.InputNanoUSD, model.ContextTokens)
	output, validOutput := mul(model.OutputNanoUSD, maxTokens)
	input, scaledInput := roundedRate(input, inputRate)
	output, scaledOutput := roundedRate(output, outputRate)
	cost, valid := add(input, output)
	next, fits := add(s.state.Daily.Committed, cost)
	if !validInput || !validOutput || !scaledInput || !scaledOutput || !valid || !fits || next > s.cfg.DailyCostCeilingNanoUSD {
		return fail("DAILY_COST_CEILING")
	}
	s.state.Daily.Committed = next
	return s.save()
}

func roundedRate(cost, basisPoints uint64) (uint64, bool) {
	scaled, valid := mul(cost, basisPoints)
	rounded, fits := add(scaled, 9999)
	return rounded / 10000, valid && fits
}

func intakeRates(fields map[string]json.RawMessage) (uint64, uint64, bool) {
	for key, allowed := range map[string]string{"speed": "standard", "service_tier": "standard_only"} {
		if raw, present := fields[key]; present {
			value, valid := str(raw)
			if !valid || value != allowed {
				return 0, 0, false
			}
		}
	}
	geoRate := uint64(100)
	if raw, present := fields["inference_geo"]; present {
		geo, valid := str(raw)
		if !valid || geo != "global" && geo != "us" {
			return 0, 0, false
		}
		if geo == "us" {
			geoRate = 110
		}
	}
	if raw, present := fields["tools"]; present {
		var tools []map[string]json.RawMessage
		if json.Unmarshal(raw, &tools) != nil {
			return 0, 0, false
		}
		for _, tool := range tools {
			for key, rawType := range tool {
				if strings.EqualFold(key, "type") {
					kind, valid := str(rawType)
					if key != "type" || !valid || kind != "custom" {
						return 0, 0, false
					}
				}
			}
		}
	}
	cacheRate := uint64(100)
	var inspect func(any) bool
	inspect = func(value any) bool {
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				if key == "input_schema" || key == "input" {
					continue
				}
				if strings.EqualFold(key, "cache_control") {
					control, valid := child.(map[string]any)
					if key != "cache_control" || !valid || control["type"] != "ephemeral" {
						return false
					}
					for field := range control {
						if field != "type" && field != "ttl" && field != "scope" {
							return false
						}
					}
					if scope, present := control["scope"]; present && scope != "global" {
						return false
					}
					rate := uint64(125)
					if ttl, present := control["ttl"]; present {
						if ttl != "5m" && ttl != "1h" {
							return false
						}
						if ttl == "1h" {
							rate = 200
						}
					}
					if rate > cacheRate {
						cacheRate = rate
					}
				} else if !inspect(child) {
					return false
				}
			}
		case []any:
			for _, child := range value {
				if !inspect(child) {
					return false
				}
			}
		}
		return true
	}
	root := map[string]any{}
	for key, raw := range fields {
		var value any
		if json.Unmarshal(raw, &value) != nil {
			return 0, 0, false
		}
		root[key] = value
	}
	if !inspect(root) {
		return 0, 0, false
	}
	return cacheRate * geoRate, geoRate * 100, true
}
