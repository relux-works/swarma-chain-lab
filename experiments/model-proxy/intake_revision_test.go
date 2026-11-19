package modelproxy

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

// Claim: exact metering fields reserve the provider-visible values; ASCII and
// Unicode case aliases, escaped keys and duplicates refuse without spending.
func TestIntakeMeterExactKeys(t *testing.T) {
	for _, key := range []string{"model", "Model", "MODEL", "mOdEl", "max_tokens", "Max_Tokens", "MAX_TOKENS", "max_tokenſ", "max_toKens", "maX_toKenS", "stream", "Stream", "ſtream", "Speed", "Inference_Geo", "Tools", "Service_Tier"} {
		t.Run(key, func(t *testing.T) {
			h := dailyFixture(t, 1000)
			canonical := key == "model" || key == "max_tokens" || key == "stream"
			body := fmt.Sprintf(`{"model":%q,"max_tokens":10}`, modelID)
			if !canonical {
				value := `1`
				if strings.EqualFold(key, "model") {
					value = fmt.Sprintf("%q", modelID)
				}
				if strings.EqualFold(key, "stream") {
					value = "false"
				}
				body = strings.TrimSuffix(body, "}") + fmt.Sprintf(",%q:%s}", key, value)
			}
			err := h.s.ReserveGeneration([]byte(body))
			if canonical {
				if err != nil {
					t.Fatal("canonical control refused")
				}
				assertDaily(t, h, 1000, 230)
			} else {
				if err == nil || err.Error() != "REQUEST" {
					t.Fatal("case alias did not refuse as REQUEST")
				}
				assertDaily(t, h, 1000, 0)
			}
		})
	}
	for _, body := range []string{
		fmt.Sprintf(`{"model":"unlisted","Model":%q,"max_tokens":1}`, modelID),
		fmt.Sprintf(`{"model":%q,"max_tokens":101,"MAX_TOKENS":1}`, modelID),
		fmt.Sprintf(`{"model":%q,"max_tokens":10,"max_tokens":1}`, modelID),
		fmt.Sprintf(`{"mo\u0064el":%q,"max_tokens":10}`, modelID),
	} {
		h := dailyFixture(t, 1000)
		if err := h.s.ReserveGeneration([]byte(body)); err == nil || err.Error() != "REQUEST" {
			t.Fatal("ambiguous metering witness admitted")
		}
		assertDaily(t, h, 1000, 0)
	}
}

// Claim: input-cache and geographic premiums are rounded up on full context
// input plus declared maximum output; unpriced features never reserve or forward.
// Mixed breakpoints repeat both ceiling neighbors across map traversal orders;
// the 1h maximum must win over default and 5m regardless of its placement.
func TestIntakeWorstCaseExposure(t *testing.T) {
	for _, sample := range []struct {
		name, extra string
		cost        uint64
	}{
		{"base", ``, 230},
		{"standard", `,"speed":"standard","inference_geo":"global"`, 230},
		{"custom-tool", `,"tools":[{"name":"local","input_schema":{"type":"object"}}]`, 230},
		{"custom-tool-schema", `,"tools":[{"name":"local","input_schema":{"type":"object","properties":{"cache_control":{"type":"object"}}}}]`, 230},
		{"custom-tool-input", `,"messages":[{"content":[{"type":"tool_use","input":{"cache_control":{"arbitrary":"application data"}}}]}]`, 230},
		{"cache-default", `,"cache_control":{"type":"ephemeral"}`, 280},
		{"cache-5m", `,"system":[{"type":"text","text":"x","cache_control":{"type":"ephemeral","ttl":"5m"}}]`, 280},
		{"cache-1h", `,"cache_control":{"type":"ephemeral","ttl":"1h"}`, 430},
		{"cache-global", `,"system":[{"type":"text","text":"x","cache_control":{"type":"ephemeral","scope":"global"}}]`, 280},
		{"cache-global-5m", `,"system":[{"type":"text","text":"x","cache_control":{"type":"ephemeral","scope":"global","ttl":"5m"}}]`, 280},
		{"cache-global-1h", `,"system":[{"type":"text","text":"x","cache_control":{"type":"ephemeral","scope":"global","ttl":"1h"}}]`, 430},
		{"cache-mixed", `,"system":[{"type":"text","text":"x","cache_control":{"type":"ephemeral","ttl":"1h"}}],"messages":[{"role":"user","content":[{"type":"text","text":"x","cache_control":{"type":"ephemeral","ttl":"5m"}}]}],"tools":[{"name":"local","input_schema":{"type":"object"},"cache_control":{"type":"ephemeral"}}]`, 430},
		{"cache-mixed-reversed", `,"system":[{"type":"text","text":"x","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":[{"type":"text","text":"x","cache_control":{"type":"ephemeral","ttl":"5m"}}]}],"tools":[{"name":"local","input_schema":{"type":"object"},"cache_control":{"type":"ephemeral","scope":"global","ttl":"1h"}}]`, 430},
		{"geo", `,"inference_geo":"us"`, 253},
		{"cache-geo", `,"inference_geo":"us","messages":[{"content":[{"cache_control":{"type":"ephemeral","ttl":"1h"}}]}]`, 473},
		{"cache-rounding", `,"inference_geo":"us","cache_control":{"type":"ephemeral","ttl":"5m"}`, 308},
		{"fast", `,"speed":"fast"`, 0},
		{"server-tool", `,"tools":[{"type":"web_search_20250305","name":"web_search"}]`, 0},
		{"unknown-tool", `,"tools":[{"type":"future_tool"}]`, 0},
		{"tool-type-alias", `,"tools":[{"Type":"custom","name":"local","input_schema":{"type":"object"}}]`, 0},
		{"custom-type", `,"tools":[{"type":"custom","name":"local","input_schema":{"type":"object"}}]`, 230},
		{"geo-unknown", `,"inference_geo":"future"`, 0},
		{"ttl-unknown", `,"cache_control":{"type":"ephemeral","ttl":"2h"}`, 0},
		{"cache-alias", `,"Cache_Control":{"type":"ephemeral","ttl":"1h"}`, 0},
		{"scope-unknown", `,"cache_control":{"type":"ephemeral","scope":"other"}`, 0},
		{"scope-case", `,"cache_control":{"type":"ephemeral","scope":"Global"}`, 0},
		{"scope-alias", `,"cache_control":{"type":"ephemeral","Scope":"global"}`, 0},
		{"scope-null", `,"cache_control":{"type":"ephemeral","scope":null}`, 0},
		{"scope-object", `,"cache_control":{"type":"ephemeral","scope":{"value":"global"}}`, 0},
		{"scope-member", `,"cache_control":{"type":"ephemeral","scope":"global","future":true}`, 0},
		{"tier", `,"service_tier":"priority"`, 0},
	} {
		t.Run(sample.name, func(t *testing.T) {
			body := []byte(fmt.Sprintf(`{"model":%q,"max_tokens":10%s}`, modelID, sample.extra))
			if sample.cost == 0 {
				h := dailyFixture(t, 1000)
				if err := h.s.ReserveGeneration(body); err == nil || err.Error() != "PRICING" {
					t.Fatal("unpriced modifier admitted")
				}
				assertDaily(t, h, 1000, 0)
				return
			}
			trials := 1
			if strings.HasPrefix(sample.name, "cache-mixed") {
				trials = 64
			}
			for trial := 0; trial < trials; trial++ {
				for _, below := range []bool{false, true} {
					ceiling := sample.cost
					if below {
						ceiling--
					}
					h := dailyFixture(t, ceiling)
					err := h.s.ReserveGeneration(body)
					if below {
						if err == nil || err.Error() != "DAILY_COST_CEILING" {
							t.Fatal("daily budget mismatch: modifier escaped worst-case ceiling")
						}
						assertDaily(t, h, ceiling, 0)
					} else {
						if err != nil {
							t.Fatal("priced modifier control refused")
						}
						h.reopen(t)
						assertDaily(t, h, ceiling, sample.cost)
					}
				}
			}
		})
	}
	if cost, valid := roundedRate(1, 13750); !valid || cost != 2 {
		t.Fatal("fractional nano-unit rounded down")
	}
	if _, valid := roundedRate(math.MaxUint64, 22000); valid {
		t.Fatal("overflowed modifier price accepted")
	}
}

// Claim: bounded parser structure accepts a nearby ordinary array, but cannot
// allocate an unbounded object inventory within a provider-sized byte body.
func TestIntakeJSONStructureBound(t *testing.T) {
	for _, count := range []int{100, 65536} {
		h := dailyFixture(t, 1000)
		body := fmt.Sprintf(`{"model":%q,"max_tokens":10,"messages":[%s0]}`, modelID, strings.Repeat("0,", count))
		err := h.s.ReserveGeneration([]byte(body))
		if count == 100 && err != nil {
			t.Fatal("bounded structure control refused")
		}
		if count == 65536 && (err == nil || err.Error() != "REQUEST") {
			t.Fatal("excessive JSON structure admitted")
		}
	}
}

// Claim: fractional output cost is rounded upward before admission and durable
// save; the exact 224-unit bound works and one nano-unit less refuses unchanged.
func TestIntakePriceRounding(t *testing.T) {
	for _, ceiling := range []uint64{224, 223} {
		h := dailyFixture(t, ceiling)
		body := []byte(fmt.Sprintf(`{"model":%q,"max_tokens":1,"inference_geo":"us"}`, modelID))
		err := h.s.ReserveGeneration(body)
		if ceiling == 224 {
			if err != nil {
				t.Fatal("rounded-cost control refused")
			}
			assertDaily(t, h, ceiling, 224)
		} else {
			if err == nil || err.Error() != "DAILY_COST_CEILING" {
				t.Fatal("fractional exposure escaped ceiling")
			}
			assertDaily(t, h, ceiling, 0)
		}
	}
}
