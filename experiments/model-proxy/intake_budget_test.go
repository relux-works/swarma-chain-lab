package modelproxy

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// Claim: only configured models and bounded positive output counts reserve
// durable daily exposure; bad JSON, duplicates and over-ceiling attempts do not.
func TestIntakeDailyAdmission(t *testing.T) {
	for _, scenario := range []string{"valid", "model", "zero", "output", "ceiling", "json", "duplicate"} {
		t.Run(scenario, func(t *testing.T) {
			ceiling := uint64(230)
			if scenario == "ceiling" {
				ceiling = 229
			}
			h := dailyFixture(t, ceiling)
			body := fmt.Sprintf(`{"model":%q,"max_tokens":10,"messages":[]}`, modelID)
			expected := ""
			switch scenario {
			case "model":
				body, expected = `{"model":"unlisted","max_tokens":10}`, "MODEL"
			case "zero":
				body, expected = fmt.Sprintf(`{"model":%q,"max_tokens":0}`, modelID), "CAP"
			case "output":
				body, expected = fmt.Sprintf(`{"model":%q,"max_tokens":101}`, modelID), "CAP"
			case "ceiling":
				expected = "DAILY_COST_CEILING"
			case "json":
				body, expected = "{", "REQUEST"
			case "duplicate":
				body, expected = fmt.Sprintf(`{"model":%q,"max_tokens":10,"max_tokens":1}`, modelID), "REQUEST"
			}
			err := h.s.ReserveGeneration([]byte(body))
			if expected == "" {
				if err != nil {
					t.Fatal("valid intake reservation refused")
				}
				assertDaily(t, h, ceiling, 230)
				h.reopen(t)
				assertDaily(t, h, ceiling, 230)
				if err := h.s.ReserveGeneration([]byte(body)); err == nil || err.Error() != "DAILY_COST_CEILING" {
					t.Fatal("restart bypassed intake ceiling")
				}
			} else {
				if err == nil || err.Error() != expected {
					t.Fatalf("intake refusal: want %s", expected)
				}
				assertDaily(t, h, ceiling, 0)
			}
		})
	}
}

// Claim: parallel intake calls share one durable ceiling, and missing or
// corrupted accounting never silently creates or overwrites a fresh budget.
func TestIntakeDailyConcurrencyAndIntegrity(t *testing.T) {
	h := dailyFixture(t, 230)
	body := []byte(fmt.Sprintf(`{"model":%q,"max_tokens":10}`, modelID))
	var admitted atomic.Int32
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if h.s.ReserveGeneration(body) == nil {
				admitted.Add(1)
			}
		})
	}
	group.Wait()
	if admitted.Load() != 1 {
		t.Fatal("parallel intake overbooked daily exposure")
	}
	assertDaily(t, h, 230, 230)
	for _, missing := range []bool{false, true} {
		isolated := dailyFixture(t, 230)
		path := filepath.Join(isolated.c.StateDir, "registry.json")
		if missing {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
			t.Fatal(err)
		}
		err := isolated.s.ReserveGeneration(body)
		expected := "DAILY_ACCOUNTING_CORRUPT"
		if missing {
			expected = "DAILY_ACCOUNTING_MISSING"
		}
		if err == nil || err.Error() != expected {
			t.Fatal("untrusted intake accounting admitted generation")
		}
	}
}

// Claim: intake and per-slot requests spend the same daily exposure in both
// directions; neither admission route can obtain a second full-cost call.
func TestIntakeSharesSlotBudget(t *testing.T) {
	for _, intakeFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(intakeFirst), func(t *testing.T) {
			h := dailyFixture(t, 230)
			h.response = fullCostReply
			body := []byte(fmt.Sprintf(`{"model":%q,"max_tokens":10}`, modelID))
			if intakeFirst {
				if err := h.s.ReserveGeneration(body); err != nil {
					t.Fatal("first intake reservation refused")
				}
				if response := h.send(request(false)); response.Code != 403 || response.Body.String() != `{"error":"DAILY_COST_CEILING"}` || h.calls.Load() != 0 {
					t.Fatal("slot route bypassed intake exposure")
				}
			} else {
				if response := h.send(request(false)); response.Code != 200 || h.calls.Load() != 1 {
					t.Fatal("first slot reservation refused")
				}
				if err := h.s.ReserveGeneration(body); err == nil || err.Error() != "DAILY_COST_CEILING" {
					t.Fatal("intake route bypassed slot exposure")
				}
			}
			assertDaily(t, h, 230, 230)
		})
	}
}
