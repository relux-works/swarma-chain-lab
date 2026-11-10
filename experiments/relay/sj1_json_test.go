package relay

import (
	"encoding/json"
	"testing"
)

// The public/local admission guard rejects ambiguous keys before mutating the
// destination, including RawMessage subtrees. This does not exercise RPC effects.
func TestSJ1KeyAdmission(t *testing.T) {
	type wire struct {
		Grant json.RawMessage `json:"grant"`
		Note  string          `json:"note"`
	}
	valid := `{"grant":{"version":3},"note":"line\nvalue"}`
	cases := map[string]string{
		"left-valid":               `{"grant":{"version":3},"grant":{"version":2},"note":"x"}`,
		"right-valid":              `{"grant":{"version":2},"grant":{"version":3},"note":"x"}`,
		"escaped-duplicate":        `{"grant":{"version":3},"gr\u0061nt":{"version":2},"note":"x"}`,
		"escaped-single":           `{"gr\u0061nt":{"version":3},"note":"x"}`,
		"nested-left-valid":        `{"grant":{"version":3,"version":2},"note":"x"}`,
		"nested-right-valid":       `{"grant":{"version":2,"version":3},"note":"x"}`,
		"nested-escaped-duplicate": `{"grant":{"version":3,"vers\u0069on":2},"note":"x"}`,
		"nested-escaped-single":    `{"grant":{"vers\u0069on":3},"note":"x"}`,
		"array-escaped-single":     `{"grant":[{"vers\u0069on":3}],"note":"x"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			out := wire{Grant: json.RawMessage(`{"retained":true}`), Note: "retained"}
			if err := strict([]byte(raw), &out); err == nil {
				t.Fatal("SJ1 ambiguous key admitted")
			}
			if string(out.Grant) != `{"retained":true}` || out.Note != "retained" {
				t.Fatal("SJ1 rejected input mutated destination")
			}
			raw = valid
			out = wire{}
			if err := strict([]byte(raw), &out); err != nil || string(out.Grant) != `{"version":3}` || out.Note != "line\nvalue" {
				t.Fatalf("valid neighbor: %v", err)
			}
		})
	}
}

// The legacy lexical layer is tested independently of the second StrictInput
// layer: its duplicate-removal plant must fail even when that second guard
// remains intact. Null refusal remains legacy policy; single escaped keys are
// refused by StrictInput, not claimed as a property of this older walker.
func TestSJ1LegacyWalker(t *testing.T) {
	for _, raw := range []string{`{"limit":1,"limit":0}`, `{"limit":0,"limit":1}`, `{"limit":1,"l\u0069mit":0}`, `{"x":[{"limit":1,"limit":0}]}`} {
		if e := strictShape([]byte(raw)); e == nil || e.Error() != "JSON" {
			t.Fatal("legacy walker accepted duplicate", e)
		}
		if e := strictShape([]byte(`{"limit":1,"note":"a\nb"}`)); e != nil {
			t.Fatal("valid legacy walker neighbor", e)
		}
	}
	if e := strictShape([]byte(`{"limit":null}`)); e == nil || e.Error() != "JSON" {
		t.Fatal("legacy walker accepted null", e)
	}
}
