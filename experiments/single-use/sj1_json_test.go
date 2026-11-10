package singleuse

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
			if err := StrictInput([]byte(raw), &out); err == nil {
				t.Fatal("SJ1 ambiguous key admitted")
			}
			if string(out.Grant) != `{"retained":true}` || out.Note != "retained" {
				t.Fatal("SJ1 rejected input mutated destination")
			}
			raw = valid
			out = wire{}
			if err := StrictInput([]byte(raw), &out); err != nil || string(out.Grant) != `{"version":3}` || out.Note != "line\nvalue" {
				t.Fatalf("valid neighbor: %v", err)
			}
		})
	}
}

// Map values retain the declared schema: encoding/json case aliases cannot
// change a nested authority field. Any spelling refusal leaves output untouched.
func TestSJ1TypedMapKeys(t *testing.T) {
	type grant struct {
		Budget int `json:"budget"`
	}
	type config struct {
		Grants map[string]grant `json:"grants"`
	}
	for _, raw := range []string{`{"grants":{"owner":{"Budget":3}}}`, `{"Grants":{"owner":{"budget":3}}}`, `{"grants":{"owner":{"b\u0075dget":3}}}`} {
		out := config{Grants: map[string]grant{"retained": {Budget: 7}}}
		if e := StrictInput([]byte(raw), &out); e == nil {
			t.Fatal("SJ1 typed key alias admitted")
		}
		if len(out.Grants) != 1 || out.Grants["retained"].Budget != 7 {
			t.Fatal("SJ1 schema refusal mutated destination")
		}
		if e := StrictInput([]byte(`{"grants":{"owner":{"budget":3}}}`), &out); e != nil || out.Grants["owner"].Budget != 3 {
			t.Fatal("valid map neighbor", e)
		}
	}
}
