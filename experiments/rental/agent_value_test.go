package rental

import (
	"strings"
	"testing"
)

// The exact LIP name shape round-trips, while spelling, ordering, cardinality,
// JSON and key mutations refuse. Each case retains an unchanged valid neighbor.
// These are codec controls; genuine Core name observation is tested separately.
func TestAgentNameValue(t *testing.T) {
	_, nostr := testKey(3)
	_, grant := testKey(1)
	keys := AgentKeys{Nostr: nostr, Grant: grant}
	good := `{"swarma":{"agent":{"nostr":"` + nostr + `","grant":"` + grant + `"}}}`
	encoded, err := AgentValue(keys)
	if err != nil || encoded != good {
		t.Fatal("encoder does not match the independently specified wire")
	}
	cases := map[string]string{
		"empty":              "",
		"outer-null":         "null",
		"empty-object":       "{}",
		"extra-root":         strings.TrimSuffix(good, "}") + `,"extra":0}`,
		"extra-key":          strings.Replace(good, `"grant":`, `"other":0,"grant":`, 1),
		"missing-grant":      `{"swarma":{"agent":{"nostr":"` + nostr + `"}}}`,
		"missing-nostr":      `{"swarma":{"agent":{"grant":"` + grant + `"}}}`,
		"alias-grant":        strings.Replace(good, `"grant":`, `"issuer":`, 1),
		"folded-grant":       strings.Replace(good, `"grant":`, `"Grant":`, 1),
		"duplicate-grant":    strings.Replace(good, `"grant":`, `"grant":"`+grant+`","grant":`, 1),
		"null-grant":         strings.Replace(good, `"`+grant+`"`, "null", 1),
		"wrong-order":        `{"swarma":{"agent":{"grant":"` + grant + `","nostr":"` + nostr + `"}}}`,
		"space":              good + " ",
		"newline":            good + "\n",
		"escaped-field":      strings.Replace(good, `"grant":`, `"\u0067rant":`, 1),
		"multiple-documents": good + good,
		"invalid-key":        strings.Replace(good, grant, strings.Repeat("f", 64), 1),
		"uppercase-key":      strings.Replace(good, grant, strings.ToUpper(grant), 1),
		"short-key":          strings.Replace(good, grant, grant[:62], 1),
		"oversize":           strings.Repeat(" ", 521),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAgentValue(raw); err == nil || (err.Error() != "AGENT_NAME_VALUE" && err.Error() != "AGENT_NAME_KEY") {
				t.Fatalf("expected name-value/key refusal, got %v", err)
			}
			actual, err := ParseAgentValue(good)
			if err != nil || actual != keys {
				t.Fatalf("valid neighbor rejected: %v", err)
			}
		})
	}
}
