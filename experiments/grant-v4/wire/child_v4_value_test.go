package wire

import (
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/grant-v4/identity"
)

// The existing pinned LIP-0010 reader distinguishes A from B before F11.
// Each refusal has a valid different-key control; these are caller facts,
// not evidence of node health, provenance, a closure write or ISSUE signing.
func TestChildV4ParentNameValueReader(t *testing.T) {
	for _, vector := range childVectorsV4(t) {
		if vector.ID != "name-valid-neighbour" {
			continue
		}
		parent, child, err := childPairV4(t, vector)
		if err != nil {
			t.Fatal(err)
		}
		delegation := parent.object.payload.root.get("delegate").get("key").text
		different := vector.Observation.ChannelKeys[0]
		binding := `"swarma":{"agent":{"landlord":"id/example-landlord"}}`
		control := `{` + binding + `,"nostr":"` + different + `"}`
		for _, test := range []struct {
			name, raw string
			state     ParentNameValueState
		}{
			{"nostr-absent", `{` + binding + `}`, ParentNameValueNoKey},
			{"npub", `{` + binding + `,"nostr":"npub1example"}`, ParentNameValueNoKey},
			{"uppercase-hex", `{` + binding + `,"nostr":"` + strings.ToUpper(delegation) + `"}`, ParentNameValueNoKey},
			{"names-underscore-missing", `{` + binding + `,"nostr":{"names":{"other":"` + different + `"}}}`, ParentNameValueNoKey},
			{"names-twice", `{` + binding + `,"nostr":{"names":{"_":"` + different + `"},"names":{"_":"` + delegation + `"}}}`, ParentNameValueNoKey},
			{"underscore-twice", `{` + binding + `,"nostr":{"names":{"_":"` + different + `","_":"` + delegation + `"}}}`, ParentNameValueNoKey},
			{"nostr-wrong-type", `{` + binding + `,"nostr":null}`, ParentNameValueNoKey},
			{"duplicate-top-level-nostr", `{` + binding + `,"nostr":"` + different + `","nostr":"` + delegation + `"}`, ParentNameValueRefused},
		} {
			t.Run(test.name, func(t *testing.T) {
				for _, example := range []struct {
					raw   string
					state ParentNameValueState
				}{{control, ParentNameValueKeys}, {test.raw, test.state}} {
					value, readErr := identity.ReadR1Value(identity.R1InForce051, []byte(example.raw))
					observation := *vector.Observation
					observation.ChannelKeys = nil
					switch {
					case readErr != nil:
						// Only this table's section-2 violation maps an error to B.
						// err != nil is NOT a B predicate: missing swarma is a
						// counterexample (section 2 rule 5; section 4 rule 6).
						observation.ValueState = ParentNameValueRefused
					case value.ChannelKey == "":
						observation.ValueState = ParentNameValueNoKey
					default:
						observation.ValueState = ParentNameValueKeys
						observation.ChannelKeys = []string{value.ChannelKey}
					}
					if observation.ValueState != example.state {
						t.Fatalf("reader state = %q, want %q; error %v", observation.ValueState, example.state, readErr)
					}
					want := "implementation:" + string(example.state)
					if example.state == ParentNameValueKeys {
						want = "ok"
					}
					childWantV4(t, childEvaluationErrorV4(t, parent, child, &observation), want, 11)
					for _, adopted := range []bool{false, true} {
						policyWant := want
						if adopted && example.state == ParentNameValueNoKey {
							policyWant = "ok"
						}
						result, policyErr := checkChildAttenuationPolicyV4(parent, child, &observation, adopted)
						childWantV4(t, policyErr, policyWant, 11)
						if policyErr != nil && result != (ChildAttenuationEvaluation{}) {
							t.Fatal("reader policy refusal leaked selection")
						}
					}
				}
			})
		}
	}
}
