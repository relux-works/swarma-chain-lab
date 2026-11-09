package relay

import (
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"strings"
	"testing"
)

// Each specified field is conjunctive; explicit empty lists match nothing.
// Limits constrain backlog only, including zero, and never suppress live events.
func TestFilters(t *testing.T) {
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	e := &nostr.Event{ID: a, PubKey: b, Kind: 1059, CreatedAt: 100, Tags: [][]string{{"p", a}, {"e", b}}}
	for _, tc := range []struct {
		raw   string
		match bool
	}{
		{`{}`, true}, {`{"ids":["` + a + `"]}`, true}, {`{"authors":["` + a + `"]}`, false},
		{`{"ids":[]}`, false}, {`{"authors":[]}`, false}, {`{"kinds":[]}`, false}, {`{"#p":[]}`, false},
		{`{"kinds":[8182,1059],"#p":["` + a + `"],"#e":["` + b + `"],"since":100,"until":100,"limit":0}`, true},
		{`{"since":101}`, false}, {`{"until":99}`, false}, {`{"#p":["` + b + `"]}`, false},
	} {
		f, err := parseFilter([]byte(tc.raw))
		if err != nil || f.match(e) != tc.match {
			t.Fatalf("filter %s match=%v error=%v", tc.raw, tc.match, err)
		}
	}
}

// Unknown, duplicate, malformed and unbounded fields refuse rather than widen
// a subscription; the valid neighbor above exercises the same parser.
func TestFilterRefusals(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `{} {}`, `{"kinds":[1059],"kinds":[]}`, `{"#p":null}`, `{"search":"x"}`, `{"ids":["ab"]}`, `{"since":-1}`, `{"limit":-1}`, `{"kinds":[65536]}`, `{"until":5,"since":6}`, `{"#p":["` + strings.Repeat("A", 64) + `"]}`} {
		if _, e := parseFilter([]byte(raw)); e == nil {
			t.Fatalf("invalid filter accepted: %s", raw)
		}
	}
}
