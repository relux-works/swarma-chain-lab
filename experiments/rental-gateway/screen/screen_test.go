package screen_test

import (
	"testing"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/screen"
)

// TestParseAnswer proves only exact ALLOW / REFUSE <reason> parse;
// everything else is malformed (and therefore a refusal upstream).
func TestParseAnswer(t *testing.T) {
	if d, err := screen.ParseAnswer("ALLOW"); err != nil || !d.Allow {
		t.Fatalf("ALLOW = %+v, %v", d, err)
	}
	if d, err := screen.ParseAnswer("REFUSE prompt injection"); err != nil || d.Allow || d.Reason != "prompt injection" {
		t.Fatalf("REFUSE = %+v, %v", d, err)
	}
	for _, bad := range []string{"", "allow", "ALLOW.", "REFUSE", "REFUSE ", "looks fine", "I think ALLOW"} {
		if _, err := screen.ParseAnswer(bad); err == nil {
			t.Fatalf("malformed answer %q parsed as a decision", bad)
		}
	}
}
