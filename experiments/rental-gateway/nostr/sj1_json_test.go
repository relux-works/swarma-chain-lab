package nostr

import (
	"strings"
	"testing"
)

// Wrapper, seal and rumor share ParseEvent. Ambiguous wire keys cannot reach
// signature verification; escaped content values remain valid Nostr text.
func TestSJ1EventKeys(t *testing.T) {
	for _, kind := range []string{"1059", "13", "14"} {
		valid := `{"id":"","pubkey":"` + strings.Repeat("a", 64) + `","created_at":1,"kind":` + kind + `,"tags":[],"content":"line\nvalue","sig":""}`
		for name, field := range map[string]string{
			"left-valid":        `"kind":` + kind + `,"kind":-1`,
			"right-valid":       `"kind":-1,"kind":` + kind,
			"escaped-duplicate": `"kind":-1,"k\u0069nd":` + kind,
			"escaped-single":    `"k\u0069nd":` + kind,
			"case-alias":        `"Kind":` + kind,
		} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				bad := strings.Replace(valid, `"kind":`+kind, field, 1)
				if e, err := ParseEvent([]byte(bad)); err == nil || e != nil {
					t.Fatal("SJ1 ambiguous event admitted")
				}
				if e, err := ParseEvent([]byte(valid)); err != nil || e.Content != "line\nvalue" {
					t.Fatal("valid neighbor refused", err)
				}
			})
		}
	}
}
