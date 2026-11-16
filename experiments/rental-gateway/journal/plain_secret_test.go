package journal

import (
	"encoding"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Populated holders and their real containers never disclose the marker through
// any fmt verb or generic JSON/text; plain values prove the detector sees it.
func TestSlotPrivateHolderRedaction(t *testing.T) {
	const marker = "synthetic-private-marker-297681"
	discloses := func(out string) bool {
		for i := 0; i+8 <= len(marker); i++ {
			part := marker[i : i+8]
			decimal := strings.Trim(fmt.Sprint([]byte(part)), "[]")
			if strings.Contains(out, part) || strings.Contains(out, fmt.Sprintf("%x", part)) || strings.Contains(out, fmt.Sprintf("%X", part)) || strings.Contains(out, decimal) {
				return true
			}
		}
		return false
	}
	holder := NewChannelSecretHex(marker)
	container := slotPrivate{ID: "visible-control", ChannelSecretHex: holder}
	for _, verb := range []string{"%v", "%+v", "%s", "%d", "%x", "%X", "%q", "%#v", "%#s", "%#d", "%#x", "%#X", "%#q", "%p", "%b", "%o", "%O", "%c", "%U", "%e", "%E", "%f", "%F", "%g", "%G", "%t", "%T", "%10v", "%-8s", "%020p", "%.8v", "%#20.8x", "%w"} {
		for _, value := range []any{holder, &holder, container, &container, []any{container}, map[string]any{"container": container}, struct{ hidden slotPrivate }{container}} {
			out := fmt.Sprintf(verb, value)
			if discloses(out) {
				t.Fatal("fmt disclosed private bytes for", verb)
			}
		}
		plain := fmt.Sprintf(verb, struct{ Control string }{marker})
		if plain == "" || (verb != "%T" && !discloses(plain)) {
			t.Fatal("formatting control did not disclose marker")
		}
	}
	for _, value := range []any{holder, &holder, container, &container} {
		raw, err := json.Marshal(value)
		if err != nil || len(raw) == 0 || discloses(string(raw)) {
			t.Fatal("generic JSON disclosed private bytes")
		}
		text, ok := value.(encoding.TextMarshaler)
		if !ok {
			t.Fatal("text projection missing")
		}
		raw, err = text.MarshalText()
		if err != nil || len(raw) == 0 || discloses(string(raw)) {
			t.Fatal("text projection disclosed private bytes")
		}
	}
	raw, _ := json.Marshal(struct{ Control string }{marker})
	if !discloses(string(raw)) {
		t.Fatal("JSON control did not disclose marker")
	}
	text, _ := container.MarshalText()
	if !strings.Contains(string(text), "visible-control") {
		t.Fatal("text dropped non-secret control")
	}
}
