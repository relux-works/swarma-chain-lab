package journal

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// Populated holders and their real containers never disclose the marker through
// the listed fmt forms and generic JSON/text/slog; plain controls calibrate detection.
func TestSlotPrivateHolderRedaction(t *testing.T) {
	const marker = "synthetic-private-marker-297681"
	discloses := func(out string) bool {
		for i := 0; i+8 <= len(marker); i++ {
			part := marker[i : i+8]
			decimal := strings.Trim(fmt.Sprint([]byte(part)), "[]")
			if strings.Contains(out, part) || strings.Contains(out, fmt.Sprintf("%x", part)) || strings.Contains(out, fmt.Sprintf("%X", part)) || strings.Contains(out, decimal) || strings.Contains(out, fmt.Sprintf("% x", part)) || strings.Contains(out, fmt.Sprintf("% X", part)) {
				return true
			}
		}
		return false
	}
	if !discloses(fmt.Sprintf("% x", marker)) || !discloses(fmt.Sprintf("% X", marker)) {
		t.Fatal("space hex control did not disclose marker")
	}
	holder := NewChannelSecretHex(marker)
	container := slotPrivate{ID: "visible-control", ChannelSecretHex: holder}
	for _, verb := range []string{"%v", "%+v", "%s", "%d", "%x", "%X", "%q", "%#v", "%#s", "%#d", "%#x", "%#X", "%#q", "%p", "%b", "%o", "%O", "%c", "%U", "%e", "%E", "%f", "%F", "%g", "%G", "%t", "%T", "%10v", "%-8s", "%020p", "%.8v", "%#20.8x", "%w", "%+p", "%#p", "% x", "% X"} {
		for _, value := range []any{holder, &holder, container, &container, []any{container}, map[string]any{"container": container}, struct{ hidden slotPrivate }{container}, struct{ hidden *slotPrivate }{&container}} {
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
	// Both handlers exercise the real containers, including hidden pointers.
	for _, value := range []any{holder, &holder, container, &container, struct{ hidden slotPrivate }{container}, struct{ hidden *slotPrivate }{&container}} {
		for _, jsonHandler := range []bool{false, true} {
			var output bytes.Buffer
			var handler slog.Handler = slog.NewTextHandler(&output, nil)
			if jsonHandler {
				handler = slog.NewJSONHandler(&output, nil)
			}
			logger := slog.New(handler)
			logger.Info("holder", "value", value)
			if output.Len() == 0 || discloses(output.String()) {
				t.Fatal("slog disclosed private bytes")
			}
			output.Reset()
			logger.Info("control", "value", marker)
			if !discloses(output.String()) {
				t.Fatal("slog control did not disclose marker")
			}
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
