package codec

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"testing"
)

// A valid synthetic v2 document must keep both credentials and every 8-byte
// fragment out of fmt/log output, including %p's method-bypassing bad-verb path.
// This probes formatting, not deliberate credential access or JSON encoding.
func TestBootstrapFormattingAllVerbs(t *testing.T) {
	const channel = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	const bearer = "eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXk"
	const raw = `{"v":2,"booking_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","station_name":"id/fixture","channel_secret":"eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=","model_bearer":"` + bearer + `","model_endpoint":"https://proxy.example","model_cert_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`
	document, err := Decode[[]byte, string]([]byte(raw))
	if err != nil {
		t.Fatal("valid synthetic v2 fixture rejected:", err)
	}
	forbidden := []string{bearer, channel, base64.StdEncoding.EncodeToString([]byte(channel))}
	// Include numeric/hex renderings of the channel: diagnostics may recurse into
	// slices without calling nested redaction methods.
	for _, format := range []string{"%v", "%#v", "%x", "%X", "%q", "%d", "%b", "%o", "%O", "%c", "%U"} {
		forbidden = append(forbidden, fmt.Sprintf(format, []byte(channel)))
	}
	check := func(t *testing.T, output string) {
		t.Helper()
		for _, secret := range forbidden {
			if strings.Contains(output, secret) {
				t.Fatal("credential disclosure in formatted bootstrap")
			}
			for i := 0; i+8 <= len(secret); i++ {
				if strings.Contains(output, secret[i:i+8]) {
					t.Fatal("8-byte credential fragment disclosure in formatted bootstrap")
				}
			}
		}
	}
	formats := []string{"%p", "%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%b", "%o", "%O", "%c", "%U", "%e", "%E", "%f", "%F", "%g", "%G", "%t", "%T", "%10v", "%-8s", "%#x", "%+p", "%#p", "%020p", "%.8v", "%#20.8x", "%w"}
	for _, value := range []struct {
		name  string
		value any
	}{{"value", document}, {"pointer", &document}, {"embedded", struct{ Document any }{document}}, {"slice", []any{document}}, {"map", map[string]any{"document": document}}} {
		t.Run(value.name, func(t *testing.T) {
			for _, format := range formats {
				t.Run(format, func(t *testing.T) {
					check(t, fmt.Sprintf(format, value.value))
					var output bytes.Buffer
					log.New(&output, "", 0).Printf(format, value.value)
					check(t, output.String())
				})
			}
			t.Run("Sprint", func(t *testing.T) { check(t, fmt.Sprint(value.value)) })
			t.Run("Sprintln", func(t *testing.T) { check(t, fmt.Sprintln(value.value)) })
			for _, format := range []string{"%v", "%w"} {
				t.Run("Errorf"+format, func(t *testing.T) { check(t, fmt.Errorf(format, value.value).Error()) })
			}
		})
	}
}
