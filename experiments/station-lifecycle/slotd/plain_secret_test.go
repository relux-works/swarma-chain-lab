package slotd

import (
	"bufio"
	"bytes"
	"context"
	"encoding"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
)

// The real request stream preserves the pre-holder JSON order, bytes, omission
// and newline; this uses only net.Pipe, never a node or a helper process.
func TestBootstrapPrivateWireGolden(t *testing.T) {
	const create = `{"v":1,"op":"create","slot":"17","boot_id":"0f8e1c3a-6b2d-4e7f-9a1b-2c3d4e5f6a7b","issued_boottime_ns":"10000000000","not_after":"1970-01-01T00:05:00Z","bootstrap":"c3ludGhldGljLWJvb3RzdHJhcA=="}`
	for _, golden := range []string{create, `{"v":1,"op":"status","slot":"17"}`} {
		var r Request
		if err := json.Unmarshal([]byte(golden), &r); err != nil {
			t.Fatal("golden request decode refused")
		}
		got := make(chan string, 1)
		c := &Client{dial: func(context.Context) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				raw, _ := bufio.NewReader(server).ReadBytes('\n')
				got <- string(raw)
				_, _ = server.Write([]byte("{\"v\":1,\"ok\":true,\"slot\":\"17\",\"state\":\"absent\"}\n"))
			}()
			return client, nil
		}}
		if _, err := c.Call(context.Background(), r); err != nil {
			t.Fatal("golden stream refused", err)
		}
		if <-got != golden+"\n" {
			t.Fatal("private request bytes changed")
		}
	}
}

// Populated holders and their real containers never disclose the marker through
// the listed fmt forms and generic JSON/text/slog; plain controls calibrate detection.
func TestBootstrapHolderRedaction(t *testing.T) {
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
	holder := NewBootstrap(marker)
	container := Request{V: 1, Op: "visible-control", Slot: "17", Bootstrap: &holder}
	for _, verb := range []string{"%v", "%+v", "%s", "%d", "%x", "%X", "%q", "%#v", "%#s", "%#d", "%#x", "%#X", "%#q", "%p", "%b", "%o", "%O", "%c", "%U", "%e", "%E", "%f", "%F", "%g", "%G", "%t", "%T", "%10v", "%-8s", "%020p", "%.8v", "%#20.8x", "%w", "%+p", "%#p", "% x", "% X"} {
		for _, value := range []any{holder, &holder, container, &container, []any{container}, map[string]any{"container": container}, struct{ hidden Request }{container}, struct{ hidden *Request }{&container}} {
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
	for _, value := range []any{holder, &holder, container, &container, struct{ hidden Request }{container}, struct{ hidden *Request }{&container}} {
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

// Invalid bootstrap encodings never dial; a neighboring canonical value does.
// Failed holder decodes clear previously retained bytes.
func TestBootstrapInvalidNeverDials(t *testing.T) {
	const prefix = `{"v":1,"op":"create","slot":"17","boot_id":"0f8e1c3a-6b2d-4e7f-9a1b-2c3d4e5f6a7b","issued_boottime_ns":"10000000000","not_after":"1970-01-01T00:05:00Z","bootstrap":`
	for _, value := range []string{`"!invalid!"`, `"c3ludGhldGlj\n"`, `null`} {
		var r Request
		if json.Unmarshal([]byte(prefix+value+"}"), &r) != nil {
			t.Fatal("fixture decode refused")
		}
		c := &Client{dial: func(context.Context) (net.Conn, error) { t.Fatal("invalid request dialed"); return nil, nil }}
		if _, err := c.Call(context.Background(), r); err == nil || err.Error() != "SLOTD_REQUEST" {
			t.Fatal("wrong invalid bootstrap refusal")
		}
	}
	var good Request
	if json.Unmarshal([]byte(prefix+`"c3ludGhldGlj"}`), &good) != nil || !ValidRequest(good) {
		t.Fatal("valid bootstrap refused")
	}
	held := NewBootstrap("c3ludGhldGlj")
	if json.Unmarshal([]byte(`123`), &held) == nil || held.valid() {
		t.Fatal("failed decode retained bootstrap")
	}
}

// The private encoder preserves null omission, a present empty string, and JSON
// escaping independently of semantic request validation.
func TestBootstrapPrivateEncodingVariants(t *testing.T) {
	for _, scalar := range []string{`""`, `"synthetic-\"-\\-\n-<>&"`, `"c3ludGhldGlj"`} {
		golden := `{"v":1,"op":"create","slot":"17","bootstrap":` + scalar + `}`
		var r Request
		if json.Unmarshal([]byte(golden), &r) != nil {
			t.Fatal("wire fixture decode refused")
		}
		var legacy map[string]json.RawMessage
		if json.Unmarshal([]byte(golden), &legacy) != nil {
			t.Fatal("legacy fixture refused")
		}
		// Re-encode the scalar with encoding/json's original HTML escaping policy.
		var value string
		_ = json.Unmarshal(legacy["bootstrap"], &value)
		expected, _ := json.Marshal(value)
		want := `{"v":1,"op":"create","slot":"17","bootstrap":` + string(expected) + `}`
		if string(encodePrivateRequest(r)) != want {
			t.Fatal("private scalar escaping changed")
		}
	}
}
