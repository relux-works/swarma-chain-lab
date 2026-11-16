package paymentchain

import (
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"

	"context"
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Populated holders and their real containers never disclose the marker through
// any fmt verb or generic JSON/text; plain values prove the detector sees it.
func TestRPCPasswordHolderRedaction(t *testing.T) {
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
	holder := NewRPCPassword(marker)
	container := Route{Host: "visible-control", Password: holder}
	for _, verb := range []string{"%v", "%+v", "%s", "%d", "%x", "%X", "%q", "%#v", "%#s", "%#d", "%#x", "%#X", "%#q", "%p", "%b", "%o", "%O", "%c", "%U", "%e", "%E", "%f", "%F", "%g", "%G", "%t", "%T", "%10v", "%-8s", "%020p", "%.8v", "%#20.8x", "%w"} {
		for _, value := range []any{holder, &holder, container, &container, []any{container}, map[string]any{"container": container}, struct{ hidden Route }{container}} {
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

// Plain JSON config strings retain the legacy schema and produce the exact
// Basic Auth header through the real RPC method, with no network or node call.
func TestRPCPasswordConfigCompatibility(t *testing.T) {
	const marker = "synthetic-config-password-13862"
	const fixture = `{"host":"127.0.0.1","port":18443,"username":"payment-observer","password":"synthetic-config-password-13862"}`
	var route Route
	if su.StrictInput([]byte(fixture), &route) != nil {
		t.Fatal("plain legacy route refused")
	}
	before := fixture
	after := string(privateRouteFixtureJSON(route))
	if before != after {
		t.Fatal("private config fixture bytes changed")
	}
	rpc, err := NewRPC(route)
	if err != nil {
		t.Fatal("legacy config failed route admission")
	}
	called := false
	rpc.client.Transport = passwordRoundTrip(func(req *http.Request) (*http.Response, error) {
		called = true
		user, password, ok := req.BasicAuth()
		if !ok || user != "payment-observer" || password != marker {
			t.Fatal("Basic Auth credential changed")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"id":1,"result":{},"error":null}`))}, nil
	})
	if _, err = rpc.Call(context.Background(), "getblockhash", 0); err != nil || !called {
		t.Fatal("synthetic RPC transport refused")
	}
	for _, raw := range []string{`123`, `true`, `{}`, `[]`} {
		held := NewRPCPassword(marker)
		if json.Unmarshal([]byte(raw), &held) == nil || held.Valid() {
			t.Fatal("invalid decode retained password")
		}
	}
	// Credential-independent config bindings previously cleared plain passwords
	// to an empty string; preserve that exact JSON representation.
	route.Password = RPCPassword{}
	empty, err := json.Marshal(route)
	if err != nil || string(empty) != string(privateRouteFixtureJSON(route)) {
		t.Fatal("empty-password binding bytes changed")
	}
	for _, n := range []int{0, 15, 16, 256, 257} {
		route.Password = NewRPCPassword(strings.Repeat("x", n))
		_, err := NewRPC(route)
		if (err == nil) != (n >= 16 && n <= 256) {
			t.Fatal("route password admission bound changed")
		}
	}
}

type passwordRoundTrip func(*http.Request) (*http.Response, error)

func (f passwordRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The scalar-schema adapter keeps aliases, duplicates, nulls and object-shaped
// credential inputs forbidden at the real strict-config entry point.
func TestRPCPasswordStrictConfigNegative(t *testing.T) {
	for _, raw := range []string{
		`{"host":"127.0.0.1","password":{"value":"synthetic-private"}}`,
		`{"password":null}`, `{"Password":"synthetic-private"}`,
		`{"password":"first","password":"second"}`, `{"pass\u0077ord":"synthetic-private"}`,
		`{"password":123}`, `{"password":true}`, `{"password":[]}`,
	} {
		var route Route
		if su.StrictInput([]byte(raw), &route) == nil || route.Password.Valid() {
			t.Fatal("strict credential schema accepted forbidden input")
		}
	}
}
