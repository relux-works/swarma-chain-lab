package notarycheck

import (
	"context"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: populated holder/reader values and pointers redact every listed fmt
// verb, JSON and text. Plain nonempty controls prove each output path ran.
// This protects diagnostics, not reflection/unsafe access to process memory.
func TestRPCPasswordRedaction(t *testing.T) {
	const synthetic = "n6-synthetic-password"
	holder := rpcPassword{value: synthetic}
	reader := NodeNameReader{user: "synthetic-user", password: holder}
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"holder/value", holder}, {"holder/pointer", &holder},
		{"reader/value", reader}, {"reader/pointer", &reader},
		{"reader/context-copy", reader.WithContext(context.Background())},
		{"holder/zero", rpcPassword{}}, {"reader/zero", NodeNameReader{}},
	} {
		for _, verb := range []string{"%v", "%s", "%d", "%x", "%X", "%q", "%#v", "%+v"} {
			t.Run("fmt/"+tc.name+"/"+verb, func(t *testing.T) {
				control := fmt.Sprintf(verb, synthetic)
				if control == "" || control == credentialRedacted {
					t.Fatal("nonempty fmt control missing")
				}
				if fmt.Sprintf(verb, tc.value) != credentialRedacted {
					t.Fatal("fmt output did not redact")
				}
			})
		}
		t.Run("json/"+tc.name, func(t *testing.T) {
			control, err := json.Marshal(struct{ Password string }{synthetic})
			if err != nil || !strings.Contains(string(control), synthetic) {
				t.Fatal("nonempty JSON control missing")
			}
			got, err := json.Marshal(tc.value)
			if err != nil || string(got) != `"[REDACTED]"` {
				t.Fatal("JSON output did not redact")
			}
		})
		t.Run("text/"+tc.name, func(t *testing.T) {
			control, err := plainPasswordText(synthetic).MarshalText()
			if err != nil || string(control) != synthetic || len(control) == 0 {
				t.Fatal("nonempty text control missing")
			}
			got, err := tc.value.(encoding.TextMarshaler).MarshalText()
			if err != nil || string(got) != credentialRedacted {
				t.Fatal("text output did not redact")
			}
		})
	}
}

type plainPasswordText string

func (p plainPasswordText) MarshalText() ([]byte, error) { return []byte(p), nil }

type passwordErrorTransport struct{}

func (passwordErrorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("n6-synthetic-password")
}

// Claim: file loading preserves prior TrimSpace/first-colon semantics and the
// exact RPC body and Basic Auth header at a fake server. RPC error details and
// transport errors containing the synthetic password become fixed refusals.
func TestRPCPasswordWireAndErrors(t *testing.T) {
	const user = "synthetic-user"
	for _, password := range []string{"n6-synthetic-password", "n6:synthetic:password", "n6-π-password"} {
		t.Run(password, func(t *testing.T) {
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				body, err := io.ReadAll(r.Body)
				legacy := &http.Request{Header: make(http.Header)}
				legacy.SetBasicAuth(user, password)
				wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
				if r.Header.Get("Authorization") != wantAuth || r.Header.Get("Authorization") != legacy.Header.Get("Authorization") {
					t.Error("Authorization bytes changed")
				}
				if err != nil || string(body) != `{"jsonrpc":"1.0","id":1,"method":"n6_probe","params":[]}` || r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
					t.Error("RPC request bytes changed")
				}
				if requests == 1 {
					_, _ = io.WriteString(w, `{"id":1,"result":true,"error":null}`)
				} else {
					_ = json.NewEncoder(w).Encode(map[string]any{"id": 1, "error": map[string]any{"code": -1, "message": password}})
				}
			}))
			defer srv.Close()
			path := filepath.Join(t.TempDir(), "credential")
			if err := os.WriteFile(path, []byte(" \t"+user+":"+password+"\n"), 0600); err != nil {
				t.Fatal("fixture write")
			}
			n, err := NewNodeNameReader(srv.URL, path)
			if err != nil {
				t.Fatal("valid credential refused")
			}
			defer n.client.CloseIdleConnections()
			var result bool
			if err := n.rpc("n6_probe", []any{}, &result); err != nil || !result {
				t.Fatal("valid RPC refused")
			}
			if err := n.rpc("n6_probe", []any{}, &result); err != Refusal("NODE_RPC_FAILURE") {
				t.Fatal("RPC error not sanitized")
			}
			n.client = &http.Client{Transport: passwordErrorTransport{}}
			if err := n.rpc("n6_probe", []any{}, &result); err != Refusal("NODE_RPC_FAILURE") {
				t.Fatal("transport error not sanitized")
			}
		})
	}
}

// Claim: malformed credential content returns only NODE_CREDENTIALS with no
// partial reader; valid whitespace/colon/UTF-8 neighbors are exercised above.
func TestRPCPasswordCredentialErrors(t *testing.T) {
	for _, raw := range []string{"", "n6-synthetic-password", ":n6-synthetic-password", "user:", "user:n6-synthetic\npassword", "user:" + strings.Repeat("n", 4096)} {
		path := filepath.Join(t.TempDir(), "credential")
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal("fixture write")
		}
		if n, err := NewNodeNameReader("http://127.0.0.1:1", path); n != nil || err != Refusal("NODE_CREDENTIALS") {
			t.Fatal("credential refusal changed or returned partial reader")
		}
	}
}
