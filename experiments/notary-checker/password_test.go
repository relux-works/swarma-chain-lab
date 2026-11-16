package notarycheck

import (
	"bytes"
	"context"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/notary-checker/internal/diagnosticcheck"
)

// Claim: populated holder/reader values and pointers redact every listed fmt
// ordinary verb, JSON and text. Plain controls exercise the real encoders;
// bad-verb diagnostics are separately checked for absence of the credential.
// This protects diagnostics, not reflection/unsafe access to process memory.
func TestRPCPasswordRedaction(t *testing.T) {
	const synthetic = "n6-synthetic-password"
	holder := newRPCPassword([]byte(synthetic))
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
		for _, verb := range []string{"%v", "%s", "%d", "%x", "%X", "%q", "%#v", "%+v", "%p", "%+p", "%w"} {
			t.Run("fmt/"+tc.name+"/"+verb, func(t *testing.T) {
				control := fmt.Sprintf(verb, synthetic)
				if control == "" || control == credentialRedacted {
					t.Fatal("nonempty fmt control missing")
				}
				got := fmt.Sprintf(verb, tc.value)
				if diagnosticcheck.NewDetector([]byte(synthetic), false).Leaks(got) {
					t.Fatal("fmt output contains credential")
				}
				if verb != "%p" && verb != "%+p" && verb != "%w" && got != credentialRedacted {
					t.Fatal("fmt output did not redact")
				}
			})
		}
		t.Run("errorf/"+tc.name, func(t *testing.T) {
			verb := "%w"
			if diagnosticcheck.NewDetector([]byte(synthetic), false).Leaks(fmt.Errorf(verb, tc.value).Error()) {
				t.Fatal("Errorf bad-verb diagnostic contains credential")
			}
		})
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
			// XML is a real encoding.TextMarshaler consumer, not a test-local echo.
			control, err := xml.Marshal(passwordTextControl{synthetic})
			if err != nil || !strings.Contains(string(control), synthetic) {
				t.Fatal("nonempty XML text control missing")
			}
			marshaler, ok := tc.value.(encoding.TextMarshaler)
			if !ok {
				t.Fatal("value no longer implements encoding.TextMarshaler")
			}
			got, err := marshaler.MarshalText()
			if err != nil || string(got) != credentialRedacted {
				t.Fatal("text output did not redact")
			}
			encoded, err := xml.Marshal(tc.value)
			if err != nil || !strings.Contains(string(encoded), credentialRedacted) || strings.Contains(string(encoded), synthetic) {
				t.Fatal("XML text consumer did not redact")
			}
		})
	}
}

// A plain named value lets the real XML encoder carry an unredacted control.
type passwordTextControl struct{ Password string }

type passwordErrorTransport struct{}

func (passwordErrorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("n6-synthetic-password")
}

// Claim: file loading preserves prior TrimSpace/first-colon semantics and the
// exact RPC body and Basic Auth header at a fake server. RPC error details and
// transport errors containing the synthetic password become fixed refusals.
func TestRPCPasswordWireAndErrors(t *testing.T) {
	for _, tc := range []struct{ name, raw, user, password string }{
		{"plain", " \tsynthetic-user:n6-synthetic-password\n", "synthetic-user", "n6-synthetic-password"},
		{"multiple-colons", " \tsynthetic-user:n6:synthetic:password\n", "synthetic-user", "n6:synthetic:password"},
		{"utf8", " \tsynthetic-user:n6-π-password\n", "synthetic-user", "n6-π-password"},
		{"trailing-colon", "user:pw:", "user", "pw:"},
		{"unicode-space", "\u00a0synthetic-user:n6-synthetic-password", "synthetic-user", "n6-synthetic-password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			user, password := tc.user, tc.password
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
			if err := os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
				t.Fatal("fixture write")
			}
			n, err := NewNodeNameReader(srv.URL, path)
			if err != nil {
				t.Fatal("valid credential refused")
			}
			defer n.client.CloseIdleConnections()
			// Basic Auth alone cannot distinguish first- from last-colon splits.
			if n.user != user || n.password.Reveal() != password {
				t.Fatal("credential TrimSpace or first-colon split changed")
			}
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

// Claim: malformed files return exactly NODE_CREDENTIALS without a partial
// reader. Exactly 4096 bytes is accepted beside the exact 4097-byte refusal;
// interior CR and LF and an empty first-colon user are independently refused.
func TestRPCPasswordCredentialErrors(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		accepted  bool
	}{
		{"empty", "", false},
		{"no-colon", "n6-synthetic-password", false},
		{"empty-user", ":n6-synthetic-password", false},
		{"leading-colon", ":user:pw", false},
		{"empty-password", "user:", false},
		{"interior-lf", "user:n6-synthetic\npassword", false},
		{"interior-cr", "user:a\rb", false},
		{"cap-4096", "user:" + strings.Repeat("n", 4091), true},
		{"cap-4097", "user:" + strings.Repeat("n", 4092), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credential")
			if err := os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
				t.Fatal("fixture write")
			}
			n, err := NewNodeNameReader("http://127.0.0.1:1", path)
			if tc.accepted {
				if err != nil || n == nil {
					t.Fatal("valid boundary credential refused")
				}
				defer n.client.CloseIdleConnections()
				if n.user != "user" || n.password.Reveal() != tc.raw[len("user:"):] {
					t.Fatal("boundary credential changed")
				}
			} else if n != nil || err != Refusal("NODE_CREDENTIALS") {
				t.Fatal("credential refusal changed or returned partial reader")
			}
		})
	}
}

// Claim: the zero holder reveals empty and the constructor copies its input.
func TestRPCPasswordStorage(t *testing.T) {
	// Pin the non-aggregate pointer; method redaction alone cannot establish it.
	shape := reflect.TypeOf(rpcPassword{})
	if shape.NumField() != 1 || shape.Field(0).Type != reflect.TypeOf((*string)(nil)) || shape.Field(0).IsExported() {
		t.Fatal("password storage must be one unexported *string field")
	}
	defer func() {
		if recover() != nil {
			t.Error("password accessor panicked")
		}
	}()

	if (rpcPassword{}).Reveal() != "" {
		t.Fatal("zero password did not reveal empty")
	}
	input := []byte("n6-synthetic-password")
	holder := newRPCPassword(input)
	clear(input)
	if holder.Reveal() != "n6-synthetic-password" {
		t.Fatal("holder changed with constructor input")
	}
}

// Claim: fmt reflection through unexported fields and slog's text consumer
// cannot print the stored credential. A plain containing struct proves these
// sinks can expose inline strings. This is a bounded diagnostic-output check.
func TestRPCPasswordContainers(t *testing.T) {
	const synthetic = "n6-synthetic-password"
	reader := NodeNameReader{user: "synthetic-user", password: newRPCPassword([]byte(synthetic))}
	plain := struct{ r struct{ value string } }{struct{ value string }{synthetic}}
	for _, tc := range []struct {
		name  string
		value any
		verbs []string
	}{
		{"unexported-value", struct{ r NodeNameReader }{reader}, []string{"%v", "%+v", "%#v", "%s"}},
		{"unexported-pointer", struct{ r *NodeNameReader }{&reader}, []string{"%s", "%q", "%t"}},
	} {
		for _, verb := range tc.verbs {
			t.Run(tc.name+"/"+verb, func(t *testing.T) {
				if !strings.Contains(fmt.Sprintf(verb, plain), synthetic) {
					t.Fatal("plain container control missing")
				}
				if diagnosticcheck.NewDetector([]byte(synthetic), false).Leaks(fmt.Sprintf(verb, tc.value)) {
					t.Fatal("container diagnostic contains credential")
				}
			})
		}
		t.Run(tc.name+"/slog-text", func(t *testing.T) {
			var control, output bytes.Buffer
			slog.New(slog.NewTextHandler(&control, nil)).Info("control", "reader", plain)
			slog.New(slog.NewTextHandler(&output, nil)).Info("candidate", "reader", tc.value)
			if !strings.Contains(control.String(), synthetic) {
				t.Fatal("slog text control missing")
			}
			if diagnosticcheck.NewDetector([]byte(synthetic), false).Leaks(output.String()) {
				t.Fatal("slog text contains credential")
			}
		})
	}
}
