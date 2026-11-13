package modelproxy

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Both duplicate orders and escaped spellings are refused before returning a map;
// value escaping remains legal. Registry durability is covered separately.
func TestSJ1KeyAdmission(t *testing.T) {
	for _, raw := range []string{`{"grant":3,"grant":2}`, `{"grant":2,"grant":3}`, `{"grant":3,"gr\u0061nt":2}`, `{"gr\u0061nt":3}`, `{"grant":[{"version":3,"version":2}]}`, `{"grant":[{"version":2,"version":3}]}`, `{"grant":[{"vers\u0069on":3}]}`} {
		if out, err := object([]byte(raw)); err == nil || out != nil {
			t.Fatal("SJ1 ambiguous key admitted")
		}
		if out, err := object([]byte(`{"grant":3,"note":"line\nvalue"}`)); err != nil || out == nil {
			t.Fatal("valid neighbor refused", err)
		}
	}
}

// Admin JSON refusal neither allocates authority nor rewrites registry bytes;
// the matching valid request still prepares a credential afterwards.
func TestSJ1AdminKeys(t *testing.T) {
	h := fixture(t)
	b := h.b
	b.SlotID = strings.Repeat("d", 64)
	raw := string(privateCanonical(adminRequest{1, "prepare", b}))
	send := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://local/v1/registry", strings.NewReader(body))
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, true))
		w := httptest.NewRecorder()
		h.s.adminHandler(w, r)
		return w
	}
	path := filepath.Join(h.c.StateDir, "registry.json")
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{`"op":"prepare","op":"invalid"`, `"op":"invalid","op":"prepare"`, `"op":"prepare","o\u0070":"invalid"`, `"o\u0070":"prepare"`} {
		if w := send(strings.Replace(raw, `"op":"prepare"`, field, 1)); w.Code != 400 {
			t.Fatal("SJ1 ambiguous admin admitted")
		}
		if _, e := h.s.Status(b.SlotID); e == nil {
			t.Fatal("refusal allocated authority")
		}
		after, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(before, after) {
			t.Fatal("refusal rewrote registry", e)
		}
	}
	if w := send(raw); w.Code != 200 {
		t.Fatal("valid neighbor refused")
	}
}

// Restart refusal retains the exact ledger and cannot expose a Service. Restoring
// the valid fixture recovers it; an advisory lock is not an authority mutation.
func TestSJ1RegistryKeys(t *testing.T) {
	h := fixture(t)
	if e := h.s.Close(); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(h.c.StateDir, "registry.json")
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{`"version":1,"version":9`, `"version":9,"version":1`, `"version":1,"vers\u0069on":9`, `"vers\u0069on":1`} {
		bad := []byte(strings.Replace(string(raw), `"version":1`, field, 1))
		if bytes.Equal(bad, raw) {
			t.Fatal("plant missing")
		}
		if e := os.WriteFile(path, bad, 0600); e != nil {
			t.Fatal(e)
		}
		if s, e := New(h.c); e == nil || s != nil {
			t.Fatal("SJ1 ambiguous registry admitted")
		}
		after, e := os.ReadFile(path)
		if e != nil || !bytes.Equal(after, bad) {
			t.Fatal("refusal rewrote ledger", e)
		}
	}
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	h.reopen(t)
}
