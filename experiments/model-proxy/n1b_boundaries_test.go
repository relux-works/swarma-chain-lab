package modelproxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Only explicit authentication reveals the operator key. All exact ASCII header
// bytes survive wrapping; failed key decodes clear their destination, and the
// persistent registry, public audits and returned status do not retain the key.
func TestN1bUpstreamKeyBoundaries(t *testing.T) {
	for i := 0; i < 64; i++ {
		raw := Secret(strings.Repeat(string(rune('!'+i)), 32))
		key := NewAPIKey(raw)
		var decoded UpstreamKey
		encoded, _ := json.Marshal(raw)
		if json.Unmarshal(encoded, &decoded) != nil || decoded.Reveal() != raw {
			t.Fatal("upstream private input bytes changed")
		}
		for _, dialect := range []Dialect{Messages{}, Responses{}} {
			headers := http.Header{}
			dialect.Headers(headers, key)
			if _, ok := dialect.(Messages); ok {
				if headers.Get("x-api-key") != string(raw) {
					t.Fatal("messages authentication bytes changed")
				}
			} else if headers.Get("Authorization") != "Bearer "+string(raw) {
				t.Fatal("responses authentication bytes changed")
			}
		}
		copied := decoded
		if json.Unmarshal([]byte(`123`), &decoded) == nil || !decoded.IsZero() || copied.Reveal() != raw {
			t.Fatal("failed key decode retained or mutated credentials")
		}
	}
	h := fixture(t)
	stored, e := h.s.disk.Read("registry.json", MaxBody)
	if e != nil || bytes.Contains(stored, []byte(keyMarker)) {
		t.Fatal("upstream key entered registry")
	}
	status, err := h.s.Status(h.b.SlotID)
	if err != nil {
		t.Fatal("status control refused")
	}
	for _, value := range []any{h.s.state, h.audits, status} {
		raw, _ := json.Marshal(value)
		if bytes.Contains(raw, []byte(keyMarker)) {
			t.Fatal("upstream key entered public state")
		}
	}
	for _, raw := range []Secret{"", Secret(strings.Repeat("a", 4097)), "contains space", "contains\nnewline"} {
		config := h.c
		config.APIKey = NewAPIKey(raw)
		service, e := New(config)
		if e == nil || e.Error() != "CONFIG" || service != nil {
			t.Fatal("invalid operator key admitted")
		}
	}
}
