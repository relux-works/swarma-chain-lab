package modelproxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// A positive signed default persists and binds registry identity, but current
// Responses still rejects an omitted/oversized explicit output limit without
// forwarding or charging. Legacy zero remains omitted from canonical bytes.
func TestSignedDefaultBindingWithoutInjection(t *testing.T) {
	legacy := Caps{1000, 1000, 10, 10, 10000, 0}
	if bytes.Contains(privateCanonical(legacy), []byte("default_max_output_tokens")) {
		t.Fatal("legacy bytes changed")
	}
	h := responsesFixture(t, 5)
	if h.status(t).Binding.Caps.DefaultMaxOutputTokens != 5 {
		t.Fatal("default not bound")
	}
	h.s.Close()
	var e error
	h.s, e = New(h.c)
	if e != nil {
		t.Fatal(e)
	}
	if h.status(t).Binding != h.b {
		t.Fatal("restart changed binding")
	}
	changed := h.b
	changed.Caps.DefaultMaxOutputTokens = 6
	if _, e = h.s.Prepare(changed); e == nil || e.Error() != "CONFLICT" {
		t.Fatal("default rebinding accepted", e)
	}
	invalid := h.b
	invalid.SlotID = strings.Repeat("d", 64)
	invalid.Caps.DefaultMaxOutputTokens = 11
	if _, e = h.s.Prepare(invalid); e == nil || e.Error() != "BINDING" {
		t.Fatal("oversized default accepted", e)
	}
	if _, e = h.s.Status(invalid.SlotID); e == nil {
		t.Fatal("invalid binding persisted")
	}
	before := h.status(t).Exposure
	for _, limit := range []uint64{0, 11} {
		var request map[string]any
		json.Unmarshal([]byte(responsesRequest(true, false)), &request)
		if limit == 0 {
			delete(request, "max_output_tokens")
		} else {
			request["max_output_tokens"] = limit
		}
		w := h.send(string(privateCanonical(request)))
		wantStatus, wantCode := 400, "REQUEST"
		if limit != 0 {
			wantStatus, wantCode = 403, "CAP"
		}
		if w.Code != wantStatus || !strings.Contains(w.Body.String(), wantCode) {
			t.Fatalf("wrong explicit-limit refusal: %d %s", w.Code, w.Body.String())
		}
		if h.calls.Load() != 0 || h.status(t).Exposure != before {
			t.Fatal("rejected request forwarded/charged")
		}
	}
	if w := h.send(responsesRequest(true, false)); w.Code != 200 || h.calls.Load() != 1 {
		t.Fatal("explicit valid neighbor refused", w.Code)
	}
}
