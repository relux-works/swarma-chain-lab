package modelproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type harness struct {
	s        *Service
	c        Config
	b        Binding
	cred     Credential
	calls    atomic.Int32
	now      atomic.Int64
	mu       sync.Mutex
	audits   []Audit
	response func(http.ResponseWriter, *http.Request)
}

const modelID = "test-model-1"
const keyMarker = "private-test-model-key-marker"

func fixture(t *testing.T) *harness {
	t.Helper()
	h := &harness{}
	h.now.Store(100)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.calls.Add(1)
		if r.Header.Get("x-api-key") != keyMarker || r.Header.Get("Authorization") != "" || r.Header.Get("anthropic-beta") != "" || r.Header.Get("anthropic-version") != "2026-10-21" {
			t.Error("client auth/header escaped")
		}
		body, e := io.ReadAll(r.Body)
		var fields map[string]json.RawMessage
		if e != nil || json.Unmarshal(body, &fields) != nil || string(fields["service_tier"]) != `"standard_only"` || string(fields["inference_geo"]) != `"global"` {
			t.Error("priced upstream profile not pinned")
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		h.response(w, r)
	}))
	t.Cleanup(upstream.Close)
	h.response = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, reply(7, 3))
	}
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	h.c = Config{StateDir: root, Endpoint: Endpoint{"https://proxy.example", strings.Repeat("a", 64)}, Upstream: upstream.URL + "/v1/messages", APIKey: keyMarker, Models: map[string]Model{modelID: {ContextTokens: 100, InputNanoUSD: 2, OutputNanoUSD: 3, Source: "fixture model bound, not production pricing"}}, Now: func() time.Time { return time.Unix(h.now.Load(), 0) }, Transport: upstream.Client().Transport, Timeout: time.Second, Audit: func(a Audit) { h.mu.Lock(); defer h.mu.Unlock(); h.audits = append(h.audits, a) }}
	var e error
	h.s, e = New(h.c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { h.s.Close() })
	h.b = Binding{strings.Repeat("b", 64), strings.Repeat("c", 64), 90, 1000, Caps{1000, 1000, 10, 10, 10000, 0}}
	h.cred, e = h.s.Prepare(h.b)
	if e != nil {
		t.Fatal(e)
	}
	if e = h.s.Activate(h.b); e != nil {
		t.Fatal(e)
	}
	return h
}
func reply(in, out uint64) string {
	return fmt.Sprintf(`{"id":"msg_fixture","type":"message","role":"assistant","model":"test-model-1","content":[{"type":"text","text":"answer"}],"stop_reason":"end_turn","usage":{"input_tokens":%d,"output_tokens":%d,"service_tier":"standard","inference_geo":"global","speed":"standard"}}`, in, out)
}
func request(stream bool) string {
	return fmt.Sprintf(`{"model":"test-model-1","messages":[{"role":"user","content":"private-prompt-marker"}],"max_tokens":10,"stream":%t}`, stream)
}
func (h *harness) send(body string) *httptest.ResponseRecorder {
	return h.sendAs(body, h.b.SlotID, h.cred.Bearer)
}
func (h *harness) sendAs(body, id string, bearer Secret) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://proxy.example/slots/"+id+"/v1/messages", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+string(bearer))
	r.Header.Set("x-api-key", "client-key-marker")
	r.Header.Set("anthropic-beta", "client-beta-marker")
	r.Header.Set("anthropic-version", "client-version-marker")
	w := httptest.NewRecorder()
	h.s.ServeHTTP(w, r)
	return w
}
func (h *harness) status(t *testing.T) Status {
	t.Helper()
	v, e := h.s.Status(h.b.SlotID)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func (h *harness) reopen(t *testing.T) {
	t.Helper()
	h.s.Close()
	s, e := New(h.c)
	if e != nil {
		t.Fatal(e)
	}
	h.s = s
}

// Exact retries preserve the bearer; terminal or conflicting bindings never mint
// new budget. A valid ordinary request settles the context-window reservation.
func TestRegistryAndUsage(t *testing.T) {
	h := fixture(t)
	again, e := h.s.Prepare(h.b)
	if e != nil || again != h.cred {
		t.Fatal("prepare replay changed credential")
	}
	other := h.b
	other.GrantID = strings.Repeat("d", 64)
	if _, e = h.s.Prepare(other); e == nil || e.Error() != "CONFLICT" {
		t.Fatal("conflict reminted")
	}
	w := h.send(request(false))
	if w.Code != 200 || h.calls.Load() != 1 {
		t.Fatal("valid neighbor refused", w.Code, w.Body.String())
	}
	v := h.status(t)
	if v.Exposure != (Counts{7, 3, 1, 23}) || v.Observed != (Usage{7, 3}) || v.InFlight {
		t.Fatal("usage not settled", v)
	}
	h.reopen(t)
	again, e = h.s.Prepare(h.b)
	if e != nil || again != h.cred || h.status(t).Exposure != v.Exposure {
		t.Fatal("restart lost binding/counters")
	}
	if e = h.s.Revoke(h.b); e != nil {
		t.Fatal(e)
	}
	h.reopen(t)
	if e = h.s.Activate(h.b); e == nil || e.Error() != "TERMINAL" {
		t.Fatal("revoke reactivated")
	}
	if w = h.send(request(false)); w.Code == 200 || h.calls.Load() != 1 {
		t.Fatal("revoked forwarded")
	}
}

// Unknown, wrong-route, not-yet-active, expired and revoked bearers have no
// upstream effects. Every fixture includes a valid active neighbor first.
func TestBearerRefusals(t *testing.T) {
	for _, kind := range []string{"unknown", "route", "prepared", "expired", "revoked", "clock"} {
		t.Run(kind, func(t *testing.T) {
			h := fixture(t)
			if h.send(request(false)).Code != 200 {
				t.Fatal("valid neighbor")
			}
			id, token := h.b.SlotID, h.cred.Bearer
			switch kind {
			case "unknown":
				token = "wrong"
			case "route":
				id = strings.Repeat("d", 64)
			case "prepared":
				h.s.mu.Lock()
				r := h.s.state.Records[id]
				r.Phase = "prepared"
				h.s.state.Records[id] = r
				h.s.mu.Unlock()
			case "expired":
				h.now.Store(h.b.NotAfter)
			case "revoked":
				if e := h.s.Revoke(h.b); e != nil {
					t.Fatal(e)
				}
			case "clock":
				h.now.Store(99)
			}
			w := h.sendAs(request(false), id, token)
			if w.Code != 401 || h.calls.Load() != 1 || strings.Contains(w.Body.String(), string(token)) {
				t.Fatal("unauthorized forwarded/leaked", w.Code)
			}
		})
	}
}

// Each cap accepts its exact reservation boundary and refuses one unit less
// before any upstream call. This proves admission arithmetic, not token prediction.
func TestCaps(t *testing.T) {
	for _, kind := range []string{"input", "output", "requests", "cost", "per-request"} {
		t.Run(kind, func(t *testing.T) {
			h := fixture(t)
			caps := Caps{100, 10, 1, 10, 230, 0}
			set := func(c Caps, prior Counts) {
				h.s.mu.Lock()
				r := h.s.state.Records[h.b.SlotID]
				r.Binding.Caps = c
				r.Exposure = prior
				h.s.state.Records[h.b.SlotID] = r
				h.s.mu.Unlock()
			}
			bad := caps
			prior := Counts{}
			switch kind {
			case "input":
				bad.InputTokens--
			case "output":
				prior.Output = 1
			case "requests":
				prior.Requests = 1
			case "cost":
				bad.CostNanoUSD--
			case "per-request":
				bad.MaxTokens--
			}
			set(bad, prior)
			if w := h.send(request(false)); w.Code != 403 || !strings.Contains(w.Body.String(), "CAP") || h.calls.Load() != 0 {
				t.Fatal("cap overrun forwarded")
			}
			set(caps, Counts{})
			if w := h.send(request(false)); w.Code != 200 || h.calls.Load() != 1 {
				t.Fatal("exact reservation neighbor refused", w.Code)
			}
			if w := h.send(request(false)); w.Code != 403 || h.calls.Load() != 1 {
				t.Fatal("used cap forwarded")
			}
		})
	}
}

// Unsupported unpriced fields and malformed/oversize inputs refuse before the
// upstream; client auth is independently checked by the positive fixture server.
func TestRequestProfile(t *testing.T) {
	h := fixture(t)
	for _, body := range []string{
		strings.Replace(request(false), `"max_tokens":10`, `"max_tokens":10,"max_tokens":1`, 1),
		strings.Replace(request(false), `"content":"private-prompt-marker"`, `"content":[{"type":"image","source":{}}]`, 1),
		strings.Replace(request(false), `"model":"test-model-1"`, `"model":"outside"`, 1),
		strings.Replace(request(false), `"stream":false`, `"stream":false,"cache_control":{"type":"ephemeral"}`, 1),
		strings.Replace(request(false), `"stream":false`, `"stream":false,"tools":[]`, 1),
		strings.Replace(request(false), `"stream":false`, `"stream":false,"service_tier":"priority"`, 1),
		strings.Replace(request(false), `"stream":false`, `"stream":false,"inference_geo":"us"`, 1),
		strings.Replace(request(false), `"max_tokens":10`, `"max_tokens":18446744073709551616`, 1),
		strings.Repeat(" ", MaxBody+1),
	} {
		w := h.send(body)
		if w.Code == 200 || h.calls.Load() != 0 {
			t.Fatal("invalid profile forwarded")
		}
	}
	if h.send(request(false)).Code != 200 {
		t.Fatal("valid profile neighbor")
	}
}
func sse(in, out uint64) string {
	return fmt.Sprintf("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"fixture\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"test-model-1\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":%d,\"output_tokens\":1}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"private-completion-marker\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":null},\"usage\":{\"output_tokens\":2}}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":%d}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n", in, out)
}

// Successful SSE settles the final cumulative count once. Truncated, malformed,
// unpriced or excessive usage retains the full reservation; errors are sanitized.
func TestStreamAccounting(t *testing.T) {
	for _, kind := range []string{"valid", "truncated", "regression", "over-bound", "server-error", "oversize", "unpriced"} {
		t.Run(kind, func(t *testing.T) {
			h := fixture(t)
			body := sse(7, 3)
			switch kind {
			case "truncated":
				body = strings.Split(body, "event: message_stop")[0]
			case "regression":
				body = sse(7, 1)
			case "over-bound":
				body = sse(101, 3)
			case "server-error":
				body = "event: error\ndata: {\"type\":\"error\",\"message\":\"" + keyMarker + "\"}\n\n"
			case "oversize":
				body = "data: " + strings.Repeat("x", MaxEvent+1) + "\n\n"
			case "unpriced":
				body = strings.Replace(body, `"input_tokens":7`, `"input_tokens":7,"cache_read_input_tokens":1`, 1)
			}
			h.response = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, body)
			}
			w := h.send(request(true))
			v := h.status(t)
			if kind == "valid" {
				if !strings.Contains(w.Body.String(), "event: message_stop") || v.Exposure != (Counts{7, 3, 1, 23}) {
					t.Fatal("cumulative stream not settled", v)
				}
			} else {
				if strings.Contains(w.Body.String(), "event: message_stop") || !strings.Contains(w.Body.String(), "proxy_error") || v.Exposure != (Counts{100, 10, 1, 230}) || v.InFlight {
					t.Fatal("uncertain stream refunded/completed", v)
				}
			}
			h.mu.Lock()
			logs := string(canonical(h.audits))
			h.mu.Unlock()
			for _, secret := range []string{keyMarker, string(h.cred.Bearer), "private-prompt-marker", "private-completion-marker"} {
				if strings.Contains(logs, secret) {
					t.Fatal("private content logged")
				}
			}
			if strings.Contains(w.Body.String(), keyMarker) {
				t.Fatal("upstream secret error echoed")
			}
		})
	}
}

// Uncertain HTTP responses and restart after a durable reservation never refund
// or retry generation. A completed neighboring request still settles normally.
func TestUncertainReservation(t *testing.T) {
	for _, kind := range []string{"http-error", "usage-missing", "usage-bound", "restart"} {
		t.Run(kind, func(t *testing.T) {
			h := fixture(t)
			if kind == "restart" {
				parsed, e := (Messages{}).Parse([]byte(request(false)))
				if e != nil {
					t.Fatal(e)
				}
				_, cancel, e := h.s.reserve(context.Background(), h.b.SlotID, h.cred.Bearer, parsed)
				if e != nil {
					t.Fatal(e)
				}
				cancel()
				h.reopen(t)
			} else {
				h.response = func(w http.ResponseWriter, r *http.Request) {
					switch kind {
					case "http-error":
						w.WriteHeader(500)
						io.WriteString(w, keyMarker)
					case "usage-missing":
						io.WriteString(w, `{"error":"`+keyMarker+`"}`)
					case "usage-bound":
						io.WriteString(w, reply(101, 3))
					}
				}
				if w := h.send(request(false)); w.Code != 502 || strings.Contains(w.Body.String(), keyMarker) {
					t.Fatal("uncertain error escaped")
				}
				h.reopen(t)
			}
			v := h.status(t)
			if v.Exposure != (Counts{100, 10, 1, 230}) || v.InFlight {
				t.Fatal("uncertain exposure refunded", v)
			}
			if kind == "usage-bound" {
				if v.Phase != "frozen" {
					t.Fatal("provider bound violation not frozen")
				}
				return
			}
			h.response = func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, reply(7, 3)) }
			if h.send(request(false)).Code != 200 {
				t.Fatal("valid recovery neighbor refused")
			}
			if h.status(t).Exposure != (Counts{107, 13, 2, 253}) {
				t.Fatal("recovery lost prior exposure")
			}
		})
	}
}

// A second concurrent call cannot spend the same reservation. Revoke interrupts
// an accepted request; its possible upstream cost remains charged across restart.
func TestConcurrentRevoke(t *testing.T) {
	h := fixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	h.response = func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
			io.WriteString(w, reply(7, 3))
		case <-r.Context().Done():
		}
	}
	finished := make(chan *httptest.ResponseRecorder, 1)
	go func() { finished <- h.send(request(false)) }()
	<-entered
	if w := h.send(request(false)); w.Code != 403 || !strings.Contains(w.Body.String(), "BUSY") || h.calls.Load() != 1 {
		t.Fatal("concurrent request double-spent")
	}
	if e := h.s.Revoke(h.b); e != nil {
		t.Fatal(e)
	}
	select {
	case w := <-finished:
		if w.Code != 502 {
			t.Fatal("revoked inflight succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revoke did not cancel")
	}
	close(release)
	h.reopen(t)
	if v := h.status(t); v.Phase != "revoked" || v.Exposure != (Counts{100, 10, 1, 230}) {
		t.Fatal("revoke lost exposure", v)
	}
}

// Corrupt/mismatched configuration cannot reopen a ledger. Missing model bounds
// or prices refuse startup; the pinned fixture demonstrates a valid neighbor.
func TestConfiguration(t *testing.T) {
	h := fixture(t)
	h.s.Close()
	for _, kind := range []string{"bound", "price", "source", "endpoint", "config-change"} {
		c := h.c
		c.Models = map[string]Model{modelID: h.c.Models[modelID]}
		m := c.Models[modelID]
		switch kind {
		case "bound":
			m.ContextTokens = 0
		case "price":
			m.InputNanoUSD = 0
		case "source":
			m.Source = ""
		case "endpoint":
			c.Endpoint.URL += "/path"
		case "config-change":
			m.ContextTokens++
		}
		c.Models[modelID] = m
		if s, e := New(c); e == nil {
			s.Close()
			t.Fatal("invalid configuration accepted", kind)
		}
	}
	h.reopen(t)
	if h.send(request(false)).Code != 200 {
		t.Fatal("valid configured neighbor")
	}
}

// No Create/generation authority follows a failed durable reservation write.
func TestWriteBeforeForward(t *testing.T) {
	h := fixture(t)
	path := h.c.StateDir + "/registry.json"
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(path, 0400); e != nil {
		t.Fatal(e)
	}
	if w := h.send(request(false)); w.Code == 200 || h.calls.Load() != 0 {
		t.Fatal("failed state write forwarded")
	}
	after, e := os.ReadFile(path)
	if e != nil || string(before) != string(after) {
		t.Fatal("failed reservation partially wrote")
	}
	if e = os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	h.reopen(t)
	if h.status(t).Exposure != (Counts{}) || h.send(request(false)).Code != 200 {
		t.Fatal("valid durable neighbor failed")
	}
}
