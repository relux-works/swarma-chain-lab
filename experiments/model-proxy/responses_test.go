package modelproxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type responsesHarness struct {
	s     *Service
	c     Config
	b     Binding
	cred  Credential
	now   atomic.Int64
	calls atomic.Int32
	reply func(http.ResponseWriter, *http.Request)
}

func responsesFixture(t *testing.T) *responsesHarness {
	t.Helper()
	h := &responsesHarness{}
	h.now.Store(100)
	h.reply = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, responseFrames(false, 7, 3))
	}
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer "+keyMarker || r.Header.Get("OpenAI-Organization") != "" || r.Header.Get("x-api-key") != "" || r.Header.Get("OpenAI-Beta") != "" {
			t.Error("Responses provider header/path escaped")
		}
		raw, e := io.ReadAll(r.Body)
		m, err := object(raw)
		if e != nil || err != nil || string(m["store"]) != "false" || string(m["background"]) != "false" || string(m["service_tier"]) != `"default"` {
			t.Error("Responses priced profile not pinned")
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		h.reply(w, r)
	}))
	t.Cleanup(up.Close)
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	h.c = Config{StateDir: root, Endpoint: Endpoint{"https://proxy.example", strings.Repeat("a", 64)}, Upstream: up.URL + "/v1/responses", APIKey: keyMarker,
		Models:        map[string]Model{modelID: {100, 2, 3, "synthetic fixture prices"}},
		ModelProfiles: map[string]ModelProfile{modelID: {OpenAIResponsesProfile, up.URL + "/v1/responses"}},
		Now:           func() time.Time { return time.Unix(h.now.Load(), 0) }, Timeout: time.Second, Transport: up.Client().Transport,
		Audit: func(a Audit) {
			if a.Code != "OK" && a.Code != "STREAM" && a.Code != "USAGE" && a.Code != "AUTH" && a.Code != "CAP" && a.Code != "REQUEST" && a.Code != "BODY" && a.Code != "PROFILE" && a.Code != "UPSTREAM" && a.Code != "ROUTE" && a.Code != "BUSY" {
				t.Error("Responses private audit content")
			}
		},
	}
	var e error
	h.s, e = New(h.c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { h.s.Close() })
	h.b = Binding{strings.Repeat("b", 64), strings.Repeat("c", 64), 90, 1000, Caps{1000, 1000, 10, 10, 10000}}
	h.cred, e = h.s.Prepare(h.b)
	if e != nil {
		t.Fatal(e)
	}
	if e = h.s.Activate(h.b); e != nil {
		t.Fatal(e)
	}
	return h
}
func (h *responsesHarness) send(body string) *httptest.ResponseRecorder {
	return h.sendAs(body, h.b.SlotID, h.cred.Bearer, "responses")
}
func (h *responsesHarness) sendAs(body, id string, bearer Secret, route string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://proxy.example/slots/"+id+"/v1/"+route, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+string(bearer))
	r.Header.Set("OpenAI-Organization", "client-organization")
	r.Header.Set("OpenAI-Beta", "client-beta")
	r.Header.Set("x-api-key", "client-key")
	w := httptest.NewRecorder()
	h.s.ServeHTTP(w, r)
	return w
}
func (h *responsesHarness) status(t *testing.T) Status {
	t.Helper()
	s, e := h.s.Status(h.b.SlotID)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func responsesRequest(stream bool, tools bool) string {
	m := map[string]any{"model": modelID, "input": "private-request-marker", "stream": stream, "max_output_tokens": 10}
	if tools {
		m["tools"] = []any{map[string]any{"type": "function", "name": "lookup", "description": "Synthetic fixture", "strict": true, "parameters": map[string]any{"type": "object", "properties": map[string]any{"x": map[string]any{"type": "integer"}}, "required": []string{"x"}, "additionalProperties": false}}}
	}
	return string(canonical(m))
}
func responseOutput(tool bool, start bool) map[string]any {
	status := "completed"
	if start {
		status = "in_progress"
	}
	if tool {
		args := `{"x":1}`
		if start {
			args = ""
		}
		return map[string]any{"id": "fc_fixture", "type": "function_call", "status": status, "call_id": "call_fixture", "name": "lookup", "arguments": args}
	}
	content := []any{}
	if !start {
		content = append(content, map[string]any{"type": "output_text", "text": "answer", "annotations": []any{}, "logprobs": []any{}})
	}
	return map[string]any{"id": "msg_fixture", "type": "message", "role": "assistant", "status": status, "content": content}
}
func responseJSON(tool bool, start bool, in, out uint64) map[string]any {
	status := "completed"
	output := []any{responseOutput(tool, false)}
	var usage any = map[string]any{"input_tokens": in, "output_tokens": out, "total_tokens": in + out, "input_tokens_details": map[string]any{"cached_tokens": uint64(0)}, "output_tokens_details": map[string]any{"reasoning_tokens": uint64(0)}}
	if start {
		status = "in_progress"
		output = []any{}
		usage = nil
	}
	return map[string]any{"id": "resp_fixture", "object": "response", "model": modelID, "status": status, "output": output, "usage": usage, "store": false, "background": false, "service_tier": "default", "error": nil, "incomplete_details": nil, "max_output_tokens": 10}
}
func responseEvents(tool bool, in, out uint64) []map[string]any {
	events := []map[string]any{
		{"type": "response.created", "response": responseJSON(tool, true, 0, 0)},
		{"type": "response.in_progress", "response": responseJSON(tool, true, 0, 0)},
		{"type": "response.output_item.added", "output_index": 0, "item": responseOutput(tool, true)},
	}
	if tool {
		events = append(events, map[string]any{"type": "response.function_call_arguments.delta", "output_index": 0, "item_id": "fc_fixture", "delta": `{"x":1}`}, map[string]any{"type": "response.function_call_arguments.done", "output_index": 0, "item_id": "fc_fixture", "arguments": `{"x":1}`})
	} else {
		events = append(events,
			map[string]any{"type": "response.content_part.added", "output_index": 0, "item_id": "msg_fixture", "content_index": 0, "part": map[string]any{"type": "output_text", "text": "", "annotations": []any{}, "logprobs": []any{}}},
			map[string]any{"type": "response.output_text.delta", "output_index": 0, "item_id": "msg_fixture", "content_index": 0, "delta": "answer", "logprobs": []any{}},
			map[string]any{"type": "response.output_text.done", "output_index": 0, "item_id": "msg_fixture", "content_index": 0, "text": "answer", "logprobs": []any{}},
			map[string]any{"type": "response.content_part.done", "output_index": 0, "item_id": "msg_fixture", "content_index": 0, "part": map[string]any{"type": "output_text", "text": "answer", "annotations": []any{}, "logprobs": []any{}}},
		)
	}
	events = append(events, map[string]any{"type": "response.output_item.done", "output_index": 0, "item": responseOutput(tool, false)}, map[string]any{"type": "response.completed", "response": responseJSON(tool, false, in, out)})
	for i, e := range events {
		e["sequence_number"] = i
	}
	return events
}
func encodeEvents(events []map[string]any, named bool) string {
	var b strings.Builder
	for _, e := range events {
		if named {
			fmt.Fprintf(&b, "event: %s\n", e["type"])
		}
		fmt.Fprintf(&b, "data: %s\n\n", canonical(e))
	}
	return b.String()
}
func responseFrames(tool bool, in, out uint64) string {
	return encodeEvents(responseEvents(tool, in, out), true)
}

// Two actual TLS calls demonstrate stateless function history and separately
// charged tool-result turns; terminal success follows durable settlement.
func TestResponsesToolRoundTrip(t *testing.T) {
	h := responsesFixture(t)
	h.reply = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, responseFrames(true, 7, 3))
	}
	body := responsesRequest(true, true)
	if w := h.send(body); !strings.Contains(w.Body.String(), "response.completed") || strings.Contains(w.Body.String(), "proxy_stream") {
		t.Fatal("Responses valid tool neighbor refused")
	}
	m, _ := object([]byte(body))
	m["input"] = canonical([]any{map[string]any{"role": "user", "content": "lookup"}, responseOutput(true, false), map[string]any{"type": "function_call_output", "call_id": "call_fixture", "output": "synthetic result"}})
	h.reply = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, encodeEvents(responseEvents(false, 7, 3), false))
	}
	if w := h.send(string(canonical(m))); !strings.Contains(w.Body.String(), "response.completed") || strings.Contains(w.Body.String(), "proxy_stream") {
		t.Fatal("Responses tool output neighbor refused")
	}
	v := h.status(t)
	if h.calls.Load() != 2 || v.Exposure != (Counts{14, 6, 2, 46}) || v.Observed != (Usage{14, 6}) || v.InFlight {
		t.Fatal("Responses tool turns not settled")
	}
	h.s.Close()
	var e error
	h.s, e = New(h.c)
	if e != nil {
		t.Fatal(e)
	}
	if h.status(t).Exposure != v.Exposure {
		t.Fatal("Responses restart lost settlement")
	}
}

// Forbidden requests have no upstream effect or accounting change; each case
// first proves the same configured service accepts its valid neighbor.
func TestResponsesRequestRefusals(t *testing.T) {
	for _, kind := range []string{"hosted", "image", "tier", "store", "background", "unknown", "duplicate", "null", "tool-output", "function-name", "tool-schema", "large"} {
		t.Run(kind, func(t *testing.T) {
			h := responsesFixture(t)
			body := responsesRequest(true, true)
			if w := h.send(body); strings.Contains(w.Body.String(), "proxy_stream") {
				t.Fatal("Responses request positive neighbor")
			}
			before := h.status(t).Exposure
			m, _ := object([]byte(body))
			switch kind {
			case "hosted":
				m["tools"] = json.RawMessage(`[{"type":"web_search","name":"lookup","parameters":{}}]`)
			case "image":
				m["input"] = json.RawMessage(`[{"role":"user","content":[{"type":"input_image","image_url":"https://example.invalid/image"}]}]`)
			case "tier":
				m["service_tier"] = json.RawMessage(`"priority"`)
			case "store":
				m["store"] = json.RawMessage("false")
			case "background":
				m["background"] = json.RawMessage("false")
			case "unknown":
				m["previous_response_id"] = json.RawMessage(`"resp_other"`)
			case "null":
				m["stream"] = json.RawMessage("null")
			case "tool-output":
				m["input"] = json.RawMessage(`[{"type":"function_call_output","call_id":"missing","output":"x"}]`)
			case "function-name":
				m["input"] = json.RawMessage(`[{"type":"function_call","call_id":"call_x","name":"undeclared","arguments":"{}"}]`)
			case "tool-schema":
				m["tools"] = json.RawMessage(`[{"type":"function","name":"lookup","parameters":[],"unknown":true}]`)
			}
			body = string(canonical(m))
			if kind == "duplicate" {
				body = strings.Replace(body, `"model":`, `"model":"other","model":`, 1)
			}
			if kind == "large" {
				m["input"] = canonical(strings.Repeat("x", MaxResponsesBody))
				body = string(canonical(m))
			}
			w := h.send(body)
			if w.Code != 400 && w.Code != 413 {
				t.Fatal("Responses invalid request forwarded")
			}
			if h.calls.Load() != 1 || h.status(t).Exposure != before {
				t.Fatal("Responses rejected request had effects")
			}
		})
	}
}

// Invalid/truncated streams never release a success terminal or refund uncertain
// exposure. Named/data-only positive streams are covered by the round trip.
func TestResponsesStreamRefusals(t *testing.T) {
	for _, kind := range []string{"missing-terminal", "after-terminal", "done-sentinel", "unknown", "sequence", "item-id", "arguments", "text", "usage-missing", "usage-negative", "usage-total", "usage-detail", "frame", "model", "output", "truncated", "tier"} {
		t.Run(kind, func(t *testing.T) {
			h := responsesFixture(t)
			if w := h.send(responsesRequest(true, true)); strings.Contains(w.Body.String(), "proxy_stream") {
				t.Fatal("Responses stream positive neighbor")
			}
			tool := kind == "arguments"
			ev := responseEvents(tool, 7, 3)
			switch kind {
			case "missing-terminal":
				ev = ev[:len(ev)-1]
			case "unknown":
				last := ev[len(ev)-1]
				ev[len(ev)-1] = map[string]any{"type": "response.unknown"}
				ev = append(ev, last)
				for i := range ev {
					ev[i]["sequence_number"] = i
				}
			case "sequence":
				ev[3]["sequence_number"] = 1
			case "item-id":
				ev[3]["item_id"] = "other"
			case "arguments":
				ev[4]["arguments"] = `{"x":2}`
			case "text":
				ev[5]["text"] = "different"
			case "usage-missing":
				delete(ev[len(ev)-1]["response"].(map[string]any), "usage")
			case "usage-negative":
				ev[len(ev)-1]["response"].(map[string]any)["usage"].(map[string]any)["input_tokens"] = -1
			case "usage-total":
				ev[len(ev)-1]["response"].(map[string]any)["usage"].(map[string]any)["total_tokens"] = 11
			case "usage-detail":
				ev[len(ev)-1]["response"].(map[string]any)["usage"].(map[string]any)["input_tokens_details"] = map[string]any{"cached_tokens": 8}
			case "frame":
				// Oversized aggregate frame with individually bounded lines;
				// this exercises the frame cap, not bufio's separate line cap.
			case "model":
				ev[0]["response"].(map[string]any)["model"] = "other"
			case "output":
				output := responseOutput(false, false)
				output["content"].([]any)[0].(map[string]any)["text"] = "different"
				ev[len(ev)-1]["response"].(map[string]any)["output"] = []any{output}
			case "tier":
				ev[len(ev)-1]["response"].(map[string]any)["service_tier"] = "priority"
			}
			stream := encodeEvents(ev, true)
			if kind == "frame" {
				stream = ":" + strings.Repeat("x", MaxResponsesEvent/2) + "\n:" + strings.Repeat("x", MaxResponsesEvent/2) + "\n" + stream
			}
			if kind == "after-terminal" {
				stream += encodeEvents(ev[:1], true)
			}
			if kind == "done-sentinel" {
				stream += "data: [DONE]\n\n"
			}
			if kind == "truncated" {
				stream = strings.TrimSuffix(stream, "\n\n")
			}
			h.reply = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, stream)
			}
			w := h.send(responsesRequest(true, true))
			if !strings.Contains(w.Body.String(), "proxy_stream") || strings.Contains(w.Body.String(), "response.completed") {
				t.Fatal("Responses invalid stream released success")
			}
			v := h.status(t)
			if v.Exposure != (Counts{107, 13, 2, 253}) || v.Observed != (Usage{7, 3}) || v.InFlight {
				t.Fatal("Responses uncertain exposure refunded")
			}
		})
	}
}

// Valid usage is settled; reported over-reservation usage freezes the slot
// before the terminal is released, including while the upstream is still open.
func TestResponsesUsageFreeze(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			h := responsesFixture(t)
			h.reply = func(w http.ResponseWriter, r *http.Request) {
				if stream {
					w.Header().Set("Content-Type", "text/event-stream")
					io.WriteString(w, responseFrames(false, 101, 3))
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				} else {
					io.WriteString(w, string(canonical(responseJSON(false, false, 101, 3))))
				}
			}
			w := h.send(responsesRequest(stream, false))
			if strings.Contains(w.Body.String(), "response.completed") || (stream && !strings.Contains(w.Body.String(), "proxy_stream")) || (!stream && w.Code != 502) {
				t.Fatal("Responses overrun terminal released")
			}
			v := h.status(t)
			if v.Phase != "frozen" || v.Exposure != (Counts{100, 10, 1, 230}) || v.InFlight {
				t.Fatal("Responses overrun did not freeze")
			}
			if h.send(responsesRequest(stream, false)).Code != 401 || h.calls.Load() != 1 {
				t.Fatal("Responses frozen slot reused")
			}
		})
	}
}

// Responses uses the same bound bearer and caps as MP1; changing a route cannot
// select a different profile or reset the durable request count.
func TestResponsesAuthAndCaps(t *testing.T) {
	for _, kind := range []string{"expired", "revoked", "wrong-bearer", "wrong-slot", "route", "cap"} {
		t.Run(kind, func(t *testing.T) {
			h := responsesFixture(t)
			if w := h.send(responsesRequest(true, false)); strings.Contains(w.Body.String(), "proxy_stream") {
				t.Fatal("Responses auth positive neighbor")
			}
			id, bearer, route := h.b.SlotID, h.cred.Bearer, "responses"
			switch kind {
			case "expired":
				h.now.Store(h.b.NotAfter)
			case "revoked":
				if e := h.s.Revoke(h.b); e != nil {
					t.Fatal(e)
				}
			case "wrong-bearer":
				bearer = "wrong"
			case "wrong-slot":
				id = strings.Repeat("d", 64)
			case "route":
				route = "messages"
			case "cap":
				h.s.mu.Lock()
				rec := h.s.state.Records[id]
				rec.Binding.Caps.Requests = 1
				h.s.state.Records[id] = rec
				h.s.mu.Unlock()
			}
			body := responsesRequest(true, false)
			if kind == "route" {
				body = request(false)
			}
			w := h.sendAs(body, id, bearer, route)
			expected := 401
			if kind == "route" {
				expected = 400
			}
			if kind == "cap" {
				expected = 403
			}
			if w.Code != expected || h.calls.Load() != 1 {
				t.Fatal("Responses auth/cap/route bypass")
			}
		})
	}
}

// Explicit model profiles bind restart identity; omission leaves the historical
// fingerprint and canonical config unchanged. This is not a state migration.
func TestResponsesProfileConfiguration(t *testing.T) {
	t.Run("fingerprint", func(t *testing.T) {
		h := responsesFixture(t)
		h.s.Close()
		c := h.c
		c.ModelProfiles = map[string]ModelProfile{modelID: {OpenAIResponsesProfile, "https://other.example/v1/responses"}}
		s, e := New(c)
		if e == nil {
			s.Close()
			t.Fatal("Responses fingerprint drift accepted")
		}
		if e.Error() != "STATE" {
			t.Fatal("unexpected fingerprint refusal")
		}
		s, e = New(h.c)
		if e != nil {
			t.Fatal("Responses unchanged profile restart refused")
		}
		h.s = s
	})
	t.Run("legacy", func(t *testing.T) {
		h := fixture(t)
		old := sum(canonical([]any{h.c.Endpoint, h.c.Upstream, h.c.Models, (Messages{}).Profile()}))
		if h.s.state.Config != old {
			t.Fatal("legacy fingerprint changed")
		}
		if strings.Contains(string(canonical(FileConfig{})), "model_profiles") {
			t.Fatal("legacy config bytes changed")
		}
		if h.s.cfg.ModelProfiles[modelID].Profile != "" {
			t.Fatal("legacy profile changed")
		}
		h.reopen(t)
		if h.send(request(false)).Code != 200 {
			t.Fatal("legacy neighbor refused")
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/slots/"+h.b.SlotID+"/v1/responses", strings.NewReader(responsesRequest(true, false)))
		r.Header.Set("Authorization", "Bearer "+string(h.cred.Bearer))
		h.s.ServeHTTP(w, r)
		if w.Code != 400 || h.calls.Load() != 1 {
			t.Fatal("Messages model used through Responses")
		}
	})
	for _, kind := range []string{"unknown-profile", "unknown-model", "http", "path", "mismatch"} {
		t.Run(kind, func(t *testing.T) {
			h := responsesFixture(t)
			h.s.Close()
			c := h.c
			c.StateDir = t.TempDir()
			if e := os.Chmod(c.StateDir, 0700); e != nil {
				t.Fatal(e)
			}
			p := c.ModelProfiles[modelID]
			key := modelID
			switch kind {
			case "unknown-profile":
				p.Profile = "meta-unqualified"
			case "unknown-model":
				key = "other"
			case "http":
				p.Upstream = "http://example.invalid/v1/responses"
			case "path":
				p.Upstream = "https://example.invalid/v1/messages"
			case "mismatch":
				c.Upstream = "https://example.invalid/v1/messages"
			}
			c.ModelProfiles = map[string]ModelProfile{key: p}
			s, e := New(c)
			if e == nil {
				s.Close()
				t.Fatal("Responses invalid profile accepted")
			}
			if e.Error() != "CONFIG_PROFILE" {
				t.Fatal("unexpected profile refusal")
			}
		})
	}
}

// Nonstreaming text/function completions and long bounded input use the same
// accounting as streaming; these fixtures do not qualify a real coding CLI.
func TestResponsesCompleteAndLongInput(t *testing.T) {
	for _, tool := range []bool{false, true} {
		h := responsesFixture(t)
		h.reply = func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, string(canonical(responseJSON(tool, false, 7, 3))))
		}
		m, _ := object([]byte(responsesRequest(false, tool)))
		m["input"] = canonical(strings.Repeat("x", MaxBody+1))
		if w := h.send(string(canonical(m))); w.Code != 200 {
			t.Fatal("Responses long input refused")
		}
		if h.status(t).Exposure != (Counts{7, 3, 1, 23}) {
			t.Fatal("Responses complete not settled")
		}
	}
}

// Expiry/revocation cancels a blocked real TLS stream and preserves its full
// reservation. A concurrent request cannot create a second upstream call.
func TestResponsesInFlightClosure(t *testing.T) {
	for _, kind := range []string{"expired", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			h := responsesFixture(t)
			started := make(chan struct{})
			h.reply = func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, encodeEvents(responseEvents(false, 7, 3)[:1], true))
				w.(http.Flusher).Flush()
				close(started)
				<-r.Context().Done()
			}
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- h.send(responsesRequest(true, false)) }()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
				t.Fatal("Responses upstream did not start")
			}
			w := h.send(responsesRequest(true, false))
			if w.Code != 403 || !strings.Contains(w.Body.String(), "BUSY") || h.calls.Load() != 1 {
				t.Fatal("Responses parallel request forwarded")
			}
			if kind == "expired" {
				h.now.Store(h.b.NotAfter)
			} else if e := h.s.Revoke(h.b); e != nil {
				t.Fatal(e)
			}
			select {
			case w = <-done:
				if !strings.Contains(w.Body.String(), "proxy_stream") || strings.Contains(w.Body.String(), "response.completed") {
					t.Fatal("Responses closed stream released success")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Responses closed stream remained blocked")
			}
			v := h.status(t)
			if v.Exposure != (Counts{100, 10, 1, 230}) || v.Observed != (Usage{}) || v.InFlight {
				t.Fatal("Responses closed stream refunded reservation")
			}
			if h.send(responsesRequest(true, false)).Code != 401 || h.calls.Load() != 1 {
				t.Fatal("Responses closed credential reused")
			}
		})
	}
}
