package payload

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
)

const responsesReply = `{"id":"resp_fixture","object":"response","model":"fixture-model-1","status":"completed","output":[{"id":"msg_fixture","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"private-answer-marker","annotations":[]}]}],"usage":{"input_tokens":7,"output_tokens":3,"total_tokens":10}}`

func responsesClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	f := newFixture(t)
	front := httptest.NewTLSServer(h)
	t.Cleanup(front.Close)
	f.doc.ModelEndpoint = front.URL
	f.doc.ModelCertSHA256 = pin(front.Certificate())
	f.roots.AddCert(front.Certificate())
	config := proxy.FileConfig{Endpoint: proxy.Endpoint{URL: front.URL, CertSHA256: f.doc.ModelCertSHA256}, Models: map[string]proxy.Model{modelID: {ContextTokens: 100}}, ModelProfiles: map[string]proxy.ModelProfile{modelID: {Profile: proxy.OpenAIResponsesProfile, Upstream: "https://upstream.invalid/v1/responses"}}}
	c, e := NewPinned(encoded(t, f.doc), Options{Model: modelID, MaxTokens: 10, Roots: f.roots}, DialectResponses, config)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return c
}

// The nonstream client sends only one user string and operator model/output
// limit. The bootstrap bearer stays on the pinned slot route; no provider key.
func TestResponsesRequest(t *testing.T) {
	calls := 0
	c := responsesClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		b, _ := io.ReadAll(r.Body)
		var q map[string]json.RawMessage
		if json.Unmarshal(b, &q) != nil || len(q) != 4 || string(q["model"]) != `"`+modelID+`"` || string(q["input"]) != `"`+prompt+`"` || string(q["stream"]) != "false" || string(q["max_output_tokens"]) != "10" {
			t.Error("Responses request shape changed")
		}
		if r.URL.Path != "/slots/"+strings.Repeat("b", 64)+"/v1/responses" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || r.Header.Get("x-api-key") != "" {
			t.Error("Responses route/auth boundary")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, responsesReply)
	})
	out, e := c.Respond(context.Background(), prompt)
	if e != nil || out != answer || calls != 1 {
		t.Fatal("Responses valid neighbor refused", e)
	}
}

// Each malformed/unsupported response has a valid neighbor and must release no
// text. Refusals have a fixed code; local response errors do not latch/retry.
func TestResponsesBodyRefusals(t *testing.T) {
	cases := map[string]string{
		"tool":          strings.Replace(responsesReply, `{"id":"msg_fixture","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"private-answer-marker","annotations":[]}]}`, `{"id":"call_fixture","type":"function_call","status":"completed","call_id":"call1","name":"tool","arguments":"{}"}`, 1),
		"refusal":       strings.Replace(responsesReply, `{"type":"output_text","text":"private-answer-marker","annotations":[]}`, `{"type":"refusal","refusal":"private-refusal-marker"}`, 1),
		"usage-missing": strings.Replace(responsesReply, `,"usage":{"input_tokens":7,"output_tokens":3,"total_tokens":10}`, "", 1),
		"usage-invalid": strings.Replace(responsesReply, `"total_tokens":10`, `"total_tokens":11`, 1),
		"incomplete":    strings.Replace(responsesReply, `"status":"completed"`, `"status":"incomplete"`, 1),
		"unknown":       strings.Replace(responsesReply, `"type":"message"`, `"type":"unknown"`, 1),
		"model":         strings.Replace(responsesReply, modelID, "wrong-model", 1),
		"text-bound":    strings.Replace(responsesReply, answer, strings.Repeat("x", MaxText+1), 1),
		"body-bound":    strings.Repeat("x", proxy.MaxResponse+1),
		"truncated":     responsesReply[:len(responsesReply)-1],
		"duplicate":     strings.Replace(responsesReply, `"status":"completed"`, `"status":"completed","status":"completed"`, 1),
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			c := responsesClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Content-Type", "application/json")
				if calls == 2 {
					io.WriteString(w, bad)
				} else {
					io.WriteString(w, responsesReply)
				}
			})
			if out, e := c.Respond(context.Background(), prompt); e != nil || out != answer {
				t.Fatal("Responses response neighbor refused")
			}
			want := error(ErrResponse)
			if name == "refusal" {
				want = Code("MODEL_REFUSAL")
			}
			if out, e := c.Respond(context.Background(), prompt); out != "" || e != want {
				t.Fatal("Responses invalid output escaped", e)
			}
			if out, e := c.Respond(context.Background(), prompt); out != answer || e != nil || calls != 3 {
				t.Fatal("Responses nonterminal failure latched/retried", e)
			}
		})
	}
}

// Exact proxy CAP and AUTH bodies latch after the first refusal; arbitrary
// provider text never becomes an error. PROFILE maps only its fixed status/body.
func TestResponsesRefusalMapping(t *testing.T) {
	for _, v := range []struct {
		name     string
		status   int
		body     string
		want     error
		terminal bool
	}{
		{"cap", 403, `{"error":"CAP"}`, Code("MODEL_CAP"), true},
		{"auth", 401, `{"error":"AUTH"}`, Code("MODEL_AUTH"), true},
		{"profile", 400, `{"error":"PROFILE"}`, Code("MODEL_PROFILE"), false},
		{"unknown", 403, `{"error":"private-provider-marker"}`, ErrResponse, false},
	} {
		t.Run(v.name, func(t *testing.T) {
			calls := 0
			c := responsesClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Content-Type", "application/json")
				if calls == 1 {
					io.WriteString(w, responsesReply)
					return
				}
				w.WriteHeader(v.status)
				io.WriteString(w, v.body)
			})
			if _, e := c.Respond(context.Background(), prompt); e != nil {
				t.Fatal("Responses refusal neighbor")
			}
			for i := 0; i < 2; i++ {
				if out, e := c.Respond(context.Background(), prompt); out != "" || e != v.want {
					t.Fatal("Responses refusal mapping escaped", e)
				}
			}
			want := 3
			if v.terminal {
				want = 2
			}
			if calls != want {
				t.Fatal("Responses terminal refusal retried")
			}
		})
	}
}
