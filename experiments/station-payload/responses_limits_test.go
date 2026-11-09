package payload

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
)

// Valid JSON followed by whitespace isolates the byte cap from JSON validation:
// the bounded reader prefix would otherwise still be a complete valid reply.
func TestResponsesBodyLimit(t *testing.T) {
	calls := 0
	c := responsesClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, responsesReply)
		if calls == 2 {
			io.WriteString(w, strings.Repeat(" ", proxy.MaxResponse))
		}
	})
	if out, e := c.Respond(context.Background(), prompt); out != answer || e != nil {
		t.Fatal("Responses size neighbor")
	}
	if out, e := c.Respond(context.Background(), prompt); out != "" || e != ErrResponse {
		t.Fatal("Responses oversized body released")
	}
}

// Responses preserves the 32KiB decoded text bound while admitting JSON escape
// expansion below MP2's larger body cap. Invalid input has no HTTP effects.
func TestResponsesInputLimits(t *testing.T) {
	f, cfg := newResponsesFixture(t)
	c, e := NewPinned(encoded(t, f.doc), Options{Model: modelID, MaxTokens: 10, Roots: f.roots}, DialectResponses, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	for _, input := range []string{strings.Repeat("x", MaxText+1), string([]byte{255})} {
		if out, e := c.Respond(context.Background(), input); out != "" || e != ErrRequest {
			t.Fatal("Responses invalid input forwarded")
		}
	}
	if f.requests.Load() != 0 {
		t.Fatal("Responses invalid input had effects")
	}
	if out, e := c.Respond(context.Background(), strings.Repeat("<", MaxText)); out != answer || e != nil {
		t.Fatal("Responses bounded escaped text refused", e)
	}
}

// A completed response with valid usage but no output has no text to deliver.
func TestResponsesEmptyOutput(t *testing.T) {
	calls := 0
	c := responsesClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		if calls == 1 {
			io.WriteString(w, responsesReply)
			return
		}
		io.WriteString(w, `{"id":"resp_fixture","object":"response","model":"fixture-model-1","status":"completed","output":[],"usage":{"input_tokens":7,"output_tokens":3,"total_tokens":10}}`)
	})
	if out, e := c.Respond(context.Background(), prompt); out != answer || e != nil {
		t.Fatal("Responses empty-output neighbor")
	}
	if out, e := c.Respond(context.Background(), prompt); out != "" || e != ErrResponse {
		t.Fatal("Responses empty output accepted")
	}
}
