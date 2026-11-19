//go:build linux

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// Claim: a structurally reconstructed client body with the measured beta header
// crosses serveGateway unchanged; scope refusals leave its priced control usable.
// This fixture is not a captured body or a live-client/provider qualification.
func TestGatewayComposedClaudeCodeCacheScope(t *testing.T) {
	raw, err := os.ReadFile("testdata/claude-code-2.1.328-messages.json")
	if err != nil {
		t.Fatal("client structure fixture unavailable")
	}
	var fixture struct {
		Beta string                     `json:"anthropic_beta"`
		Body map[string]json.RawMessage `json:"body"`
	}
	if json.Unmarshal(raw, &fixture) != nil || fixture.Beta == "" {
		t.Fatal("client structure fixture invalid")
	}
	var calls atomic.Int32
	var forwarded, beta atomic.Value
	intakeUpstream(t, func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil || request.Header.Get("Authorization") != "Bearer "+brokerCanary {
			t.Error("client structure upstream boundary failed")
		}
		forwarded.Store(string(body))
		beta.Store(request.Header.Get("Anthropic-Beta"))
		_, _ = io.WriteString(writer, `{"echo":"`+request.Header.Get("Authorization")+`"}`)
	})
	for _, sample := range []struct {
		name, control string
		cost          uint64
	}{
		{"plain", `{"type":"ephemeral"}`, 280},
		{"global", `{"type":"ephemeral","scope":"global"}`, 280},
		{"global-5m", `{"type":"ephemeral","scope":"global","ttl":"5m"}`, 280},
		{"global-1h", `{"type":"ephemeral","scope":"global","ttl":"1h"}`, 430},
		{"unknown", `{"type":"ephemeral","scope":"other"}`, 0},
		{"case-value", `{"type":"ephemeral","scope":"Global"}`, 0},
		{"alias", `{"type":"ephemeral","Scope":"global"}`, 0},
		{"extra-member", `{"type":"ephemeral","scope":"global","future":true}`, 0},
	} {
		t.Run(sample.name, func(t *testing.T) {
			makeBody := func(control string) string {
				var system []map[string]json.RawMessage
				if json.Unmarshal(fixture.Body["system"], &system) != nil {
					t.Fatal("client system fixture invalid")
				}
				system[0]["cache_control"] = json.RawMessage(control)
				blocks, marshalErr := json.Marshal(system)
				if marshalErr != nil {
					t.Fatal("client system fixture encoding failed")
				}
				fixture.Body["system"] = blocks
				body, marshalErr := json.Marshal(fixture.Body)
				if marshalErr != nil {
					t.Fatal("client request fixture encoding failed")
				}
				return string(body)
			}
			cost := sample.cost
			if cost == 0 {
				cost = 280
			}
			client := startIntake(t, startBroker(t), gatewayConfig(t, cost))
			before := calls.Load()
			send := func(body string, status int, expectedCalls int32) {
				request := composedMessages(t, body)
				request.Header.Set("Anthropic-Beta", fixture.Beta)
				response, transportErr := client.Do(request)
				if transportErr != nil {
					t.Fatal("client scope transport failed")
				}
				worker, readErr := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if readErr != nil || response.StatusCode != status || calls.Load() != before+expectedCalls {
					t.Fatal("client scope admission or reservation boundary failed")
				}
				if strings.Contains(string(worker), brokerCanary) || strings.Contains(string(worker), renewedCanary) {
					t.Fatal("client scope response crossed the secret boundary")
				}
				if status == 403 && string(worker) != "GATEWAY_REFUSED\n" {
					t.Fatal("client scope refusal was not constant")
				}
				if status == 200 && (forwarded.Load() != body || beta.Load() != fixture.Beta) {
					t.Fatal("client scope body or measured beta header changed")
				}
			}
			body := makeBody(sample.control)
			if sample.cost == 0 {
				send(body, 403, 0)
				body = makeBody(`{"type":"ephemeral","scope":"global"}`)
			}
			send(body, 200, 1)
			send(body, 403, 1)
		})
	}
}
