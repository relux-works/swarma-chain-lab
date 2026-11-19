//go:build linux

package main

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// Claim: production intake rejects ambiguous meter fields and unpriced request
// modifiers before forwarding; priced bytes survive unchanged and spend the
// full 473-unit cache/US bound, not the former 230-unit base reservation.
func TestGatewayComposedPricingBoundary(t *testing.T) {
	var calls atomic.Int32
	var forwarded atomic.Value
	intakeUpstream(t, func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(request.Body)
		forwarded.Store(string(body))
		_, _ = io.WriteString(writer, `{"echo":"`+request.Header.Get("Authorization")+`"}`)
	})
	client := startIntake(t, startBroker(t), gatewayConfig(t, 473))
	for _, body := range []string{
		`{"model":"unlisted","Model":"test-model-1","max_tokens":1}`,
		`{"model":"test-model-1","max_tokens":101,"MAX_TOKENS":1}`,
		`{"model":"test-model-1","max_tokens":10,"max_tokenſ":1}`,
		`{"model":"test-model-1","max_tokens":10,"speed":"fast"}`,
		`{"model":"test-model-1","max_tokens":10,"tools":[{"type":"web_search_20250305"}]}`,
	} {
		response, err := client.Do(composedMessages(t, body))
		if err != nil {
			t.Fatal("composed refusal transport failed")
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != 403 || calls.Load() != 0 {
			t.Fatal("ambiguous or unpriced request reached the provider")
		}
	}
	body := `{"model":"test-model-1","max_tokens":10,"inference_geo":"us","cache_control":{"type":"ephemeral","ttl":"1h"}}`
	for _, status := range []int{200, 403} {
		response, err := client.Do(composedMessages(t, body))
		if err != nil {
			t.Fatal("composed priced control transport failed")
		}
		worker, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != status || calls.Load() != 1 || forwarded.Load() != body || strings.Contains(string(worker), brokerCanary) || strings.Contains(string(worker), renewedCanary) {
			t.Fatal("composed worst-case reservation or secret boundary failed")
		}
	}
}
