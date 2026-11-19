//go:build linux

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
)

func intakeUpstream(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	original := http.DefaultTransport
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}, TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}}
	http.DefaultTransport = transport
	t.Cleanup(func() { transport.CloseIdleConnections(); http.DefaultTransport = original })
}

func startIntake(t *testing.T, fixture *brokerFixture, config proxy.GatewayFileConfig) *http.Client {
	t.Helper()
	fixture.config.AgentUID = uint32(os.Geteuid())
	raw, _ := json.Marshal(fixture.config)
	socket := gatewayDirectory(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveGateway(ctx, config, "protected-mapping", socket, func(string, int64) ([]byte, error) { return raw, nil })
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error("intake shutdown refused")
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for {
		if info, err := os.Lstat(socket); err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0660 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("intake listener unavailable")
		}
		time.Sleep(time.Millisecond)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

func composedMessages(t *testing.T, body string) *http.Request {
	t.Helper()
	request, err := http.NewRequest("POST", "http://api.anthropic.com/v1/messages?beta=true", strings.NewReader(body))
	if err != nil {
		t.Fatal("fixture request refused")
	}
	request.Header.Set("Authorization", "Bearer ssh-placeholder")
	request.Header.Set("Content-Type", "application/json")
	return request
}

// Claim: the real listener, holder and intake enforce the configured model and
// daily ceiling, admit a >64 KiB valid Messages request, and redact reflection.
func TestGatewayComposedMetering(t *testing.T) {
	var calls atomic.Int32
	intakeUpstream(t, func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Host != "api.anthropic.com" || !strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") || request.Header.Get("Authorization") == "Bearer ssh-placeholder" {
			t.Error("upstream credential or origin mismatch")
		}
		_, _ = io.Copy(io.Discard, request.Body)
		_, _ = io.WriteString(writer, `{"echo":"`+request.Header.Get("Authorization")+`"}`)
	})
	client := startIntake(t, startBroker(t), gatewayConfig(t, 460))
	for _, sample := range []struct {
		body   string
		status int
		calls  int32
	}{
		{`{"model":"unlisted","max_tokens":10}`, 403, 0},
		{`{"model":"test-model-1","max_tokens":101}`, 403, 0},
		{`{"model":"test-model-1","max_tokens":10,"messages":[{"role":"user","content":"` + strings.Repeat("x", 70<<10) + `"}]}`, 200, 1},
		{`{"model":"test-model-1","max_tokens":10}`, 200, 2},
		{`{"model":"test-model-1","max_tokens":10}`, 403, 2},
	} {
		response, err := client.Do(composedMessages(t, sample.body))
		if err != nil {
			t.Fatal("composed metering transport failed")
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != sample.status || calls.Load() != sample.calls || strings.Contains(string(body), brokerCanary) || strings.Contains(string(body), renewedCanary) {
			t.Fatal("composed intake bypassed metering or reflected material")
		}
	}
}

// Claim: after startup idle retirement the first real policy request succeeds
// without spending generation budget; a credential-bearing neighbour still refuses.
func TestGatewayComposedStartupIdle(t *testing.T) {
	var calls atomic.Int32
	intakeUpstream(t, func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(writer, `{"restrictions":{}}`)
	})
	fixture := startBroker(t)
	fixture.mu.Lock()
	fixture.idle = time.Second
	fixture.mu.Unlock()
	client := startIntake(t, fixture, gatewayConfig(t))
	time.Sleep(1500 * time.Millisecond)
	response, err := client.Get("http://api.anthropic.com/api/claude_code/policy_limits")
	if err != nil {
		t.Fatal("first policy transport failed")
	}
	_ = response.Body.Close()
	if response.StatusCode != 200 || calls.Load() != 1 {
		t.Fatal("first valid policy after startup idle refused")
	}
	request, _ := http.NewRequest("GET", "http://api.anthropic.com/api/claude_code/policy_limits", nil)
	request.Header.Set("Cookie", "untrusted-fixture")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal("policy neighbour transport failed")
	}
	_ = response.Body.Close()
	if response.StatusCode != 400 || calls.Load() != 1 {
		t.Fatal("credential-bearing policy neighbour admitted")
	}
}

// Claim: the composed streaming path preserves progress beyond the revocation
// interval, then cancels an in-flight call and refuses new work after revocation.
func TestGatewayComposedRevocation(t *testing.T) {
	cancelled := make(chan struct{})
	var calls atomic.Int32
	intakeUpstream(t, func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		writer.Header().Set("Content-Type", "text/event-stream")
		for {
			_, _ = io.WriteString(writer, "event: ping\ndata: {}\n\n")
			writer.(http.Flusher).Flush()
			select {
			case <-request.Context().Done():
				close(cancelled)
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	})
	fixture := startBroker(t)
	client := startIntake(t, fixture, gatewayConfig(t))
	response, err := client.Do(composedMessages(t, `{"model":"test-model-1","max_tokens":10,"stream":true}`))
	if err != nil || response.StatusCode != 200 {
		t.Fatal("composed stream control refused")
	}
	reader := bufio.NewReader(response.Body)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal("composed stream did not begin")
	}
	time.Sleep(1500 * time.Millisecond)
	fixture.mu.Lock()
	fixture.verdict = "revoked"
	fixture.mu.Unlock()
	started := time.Now()
	_, readErr := io.ReadAll(reader)
	_ = response.Body.Close()
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("revocation did not cancel composed upstream")
	}
	if readErr == nil || time.Since(started) > 1500*time.Millisecond {
		t.Fatal("composed revocation missed the fencing bound")
	}
	response, err = client.Do(composedMessages(t, `{"model":"test-model-1","max_tokens":10}`))
	if err != nil {
		t.Fatal("post-revocation transport failed")
	}
	_ = response.Body.Close()
	if response.StatusCode != 503 || calls.Load() != 1 {
		t.Fatal("revoked composed source reached the provider")
	}
}

// Claim: a real 70-second progressing response reaches message_stop through
// production server/client settings, not only through the shortened idle fixture.
func TestGatewayLongStream(t *testing.T) {
	if os.Getenv("GATEWAY_LONG_STREAM") != "1" {
		t.Skip("GATEWAY_LONG_STREAM=1 runs the 70-second production timeout regression")
	}
	intakeUpstream(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		for range 70 {
			_, _ = io.WriteString(writer, "event: ping\ndata: {}\n\n")
			writer.(http.Flusher).Flush()
			select {
			case <-request.Context().Done():
				return
			case <-time.After(time.Second):
			}
		}
		_, _ = io.WriteString(writer, "event: message_stop\ndata: {}\n\n")
		writer.(http.Flusher).Flush()
	})
	client := startIntake(t, startBroker(t), gatewayConfig(t))
	response, err := client.Do(composedMessages(t, `{"model":"test-model-1","max_tokens":10,"stream":true}`))
	if err != nil {
		t.Fatal("long stream control refused")
	}
	body, readErr := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if readErr != nil || strings.Count(string(body), "event: ping") != 70 || !strings.Contains(string(body), "event: message_stop") {
		t.Fatal("production intake truncated a progressing long stream")
	}
}
