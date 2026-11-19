//go:build linux

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
)

const managedAnswer = `{"id":"msg_fixture","type":"message","role":"assistant","model":"test-model-1","content":[{"type":"text","text":"answer"}],"stop_reason":"end_turn","usage":{"input_tokens":7,"output_tokens":3,"service_tier":"standard","inference_geo":"global","speed":"standard"}}`

type managedGateway struct {
	service *proxy.Service
	slot    string
	bearer  string
	calls   atomic.Int32
}

func newManagedGateway(t *testing.T, fixture *brokerFixture, transport providerTransport) *managedGateway {
	t.Helper()
	raw, _ := json.Marshal(fixture.config)
	source, closeSource, err := managedSource(context.Background(), raw)
	if err != nil {
		t.Fatal("managed source startup refused")
	}
	t.Cleanup(closeSource)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal("private state directory refused")
	}
	gateway := &managedGateway{slot: strings.Repeat("1", 64)}
	config := proxy.Config{StateDir: root, DailyCostCeilingNanoUSD: 1000000000, Endpoint: proxy.Endpoint{URL: "https://gateway.example", CertSHA256: strings.Repeat("b", 64)}, Upstream: proxy.ManagedUpstream, Source: source, Mode: proxy.ModeManaged, RunMaxWindowSeconds: 3600, Models: map[string]proxy.Model{"test-model-1": {ContextTokens: 100, InputNanoUSD: 2, OutputNanoUSD: 3, Source: "fixture bound"}}, Now: time.Now, Timeout: 5 * time.Second}
	config.Transport = providerTransport(func(request *http.Request) (*http.Response, error) {
		gateway.calls.Add(1)
		authorization := request.Header.Get("Authorization")
		if request.URL.String() != proxy.ManagedUpstream || (authorization != "Bearer "+brokerCanary && authorization != "Bearer "+renewedCanary) || request.Header.Get("X-Api-Key") != "" || request.Header.Get("X-Worker-Probe") != "" {
			t.Error("provider credential boundary mismatch")
		}
		if transport != nil {
			return transport(request)
		}
		return managedResponse(200), nil
	})
	if err := proxy.InitializeAccounting(config); err != nil {
		t.Fatal("accounting initialization refused")
	}
	gateway.service, err = proxy.New(config)
	if err != nil {
		t.Fatal("gateway construction refused")
	}
	t.Cleanup(func() { gateway.service.Close() })
	now := time.Now().Unix()
	binding := proxy.Binding{SlotID: gateway.slot, GrantID: strings.Repeat("2", 64), NotBefore: now - 1, NotAfter: now + 600, Caps: proxy.Caps{InputTokens: 100000, OutputTokens: 100000, Requests: 100, MaxTokens: 10, CostNanoUSD: 100000000}, Run: proxy.RunBinding{Generation: strings.Repeat("3", 64), RunID: strings.Repeat("4", 64), Account: fixture.config.Account}}
	credential, err := gateway.service.Prepare(binding)
	if err != nil || gateway.service.Activate(binding) != nil {
		t.Fatal("binding activation refused")
	}
	gateway.bearer = string(credential.Bearer.Reveal())
	return gateway
}

func managedResponse(status int) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(managedAnswer))}
}

func (gateway *managedGateway) send(ctx context.Context, extra http.Header) *httptest.ResponseRecorder {
	request := httptest.NewRequest("POST", "https://gateway.example/slots/"+gateway.slot+"/v1/messages", strings.NewReader(`{"model":"test-model-1","messages":[{"role":"user","content":"hello"}],"max_tokens":10,"stream":false}`)).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer "+gateway.bearer)
	for name, values := range extra {
		request.Header[name] = values
	}
	response := httptest.NewRecorder()
	gateway.service.ServeHTTP(response, request)
	return response
}

func eventuallyManaged(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("managed recovery deadline exceeded")
}

// A healthy call outlives the poll interval. Revocation or principal-generation
// loss cancels an admitted upstream call within that interval and admits no next
// call while authority is absent. This does not prove provider billing stopped.
func TestManagedInflightRevocation(t *testing.T) {
	for _, scenario := range []string{"healthy", "revoked", "generation"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := startBroker(t)
			entered := make(chan struct{})
			release := make(chan struct{})
			var released sync.Once
			unblock := func() { released.Do(func() { close(release) }) }
			defer unblock()
			gateway := newManagedGateway(t, fixture, func(request *http.Request) (*http.Response, error) {
				close(entered)
				select {
				case <-request.Context().Done():
					return nil, request.Context().Err()
				case <-release:
					return managedResponse(200), nil
				}
			})
			result := make(chan int, 1)
			go func() { result <- gateway.send(context.Background(), nil).Code }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("valid in-flight control never entered provider")
			}
			if scenario == "healthy" {
				time.Sleep(1500 * time.Millisecond)
				select {
				case <-result:
					t.Fatal("healthy call fenced")
				default:
				}
				unblock()
				if status := <-result; status != 200 {
					t.Fatal("healthy in-flight control refused")
				}
				return
			}
			fixture.mu.Lock()
			checks := fixture.checks
			if scenario == "revoked" {
				fixture.verdict = "revoked"
			} else {
				fixture.checkRefusal = "principal_ledger_mismatch"
				fixture.generation = "service-replaced"
			}
			fixture.mu.Unlock()
			started := time.Now()
			select {
			case status := <-result:
				if status == 200 {
					t.Fatal("revoked in-flight request served")
				}
			case <-time.After(managedPollInterval):
				t.Fatal("revoked in-flight request not fenced within poll interval")
			}
			t.Logf("authority-loss fence elapsed=%s", time.Since(started))
			if response := gateway.send(context.Background(), nil); response.Code == 200 || gateway.calls.Load() != 1 {
				t.Fatal("lost authority admitted another provider call")
			}
			fixture.mu.Lock()
			polled := fixture.checks > checks
			fixture.mu.Unlock()
			if !polled {
				t.Fatal("revocation was not polled")
			}
		})
	}
}

// Cancellation on admission or during the explicit-401 path affects only that
// worker. Later healthy calls use the same broker connection and live lease.
func TestManagedWorkerCancellation(t *testing.T) {
	for _, scenario := range []string{"control", "admission", "renewal"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := startBroker(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var reject atomic.Bool
			gateway := newManagedGateway(t, fixture, func(request *http.Request) (*http.Response, error) {
				if reject.Swap(false) {
					cancel()
					return managedResponse(401), nil
				}
				return managedResponse(200), nil
			})
			if gateway.send(context.Background(), nil).Code != 200 {
				t.Fatal("valid cancellation control refused")
			}
			if scenario == "admission" {
				cancel()
			} else if scenario == "renewal" {
				reject.Store(true)
			}
			response := gateway.send(ctx, nil)
			if scenario != "control" && response.Code == 200 {
				t.Fatal("cancelled worker served")
			}
			for range 3 {
				if gateway.send(context.Background(), nil).Code != 200 {
					t.Fatal("worker cancellation disabled shared broker session")
				}
			}
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			if fixture.connections != 1 || fixture.requests != 1 {
				t.Fatal("worker cancellation rebuilt shared broker session")
			}
			if scenario == "renewal" && fixture.renewals != 1 {
				t.Fatal("cancelled renewal did not preserve broker operation")
			}
		})
	}
}

// Concurrent bindings share one broker source while old-value 401s race
// renewal. Each valid exchange either uses the current value or retries once;
// no worker auth header, duplicate acquisition or data race is permitted.
func TestManagedConcurrentRenewal(t *testing.T) {
	fixture := startBroker(t)
	gateway := newManagedGateway(t, fixture, func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") == "Bearer "+brokerCanary {
			return managedResponse(401), nil
		}
		return managedResponse(200), nil
	})
	workers := []*managedGateway{gateway}
	for _, suffix := range "abcdef0" {
		now := time.Now().Unix()
		slot := strings.Repeat(string(suffix), 64)
		binding := proxy.Binding{SlotID: slot, GrantID: strings.Repeat("2", 64), NotBefore: now - 1, NotAfter: now + 600, Caps: proxy.Caps{InputTokens: 1000, OutputTokens: 1000, Requests: 10, MaxTokens: 10, CostNanoUSD: 1000000}, Run: proxy.RunBinding{Generation: strings.Repeat("3", 64), RunID: slot, Account: fixture.config.Account}}
		credential, err := gateway.service.Prepare(binding)
		if err != nil || gateway.service.Activate(binding) != nil {
			t.Fatal("concurrent binding refused")
		}
		workers = append(workers, &managedGateway{service: gateway.service, slot: slot, bearer: string(credential.Bearer.Reveal())})
	}
	results := make(chan int, len(workers))
	for _, worker := range workers {
		go func() { results <- worker.send(context.Background(), nil).Code }()
	}
	for range workers {
		if status := <-results; status != 200 {
			t.Fatal("concurrent valid renewal refused")
		}
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.requests != 1 || fixture.renewals < 1 || gateway.calls.Load() < int32(len(workers)) || gateway.calls.Load() > int32(2*len(workers)) {
		t.Fatal("concurrent renewal exceeded one retry or reacquired lease")
	}
}

// The broker may grant less than the configured ceiling: a two-second lease
// keeps serving beyond two periods without any upstream 401 or reacquisition.
func TestManagedLeaseRenewal(t *testing.T) {
	fixture := startBroker(t)
	fixture.mu.Lock()
	fixture.lease = 2 * time.Second
	fixture.mu.Unlock()
	gateway := newManagedGateway(t, fixture, nil)
	started := time.Now()
	for time.Since(started) < 4500*time.Millisecond {
		if gateway.send(context.Background(), nil).Code != 200 {
			t.Fatal("valid lease starved across two periods")
		}
		time.Sleep(200 * time.Millisecond)
	}
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	if fixture.renewals < 2 || fixture.requests != 1 {
		t.Fatal("lease was not renewed ahead of expiry")
	}
	t.Logf("served duration=%s renewals=%d acquisitions=%d", time.Since(started), fixture.renewals, fixture.requests)
}

// Renewal refusal never falls back to the old token. Fresh authority can recover
// ordinary failures, but broker account holds remain closed after disconnects.
func TestManagedRenewalRefusal(t *testing.T) {
	for _, scenario := range []string{"renew_failed", "account_hold_unknown", "account_hold_active"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := startBroker(t)
			gateway := newManagedGateway(t, fixture, nil)
			if gateway.send(context.Background(), nil).Code != 200 {
				t.Fatal("valid renewal-refusal control refused")
			}
			fixture.mu.Lock()
			fixture.renewRefusal, fixture.refusal = scenario, "role_not_permitted"
			fixture.mu.Unlock()
			eventuallyManaged(t, func() bool {
				fixture.mu.Lock()
				defer fixture.mu.Unlock()
				return fixture.renewals > 0
			})
			if response := gateway.send(context.Background(), nil); response.Code != 503 || gateway.calls.Load() != 1 {
				t.Fatal("refused renewal forwarded old credential")
			}
			fixture.mu.Lock()
			fixture.renewRefusal, fixture.refusal = "", ""
			fixture.conn.Close()
			fixture.mu.Unlock()
			if scenario == "renew_failed" {
				eventuallyManaged(t, func() bool { return gateway.send(context.Background(), nil).Code == 200 })
			} else {
				time.Sleep(2 * managedCheckInterval)
				if response := gateway.send(context.Background(), nil); response.Code != 503 || gateway.calls.Load() != 1 {
					t.Fatal("account block lost across reconnect")
				}
				fixture.mu.Lock()
				defer fixture.mu.Unlock()
				if fixture.requests != 1 || fixture.connections != 1 {
					t.Fatal("blocked account reacquired authority")
				}
			}
		})
	}
}

// Idle-safe polling keeps a healthy socket alive. Explicit closure, an expired
// short lease and a slow check refuse without provider I/O, then rebuild against
// the same protected mapping. No persistent gateway account block is cleared.
func TestManagedSourceRecovery(t *testing.T) {
	for _, scenario := range []string{"idle", "closed", "slow-check", "expired"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := startBroker(t)
			fixture.mu.Lock()
			if scenario == "idle" {
				fixture.idle = time.Second
			} else if scenario == "expired" {
				fixture.lease = 150 * time.Millisecond
			}
			fixture.mu.Unlock()
			gateway := newManagedGateway(t, fixture, nil)
			if gateway.send(context.Background(), nil).Code != 200 {
				t.Fatal("valid recovery control refused")
			}
			if scenario == "idle" {
				time.Sleep(1500 * time.Millisecond)
				if gateway.send(context.Background(), nil).Code != 200 {
					t.Fatal("idle-safe polling did not keep source live")
				}
				fixture.mu.Lock()
				defer fixture.mu.Unlock()
				if fixture.connections != 1 || fixture.checks < 3 {
					t.Fatal("healthy idle socket was not polled")
				}
				return
			}
			fixture.mu.Lock()
			if scenario == "slow-check" {
				fixture.checkDelay = 750 * time.Millisecond
			} else if scenario == "expired" {
				fixture.refusal = "role_not_permitted"
			} else {
				fixture.refusal = "role_not_permitted"
				fixture.conn.Close()
			}
			fixture.mu.Unlock()
			if scenario == "expired" {
				time.Sleep(180 * time.Millisecond)
			}
			if gateway.send(context.Background(), nil).Code != 503 || gateway.calls.Load() != 1 {
				t.Fatal("closed source forwarded a request")
			}
			fixture.mu.Lock()
			fixture.refusal, fixture.lease = "", 30*time.Second
			fixture.mu.Unlock()
			eventuallyManaged(t, func() bool { return gateway.send(context.Background(), nil).Code == 200 })
			fixture.mu.Lock()
			defer fixture.mu.Unlock()
			if fixture.connections < 2 || fixture.requests < 2 {
				t.Fatal("closed source was never rebuilt")
			}
		})
	}
}

// The existing 900-second ceiling accepts a valid lease at the boundary and
// rejects both a larger configured ceiling and broker authority above it.
func TestManagedLeaseCeiling(t *testing.T) {
	for _, scenario := range []string{"ceiling", "broker-over-ceiling"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := startBroker(t)
			fixture.mu.Lock()
			fixture.config.MaxLifetimeSeconds = 900
			fixture.lease = 900 * time.Second
			if scenario == "broker-over-ceiling" {
				fixture.lease += time.Second
			}
			fixture.mu.Unlock()
			gateway := newManagedGateway(t, fixture, nil)
			response := gateway.send(context.Background(), nil)
			if scenario == "ceiling" {
				if response.Code != 200 || gateway.calls.Load() != 1 {
					t.Fatal("valid ceiling control refused")
				}
			} else if response.Code != 503 || gateway.calls.Load() != 0 {
				t.Fatal("broker exceeded lease ceiling")
			}
		})
	}
}

// New sessions do not clear the gateway's persisted leak block. Worker headers
// remain stripped, and only the fixture bearer reaches the provider control.
func TestManagedRecoveryKeepsLocalBlock(t *testing.T) {
	fixture := startBroker(t)
	gateway := newManagedGateway(t, fixture, nil)
	if gateway.send(context.Background(), http.Header{"X-Api-Key": {"worker-key"}, "X-Worker-Probe": {"probe"}}).Code != 200 {
		t.Fatal("valid header-stripping control refused")
	}
	if gateway.send(context.Background(), http.Header{"X-Leak": {brokerCanary}}).Code != 403 {
		t.Fatal("leak did not block account")
	}
	fixture.mu.Lock()
	fixture.conn.Close()
	fixture.mu.Unlock()
	eventuallyManaged(t, func() bool {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		return fixture.connections > 1
	})
	if response := gateway.send(context.Background(), nil); response.Code != 403 || gateway.calls.Load() != 1 || !strings.Contains(response.Body.String(), "ACCOUNT_BLOCKED") {
		t.Fatal("gateway account block lost on source rebuild")
	}
}

// Wrong peer, missing socket and stale service generation cannot start; a live
// identically bound broker is the positive control. Values remain closed codes.
func TestManagedStartupRefusals(t *testing.T) {
	for _, scenario := range []string{"control", "generation", "uid", "unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := startBroker(t)
			config := fixture.config
			switch scenario {
			case "generation":
				config.ServiceGeneration = "stale-service"
			case "uid":
				config.BrokerUID++
			case "unavailable":
				config.Socket += ".missing"
			}
			raw, _ := json.Marshal(config)
			source, closeSource, err := managedSource(context.Background(), raw)
			if closeSource != nil {
				defer closeSource()
			}
			if scenario == "control" {
				if err != nil || source == nil || closeSource == nil {
					t.Fatal("valid startup control refused")
				}
			} else if err == nil || err.Error() != "CREDENTIAL_SOURCE" || source != nil || closeSource != nil {
				t.Fatal("invalid startup authority admitted")
			}
		})
	}
}
