//go:build linux && gateway_lab

package service

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/labtest"
)

func labAttemptControl(test *testing.T, edit func(*labtest.AttemptFixture)) (*LabGateway, *LabAttemptGate, *labtest.AttemptFixture, *int) {
	test.Helper()
	fixture := labtest.NewFixture(test, "testdata/lab-v0/fixtures.json")
	attempts := labtest.NewAttemptFixture(test, "testdata/lab-v0-c0e", fixture)
	if edit != nil {
		edit(attempts)
		attempts.Rebind()
	}
	if err := PrepareLabAttemptGroup(attempts.Root); err != nil {
		test.Fatal("prepare control", err)
	}
	attempts.PublishStart()
	source, _ := labComposedSource(test, fixture)
	gate, err := OpenLabAttempts(context.Background(), attempts.Root, source)
	if err != nil {
		test.Fatal("open control", err)
	}
	test.Cleanup(func() { gate.Close() })
	calls := new(int)
	gateway, err := NewLabGateway(source, func([]byte) error { return nil }, LabGatewayIO{Attempts: gate, Transport: labRoundTrip(func(*http.Request) (*http.Response, error) {
		*calls++
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}, "Request-Id": {"control-request"}}, Body: io.NopCloser(strings.NewReader(labtest.AttemptSSE()))}, nil
	})})
	if err != nil {
		test.Fatal(err)
	}
	test.Cleanup(gateway.Close)
	return gateway, gate, attempts, calls
}
func labAttemptRequest(test *testing.T, gateway *LabGateway) *httptest.ResponseRecorder {
	test.Helper()
	recorder := httptest.NewRecorder()
	source := gateway.labSource.(*LabSource)
	labServe(gateway, recorder, labComposedRequest(test, source, nil))
	return recorder
}

// TestLabAttemptReservationThroughHTTP proves exact durable ordinal/capacity precede each forward and complete cumulative usage settles once at the pinned price.
func TestLabAttemptReservationThroughHTTP(test *testing.T) {
	gateway, gate, fixture, calls := labAttemptControl(test, nil)
	for ordinal := int64(1); ordinal <= 3; ordinal++ {
		recorder := labAttemptRequest(test, gateway)
		if recorder.Code != 200 || int64(*calls) != ordinal {
			test.Fatal("admitted attempt refused", recorder.Code, *calls)
		}
		raw, err := gate.Status(fixture.Plan["operation_id"].(string), labAttemptHash(fixture.Plan), ordinal)
		if err != nil {
			test.Fatal(err)
		}
		ledger, err := labAttemptRecord(raw, labAttemptLedgerFormat)
		if err != nil {
			test.Fatal(err)
		}
		attempt := labObject(ledger["attempts"].([]any)[ordinal-1])
		if attempt["ordinal"] != ordinal || attempt["state"] != "settled" || attempt["reservation_cost_usd"] != "10.560000" || attempt["settled_micro_usd"] != int64(3720) || attempt["usage_sha256"] != labAttemptHash(attempt["usage"]) {
			test.Fatal("reservation or settlement mismatch")
		}
	}
	if response := labAttemptRequest(test, gateway); response.Code < 400 || *calls != 3 {
		test.Fatal("retry passed count bound")
	}
}

// TestLabAttemptWireThroughHTTP proves every C0 wire negative is 4xx/no-forward through the bounded gateway beside both admitted routes.
func TestLabAttemptWireThroughHTTP(test *testing.T) {
	for _, fixture := range labWireCases(test) {
		test.Run(fixture.Name, func(test *testing.T) {
			gateway, _, _, calls := labAttemptControl(test, nil)
			request := labRequest(fixture)
			source := gateway.labSource.(*LabSource)
			caller, _ := source.GatewayBinding()
			if fixture.Request.Scheme != "api-key" && fixture.Request.Scheme != "" {
				gateway.labSource = labWrongScheme{gateway.labSource}
			}
			request = request.WithContext(context.WithValue(request.Context(), gatewayPeerKey{}, gatewayPeer{caller.UID}))
			recorder := httptest.NewRecorder()
			labServe(gateway, recorder, request)
			if fixture.Admit {
				if recorder.Code != 200 || *calls != 1 {
					test.Fatal("admitted route refused")
				}
			} else if recorder.Code < 400 || recorder.Code >= 500 || *calls != 0 {
				test.Fatal("wire negative escaped bounded gateway")
			}
		})
	}
}

// TestLabAttemptBoundsThroughHTTP proves exact-fit reservations run, insufficient cost/count reject without an ordinal, and concurrent requests cannot queue behind one active attempt.
func TestLabAttemptBoundsThroughHTTP(test *testing.T) {
	for _, mode := range []string{"fits", "cost", "count", "concurrent", "missing-head", "orphan", "clock-regression"} {
		test.Run(mode, func(test *testing.T) {
			gateway, gate, fixture, calls := labAttemptControl(test, func(fixture *labtest.AttemptFixture) {
				if mode == "fits" {
					fixture.Plan["max_total_cost_usd"] = "10.560000"
				}
				if mode == "cost" {
					fixture.Plan["max_total_cost_usd"] = "10.559999"
				}
				if mode == "count" {
					fixture.Plan["max_invocations"] = int64(1)
				}
			})
			if mode == "concurrent" {
				entered, release := make(chan struct{}), make(chan struct{})
				gateway.transport = labRoundTrip(func(request *http.Request) (*http.Response, error) {
					*calls++
					raw, err := gate.Status(fixture.Plan["operation_id"].(string), labAttemptHash(fixture.Plan), 1)
					if err != nil {
						test.Error("no durable reservation before upstream")
					} else {
						ledger, _ := labAttemptRecord(raw, labAttemptLedgerFormat)
						last := labObject(ledger["attempts"].([]any)[0])
						if last["state"] != "reserved" || last["reservation_cost_usd"] != "10.560000" || last["ordinal"] != int64(1) {
							test.Error("unreserved forward")
						}
					}
					if *calls == 1 {
						close(entered)
						<-release
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}, "Request-Id": {"control-request"}}, Body: io.NopCloser(strings.NewReader(labtest.AttemptSSE()))}, nil
				})
				finished := make(chan *httptest.ResponseRecorder, 1)
				go func() { finished <- labAttemptRequest(test, gateway) }()
				<-entered
				response := labAttemptRequest(test, gateway)
				if response.Code < 400 || *calls != 1 {
					test.Error("concurrent request forwarded or queued")
				}
				close(release)
				if (<-finished).Code != 200 {
					test.Fatal("active admitted attempt did not finish")
				}
				return
			}
			if mode == "cost" {
				if recorder := labAttemptRequest(test, gateway); recorder.Code < 400 || *calls != 0 {
					test.Fatal("over-budget forward")
				}
				return
			}
			if recorder := labAttemptRequest(test, gateway); recorder.Code != 200 || *calls != 1 {
				test.Fatal("valid control refused")
			}
			switch mode {
			case "missing-head":
				if gate.store.Remove("head") != nil {
					test.Fatal("plant head")
				}
			case "orphan":
				if labWriteImmutable(gate.store, "000000004.json", []byte("{}")) != nil {
					test.Fatal("plant orphan")
				}
			case "clock-regression":
				gate.mu.Lock()
				gate.lastClock += 100000
				gate.mu.Unlock()
			}
			if recorder := labAttemptRequest(test, gateway); recorder.Code < 400 || *calls != 1 {
				test.Fatal("retry crossed first bound or corrupt store")
			}
		})
	}
}

// TestLabAttemptUnknownThroughHTTP proves authoritative cumulative usage controls settlement; uncertain responses consume the full reservation and cannot be retried after recovery of the upstream.
func TestLabAttemptUnknownThroughHTTP(test *testing.T) {
	for _, mode := range []string{"complete", "nested", "round-up", "nested-missing", "nested-tier", "missing", "partial", "regression", "cache-sum", "missing-counter", "model", "tier", "output-limit", "output-over", "counter-overflow", "request-id", "error", "disconnect", "usage-null"} {
		test.Run(mode, func(test *testing.T) {
			gateway, gate, _, calls := labAttemptControl(test, nil)
			body := labtest.AttemptSSE()
			status := 200
			headers := http.Header{"Content-Type": {"text/event-stream"}, "Request-Id": {"control-request"}}
			switch mode {
			case "nested", "nested-missing", "nested-tier":
				body = strings.ReplaceAll(body, `"service_tier":"standard",`, "")
				body = strings.ReplaceAll(body, `"cache_creation_5m_input_tokens":100,"cache_creation_1h_input_tokens":300`, `"cache_creation":{"ephemeral_5m_input_tokens":100,"ephemeral_1h_input_tokens":300},"service_tier":"standard"`)
				body = strings.ReplaceAll(body, `"output_tokens":0`, `"output_tokens":1`)
				if mode == "nested-missing" {
					body = strings.ReplaceAll(body, `,"ephemeral_1h_input_tokens":300`, "")
				}
				if mode == "nested-tier" {
					body = strings.ReplaceAll(body, "standard", "priority")
				}
			case "round-up":
				body = strings.ReplaceAll(body, `"cache_read_input_tokens":500`, `"cache_read_input_tokens":501`)
			case "missing":
				body = "data: genuine response\n\n"
			case "partial":
				body = strings.ReplaceAll(body, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n", "")
			case "regression":
				body = strings.ReplaceAll(body, `"output_tokens":16`, `"output_tokens":9`)
			case "cache-sum":
				body = strings.ReplaceAll(body, `"cache_creation_input_tokens":400`, `"cache_creation_input_tokens":399`)
			case "missing-counter":
				body = strings.ReplaceAll(body, `,"cache_read_input_tokens":500`, "")
			case "model":
				body = strings.ReplaceAll(body, "claude-opus-5-5", "other-model")
			case "tier":
				body = strings.ReplaceAll(body, "standard", "priority")
			case "output-limit":
				body = strings.ReplaceAll(body, `"output_tokens":16`, `"output_tokens":128000`)
			case "output-over":
				body = strings.ReplaceAll(body, `"output_tokens":16`, `"output_tokens":128001`)
			case "counter-overflow":
				body = strings.ReplaceAll(body, `"input_tokens":100`, `"input_tokens":9007199254740992`)
			case "request-id":
				headers.Del("Request-Id")
			case "error":
				status = 429
				body = "genuine error"
			case "usage-null":
				body = strings.ReplaceAll(body, `"output_tokens":16`, `"output_tokens":null`)
			}
			gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
				*calls++
				if mode == "disconnect" {
					return nil, io.ErrUnexpectedEOF
				}
				return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			labAttemptRequest(test, gateway)
			gate.mu.Lock()
			last := labObject(gate.ledger["attempts"].([]any)[0])
			state := last["state"]
			charge := last["settled_micro_usd"]
			group := gate.ledger["status"]
			gate.mu.Unlock()
			if mode == "complete" || mode == "nested" || mode == "round-up" {
				expected := int64(3720)
				if mode == "round-up" {
					expected = 3721
				}
				if state != "settled" || charge != expected || group != "open" {
					test.Fatal("authoritative control not settled")
				}
				return
			}
			if state != "unknown" || group != "unknown" || charge != int64(10560000) {
				test.Fatal("uncertain outcome refunded or not sticky UNKNOWN", state, charge, group)
			}
			if response := labAttemptRequest(test, gateway); response.Code < 400 || *calls != 1 {
				test.Fatal("retry reopened UNKNOWN")
			}
		})
	}
}

type labWrongScheme struct{ LabGatewaySource }

func (source labWrongScheme) CredentialValue(ctx context.Context) (string, []byte, string, error) {
	_, material, version, err := source.LabGatewaySource.CredentialValue(ctx)
	return "oauth-bearer", material, version, err
}

// TestLabAttemptTransportThroughHTTP proves the composed lab transport uses HTTP/1.1/new connections and non-replayable bodies, retaining one reservation when a real loopback upstream disconnects.
func TestLabAttemptTransportThroughHTTP(test *testing.T) {
	for _, disconnect := range []bool{false, true} {
		test.Run(map[bool]string{false: "complete", true: "disconnect"}[disconnect], func(test *testing.T) {
			gateway, gate, _, _ := labAttemptControl(test, nil)
			calls := 0
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				calls++
				if request.ProtoMajor != 1 || !request.Close {
					test.Error("retry-capable transport protocol or connection reuse")
				}
				if disconnect {
					conn, _, err := writer.(http.Hijacker).Hijack()
					if err == nil {
						conn.Close()
					}
					return
				}
				writer.Header().Set("Content-Type", "text/event-stream")
				writer.Header().Set("Request-Id", "control-request")
				_, _ = io.WriteString(writer, labtest.AttemptSSE())
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			source := gateway.labSource
			actual, err := NewLabGateway(source, func([]byte) error { return nil }, LabGatewayIO{Attempts: gate})
			if err != nil {
				test.Fatal(err)
			}
			defer actual.Close()
			transport := actual.transport.(*http.Transport)
			transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
			transport.TLSClientConfig.ServerName = server.Certificate().DNSNames[0]
			transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}
			recorder := labAttemptRequest(test, actual)
			if calls != 1 {
				test.Fatal("transport retried outside reservation gate")
			}
			gate.mu.Lock()
			last := labObject(gate.ledger["attempts"].([]any)[0])
			state := last["state"]
			gate.mu.Unlock()
			if disconnect {
				if recorder.Code != 502 || state != "unknown" {
					test.Fatal("disconnect refunded")
				}
			} else if recorder.Code != 200 || state != "settled" {
				test.Fatal("TLS control refused")
			}
		})
	}
}

// TestLabAttemptNonReplayableThroughHTTP proves the real forward has no replay body factory; missing gate configuration refuses beside the admitted durable control.
func TestLabAttemptNonReplayableThroughHTTP(test *testing.T) {
	gateway, gate, _, calls := labAttemptControl(test, nil)
	original := gateway.transport
	gateway.transport = labRoundTrip(func(request *http.Request) (*http.Response, error) {
		if request.GetBody != nil {
			test.Error("transport can replay without a new ordinal")
		}
		return original.RoundTrip(request)
	})
	if labAttemptRequest(test, gateway).Code != 200 || *calls != 1 {
		test.Fatal("non-replay control")
	}
	if configured, err := NewLabGateway(gateway.labSource, func([]byte) error { return nil }, LabGatewayIO{Transport: original}); err == nil {
		defer configured.Close()
		labAttemptRequest(test, configured)
		test.Fatal("missing reservation gate admitted a gateway")
	}
	operation := gate.ledger["operation_id"].(string)
	plan := gate.ledger["plan_sha256"].(string)
	if _, err := gate.Status(operation, plan, 1); err != nil {
		test.Fatal("exact status control")
	}
	for _, query := range []struct {
		operation, plan string
		ordinal         int64
	}{{strings.Repeat("0", 32), plan, 1}, {operation, "sha256:" + strings.Repeat("0", 64), 1}, {operation, plan, 0}, {operation, plan, 2}} {
		if _, err := gate.Status(query.operation, query.plan, query.ordinal); err == nil {
			test.Fatal("status accepted a different operation/plan/ordinal")
		}
	}
}

// TestLabAttemptStatusThroughHTTP proves protected exact-tuple status matches the forwarded ledger and reading it never changes any snapshot/head or emits another request.
func TestLabAttemptStatusThroughHTTP(test *testing.T) {
	gateway, gate, fixture, calls := labAttemptControl(test, nil)
	if labAttemptRequest(test, gateway).Code != 200 {
		test.Fatal("status forward control")
	}
	operation, plan := fixture.Plan["operation_id"].(string), labAttemptHash(fixture.Plan)
	before, err := gate.Status(operation, plan, 1)
	if err != nil {
		test.Fatal(err)
	}
	raw, err := ReadLabAttemptStatus(fixture.Root, operation, plan, 1)
	if err != nil || string(raw) != string(before) || *calls != 1 {
		test.Fatal("read-only protected status mismatch", err)
	}
	after, err := gate.Status(operation, plan, 1)
	if err != nil || string(before) != string(after) {
		test.Fatal("status changed protected head")
	}
	for _, query := range []struct {
		operation, plan string
		ordinal         int64
	}{{strings.Repeat("0", 32), plan, 1}, {operation, "sha256:" + strings.Repeat("0", 64), 1}, {operation, plan, 0}, {operation, plan, 2}} {
		if _, err := ReadLabAttemptStatus(fixture.Root, query.operation, query.plan, query.ordinal); err == nil {
			test.Fatal("status treated missing/foreign attempt as no effect")
		}
	}
}

// TestLabAttemptSourceBindingThroughHTTP proves a gate cannot authorize a different managed source, beside the gate's admitted source control.
func TestLabAttemptSourceBindingThroughHTTP(test *testing.T) {
	gateway, gate, _, calls := labAttemptControl(test, nil)
	if labAttemptRequest(test, gateway).Code != 200 || *calls != 1 {
		test.Fatal("binding control")
	}
	fixture := labtest.NewFixture(test, "testdata/lab-v0/fixtures.json")
	other, _ := labComposedSource(test, fixture)
	if foreign, err := NewLabGateway(other, func([]byte) error { return nil }, LabGatewayIO{Attempts: gate, Transport: gateway.transport}); err == nil {
		defer foreign.Close()
		labAttemptRequest(test, foreign)
		test.Fatal("reservation retargeted to another managed source")
	}
}

// TestLabAttemptPersistenceErrorsThroughHTTP proves real file/directory fsync and close uncertainty blocks the next forward without refunding the previous complete control.
func TestLabAttemptPersistenceErrorsThroughHTTP(test *testing.T) {
	for _, mode := range []string{"file-sync", "directory-sync", "file-close"} {
		test.Run(mode, func(test *testing.T) {
			gateway, gate, _, calls := labAttemptControl(test, nil)
			if labAttemptRequest(test, gateway).Code != 200 || *calls != 1 {
				test.Fatal("persistence control refused")
			}
			gate.mu.Lock()
			original := gate.io
			gate.io.SyncFile = func(file *os.File) error {
				err := original.SyncFile(file)
				if err != nil {
					return err
				}
				info, err := file.Stat()
				if err != nil {
					return err
				}
				if mode == "directory-sync" && info.IsDir() || mode == "file-sync" && !info.IsDir() {
					return io.ErrUnexpectedEOF
				}
				return nil
			}
			gate.io.CloseFile = func(file *os.File) error {
				err := original.CloseFile(file)
				if err == nil && mode == "file-close" {
					return io.ErrUnexpectedEOF
				}
				return err
			}
			gate.mu.Unlock()
			response := labAttemptRequest(test, gateway)
			if response.Code < 400 || *calls != 1 || gate.Err() != ErrUnknown {
				test.Fatal("uncertain persistence emitted upstream bytes")
			}
		})
	}
}

// TestLabAttemptCASThroughHTTP proves a changed protected head during reservation publication cannot be overwritten or followed by an upstream request, beside an unchanged-head control.
func TestLabAttemptCASThroughHTTP(test *testing.T) {
	for _, changed := range []bool{false, true} {
		test.Run(map[bool]string{false: "control", true: "changed-head"}[changed], func(test *testing.T) {
			gateway, gate, fixture, calls := labAttemptControl(test, nil)
			if response := labAttemptRequest(test, gateway); response.Code != 200 {
				test.Fatal("valid CAS control")
			}
			gate.mu.Lock()
			gate.io.SyncFile = func(file *os.File) error {
				if err := file.Sync(); err != nil {
					return err
				}
				if changed && filepath.Base(file.Name()) == "head.next" {
					fixture.Put("accounting/head", []byte("sha256:"+strings.Repeat("0", 64)))
				}
				return nil
			}
			gate.mu.Unlock()
			response := labAttemptRequest(test, gateway)
			if changed {
				if response.Code < 400 || *calls != 1 || gate.Err() != ErrUnknown {
					test.Fatal("lost CAS forwarded or republished")
				}
			} else if response.Code != 200 || *calls != 2 {
				test.Fatal("unchanged CAS refused")
			}
		})
	}
}

// TestLabAttemptNoQueueThroughHTTP proves a second real request refuses while reservation fsync is blocked, without another ordinal/forward, beside settled first and subsequent sequential controls.
func TestLabAttemptNoQueueThroughHTTP(test *testing.T) {
	gateway, gate, _, calls := labAttemptControl(test, nil)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	blocked := false
	gate.io.SyncFile = func(file *os.File) error {
		if err := file.Sync(); err != nil {
			return err
		}
		if filepath.Base(file.Name()) == "head.next" && !blocked {
			blocked = true
			close(entered)
			<-release
		}
		return nil
	}
	first := httptest.NewRecorder()
	second := httptest.NewRecorder()
	firstRequest := labComposedRequest(test, gateway.labSource.(*LabSource), nil)
	secondRequest := labComposedRequest(test, gateway.labSource.(*LabSource), nil)
	firstDone := make(chan struct{})
	go func() { labServe(gateway, first, firstRequest); close(firstDone) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		test.Fatal("no reservation barrier control")
	}
	secondDone := make(chan struct{})
	go func() { labServe(gateway, second, secondRequest); close(secondDone) }()
	select {
	case <-secondDone:
		if second.Code < 400 || second.Code >= 500 {
			test.Fatal("busy reservation was not refused", second.Code)
		}
	case <-time.After(time.Second):
		test.Fatal("second request queued behind durable allocation")
	}
	if *calls != 0 {
		test.Fatal("forward before durable publication")
	}
	unblock()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		test.Fatal("reserved control did not settle")
	}
	if first.Code != 200 || *calls != 1 || len(gate.ledger["attempts"].([]any)) != 1 {
		test.Fatal("busy request consumed an ordinal or broke its control")
	}
	if response := labAttemptRequest(test, gateway); response.Code != 200 || *calls != 2 || len(gate.ledger["attempts"].([]any)) != 2 {
		test.Fatal("sequential post-settlement control refused")
	}
}
