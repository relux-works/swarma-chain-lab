//go:build linux && gateway_lab

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/labtest"
)

func labWait(test *testing.T, claim string, ready func() bool) {
	test.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			test.Fatal(claim)
		}
		time.Sleep(time.Millisecond)
	}
}
func labComposedSource(test *testing.T, fixture *labtest.Fixture) (*LabSource, *labtest.Broker) {
	test.Helper()
	records := fixture.Records
	pins, err := NewLabPins(records[0], records[1], records[2], records[3], records[4])
	if err != nil {
		test.Fatal(err)
	}
	broker := labtest.StartBroker(test, fixture)
	source, err := OpenLabSource(context.Background(), Config{Socket: broker.Listener.Addr().String(), BrokerUID: uint32(pins.gateway["uid"].(int64)), ServiceUID: uint32(pins.gateway["uid"].(int64)), Generation: pins.gateway["generation"].(string), MaxLifetime: pins.lifetime}, pins, func() {})
	if err != nil {
		test.Fatal(err)
	}
	test.Cleanup(source.Close)
	return source, broker
}
func labComposedRequest(test *testing.T, source LabGatewaySource, body []byte) *http.Request {
	test.Helper()
	request := labRequest(labWireCases(test)[0])
	if body != nil {
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.ContentLength = int64(len(body))
	}
	caller, _ := source.GatewayBinding()
	return request.WithContext(context.WithValue(request.Context(), gatewayPeerKey{}, gatewayPeer{caller.UID}))
}
func labServe(gateway *LabGateway, writer http.ResponseWriter, request *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil && recovered != http.ErrAbortHandler {
			panic(recovered)
		}
	}()
	gateway.ServeHTTP(writer, request)
}

// TestLabServeHTTPWireCatalogue proves all 76 C0 fixtures reach real intake: every negative is 4xx with no upstream call, beside both admitted controls.
func TestLabServeHTTPWireCatalogue(test *testing.T) {
	for _, fixture := range labWireCases(test) {
		test.Run(fixture.Name, func(test *testing.T) {
			source := newLabHTTPSource()
			defer source.cancel()
			source.scheme = fixture.Request.Scheme
			calls := 0
			gateway, err := NewLabGateway(source, func([]byte) error { return nil }, LabGatewayIO{Transport: labRoundTrip(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method == http.MethodPost && (request.Header.Get("Anthropic-Beta") != labBeta || request.Header.Get("X-Api-Key") != labMaterial) {
					test.Error("canonical API-key emission missing")
				}
				if request.Method == http.MethodGet && (request.Header.Get("X-Api-Key") != "" || request.Header.Get("Authorization") != "") {
					test.Error("credential on policy GET")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("admitted"))}, nil
			})})
			if err != nil {
				test.Fatal(err)
			}
			defer gateway.Close()
			writer := httptest.NewRecorder()
			labServe(gateway, writer, labRequest(fixture))
			if fixture.Admit {
				if calls != 1 || writer.Code != 200 || writer.Body.String() != "admitted" {
					test.Fatalf("valid control: calls=%d status=%d", calls, writer.Code)
				}
			} else if calls != 0 || writer.Code < 400 || writer.Code >= 500 {
				test.Fatalf("negative: calls=%d status=%d", calls, writer.Code)
			}
		})
	}
	for _, duplicate := range []string{"field-values", "case-alias", "upper-control"} {
		test.Run(duplicate, func(test *testing.T) {
			source := newLabHTTPSource()
			defer source.cancel()
			calls := 0
			gateway, _ := NewLabGateway(source, func([]byte) error { return nil })
			defer gateway.Close()
			gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("control"))}, nil
			})
			control := httptest.NewRecorder()
			labServe(gateway, control, labRequest(labWireCases(test)[0]))
			if calls != 1 || control.Code != 200 {
				test.Fatal("single field control refused")
			}
			request := labRequest(labWireCases(test)[0])
			if duplicate == "upper-control" {
				request.Header = http.Header{}
				for _, header := range labWireCases(test)[0].Request.Headers {
					request.Header[strings.ToUpper(header[0])] = []string{header[1]}
				}
			} else if duplicate == "field-values" {
				request.Header["anthropic-beta"] = []string{labBeta, labBeta}
			} else {
				request.Header["Anthropic-Beta"] = []string{labBeta}
			}
			writer := httptest.NewRecorder()
			labServe(gateway, writer, request)
			if duplicate == "upper-control" {
				if calls != 2 || writer.Code != 200 {
					test.Fatal("ASCII header case control refused")
				}
			} else if calls != 1 || writer.Code != 400 {
				test.Fatal("duplicate beta field forwarded")
			}
		})
	}

}

// TestLabServeHTTPResponseGates proves genuine errors pass unchanged, redirects do not retry, and encoded responses refuse before disclosure.
func TestLabServeHTTPResponseGates(test *testing.T) {
	for _, mode := range []string{"error", "redirect", "encoded", "get-body"} {
		test.Run(mode, func(test *testing.T) {
			source := newLabHTTPSource()
			defer source.cancel()
			calls := 0
			gateway, _ := NewLabGateway(source, func([]byte) error { return nil })
			defer gateway.Close()
			gateway.transport = labRoundTrip(func(request *http.Request) (*http.Response, error) {
				calls++
				status := 401
				headers := http.Header{}
				if mode == "redirect" {
					status = 307
					headers.Set("Location", "https://invalid.example/")
				}
				if mode == "encoded" {
					headers.Set("Content-Encoding", "gzip")
				}
				return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader("genuine-error")), Request: request}, nil
			})
			request := labRequest(labWireCases(test)[0])
			expected := 401
			if mode == "get-body" {
				for _, fixture := range labWireCases(test) {
					if fixture.Name == "policy-valid" {
						request = labRequest(fixture)
					}
				}
				request.Body = io.NopCloser(strings.NewReader("x"))
				request.ContentLength = 1
				expected = 400
			}
			if mode == "redirect" {
				expected = 307
			}
			if mode == "encoded" {
				expected = 502
			}
			writer := httptest.NewRecorder()
			labServe(gateway, writer, request)
			if writer.Code != expected || mode == "get-body" && calls != 0 || mode != "get-body" && calls != 1 {
				test.Fatalf("status=%d calls=%d", writer.Code, calls)
			}
			if mode == "error" && writer.Body.String() != "genuine-error" || mode == "encoded" && strings.Contains(writer.Body.String(), "genuine-error") {
				test.Fatal("response gate or passthrough broken")
			}
		})
	}
}

// TestLabLeaseBindingsThroughHTTP proves broker replies cannot install foreign joins or widened deadlines on a real managed request.
func TestLabLeaseBindingsThroughHTTP(test *testing.T) {
	for _, mode := range []string{"", "operation", "context", "gateway", "caller", "activation", "authority", "fence", "floor", "extra", "noncanonical", "future", "pinned-deadline", "lifetime", "expired", "interval", "authority_until", "caller_until", "qualification_until", "time_until"} {
		test.Run("case-"+mode, func(test *testing.T) {
			fixture := labtest.NewFixture(test, "testdata/lab-v0/fixtures.json")
			fixture.Deadline = time.Now().Add(3 * time.Second)
			fixture.Rebuild()
			source, broker := labComposedSource(test, fixture)
			broker.LeaseMode.Store(mode)
			calls := 0
			gateway, _ := NewLabGateway(source, func([]byte) error { return nil })
			defer gateway.Close()
			gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("control"))}, nil
			})
			writer := httptest.NewRecorder()
			labServe(gateway, writer, labComposedRequest(test, source, nil))
			if mode == "" {
				if calls != 1 || writer.Code != 200 {
					test.Fatal("admitted control")
				}
			} else {
				if calls != 0 || writer.Code != 503 || source.ctx.Err() == nil || len(source.Inventory()) != 0 {
					test.Fatalf("invalid reply installed: calls=%d status=%d", calls, writer.Code)
				}
				broker.LeaseMode.Store("")
				labServe(gateway, httptest.NewRecorder(), labComposedRequest(test, source, nil))
				if calls != 0 || broker.Requests.Load() != 1 {
					test.Fatal("retired source reopened")
				}
			}
		})
	}
}

// TestLabSequenceThroughHTTP proves equal/advanced checks remain usable but a regressed current or renewal sequence retires the real managed path.
func TestLabSequenceThroughHTTP(test *testing.T) {
	for _, mode := range []string{"", "advance", "zero", "regress", "null", "null-zero", "renew-regress", "renew-lease-id"} {
		test.Run("case-"+mode, func(test *testing.T) {
			fixture := labtest.NewFixture(test, "testdata/lab-v0/fixtures.json")
			if strings.HasPrefix(mode, "renew-") {
				fixture.Lifetime = time.Second
				fixture.Rebuild()
			}
			source, broker := labComposedSource(test, fixture)
			if mode == "zero" || mode == "null-zero" {
				broker.LeaseMode.Store("zero")
				broker.CheckMode.Store("zero")
			}
			calls := 0
			gateway, _ := NewLabGateway(source, func([]byte) error { return nil })
			defer gateway.Close()
			gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("control"))}, nil
			})
			writer := httptest.NewRecorder()
			labServe(gateway, writer, labComposedRequest(test, source, nil))
			if writer.Code != 200 || calls != 1 {
				test.Fatal("valid initial control")
			}
			if strings.HasPrefix(mode, "renew-") {
				broker.LeaseMode.Store(mode)
				labWait(test, "renewal not driven", func() bool { return broker.Renews.Load() > 0 })
				time.Sleep(20 * time.Millisecond)
			} else {
				if mode == "null-zero" {
					broker.CheckMode.Store("null")
				} else {
					broker.CheckMode.Store(mode)
				}
			}
			writer = httptest.NewRecorder()
			labServe(gateway, writer, labComposedRequest(test, source, nil))
			if mode == "" || mode == "advance" || mode == "zero" {
				if writer.Code != 200 || calls != 2 {
					test.Fatal("equal/advanced control")
				}
			} else if calls != 1 || writer.Code != 503 || source.ctx.Err() == nil {
				test.Fatalf("stale source usable: calls=%d status=%d", calls, writer.Code)
			}
		})
	}
}

// TestLabPostLoadHoldThroughHTTP proves first-issue inventory rescanning refuses a planted request before injection and reconciles only an exactly bound hold.
func TestLabPostLoadHoldThroughHTTP(test *testing.T) {
	for _, mode := range []string{"clean", "", "operation", "digest", "context", "caller", "unknown", "lost"} {
		test.Run("case-"+mode, func(test *testing.T) {
			fixture := labtest.NewFixture(test, "testdata/lab-v0/fixtures.json")
			source, broker := labComposedSource(test, fixture)
			if mode != "clean" {
				broker.HoldMode.Store(mode)
			}
			calls := 0
			gateway, _ := NewLabGateway(source, func([]byte) error { return nil })
			defer gateway.Close()
			gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("control"))}, nil
			})
			body := labWireCases(test)[0].Request.Body
			if mode != "clean" {
				body = bytes.ReplaceAll(body, []byte("PUBLIC SYNTHETIC PROMPT"), []byte(labMaterial))
			}
			if len(source.Inventory()) != 0 {
				test.Fatal("first-issue inventory not empty")
			}
			writer := httptest.NewRecorder()
			labServe(gateway, writer, labComposedRequest(test, source, body))
			if mode == "clean" {
				if writer.Code != 200 || calls != 1 || broker.Holds.Load() != 0 {
					test.Fatal("clean control")
				}
				return
			}
			if writer.Code != 403 || calls != 0 || bytes.Contains(writer.Body.Bytes(), []byte(labMaterial)) {
				test.Fatalf("first-issued leak forwarded: status=%d calls=%d", writer.Code, calls)
			}
			if mode != "" {
				labWait(test, "mis-bound hold not retried", func() bool { return broker.Holds.Load() >= 2 })
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
				err := source.AwaitHold(ctx)
				cancel()
				if err != ErrUnknown || !broker.SameHold() {
					test.Fatal("mis-bound acknowledgment treated as committed")
				}
				broker.HoldMode.Store("")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if source.AwaitHold(ctx) != nil || !broker.SameHold() {
				test.Fatal("exact same-ID recovery failed")
			}
			labServe(gateway, httptest.NewRecorder(), labComposedRequest(test, source, nil))
			if calls != 0 {
				test.Fatal("held source reopened")
			}
		})
	}
}

type labRenewRace struct {
	*LabSource
	broker *labtest.Broker
	test   *testing.T
}

func (source labRenewRace) CredentialValue(ctx context.Context) (string, []byte, string, error) {
	scheme, material, version, err := source.LabSource.CredentialValue(ctx)
	if err == nil {
		labWait(source.test, "renewal not observed", func() bool { source.mu.Lock(); defer source.mu.Unlock(); return source.version != version })
	}
	return scheme, material, version, err
}

// TestLabVersionRaceThroughHTTP proves a renewal between material fetch and context binding cannot forward using a newer deadline.
func TestLabVersionRaceThroughHTTP(test *testing.T) {
	for _, race := range []bool{false, true} {
		test.Run(map[bool]string{false: "same-version", true: "renewed-version"}[race], func(test *testing.T) {
			fixture := labtest.NewFixture(test, "testdata/lab-v0/fixtures.json")
			fixture.Lifetime = time.Second
			fixture.Rebuild()
			source, broker := labComposedSource(test, fixture)
			var selected LabGatewaySource = source
			if race {
				selected = labRenewRace{source, broker, test}
			}
			calls := 0
			gateway, _ := NewLabGateway(selected, func([]byte) error { return nil })
			defer gateway.Close()
			gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("control"))}, nil
			})
			writer := httptest.NewRecorder()
			labServe(gateway, writer, labComposedRequest(test, source, nil))
			if !race && (calls != 1 || writer.Code != 200) || race && (calls != 0 || writer.Code != 503) {
				test.Fatalf("version gate: calls=%d status=%d", calls, writer.Code)
			}
		})
	}
}

type labObservedBody struct {
	*io.PipeReader
	closed  atomic.Bool
	reading chan struct{}
	once    sync.Once
}

func (body *labObservedBody) Read(buffer []byte) (int, error) {
	body.once.Do(func() {
		if body.reading != nil {
			close(body.reading)
		}
	})
	return body.PipeReader.Read(buffer)
}

func (body *labObservedBody) Close() error { body.closed.Store(true); return body.PipeReader.Close() }

// TestLabAuthorityCancellationThroughHTTP proves real source retirement cancels an in-flight LabGateway request/body; a locked supervisor cannot postpone the 500-ms watchdog.
func TestLabAuthorityCancellationThroughHTTP(test *testing.T) {
	for _, mode := range []string{"revoked", "watchdog"} {
		test.Run(mode, func(test *testing.T) {
			fixture := labtest.NewFixture(test, "testdata/lab-v0/fixtures.json")
			source, broker := labComposedSource(test, fixture)
			reader, writer := io.Pipe()
			defer writer.Close()
			body := &labObservedBody{PipeReader: reader, reading: make(chan struct{})}
			entered := make(chan context.Context, 1)
			returned := make(chan struct{})
			gateway, _ := NewLabGateway(source, func([]byte) error { return nil })
			defer gateway.Close()
			gateway.transport = labRoundTrip(func(request *http.Request) (*http.Response, error) {
				entered <- request.Context()
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: body}, nil
			})
			go func() {
				defer close(returned)
				labServe(gateway, httptest.NewRecorder(), labComposedRequest(test, source, nil))
			}()
			var upstream context.Context
			select {
			case upstream = <-entered:
			case <-time.After(time.Second):
				test.Fatal("no upstream control")
			}
			select {
			case <-body.reading:
			case <-time.After(time.Second):
				test.Fatal("response body not driven")
			}
			if upstream.Err() != nil || body.closed.Load() {
				test.Fatal("live control already closed")
			}
			started := time.Now()
			if mode == "watchdog" {
				source.mu.Lock()
				defer source.mu.Unlock()
			} else {
				broker.CheckMode.Store("revoked")
			}
			bound := time.Second
			if mode == "watchdog" {
				bound = 650 * time.Millisecond
			}
			select {
			case <-upstream.Done():
			case <-time.After(bound):
				test.Fatal("in-flight upstream context not cancelled")
			}
			select {
			case <-returned:
			case <-time.After(time.Until(started.Add(bound))):
				test.Fatal("handler/body did not close within bound")
			}
			if !body.closed.Load() || time.Since(started) > bound {
				test.Fatal("upstream body not closed within bound")
			}
		})
	}
}

// TestLabBodyOperatorsThroughHTTP proves C0-compatible cache relocation stays admitted while duplicate members and numeric aliases refuse through intake.
func TestLabBodyOperatorsThroughHTTP(test *testing.T) {
	for _, mode := range []string{"control", "cache-move", "duplicate", "number"} {
		test.Run(mode, func(test *testing.T) {
			source := newLabHTTPSource()
			defer source.cancel()
			calls := 0
			body := append([]byte(nil), labWireCases(test)[0].Request.Body...)
			switch mode {
			case "cache-move":
				object, _ := labJSON(body)
				system := object.(map[string]any)["system"].([]any)
				first, second := system[0].(map[string]any), system[1].(map[string]any)
				first["cache_control"], second["cache_control"] = second["cache_control"], first["cache_control"]
				body, _ = json.Marshal(object)
			case "duplicate":
				body = bytes.Replace(body, []byte(`"max_tokens":128000`), []byte(`"max_tokens":128000,"max_tokens":128000`), 1)
			case "number":
				body = bytes.Replace(body, []byte(`128000`), []byte(`128000.000000000001`), 1)
			}
			gateway, _ := NewLabGateway(source, func([]byte) error { return nil })
			defer gateway.Close()
			gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("control"))}, nil
			})
			writer := httptest.NewRecorder()
			labServe(gateway, writer, labComposedRequest(test, source, body))
			valid := mode == "control" || mode == "cache-move"
			if valid && (writer.Code != 200 || calls != 1) || !valid && (writer.Code != 400 || calls != 0) {
				test.Fatalf("body mode: calls=%d status=%d", calls, writer.Code)
			}
		})
	}
}

// TestLabLeakSurfacesThroughHTTP proves real issued inventory closes request URL/header/body and response header/split-body leak paths with a committed hold and no material disclosure.
func TestLabLeakSurfacesThroughHTTP(test *testing.T) {
	for _, mode := range []string{"clean", "request-url", "request-header", "request-body", "response-header", "response-body"} {
		test.Run(mode, func(test *testing.T) {
			fixture := labtest.NewFixture(test, "testdata/lab-v0/fixtures.json")
			source, broker := labComposedSource(test, fixture)
			calls := 0
			gateway, _ := NewLabGateway(source, func([]byte) error { return nil })
			defer gateway.Close()
			gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("control"))}, nil
			})
			control := httptest.NewRecorder()
			labServe(gateway, control, labComposedRequest(test, source, nil))
			if control.Code != 200 || calls != 1 {
				test.Fatal("clean issued control")
			}
			gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				header := http.Header{}
				body := "control"
				if mode == "response-header" {
					header.Set("X-Diagnostic", labMaterial)
				}
				if mode == "response-body" {
					body = "data: " + labMaterial + "\n\n"
				}
				return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(&labByteReader{raw: []byte(body)})}, nil
			})
			request := labComposedRequest(test, source, nil)
			switch mode {
			case "request-url":
				request.URL.RawQuery = labMaterial
			case "request-header":
				request.Header.Set("X-Stainless-Diagnostic", labMaterial)
			case "request-body":
				body := bytes.ReplaceAll(labWireCases(test)[0].Request.Body, []byte("PUBLIC SYNTHETIC PROMPT"), []byte(labMaterial))
				request = labComposedRequest(test, source, body)
			}
			writer := httptest.NewRecorder()
			labServe(gateway, writer, request)
			if bytes.Contains(writer.Body.Bytes(), []byte(labMaterial)) {
				test.Fatal("whole material disclosed")
			}
			if mode == "clean" {
				if writer.Code != 200 || broker.Holds.Load() != 0 || calls != 2 {
					test.Fatal("clean control")
				}
				return
			}
			if strings.HasPrefix(mode, "request-") && (calls != 1 || writer.Code != 403) {
				test.Fatal("inbound material forwarded")
			}
			if strings.HasPrefix(mode, "response-") && calls != 2 {
				test.Fatal("response path not reached")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if source.AwaitHold(ctx) != nil || broker.Holds.Load() == 0 || !broker.SameHold() {
				test.Fatal("leak did not commit hold")
			}
		})
	}
}

// TestLabSSEThroughHTTP proves real managed intake flushes a safe SSE event before upstream EOF and preserves its bytes.
func TestLabSSEThroughHTTP(test *testing.T) {
	fixture := labtest.NewFixture(test, "testdata/lab-v0/fixtures.json")
	source, _ := labComposedSource(test, fixture)
	reader, writer := io.Pipe()
	defer writer.Close()
	defer reader.Close()
	gateway, _ := NewLabGateway(source, func([]byte) error { return nil })
	defer gateway.Close()
	gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: reader}, nil
	})
	recorder := &labFlushRecorder{ResponseRecorder: httptest.NewRecorder(), flushed: make(chan struct{}, 1)}
	returned := make(chan struct{})
	go func() { defer close(returned); labServe(gateway, recorder, labComposedRequest(test, source, nil)) }()
	if _, err := writer.Write([]byte("data: control\n\n")); err != nil {
		test.Fatal(err)
	}
	select {
	case <-recorder.flushed:
	case <-time.After(200 * time.Millisecond):
		test.Fatal("safe SSE event buffered until EOF")
	}
	writer.Close()
	select {
	case <-returned:
	case <-time.After(time.Second):
		test.Fatal("EOF not propagated")
	}
	if recorder.Body.String() != "data: control\n\n" {
		test.Fatal("SSE bytes changed")
	}
}

// TestLabRenewalThroughHTTP proves real managed requests renew short leases, avoid half-second churn on long leases and never resurrect a handle that expired during renewal.
func TestLabRenewalThroughHTTP(test *testing.T) {
	for _, mode := range []string{"long", "short", "renew-expired"} {
		test.Run(mode, func(test *testing.T) {
			fixture := labtest.NewFixture(test, "testdata/lab-v0/fixtures.json")
			if mode != "long" {
				fixture.Lifetime = time.Second
				fixture.Rebuild()
			}
			source, broker := labComposedSource(test, fixture)
			if mode == "renew-expired" {
				broker.LeaseMode.Store(mode)
			}
			calls := 0
			gateway, _ := NewLabGateway(source, func([]byte) error { return nil })
			defer gateway.Close()
			gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("control"))}, nil
			})
			control := httptest.NewRecorder()
			labServe(gateway, control, labComposedRequest(test, source, nil))
			if control.Code != 200 || calls != 1 {
				test.Fatal("initial control")
			}
			if mode == "renew-expired" {
				time.Sleep(960 * time.Millisecond)
			} else {
				time.Sleep(850 * time.Millisecond)
			}
			writer := httptest.NewRecorder()
			labServe(gateway, writer, labComposedRequest(test, source, nil))
			if mode == "renew-expired" {
				if calls != 1 || writer.Code != 503 || broker.Renews.Load() == 0 {
					test.Fatalf("ended renewal reopened: calls=%d status=%d renews=%d", calls, writer.Code, broker.Renews.Load())
				}
				return
			}
			if writer.Code != 200 || calls != 2 || mode == "long" && broker.Renews.Load() != 0 || mode == "short" && broker.Renews.Load() == 0 {
				test.Fatal("renewal cadence or live control")
			}
		})
	}
}

// TestLabWatchdogAgeThroughHTTP proves broker round-trip time consumes the 500-ms watchdog budget rather than extending authority from reply completion.
func TestLabWatchdogAgeThroughHTTP(test *testing.T) {
	fixture := labtest.NewFixture(test, "testdata/lab-v0/fixtures.json")
	source, broker := labComposedSource(test, fixture)
	broker.CheckMode.Store("slow")
	reader, writer := io.Pipe()
	defer writer.Close()
	defer reader.Close()
	body := &labObservedBody{PipeReader: reader, reading: make(chan struct{})}
	entered := make(chan context.Context, 1)
	returned := make(chan struct{})
	gateway, _ := NewLabGateway(source, func([]byte) error { return nil })
	defer gateway.Close()
	gateway.transport = labRoundTrip(func(request *http.Request) (*http.Response, error) {
		entered <- request.Context()
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: body}, nil
	})
	started := time.Now()
	go func() {
		defer close(returned)
		labServe(gateway, httptest.NewRecorder(), labComposedRequest(test, source, nil))
	}()
	var upstream context.Context
	select {
	case upstream = <-entered:
	case <-time.After(time.Second):
		test.Fatal("slow successful check control refused")
	}
	select {
	case <-body.reading:
	case <-time.After(time.Second):
		test.Fatal("body read not driven")
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if upstream.Err() != nil {
		test.Fatal("live check control already retired")
	}
	select {
	case <-upstream.Done():
	case <-time.After(time.Until(started.Add(550 * time.Millisecond))):
		test.Fatal("RPC time extended watchdog authority")
	}
	select {
	case <-returned:
	case <-time.After(100 * time.Millisecond):
		test.Fatal("watchdog did not cancel in-flight body")
	}
}

type labSpaces struct{ remaining int64 }

func (reader *labSpaces) Read(buffer []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	count := len(buffer)
	if int64(count) > reader.remaining {
		count = int(reader.remaining)
	}
	for index := range buffer[:count] {
		buffer[index] = ' '
	}
	reader.remaining -= int64(count)
	return count, nil
}

// TestLabPayloadThroughHTTP proves a valid body at the actual 128-MiB intake ceiling forwards but one byte over refuses before any upstream call.
func TestLabPayloadThroughHTTP(test *testing.T) {
	for _, length := range []int64{MaxIntakeBody, MaxIntakeBody + 1} {
		test.Run(fmt.Sprint(length), func(test *testing.T) {
			source := newLabHTTPSource()
			defer source.cancel()
			calls := 0
			gateway, _ := NewLabGateway(source, func([]byte) error { return nil })
			defer gateway.Close()
			gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("control"))}, nil
			})
			request := labRequest(labWireCases(test)[0])
			request.Body = io.NopCloser(io.MultiReader(bytes.NewReader(labWireCases(test)[0].Request.Body), &labSpaces{remaining: length - int64(len(labWireCases(test)[0].Request.Body))}))
			request.ContentLength = length
			writer := httptest.NewRecorder()
			labServe(gateway, writer, request)
			if length == MaxIntakeBody && (writer.Code != 200 || calls != 1) || length > MaxIntakeBody && (writer.Code != 400 || calls != 0) {
				test.Fatalf("payload boundary: calls=%d status=%d", calls, writer.Code)
			}
		})
	}
}
