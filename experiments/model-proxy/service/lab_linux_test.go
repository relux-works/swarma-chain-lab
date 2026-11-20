//go:build linux && gateway_lab

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/internal/wire"
)

const labMaterial = "PUBLIC-SYNTHETIC-ONLY-NOT-A-VENDOR-KEY"

func labFixtures(test *testing.T) map[string]map[string]any {
	test.Helper()
	raw, err := os.ReadFile("testdata/lab-v0/fixtures.json")
	if err != nil {
		test.Fatal(err)
	}
	var fixtures struct {
		Cases []struct {
			Surface string          `json:"surface"`
			Valid   json.RawMessage `json:"valid"`
		} `json:"cases"`
	}
	if json.Unmarshal(raw, &fixtures) != nil {
		test.Fatal("fixtures")
	}
	result := map[string]map[string]any{}
	for _, fixture := range fixtures.Cases {
		object, err := wire.Parse(fixture.Valid)
		if err != nil {
			test.Fatal(err)
		}
		result[fixture.Surface] = object
	}
	return result
}
func labBytes(test *testing.T, value any) []byte {
	test.Helper()
	raw, err := wire.Encode(value)
	if err != nil {
		test.Fatal(err)
	}
	return raw
}
func labClone(test *testing.T, value map[string]any) map[string]any {
	test.Helper()
	object, err := wire.Parse(labBytes(test, value))
	if err != nil {
		test.Fatal(err)
	}
	return object
}
func labPinRecords(test *testing.T) ([][]byte, *LabPins) {
	test.Helper()
	fixtures := labFixtures(test)
	authority := fixtures["swarma-broker-lab-authority/1"]
	scope := labObject(authority["context"])
	scope["qualification_expires_at"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	authority["per_use_expires_at"] = scope["qualification_expires_at"]
	labObject(authority["gateway"])["uid"] = int64(os.Geteuid())
	activation := fixtures["swarma-broker-lab-activation/1"]
	for key, value := range scope {
		activation[key] = value
	}
	floor := fixtures["swarma-broker-lab-consumer-high-water/1"]
	floor["context"] = scope
	floor["hold_ids"] = []any{}
	authority["manager_head"] = floor["manager_prefix"]
	fence := fixtures["swarma-broker-lab-start-fence/1"]
	fence["context"] = scope
	fence["consumed"] = true
	labObject(fence["heads"])["manager"] = floor["manager_prefix"]
	release := fixtures["swarma-lab-release-set/1"]
	release["context"] = scope
	release["contract_index_sha256"] = labContractIndex
	records := [][]byte{nil, labBytes(test, authority), labBytes(test, fence), labBytes(test, floor), labBytes(test, release)}
	activation["authority_sha256"] = labDigest(records[1])
	activation["fence_sha256"] = labDigest(records[2])
	activation["release_set_sha256"] = labDigest(records[4])
	records[0] = labBytes(test, activation)
	pins, err := NewLabPins(records[0], records[1], records[2], records[3], records[4])
	if err != nil {
		test.Fatal(err)
	}
	return records, pins
}

// TestLabActivationJoins proves joined enabled lab records admit while mismatched, disabled and production substitutions refuse.
func TestLabActivationJoins(test *testing.T) {
	records, _ := labPinRecords(test)
	for _, change := range []func(map[string]any){func(record map[string]any) { record["enabled"] = false }, func(record map[string]any) { record["test_api_key"] = false }, func(record map[string]any) { record["format"] = "swarma-broker-activation/1" }, func(record map[string]any) { record["service_lease_max_lifetime_seconds"] = int64(901) }, func(record map[string]any) { record["authority_sha256"] = "sha256:" + strings.Repeat("0", 64) }, func(record map[string]any) { record["qualification_revision"] = "other" }} {
		if _, err := NewLabPins(records[0], records[1], records[2], records[3], records[4]); err != nil {
			test.Fatal(err)
		}
		record, _ := wire.Parse(records[0])
		change(record)
		if _, err := NewLabPins(labBytes(test, record), records[1], records[2], records[3], records[4]); err == nil {
			test.Fatal("admitted invalid activation")
		}
	}
}

type labWireCase struct {
	Name    string `json:"name"`
	Admit   bool   `json:"admit"`
	Request struct {
		Method  string          `json:"method"`
		Path    string          `json:"path"`
		Headers [][2]string     `json:"headers"`
		Body    json.RawMessage `json:"body"`
		Scheme  string          `json:"source_scheme"`
	} `json:"request"`
}

func labWireCases(test *testing.T) []labWireCase {
	test.Helper()
	var fixtures struct {
		Cases []labWireCase `json:"cases"`
	}
	if json.Unmarshal(labWireFixtures, &fixtures) != nil {
		test.Fatal("wire fixtures")
	}
	return fixtures.Cases
}
func labRequest(fixture labWireCase) *http.Request {
	raw := fixture.Request.Body
	if string(raw) == "null" || fixture.Request.Method == http.MethodGet && string(raw) == "{}" {
		raw = nil
	}
	request := httptest.NewRequest(fixture.Request.Method, fixture.Request.Path, bytes.NewReader(raw))
	request.Header = http.Header{}
	for _, header := range fixture.Request.Headers {
		request.Header[header[0]] = append(request.Header[header[0]], header[1])
	}
	return request.WithContext(context.WithValue(request.Context(), gatewayPeerKey{}, gatewayPeer{4102}))
}

// TestLabFrozenWirePairs proves the actual intake classifier accepts every C0 positive and refuses every frozen request negative.
func TestLabFrozenWirePairs(test *testing.T) {
	for _, fixture := range labWireCases(test) {
		test.Run(fixture.Name, func(test *testing.T) {
			request := labRequest(fixture)
			admitted := fixture.Request.Scheme == "api-key" && labShapeValid(request)
			if request.Method == http.MethodPost {
				admitted = admitted && labBodyValid(fixture.Request.Body)
			}
			if admitted != fixture.Admit {
				test.Fatalf("admission=%t expected=%t", admitted, fixture.Admit)
			}
		})
	}
}

// TestLabAPIKeyDuplicateBetaFields proves one measured beta field works while duplicate and case-colliding fields refuse.
func TestLabAPIKeyDuplicateBetaFields(test *testing.T) {
	valid := labWireCases(test)[0]
	for _, key := range []string{"anthropic-beta", "Anthropic-Beta"} {
		request := labRequest(valid)
		if !labShapeValid(request) {
			test.Fatal("valid")
		}
		request.Header[key] = append(request.Header[key], labBeta)
		if labShapeValid(request) {
			test.Fatal("duplicate admitted")
		}
	}
}

// TestLabBetaCatalogue proves exact tokens and SP/HTAB controls while the C0 byte and literal operators refuse profile drift.
func TestLabBetaCatalogue(test *testing.T) {
	flags := strings.Split(labBeta, ",")
	control := " \t" + strings.Join(flags, ",\t ") + "\t "
	if !labBetaValid(control) {
		test.Fatal("OWS valid control")
	}
	for offset := 0; offset <= len(labBeta); offset++ {
		for char := 0; char <= 255; char++ {
			if char == 9 || char >= 32 && char < 127 {
				continue
			}
			candidate := labBeta[:offset] + string([]byte{byte(char)}) + labBeta[offset:]
			if !labBetaValid(control) || labBetaValid(candidate) {
				test.Fatalf("byte boundary %d class %d", offset, char)
			}
		}
	}
	for index, flag := range flags {
		for _, mutation := range literalMutations(flag) {
			if mutation.Admit {
				continue
			}
			candidate := append([]string(nil), flags...)
			candidate[index] = mutation.Value.(string)
			expected := strings.Trim(mutation.Value.(string), " \t") == flag
			if !labBetaValid(control) || labBetaValid(strings.Join(candidate, ",")) != expected {
				test.Fatalf("token %d operator %s", index, mutation.Name)
			}
		}
	}
	for offset, char := range labBeta {
		if char == ',' {
			for _, mutation := range separatorMutations(labBeta, offset) {
				expected := strings.ReplaceAll(strings.ReplaceAll(mutation.Value.(string), " ", ""), "\t", "") == labBeta
				if labBetaValid(mutation.Value.(string)) != expected {
					test.Fatalf("separator %s", mutation.Name)
				}
			}
		}
	}
}

type labHTTPSource struct {
	caller Caller
	scheme string
	ctx    context.Context
	cancel context.CancelFunc
	holds  atomic.Int64
	calls  atomic.Int64
}

func newLabHTTPSource() *labHTTPSource {
	ctx, cancel := context.WithCancel(context.Background())
	return &labHTTPSource{caller: Caller{"lab/anthropic", 4102, "worker-generation", "worker-execution"}, scheme: "api-key", ctx: ctx, cancel: cancel}
}
func (source *labHTTPSource) GatewayBinding() (Caller, string) {
	return source.caller, "gateway-generation"
}
func (source *labHTTPSource) CredentialValue(context.Context) (string, []byte, string, error) {
	source.calls.Add(1)
	return source.scheme, []byte(labMaterial), "issued-version", nil
}
func (source *labHTTPSource) CredentialContext(ctx context.Context, _ string) (context.Context, context.CancelFunc) {
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(source.ctx, cancel)
	return call, func() { stop(); cancel() }
}
func (source *labHTTPSource) Inventory() [][]byte { return [][]byte{[]byte(labMaterial)} }
func (source *labHTTPSource) ReportLeak()         { source.holds.Add(1); source.cancel() }

type labRoundTrip func(*http.Request) (*http.Response, error)

func (roundTrip labRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

// TestLabAPIKeyForwarding proves unchanged body/SSE and genuine policy errors, isolated POST injection, no redirects, and terminal header cleanup.
func TestLabAPIKeyForwarding(test *testing.T) {
	source := newLabHTTPSource()
	defer source.cancel()
	gateway, err := NewLabGateway(source, func([]byte) error { return nil })
	if err != nil {
		test.Fatal(err)
	}
	defer gateway.Close()
	var captured *http.Request
	calls := 0
	gateway.transport = labRoundTrip(func(request *http.Request) (*http.Response, error) {
		calls++
		captured = request
		if request.URL.Host != "api.anthropic.com" || request.URL.Scheme != "https" {
			test.Fatal("origin")
		}
		if request.Method == http.MethodPost {
			if request.Header.Get("X-Api-Key") != labMaterial || request.Header.Get("Authorization") != "" || request.Header.Get("Anthropic-Beta") != labBeta {
				test.Fatal("key-mode header")
			}
			raw, _ := io.ReadAll(request.Body)
			if !bytes.Equal(raw, labWireCases(test)[0].Request.Body) {
				test.Fatal("body changed")
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: {\"type\":\"message_stop\"}\n\n"))}, nil
		}
		if request.Header.Get("X-Api-Key") != "" || request.Header.Get("Authorization") != "" {
			test.Fatal("policy injection")
		}
		return &http.Response{StatusCode: 401, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("genuine-policy-error"))}, nil
	})
	for _, fixture := range labWireCases(test) {
		if !fixture.Admit || fixture.Name != "messages-valid" && fixture.Name != "policy-valid" {
			continue
		}
		writer := httptest.NewRecorder()
		gateway.ServeHTTP(writer, labRequest(fixture))
		expected := 200
		if fixture.Request.Method == http.MethodGet {
			expected = 401
		}
		if writer.Code != expected || captured.Header.Get("Authorization") != "" || captured.Header.Get("X-Api-Key") != "" {
			test.Fatalf("status=%d expected=%d header-clean=%t case=%s", writer.Code, expected, captured.Header.Get("X-Api-Key") == "", fixture.Name)
		}
		if expected == 401 && writer.Body.String() != "genuine-policy-error" {
			test.Fatal("fake policy success")
		}
	}
	before := calls
	request := labRequest(labWireCases(test)[0])
	source.scheme = "oauth-bearer"
	gateway.ServeHTTP(httptest.NewRecorder(), request)
	if calls != before {
		test.Fatal("wrong scheme forwarded")
	}
	source.scheme = "api-key"
	gateway.transport = labRoundTrip(func(request *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 307, Header: http.Header{"Location": []string{"https://invalid.example/"}}, Body: io.NopCloser(strings.NewReader("redirect")), Request: request}, nil
	})
	writer := httptest.NewRecorder()
	gateway.ServeHTTP(writer, labRequest(labWireCases(test)[0]))
	if writer.Code != 307 || calls != before+1 {
		test.Fatal("redirect followed")
	}
}

// TestLabKernelCallerRefusal proves the pinned kernel UID control while a missing or wrong peer cannot lease or forward.
func TestLabKernelCallerRefusal(test *testing.T) {
	source := newLabHTTPSource()
	defer source.cancel()
	gateway, _ := NewLabGateway(source, func([]byte) error { return nil })
	defer gateway.Close()
	calls := 0
	gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})
	valid := labRequest(labWireCases(test)[0])
	gateway.ServeHTTP(httptest.NewRecorder(), valid)
	if calls != 1 {
		test.Fatal("valid peer")
	}
	for _, ctx := range []context.Context{context.Background(), context.WithValue(context.Background(), gatewayPeerKey{}, gatewayPeer{1})} {
		writer := httptest.NewRecorder()
		gateway.ServeHTTP(writer, valid.WithContext(ctx))
		if writer.Code != 403 || calls != 1 || source.calls.Load() != 1 {
			test.Fatal("peer spoof")
		}
	}
}

// TestLabLeakPaths proves clean controls stream while request, header and cross-read response matches invoke the same hold without forwarding material.
func TestLabLeakPaths(test *testing.T) {
	for _, surface := range []string{"request", "response", "header"} {
		test.Run(surface, func(test *testing.T) {
			source := newLabHTTPSource()
			defer source.cancel()
			gateway, _ := NewLabGateway(source, func([]byte) error { return nil })
			defer gateway.Close()
			calls := 0
			gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				header := http.Header{}
				body := "clean"
				if surface == "response" {
					body = "before-" + labMaterial + "-after"
				}
				if surface == "header" {
					header.Set("X-Diagnostic", labMaterial)
				}
				return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(&labByteReader{raw: []byte(body)})}, nil
			})
			request := labRequest(labWireCases(test)[0])
			if surface == "request" {
				raw := bytes.ReplaceAll(labWireCases(test)[0].Request.Body, []byte("PUBLIC SYNTHETIC PROMPT"), []byte(labMaterial))
				request.Body = io.NopCloser(bytes.NewReader(raw))
				request.ContentLength = int64(len(raw))
			}
			writer := httptest.NewRecorder()
			func() {
				defer func() {
					if recovered := recover(); recovered != nil && recovered != http.ErrAbortHandler {
						panic(recovered)
					}
				}()
				gateway.ServeHTTP(writer, request)
			}()
			if source.holds.Load() != 1 || bytes.Contains(writer.Body.Bytes(), []byte(labMaterial)) || surface == "request" && calls != 0 {
				test.Fatal("missing durable-hold callback or disclosure")
			}
		})
	}
	source := newLabHTTPSource()
	defer source.cancel()
	writer := httptest.NewRecorder()
	if err := labStream(context.Background(), writer, strings.NewReader("clean control"), source.Inventory(), source.ReportLeak); err != nil || source.holds.Load() != 0 || writer.Body.String() != "clean control" {
		test.Fatal("clean control")
	}
}

type labByteReader struct{ raw []byte }

func (reader *labByteReader) Read(buffer []byte) (int, error) {
	if len(reader.raw) == 0 {
		return 0, io.EOF
	}
	buffer[0] = reader.raw[0]
	reader.raw = reader.raw[1:]
	return 1, nil
}

func labLeaseResult(test *testing.T, pins *LabPins, operation string) map[string]any {
	test.Helper()
	record := labFixtures(test)["anthropic-api-key-lab/1"]
	record["context"], record["gateway"], record["caller"], record["manager_floor"] = pins.context, pins.gateway, pins.worker, pins.floor
	record["activation_sha256"], record["authority_sha256"], record["fence_sha256"] = pins.activation, pins.authority, pins.fence
	record["request_id"] = operation
	now := time.Now().UTC()
	until := now.Add(pins.lifetime)
	bounds := labObject(record["bounds"])
	bounds["issued_at"] = now.Format(time.RFC3339Nano)
	bounds["authorized_until"] = until.Format(time.RFC3339Nano)
	bounds["lifetime_seconds"] = int64(pins.lifetime / time.Second)
	for _, name := range []string{"authority_until", "caller_until", "qualification_until", "time_until"} {
		bounds[name] = pins.deadline.UTC().Format(time.RFC3339Nano)
	}
	return record
}

// TestLabLeaseBounds proves valid 1/900-second results while over-ceiling, early-bound, wrong-caller and replayed responses cannot install material.
func TestLabLeaseBounds(test *testing.T) {
	for _, lifetime := range []time.Duration{time.Second, 900 * time.Second} {
		_, pins := labPinRecords(test)
		pins.lifetime = lifetime
		for _, change := range []func(map[string]any){nil, func(record map[string]any) { labObject(record["bounds"])["lifetime_seconds"] = int64(901) }, func(record map[string]any) {
			labObject(record["bounds"])["caller_until"] = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
		}, func(record map[string]any) { record["caller"] = record["gateway"] }, func(record map[string]any) { record["request_id"] = strings.Repeat("a", 32) }} {
			ctx, cancel := context.WithCancel(context.Background())
			client := &Client{leases: map[*Lease]bool{}}
			source := &LabSource{&labSourceState{pins: pins, ctx: ctx, cancel: cancel, client: client}}
			operation := strings.Repeat("b", 32)
			record := labLeaseResult(test, pins, operation)
			if change != nil {
				change(record)
			}
			err := source.accept(labBytes(test, record), operation, time.Now(), "")
			if (err == nil) != (change == nil) {
				test.Fatal("lease bound")
			}
			if err != nil && source.lease != nil {
				test.Fatal("invalid material installed")
			}
			cancel()
		}
	}
}

type labBroker struct {
	listener      net.Listener
	pins          *LabPins
	mu            sync.Mutex
	connections   map[net.Conn]bool
	checkDelay    time.Duration
	revoked       atomic.Bool
	silent        atomic.Bool
	requests      atomic.Int64
	renews        atomic.Int64
	holds         atomic.Int64
	loseAck       atomic.Bool
	holdOperation string
	holdMismatch  bool
	unknownIssue  atomic.Bool
	sequenceMode  atomic.Int64
	unknownHold   atomic.Bool
}

func labSocketDir(test *testing.T) string {
	test.Helper()
	directory, err := os.MkdirTemp("", "s-")
	if err != nil {
		test.Fatal(err)
	}
	test.Cleanup(func() { os.RemoveAll(directory) })
	return directory
}
func startLabBroker(test *testing.T, pins *LabPins) *labBroker {
	test.Helper()
	path := filepath.Join(labSocketDir(test), "broker.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		test.Fatal(err)
	}
	broker := &labBroker{listener: listener, pins: pins, connections: map[net.Conn]bool{}}
	test.Cleanup(func() {
		listener.Close()
		broker.mu.Lock()
		defer broker.mu.Unlock()
		for conn := range broker.connections {
			conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			broker.mu.Lock()
			broker.connections[conn] = true
			broker.mu.Unlock()
			go broker.serve(test, conn)
		}
	}()
	return broker
}
func (broker *labBroker) serve(test *testing.T, conn net.Conn) {
	defer conn.Close()
	for {
		raw, err := wire.Read(conn)
		if err != nil {
			return
		}
		var request struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
			ID     string          `json:"request_id"`
		}
		if json.Unmarshal(raw, &request) != nil {
			return
		}
		params, _ := wire.Parse(request.Params)
		var result any
		switch request.Method {
		case "hello":
			result = map[string]any{"version": 1, "principal": map[string]any{"service_name": "credential-gateway", "uid": os.Geteuid(), "service_generation": broker.pins.gateway["generation"]}}
		case "service.lease.request", "service.lease.renew":
			if request.Method == "service.lease.request" {
				broker.requests.Add(1)
				if broker.unknownIssue.Swap(false) {
					return
				}
			} else {
				broker.renews.Add(1)
			}
			result = labLeaseResult(test, broker.pins, params["operation_id"].(string))
		case "service.revocation.check":
			if broker.silent.Load() {
				time.Sleep(time.Second)
				return
			}
			time.Sleep(broker.checkDelay)
			verdict := "not_revoked"
			if broker.revoked.Load() {
				verdict = "revoked"
			}
			result = map[string]any{"verdict": verdict, "revocation_sequence": 1}
			if broker.sequenceMode.Load() == 1 {
				result = map[string]any{"verdict": verdict}
			}
			if broker.sequenceMode.Load() == 2 {
				result = map[string]any{"verdict": verdict, "revocation_sequence": nil}
			}
		case "account.hold":
			broker.holds.Add(1)
			broker.mu.Lock()
			operation := params["operation_id"].(string)
			if broker.holdOperation != "" && broker.holdOperation != operation {
				broker.holdMismatch = true
			}
			broker.holdOperation = operation
			broker.mu.Unlock()
			if broker.loseAck.Swap(false) {
				return
			}
			hold := labFixtures(test)["swarma-broker-lab-hold/1"]
			hold["context"], hold["caller"], hold["operation_id"] = broker.pins.context, broker.pins.worker, operation
			hold["request_sha256"] = labDigest(request.Params)
			if broker.unknownHold.Swap(false) {
				hold["result"] = "unknown"
			}
			result = hold
		default:
			return
		}
		if wire.Write(conn, map[string]any{"request_id": request.ID, "result": result}) != nil {
			return
		}
	}
}
func labOpen(test *testing.T, broker *labBroker, onClose func()) *LabSource {
	test.Helper()
	source, err := OpenLabSource(context.Background(), Config{Socket: broker.listener.Addr().String(), BrokerUID: uint32(os.Geteuid()), ServiceUID: uint32(os.Geteuid()), Generation: broker.pins.gateway["generation"].(string), MaxLifetime: broker.pins.lifetime}, broker.pins, onClose)
	if err != nil {
		test.Fatal(err)
	}
	test.Cleanup(source.Close)
	return source
}
func labUse(test *testing.T, source *LabSource) {
	test.Helper()
	scheme, material, _, err := source.CredentialValue(context.Background())
	defer clear(material)
	if err != nil || scheme != "api-key" || string(material) != labMaterial {
		test.Fatal("managed valid control", err)
	}
}

// TestLabDeadlineRenewal proves 900-second leases are checked without half-second renewal churn and a short lease renews before expiry.
func TestLabDeadlineRenewal(test *testing.T) {
	for _, lifetime := range []time.Duration{900 * time.Second, time.Second} {
		test.Run(lifetime.String(), func(test *testing.T) {
			_, pins := labPinRecords(test)
			pins.lifetime = lifetime
			broker := startLabBroker(test, pins)
			source := labOpen(test, broker, func() {})
			labUse(test, source)
			time.Sleep(850 * time.Millisecond)
			renews := broker.renews.Load()
			if lifetime == 900*time.Second && renews != 0 || lifetime == time.Second && renews == 0 {
				test.Fatalf("deadline renewal count %d", renews)
			}
		})
	}
}

// TestLabWatchdogSlowCurrentCheck proves repeated 190-ms current checks preserve valid use under the 500-ms watchdog.
func TestLabWatchdogSlowCurrentCheck(test *testing.T) {
	_, pins := labPinRecords(test)
	broker := startLabBroker(test, pins)
	broker.checkDelay = 190 * time.Millisecond
	ended := make(chan struct{})
	source := labOpen(test, broker, func() { close(ended) })
	labUse(test, source)
	select {
	case <-ended:
		test.Fatal("slow valid checks retired")
	case <-time.After(1150 * time.Millisecond):
	}
	labUse(test, source)
}

// TestLabWatchdogIndependent proves a stalled supervisor cannot delay the independent watchdog beyond 500 ms plus bounded closure.
func TestLabWatchdogIndependent(test *testing.T) {
	_, pins := labPinRecords(test)
	broker := startLabBroker(test, pins)
	ended := make(chan struct{})
	source := labOpen(test, broker, func() { close(ended) })
	labUse(test, source)
	source.mu.Lock()
	started := time.Now()
	select {
	case <-ended:
	case <-time.After(750 * time.Millisecond):
		source.mu.Unlock()
		test.Fatal("watchdog waited for supervisor")
	}
	source.mu.Unlock()
	if time.Since(started) > 750*time.Millisecond {
		test.Fatal("watchdog exceeded bound")
	}
	if _, _, _, err := source.CredentialValue(context.Background()); err == nil {
		test.Fatal("watchdog resurrected")
	}
}

// TestLabPollTeardown proves live broker/downstream connections, an active stream and listener close within one second of removal with no redial.
func TestLabPollTeardown(test *testing.T) {
	_, pins := labPinRecords(test)
	broker := startLabBroker(test, pins)
	listener, err := net.Listen("unix", filepath.Join(labSocketDir(test), "gateway.sock"))
	if err != nil {
		test.Fatal(err)
	}
	server := &http.Server{}
	closed := make(chan struct{})
	source := labOpen(test, broker, func() { server.Close(); listener.Close(); close(closed) })
	labUse(test, source)
	entered := make(chan struct{})
	server.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		close(entered)
		writer.Write([]byte("active\n"))
		writer.(http.Flusher).Flush()
		<-source.ctx.Done()
	})
	go server.Serve(listener)
	defer server.Close()
	conn, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		test.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: local\r\n\r\n")
	<-entered
	started := time.Now()
	broker.revoked.Store(true)
	select {
	case <-closed:
	case <-time.After(time.Second):
		test.Fatal("teardown timeout")
	}
	if time.Since(started) > time.Second {
		test.Fatal("poll bound")
	}
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err = io.ReadAll(conn)
	if err != nil {
		test.Fatal("downstream remained open")
	}
	if next, err := net.DialTimeout("unix", listener.Addr().String(), 100*time.Millisecond); err == nil {
		next.Close()
		test.Fatal("listener remained open")
	}
	if _, err := source.client.conn.Write([]byte{0}); err == nil {
		test.Fatal("broker connection remained open")
	}
	requests := broker.requests.Load()
	if _, _, _, err := source.CredentialValue(context.Background()); err == nil || broker.requests.Load() != requests {
		test.Fatal("revoked redial")
	}
}

// TestLabHoldAckLoss proves clean use then same-ID reconciliation across a lost acknowledgment with no local reopening or second lease.
func TestLabHoldAckLoss(test *testing.T) {
	_, pins := labPinRecords(test)
	broker := startLabBroker(test, pins)
	broker.loseAck.Store(true)
	source := labOpen(test, broker, func() {})
	labUse(test, source)
	source.ReportLeak()
	if _, _, _, err := source.CredentialValue(context.Background()); err == nil {
		test.Fatal("unknown hold reopened")
	}
	select {
	case <-source.holdDone:
	case <-time.After(2 * time.Second):
		test.Fatal("hold not reconciled")
	}
	source.mu.Lock()
	committed := source.holdCommitted
	source.mu.Unlock()
	broker.mu.Lock()
	mismatch := broker.holdMismatch
	broker.mu.Unlock()
	if !committed || mismatch || broker.holds.Load() != 2 {
		test.Fatal("same-ID hold reconciliation")
	}
	source.ReportLeak()
	if _, _, _, err := source.CredentialValue(context.Background()); err == nil || broker.requests.Load() != 1 {
		test.Fatal("held account reopened")
	}
}

// TestLabNativeCaller proves real Unix SO_PEERCRED admission and wrong-UID refusal on the actual HTTP parser, without a vendor connection.
func TestLabNativeCaller(test *testing.T) {
	for _, allowed := range []bool{true, false} {
		test.Run(fmt.Sprint(allowed), func(test *testing.T) {
			source := newLabHTTPSource()
			defer source.cancel()
			source.caller.UID = uint32(os.Geteuid())
			if !allowed {
				source.caller.UID++
			}
			gateway, err := NewLabGateway(source, func([]byte) error { return nil })
			if err != nil {
				test.Fatal(err)
			}
			defer gateway.Close()
			calls := 0
			gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
			})
			listener, err := net.Listen("unix", filepath.Join(labSocketDir(test), "http.sock"))
			if err != nil {
				test.Fatal(err)
			}
			defer listener.Close()
			server := &http.Server{Handler: gateway, ConnContext: gateway.ConnContext}
			defer server.Close()
			go server.Serve(listener)
			transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", listener.Addr().String())
			}}
			defer transport.CloseIdleConnections()
			request := labRequest(labWireCases(test)[0])
			headers := http.Header{}
			for name, values := range request.Header {
				for _, value := range values {
					headers.Add(name, value)
				}
			}
			request.Header = headers
			request.URL.Scheme = "http"
			request.URL.Host = "local"
			request.RequestURI = ""
			request.Header.Set("Content-Type", "application/json")
			response, err := (&http.Client{Transport: transport}).Do(request)
			if err != nil {
				test.Fatal("local HTTP failed")
			}
			defer response.Body.Close()
			io.Copy(io.Discard, response.Body)
			expected := 403
			if allowed {
				expected = 200
			}
			if response.StatusCode != expected || allowed && calls != 1 || !allowed && calls != 0 {
				test.Fatalf("native status=%d calls=%d", response.StatusCode, calls)
			}
		})
	}
}

// TestLabWatchdogTeardown proves an independently fired watchdog closes the listener, broker, downstream and live stream within one second.
func TestLabWatchdogTeardown(test *testing.T) {
	_, pins := labPinRecords(test)
	broker := startLabBroker(test, pins)
	listener, err := net.Listen("unix", filepath.Join(labSocketDir(test), "http.sock"))
	if err != nil {
		test.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{}
	defer server.Close()
	closed := make(chan struct{})
	source := labOpen(test, broker, func() { server.Close(); listener.Close(); close(closed) })
	labUse(test, source)
	entered := make(chan struct{})
	server.Handler = http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Write([]byte("active\n"))
		writer.(http.Flusher).Flush()
		close(entered)
		<-source.ctx.Done()
	})
	go server.Serve(listener)
	conn, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		test.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: local\r\n\r\n")
	<-entered
	source.mu.Lock()
	started := time.Now()
	select {
	case <-closed:
	case <-time.After(time.Second):
		source.mu.Unlock()
		test.Fatal("watchdog full teardown timeout")
	}
	source.mu.Unlock()
	if time.Since(started) > time.Second {
		test.Fatal("watchdog full bound")
	}
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := io.ReadAll(conn); err != nil {
		test.Fatal("live stream remained")
	}
	if other, err := net.DialTimeout("unix", listener.Addr().String(), 100*time.Millisecond); err == nil {
		other.Close()
		test.Fatal("listener remained")
	}
	if _, err := source.client.conn.Write([]byte{0}); err == nil {
		test.Fatal("broker remained")
	}
}

// TestLabCeilingAndPrincipalMismatch proves matching current pins connect but a different selector, service generation or broker peer refuses before leasing.
func TestLabCeilingAndPrincipalMismatch(test *testing.T) {
	_, pins := labPinRecords(test)
	broker := startLabBroker(test, pins)
	config := Config{Socket: broker.listener.Addr().String(), BrokerUID: uint32(os.Geteuid()), ServiceUID: uint32(os.Geteuid()), Generation: pins.gateway["generation"].(string), MaxLifetime: pins.lifetime}
	source, err := OpenLabSource(context.Background(), config, pins, func() {})
	if err != nil {
		test.Fatal("valid config", err)
	}
	source.Close()
	for _, change := range []func(*Config){func(config *Config) { config.MaxLifetime = time.Second }, func(config *Config) { config.MaxLifetime = 901 * time.Second }, func(config *Config) { config.Generation = "stale-generation" }, func(config *Config) { config.BrokerUID++ }, func(config *Config) { config.ServiceUID++ }} {
		candidate := config
		change(&candidate)
		if opened, err := OpenLabSource(context.Background(), candidate, pins, func() {}); err == nil {
			opened.Close()
			test.Fatal("mismatched config connected")
		}
	}
	if broker.requests.Load() != 0 {
		test.Fatal("mismatch leased")
	}
}

// TestLabLeaseContextExpiry proves issued use is initially live and cancels at its exclusive lease deadline even if the same lease later renews.
func TestLabLeaseContextExpiry(test *testing.T) {
	_, pins := labPinRecords(test)
	pins.lifetime = time.Second
	broker := startLabBroker(test, pins)
	source := labOpen(test, broker, func() {})
	_, material, version, err := source.CredentialValue(context.Background())
	clear(material)
	if err != nil {
		test.Fatal(err)
	}
	call, cancel := source.CredentialContext(context.Background(), version)
	defer cancel()
	if call.Err() != nil {
		test.Fatal("live context")
	}
	select {
	case <-call.Done():
	case <-time.After(1200 * time.Millisecond):
		test.Fatal("expired use survived")
	}
}

// TestLabFrozenContentPins proves the runtime contract copies match C0 and detects one changed byte beside each exact control.
func TestLabFrozenContentPins(test *testing.T) {
	for _, file := range []struct {
		raw    []byte
		digest string
	}{{labSurfaces, "sha256:8d819e57121a3993023e33fe085340269ff34e58676dafda5e55f03d39e458b7"}, {labWireFixtures, "sha256:6b0196268f5e920abf0cdfe10b2f94fb6ebccbb9dc330d3f218217b01f91423f"}} {
		if labDigest(file.raw) != file.digest {
			test.Fatal("C0 copy changed")
		}
		changed := append([]byte(nil), file.raw...)
		changed[len(changed)-1] ^= 1
		if labDigest(changed) == file.digest {
			test.Fatal("content detector failed")
		}
	}
}

// TestLabSourceRedaction proves both pointer and copied-value formatting and JSON omit holder material and transport state.
func TestLabSourceRedaction(test *testing.T) {
	_, pins := labPinRecords(test)
	broker := startLabBroker(test, pins)
	source := labOpen(test, broker, func() {})
	labUse(test, source)
	for _, value := range []any{source, *source} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(format, value) != "<lab-managed-source>" {
				test.Fatal("holder formatting exposed state")
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || bytes.Contains(raw, []byte(labMaterial)) {
			test.Fatal("holder JSON")
		}
	}
}

// TestLabUnknownIssue proves a healthy request works while a lost material reply closes authority and cannot mint a second operation by retry.
func TestLabUnknownIssue(test *testing.T) {
	for _, unknown := range []bool{false, true} {
		test.Run(fmt.Sprint(unknown), func(test *testing.T) {
			_, pins := labPinRecords(test)
			broker := startLabBroker(test, pins)
			broker.unknownIssue.Store(unknown)
			source := labOpen(test, broker, func() {})
			if !unknown {
				labUse(test, source)
				return
			}
			_, value, _, err := source.CredentialValue(context.Background())
			clear(value)
			if err != ErrUnknown {
				test.Fatal("lost issue not UNKNOWN")
			}
			if _, _, _, err := source.CredentialValue(context.Background()); err == nil || broker.requests.Load() != 1 {
				test.Fatal("UNKNOWN replay widened")
			}
		})
	}
}

// TestLabHoldUnknownResult proves a broker UNKNOWN acknowledgment stays closed until the same operation is durably acknowledged committed.
func TestLabHoldUnknownResult(test *testing.T) {
	_, pins := labPinRecords(test)
	broker := startLabBroker(test, pins)
	broker.unknownHold.Store(true)
	source := labOpen(test, broker, func() {})
	labUse(test, source)
	source.ReportLeak()
	if _, _, _, err := source.CredentialValue(context.Background()); err == nil {
		test.Fatal("unknown hold reopened")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if source.AwaitHold(ctx) != nil {
		test.Fatal("hold did not commit")
	}
	if broker.holds.Load() != 2 {
		test.Fatal("unknown was treated as committed")
	}
}

// TestLabReadStall proves a clean response control works and an upstream body stall is canceled at the existing intake idle budget.
func TestLabReadStall(test *testing.T) {
	source := newLabHTTPSource()
	defer source.cancel()
	gateway, _ := NewLabGateway(source, func([]byte) error { return nil })
	defer gateway.Close()
	gateway.idleTimeout = 15 * time.Millisecond
	for _, stall := range []bool{false, true} {
		reader, pipeWriter := io.Pipe()
		gateway.transport = labRoundTrip(func(*http.Request) (*http.Response, error) {
			if !stall {
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("clean"))}, nil
			}
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: reader}, nil
		})
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			defer func() {
				if recovered := recover(); recovered != nil && recovered != http.ErrAbortHandler {
					panic(recovered)
				}
			}()
			gateway.ServeHTTP(httptest.NewRecorder(), labRequest(labWireCases(test)[0]))
		}()
		select {
		case <-finished:
		case <-time.After(300 * time.Millisecond):
			reader.Close()
			pipeWriter.Close()
			test.Fatal("stalled response survived idle budget")
		}
		reader.Close()
		pipeWriter.Close()
	}
}

// TestLabBodyNumberAliases proves the pinned integer control is admitted without lossy rounding or unsupported billing aliases.
func TestLabBodyNumberAliases(test *testing.T) {
	control := labWireCases(test)[0].Request.Body
	if !labBodyValid(control) {
		test.Fatal("valid control")
	}
	for _, replacement := range []string{"128000.0000000000000001", "128000.0", "1.28e5", "128001", "127999"} {
		candidate := bytes.Replace(control, []byte("128000"), []byte(replacement), 1)
		if labBodyValid(candidate) {
			test.Fatalf("numeric alias admitted: %s", replacement)
		}
	}
}

// TestLabPrincipalWidth proves the joined native UID control works while a larger integer cannot wrap into the same kernel UID.
func TestLabPrincipalWidth(test *testing.T) {
	records, _ := labPinRecords(test)
	if _, err := NewLabPins(records[0], records[1], records[2], records[3], records[4]); err != nil {
		test.Fatal("valid control")
	}
	for _, role := range []string{"gateway", "worker"} {
		authority, _ := wire.Parse(records[1])
		principal := labObject(authority[role])
		principal["uid"] = principal["uid"].(int64) + 1<<32
		changed := labBytes(test, authority)
		activation, _ := wire.Parse(records[0])
		activation["authority_sha256"] = labDigest(changed)
		if _, err := NewLabPins(labBytes(test, activation), changed, records[2], records[3], records[4]); err == nil {
			test.Fatal("UID truncation admitted")
		}
	}
}

// TestLabCurrentSequence proves a complete current result refreshes authority but missing/null zero-baseline sequences retire use without reacquisition.
func TestLabCurrentSequence(test *testing.T) {
	for _, mode := range []int64{1, 2} {
		test.Run(fmt.Sprint(mode), func(test *testing.T) {
			_, pins := labPinRecords(test)
			broker := startLabBroker(test, pins)
			source := labOpen(test, broker, func() {})
			defer source.Close()
			labUse(test, source)
			source.mu.Lock()
			source.revocation = 0
			source.mu.Unlock()
			broker.sequenceMode.Store(mode)
			_, material, _, err := source.CredentialValue(context.Background())
			expected := ErrFrame
			if mode == 2 {
				expected = ErrRevoked
			}
			if err != expected || source.ctx.Err() == nil || len(material) != 0 {
				test.Fatalf("current sequence mode %d: error=%v closed=%t material=%t", mode, err, source.ctx.Err() != nil, len(material) > 0)
			}
			if broker.requests.Load() != 1 {
				test.Fatal("material reacquired")
			}
		})
	}
}
