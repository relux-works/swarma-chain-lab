//go:build linux && gateway_lab

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service"
	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/labtest"
)

type commandTransport func(*http.Request) (*http.Response, error)

func (transport commandTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

type commandHarness struct {
	mappingEdit  func(*brokerMapping)
	responseBody func() io.ReadCloser
	fixture      *labtest.Fixture
	broker       *labtest.Broker
	config       proxy.GatewayFileConfig
	root         string
	socket       string
	paths        []*string
	mapping      []byte
	ctx          context.Context
	cancel       context.CancelFunc
	result       chan error
	calls        atomic.Int64
	entered      chan context.Context
	bodies       sync.Map
	returned     atomic.Bool
}

func commandFixture(test *testing.T) *commandHarness {
	test.Helper()
	fixture := labtest.NewFixture(test, "../../service/testdata/lab-v0/fixtures.json")
	root := labtest.ShortDir(test)
	gateway := labtest.Object(fixture.Objects["swarma-broker-lab-authority/1"]["gateway"])
	gateway["generation"] = "g"
	fixture.Rebuild()
	config := proxy.GatewayFileConfig{Mode: proxy.ModeManaged}
	config.Upstream = proxy.ManagedUpstream
	config.StateDir = filepath.Join(root, "state")
	if os.Mkdir(config.StateDir, 0700) != nil {
		test.Fatal("accounting directory")
	}
	config.Endpoint = proxy.Endpoint{URL: "https://gateway.example", CertSHA256: strings.Repeat("b", 64)}
	config.Models = map[string]proxy.Model{"claude-opus-5-5": {ContextTokens: 256000, InputNanoUSD: 1, OutputNanoUSD: 1, Source: "public synthetic model bound"}}
	config.DailyCostCeilingNanoUSD = 1000000000000
	if err := proxy.InitializeAccounting(proxy.Config{StateDir: config.StateDir, DailyCostCeilingNanoUSD: config.DailyCostCeilingNanoUSD, Endpoint: config.Endpoint, Upstream: config.Upstream, Models: config.Models, APIKey: proxy.NewAPIKey(labtest.Material), Now: time.Now}); err != nil {
		test.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	test.Cleanup(cancel)
	harness := &commandHarness{fixture: fixture, config: config, root: root, ctx: ctx, cancel: cancel, result: make(chan error, 1), entered: make(chan context.Context, 16)}
	harness.socket = filepath.Join(root, "credential-gateway", "g", "gateway.sock")
	if err := os.MkdirAll(filepath.Dir(harness.socket), 0750); err != nil {
		test.Fatal(err)
	}
	return harness
}
func (harness *commandHarness) start(test *testing.T, leak bool) {
	test.Helper()
	harness.fixture.Rebuild()
	harness.broker = labtest.StartBroker(test, harness.fixture)
	authority := harness.fixture.Objects["swarma-broker-lab-authority/1"]
	worker := labtest.Object(authority["worker"])
	mapping := brokerMapping{Socket: harness.broker.Listener.Addr().String(), BrokerUID: uint32(os.Geteuid()), Generation: "g", Account: labtest.Object(authority["context"])["account"].(string), WorkerUID: uint32(worker["uid"].(int64)), WorkerGeneration: worker["generation"].(string), LaunchID: worker["execution_id"].(string), Lifetime: uint64(harness.fixture.Lifetime / time.Second)}
	if harness.mappingEdit != nil {
		harness.mappingEdit(&mapping)
	}
	harness.mapping, _ = json.Marshal(mapping)
	for index, raw := range harness.fixture.Records {
		path := filepath.Join(harness.root, fmt.Sprintf("record-%d", index))
		if os.WriteFile(path, raw, 0400) != nil {
			test.Fatal("snapshot write")
		}
		harness.paths = append(harness.paths, &path)
	}
	inputs := runInputs{
		loadConfig: func(path string) (proxy.GatewayFileConfig, error) {
			if path != "config" {
				test.Error("config path retargeted")
			}
			return harness.config, nil
		},
		readInstalled: func(path string, limit int64) ([]byte, error) {
			if path != "mapping" || limit != 65536 {
				test.Error("mapping read retargeted")
			}
			return harness.mapping, nil
		},
		readPrivate: proxy.ReadPrivateFile,
		gatewayIO: service.LabGatewayIO{PeerUID: func(net.Conn) (uint32, error) { return mapping.WorkerUID, nil }, Transport: commandTransport(func(request *http.Request) (*http.Response, error) {
			harness.calls.Add(1)
			if request.URL.Scheme != "https" || request.URL.Host != "api.anthropic.com" || request.Header.Get("X-Api-Key") != labtest.Material {
				test.Error("fixed upstream or key boundary")
			}
			harness.entered <- request.Context()
			if harness.responseBody != nil {
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: harness.responseBody()}, nil
			}
			reader, writer := io.Pipe()
			body := &commandBody{PipeReader: reader}
			harness.bodies.Store(body, true)
			go func() {
				data := "data: control\n\n"
				if leak {
					data = "data: " + labtest.Material + "\n\n"
				}
				_, _ = io.WriteString(writer, data)
				<-request.Context().Done()
				writer.Close()
			}()
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: body}, nil
		})},
	}
	go func() {
		err := run(harness.ctx, "config", "mapping", harness.socket, harness.paths, inputs)
		harness.returned.Store(true)
		harness.result <- err
	}()
	test.Cleanup(func() {
		harness.cancel()
		select {
		case <-harness.result:
		case <-time.After(2 * time.Second):
			test.Error("command leaked after cleanup")
		}
	})
}
func (harness *commandHarness) dial(test *testing.T) net.Conn {
	test.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("unix", harness.socket, 20*time.Millisecond)
		if err == nil {
			test.Cleanup(func() { conn.Close() })
			return conn
		}
		if harness.returned.Load() || time.Now().After(deadline) {
			test.Fatal("command did not admit control connection")
		}
		time.Sleep(time.Millisecond)
	}
}
func (harness *commandHarness) request(test *testing.T, conn net.Conn) {
	test.Helper()
	raw, err := os.ReadFile("../../service/testdata/lab-v0/wire-fixtures.json")
	if err != nil {
		test.Fatal(err)
	}
	var fixtures struct {
		Cases []struct {
			Request struct {
				Headers [][2]string     `json:"headers"`
				Body    json.RawMessage `json:"body"`
			} `json:"request"`
		} `json:"cases"`
	}
	if json.Unmarshal(raw, &fixtures) != nil {
		test.Fatal("wire fixture")
	}
	fixture := fixtures.Cases[0].Request
	var request bytes.Buffer
	fmt.Fprintf(&request, "POST /v1/messages?beta=true HTTP/1.1\r\nHost: gateway\r\nContent-Length: %d\r\n", len(fixture.Body))
	for _, header := range fixture.Headers {
		fmt.Fprintf(&request, "%s: %s\r\n", header[0], header[1])
	}
	request.WriteString("\r\n")
	request.Write(fixture.Body)
	if _, err := conn.Write(request.Bytes()); err != nil {
		test.Fatal(err)
	}
}
func (harness *commandHarness) closed(test *testing.T, connections []net.Conn, started time.Time) {
	test.Helper()
	deadline := started.Add(time.Second)
	for _, conn := range connections {
		_ = conn.SetReadDeadline(deadline)
		if _, err := io.Copy(io.Discard, conn); err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				test.Fatal("downstream survived one-second teardown")
			}
		}
	}
	for time.Now().Before(deadline) {
		_, err := os.Lstat(harness.socket)
		conn, dialErr := net.DialTimeout("unix", harness.socket, 10*time.Millisecond)
		if conn != nil {
			conn.Close()
		}
		if os.IsNotExist(err) && dialErr != nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	test.Fatal("listener remained connectable or linked beyond one second")
}

type commandBody struct {
	*io.PipeReader
	closed atomic.Bool
}

func (body *commandBody) Close() error { body.closed.Store(true); return body.PipeReader.Close() }

// TestLabRunAuthorityTeardown proves shipped run closes every live/idle/partial downstream and listener and cancels upstream within one second after revocation, a stalled poll or pinned expiry.
func TestLabRunAuthorityTeardown(test *testing.T) {
	for _, mode := range []string{"revoke", "watchdog", "deadline"} {
		test.Run(mode, func(test *testing.T) {
			harness := commandFixture(test)
			if mode == "deadline" {
				harness.fixture.Deadline = time.Now().Add(1500 * time.Millisecond)
			}
			harness.start(test, false)
			live := harness.dial(test)
			second := harness.dial(test)
			idle := harness.dial(test)
			partial := harness.dial(test)
			_, _ = partial.Write([]byte("POST /v1/messages?beta=true HTTP/1.1\r\n"))
			harness.request(test, live)
			var upstream context.Context
			select {
			case upstream = <-harness.entered:
			case <-time.After(time.Second):
				test.Fatal("request not composed through source and gateway")
			}
			response, err := http.ReadResponse(bufio.NewReader(live), nil)
			if err != nil || response.StatusCode != 200 {
				test.Fatal("live SSE positive control", err)
			}
			harness.request(test, second)
			var secondUpstream context.Context
			select {
			case secondUpstream = <-harness.entered:
			case <-time.After(time.Second):
				test.Fatal("second stream not admitted")
			}
			secondResponse, secondErr := http.ReadResponse(bufio.NewReader(second), nil)
			if secondErr != nil || secondResponse.StatusCode != 200 {
				test.Fatal("second live stream control")
			}
			if harness.returned.Load() || harness.broker.Requests.Load() != 1 || upstream.Err() != nil || secondUpstream.Err() != nil {
				test.Fatal("live command control")
			}
			started := time.Now()
			switch mode {
			case "revoke":
				harness.broker.CheckMode.Store("revoked")
			case "watchdog":
				harness.broker.CheckMode.Store("stall")
			case "deadline":
				started = harness.fixture.Deadline
			}
			harness.closed(test, []net.Conn{live, second, idle, partial}, started)
			select {
			case <-upstream.Done():
			case <-time.After(time.Until(started.Add(time.Second))):
				test.Fatal("upstream context survived retirement")
			}
			select {
			case <-secondUpstream.Done():
			case <-time.After(time.Until(started.Add(time.Second))):
				test.Fatal("second upstream survived retirement")
			}
			for {
				allClosed := true
				harness.bodies.Range(func(key, value any) bool { allClosed = allClosed && key.(*commandBody).closed.Load(); return true })
				if allClosed {
					break
				}
				if !time.Now().Before(started.Add(time.Second)) {
					test.Fatal("upstream body not closed within teardown budget")
				}
				time.Sleep(time.Millisecond)
			}
			for harness.broker.Active.Load() != 0 && time.Now().Before(started.Add(time.Second)) {
				time.Sleep(time.Millisecond)
			}
			if harness.broker.Active.Load() != 0 {
				test.Fatal("broker connection survived teardown")
			}
		})
	}
}

// TestLabRunHoldBinding proves run stays closed but alive across lost/UNKNOWN/mis-bound acknowledgments, then accepts only the same-ID exact commit without reopening.
func TestLabRunHoldBinding(test *testing.T) {
	for _, mode := range []string{"", "lost", "unknown", "operation", "digest", "context", "caller"} {
		test.Run("case-"+mode, func(test *testing.T) {
			harness := commandFixture(test)
			harness.start(test, true)
			harness.broker.HoldMode.Store(mode)
			live := harness.dial(test)
			idle := harness.dial(test)
			harness.request(test, live)
			started := time.Now()
			harness.closed(test, []net.Conn{live, idle}, started)
			deadline := time.Now().Add(time.Second)
			for harness.broker.Holds.Load() < 2 && mode != "" && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if mode != "" {
				if harness.returned.Load() || harness.broker.Holds.Load() < 2 || !harness.broker.SameHold() {
					test.Fatal("unacknowledged hold allowed command exit or changed operation")
				}
				time.Sleep(80 * time.Millisecond)
				if harness.returned.Load() {
					test.Fatal("mis-bound hold completed")
				}
				harness.broker.HoldMode.Store("")
			}
			deadline = time.Now().Add(time.Second)
			for !harness.returned.Load() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if !harness.returned.Load() || !harness.broker.SameHold() || harness.calls.Load() != 1 {
				test.Fatal("exact-ack recovery failed or reopened forwarding")
			}
		})
	}
}

// TestLabRunStartupFloor proves run admits the empty floor but refuses an active hold before broker or listener activity.
func TestLabRunStartupFloor(test *testing.T) {
	for _, held := range []bool{false, true} {
		test.Run(map[bool]string{false: "clear", true: "held"}[held], func(test *testing.T) {
			harness := commandFixture(test)
			if held {
				harness.fixture.Objects["swarma-broker-lab-consumer-high-water/1"]["hold_ids"] = []any{"fixture-hold"}
			}
			harness.start(test, false)
			if !held {
				conn := harness.dial(test)
				harness.request(test, conn)
				select {
				case <-harness.entered:
				case <-time.After(time.Second):
					test.Fatal("clear floor control refused")
				}
				return
			}
			deadline := time.Now().Add(time.Second)
			for !harness.returned.Load() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if !harness.returned.Load() || harness.broker.Active.Load() != 0 || harness.broker.Requests.Load() != 0 {
				test.Fatal("held floor admitted startup")
			}
			if _, err := os.Lstat(harness.socket); !os.IsNotExist(err) {
				test.Fatal("held floor published listener")
			}
		})
	}
}

// TestLabRunAdmission proves ordinary startup admits while truncating worker width, mismatched lifetime and each protected caller mapping refuse before publishing a listener.
func TestLabRunAdmission(test *testing.T) {
	for _, mode := range []string{"", "worker-width", "lifetime", "account", "worker", "generation", "launch"} {
		test.Run("case-"+mode, func(test *testing.T) {
			harness := commandFixture(test)
			if mode == "worker-width" {
				worker := labtest.Object(harness.fixture.Objects["swarma-broker-lab-authority/1"]["worker"])
				worker["uid"] = worker["uid"].(int64) + (1 << 32)
			}
			harness.mappingEdit = func(mapping *brokerMapping) {
				switch mode {
				case "lifetime":
					mapping.Lifetime--
				case "account":
					mapping.Account = "foreign"
				case "worker":
					mapping.WorkerUID++
				case "generation":
					mapping.WorkerGeneration = "foreign"
				case "launch":
					mapping.LaunchID = "foreign"
				}
			}
			harness.start(test, false)
			if mode == "" {
				conn := harness.dial(test)
				harness.request(test, conn)
				select {
				case <-harness.entered:
				case <-time.After(time.Second):
					test.Fatal("valid control refused")
				}
				return
			}
			deadline := time.Now().Add(time.Second)
			for !harness.returned.Load() && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if !harness.returned.Load() || harness.calls.Load() != 0 {
				test.Fatal("invalid startup admitted")
			}
			if _, err := os.Lstat(harness.socket); !os.IsNotExist(err) {
				test.Fatal("invalid startup published listener")
			}
		})
	}
}

type commandLateLeak struct {
	once   sync.Once
	closed chan struct{}
	read   bool
}

func (body *commandLateLeak) Close() error { body.once.Do(func() { close(body.closed) }); return nil }
func (body *commandLateLeak) Read(buffer []byte) (int, error) {
	if body.read {
		return 0, io.EOF
	}
	<-body.closed
	time.Sleep(100 * time.Millisecond)
	body.read = true
	return copy(buffer, labtest.Material), io.EOF
}

// TestLabRunLateLeak proves retirement drains active intake before the hold gate, including a material match delivered by an already-started read after cancellation.
func TestLabRunLateLeak(test *testing.T) {
	harness := commandFixture(test)
	harness.responseBody = func() io.ReadCloser { return &commandLateLeak{closed: make(chan struct{})} }
	harness.start(test, false)
	harness.broker.HoldMode.Store("unknown")
	live := harness.dial(test)
	harness.request(test, live)
	select {
	case <-harness.entered:
	case <-time.After(time.Second):
		test.Fatal("upstream not entered")
	}
	started := time.Now()
	harness.broker.CheckMode.Store("revoked")
	harness.closed(test, []net.Conn{live}, started)
	deadline := time.Now().Add(time.Second)
	for harness.broker.Holds.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if harness.returned.Load() || harness.broker.Holds.Load() == 0 {
		test.Fatal("late material match escaped command hold reconciliation")
	}
	harness.broker.HoldMode.Store("")
	deadline = time.Now().Add(time.Second)
	for !harness.returned.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !harness.returned.Load() || !harness.broker.SameHold() {
		test.Fatal("late hold did not commit same operation")
	}
}
