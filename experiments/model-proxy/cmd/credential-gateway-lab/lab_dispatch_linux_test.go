//go:build linux && gateway_lab

package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service"
	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/labtest"
)

// TestLabRunRetiredDispatch proves the shipped request dispatcher refuses an already-read request after drain, over Unix HTTP with a still-live real source and gateway beside a 200 control.
func TestLabRunRetiredDispatch(test *testing.T) {
	harness := commandFixture(test)
	records := harness.fixture.Records
	pins, err := service.NewLabPins(records[0], records[1], records[2], records[3], records[4])
	if err != nil {
		test.Fatal("pins control")
	}
	broker := labtest.StartBroker(test, harness.fixture)
	authority := harness.fixture.Objects["swarma-broker-lab-authority/1"]
	identity := labtest.Object(authority["gateway"])
	worker := labtest.Object(authority["worker"])
	source, err := service.OpenLabSource(context.Background(), service.Config{Socket: broker.Listener.Addr().String(), BrokerUID: uint32(os.Geteuid()), ServiceUID: uint32(os.Geteuid()), Generation: identity["generation"].(string), MaxLifetime: harness.fixture.Lifetime}, pins, func() {})
	if err != nil {
		test.Fatal("source control")
	}
	defer source.Close()
	if service.PrepareLabAttemptGroup(harness.attempts.Root) != nil {
		test.Fatal("attempt group")
	}
	harness.attempts.PublishStart()
	attempts, err := service.OpenLabAttempts(context.Background(), harness.attempts.Root, source)
	if err != nil {
		test.Fatal("attempt admission", err)
	}
	defer attempts.Close()
	var calls atomic.Int32
	gateway, err := service.NewLabGateway(source, func([]byte) error { return nil }, service.LabGatewayIO{
		Attempts: attempts,
		PeerUID:  func(net.Conn) (uint32, error) { return uint32(worker["uid"].(int64)), nil },
		Transport: commandTransport(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}, "Request-Id": {"control-request"}}, Body: io.NopCloser(strings.NewReader(labtest.AttemptSSE()))}, nil
		}),
	})
	if err != nil {
		test.Fatal("gateway control")
	}
	defer gateway.Close()
	requests := &labRequests{next: gateway}
	listener, err := net.Listen("unix", harness.socket)
	if err != nil {
		test.Fatal("listener control")
	}
	server := &http.Server{Handler: requests, ConnContext: gateway.ConnContext}
	stopped := make(chan struct{})
	go func() { defer close(stopped); _ = server.Serve(listener) }()
	defer func() { _ = server.Close(); <-stopped }()
	conn, err := net.Dial("unix", harness.socket)
	if err != nil {
		test.Fatal("connection control")
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for _, retired := range []bool{false, true} {
		if retired {
			requests.drain()
		}
		harness.request(test, conn)
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			test.Fatal("dispatcher response")
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		want := 200
		if retired {
			want = 503
		}
		if response.StatusCode != want || calls.Load() != 1 {
			test.Fatal("retired dispatcher forwarded through a live gateway")
		}
	}
}
