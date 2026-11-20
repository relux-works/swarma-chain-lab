//go:build linux && gateway_lab

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service"
	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/labtest"
)

type attemptCrashManifest struct {
	Config                                    proxy.GatewayFileConfig
	Mapping                                   brokerMapping
	Paths                                     []string
	Socket, Root, Checkpoint, Upstream, Point string
	Traced                                    bool
}

func attemptCrashInputs(manifest attemptCrashManifest, transport http.RoundTripper) runInputs {
	return runInputs{loadConfig: func(string) (proxy.GatewayFileConfig, error) { return manifest.Config, nil }, readInstalled: func(string, int64) ([]byte, error) { return json.Marshal(manifest.Mapping) }, readPrivate: proxy.ReadPrivateFile, gatewayIO: service.LabGatewayIO{PeerUID: func(net.Conn) (uint32, error) { return manifest.Mapping.WorkerUID, nil }, Transport: transport}}
}
func attemptCrashPaths(manifest attemptCrashManifest) []*string {
	var paths []*string
	for _, path := range manifest.Paths {
		copy := path
		paths = append(paths, &copy)
	}
	return paths
}

// TestLabAttemptCrashChild drives the shipped run/source/gateway in a separate process; its only fault seam blocks immediately before or after the loopback upstream sees the reserved request.
func TestLabAttemptCrashChild(test *testing.T) {
	path := os.Getenv("LAB_ATTEMPT_CRASH_MANIFEST")
	if path == "" {
		test.Skip("subprocess fixture only")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		test.Fatal(err)
	}
	var manifest attemptCrashManifest
	if json.Unmarshal(raw, &manifest) != nil {
		test.Fatal("manifest")
	}
	transport := commandTransport(func(request *http.Request) (*http.Response, error) {
		checkpoint := func() {
			if os.WriteFile(manifest.Checkpoint, []byte("reserved"), 0400) != nil {
				test.Error("checkpoint")
			}
		}
		if manifest.Point == "before-forward" {
			checkpoint()
			<-request.Context().Done()
			return nil, request.Context().Err()
		}
		outbound := request.Clone(request.Context())
		outbound.URL.Scheme = "http"
		outbound.URL.Host = manifest.Upstream
		outbound.RequestURI = ""
		response, err := http.DefaultTransport.RoundTrip(outbound)
		if err == nil {
			checkpoint()
		}
		return response, err
	})
	if err := run(context.Background(), "config", "mapping", manifest.Socket, attemptCrashPaths(manifest), attemptCrashInputs(manifest, transport)); err != nil {
		if manifest.Traced && errors.Is(err, service.ErrUnknown) {
			return
		}
		test.Fatal("child command", err)
	}
}

// TestLabAttemptRunCrash proves real process death on both sides of the forward consumes the durable ordinal, recovers full UNKNOWN, and makes a repeated command status-only with no resend.
func TestLabAttemptRunCrash(test *testing.T) {
	for _, point := range []string{"before-forward", "after-forward"} {
		test.Run(point, func(test *testing.T) { attemptCrash(test, point, false) })
	}
}

// TestLabAttemptRunDurability proves the real run's pre-forward immutable writes and file/directory fsync barriers, reading the kernel trace only after controlled cancellation and tracer exit guarantee complete output.
func TestLabAttemptRunDurability(test *testing.T) { attemptCrash(test, "before-forward", true) }

func attemptCrash(test *testing.T, point string, traced bool) {
	test.Helper()
	harness := commandFixture(test)
	harness.attempts.Rebind()
	if service.PrepareLabAttemptGroup(harness.attempts.Root) != nil {
		test.Fatal("group")
	}
	harness.attempts.PublishStart()
	broker := labtest.StartBroker(test, harness.fixture)
	identity := labtest.Object(harness.fixture.Objects["swarma-broker-lab-authority/1"]["worker"])
	received := make(chan struct{}, 1)
	upstreamCancelled := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		_ = request.Body.Close()
		received <- struct{}{}
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.Header().Set("Request-Id", "control-request")
		_, _ = io.WriteString(writer, "data: in-flight control\n\n")
		writer.(http.Flusher).Flush()
		<-request.Context().Done()
		upstreamCancelled <- struct{}{}
	}))
	defer func() { upstream.CloseClientConnections(); upstream.Close() }()
	manifest := attemptCrashManifest{Config: harness.config, Mapping: brokerMapping{Socket: broker.Listener.Addr().String(), BrokerUID: uint32(os.Geteuid()), Generation: "g", Account: labtest.Object(harness.fixture.Objects["swarma-broker-lab-authority/1"]["context"])["account"].(string), WorkerUID: uint32(identity["uid"].(int64)), WorkerGeneration: identity["generation"].(string), LaunchID: identity["execution_id"].(string), Lifetime: uint64(harness.fixture.Lifetime / time.Second)}, Socket: harness.socket, Root: harness.attempts.Root, Checkpoint: filepath.Join(harness.root, "checkpoint"), Upstream: upstream.Listener.Addr().String(), Point: point, Traced: traced}
	for index, raw := range harness.fixture.Records {
		path := filepath.Join(harness.root, "crash-record-"+strconv.Itoa(index))
		if os.WriteFile(path, raw, 0400) != nil {
			test.Fatal("record")
		}
		manifest.Paths = append(manifest.Paths, path)
	}
	manifest.Paths = append(manifest.Paths, manifest.Root)
	path := filepath.Join(harness.root, "manifest")
	raw, _ := json.Marshal(manifest)
	if os.WriteFile(path, raw, 0400) != nil {
		test.Fatal("manifest")
	}
	child := exec.Command(os.Args[0], "-test.run=^TestLabAttemptCrashChild$", "-test.timeout=15s")
	if traced {
		if _, err := exec.LookPath("strace"); err != nil {
			test.Fatal("strace is required for durability qualification")
		}
		child = exec.Command("strace", "-ff", "-ttt", "-yy", "--kill-on-exit", "-o", filepath.Join(harness.root, "trace"), "-e", "trace=fsync,renameat,renameat2,openat,write", os.Args[0], "-test.run=^TestLabAttemptCrashChild$", "-test.timeout=15s")
	}
	child.Env = append(os.Environ(), "LAB_ATTEMPT_CRASH_MANIFEST="+path)
	output, err := os.Create(filepath.Join(harness.root, "child.log"))
	if err != nil {
		test.Fatal(err)
	}
	defer output.Close()
	child.Stdout = output
	child.Stderr = output
	if child.Start() != nil {
		test.Fatal("child start")
	}
	waited := false
	defer func() {
		if !waited {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	var conn net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout("unix", harness.socket, 25*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if conn == nil {
		test.Fatal("child listener")
	}
	defer conn.Close()
	harness.request(test, conn)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(manifest.Checkpoint); err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := os.Stat(manifest.Checkpoint); err != nil {
		test.Fatal("reserved checkpoint not reached")
	}
	ledger := attemptRunLedger(test, harness)
	attempt := labtest.Object(ledger["attempts"].([]any)[0])
	if attempt["state"] != "reserved" || attempt["ordinal"] != json.Number("1") || attempt["reservation_cost_usd"] != "10.560000" {
		test.Fatal("crash had no durable reservation")
	}
	if point == "before-forward" {
		select {
		case <-received:
			test.Fatal("forward preceded reservation checkpoint")
		default:
		}
	} else {
		select {
		case <-received:
		default:
			test.Fatal("forward not observed")
		}
	}
	if traced {
		_ = conn.Close()
		if err := child.Wait(); err != nil {
			test.Fatal("trace did not drain after controlled cancellation", err)
		}
		waited = true
		attemptCheckTrace(test, harness)
	} else {
		if child.Process.Kill() != nil {
			test.Fatal("crash injection")
		}
		_ = child.Wait()
		waited = true
	}
	if point == "after-forward" {
		select {
		case <-upstreamCancelled:
		case <-time.After(time.Second):
			test.Fatal("dead process left upstream active")
		}
	}
	for broker.Active.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	calls := 0
	err = run(context.Background(), "config", "mapping", manifest.Socket, attemptCrashPaths(manifest), attemptCrashInputs(manifest, commandTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, io.ErrUnexpectedEOF })))
	if !errors.Is(err, service.ErrUnknown) || calls != 0 {
		test.Fatal("replayed command resent or reopened")
	}
	ledger = attemptRunLedger(test, harness)
	attempt = labtest.Object(ledger["attempts"].([]any)[0])
	if ledger["status"] != "unknown" || attempt["state"] != "unknown" || attempt["settled_micro_usd"] != json.Number("10560000") || len(ledger["attempts"].([]any)) != 1 {
		test.Fatal("crash recovery refunded/reused ordinal")
	}
	before := labtest.Encode(test, ledger)
	err = run(context.Background(), "config", "mapping", manifest.Socket, attemptCrashPaths(manifest), attemptCrashInputs(manifest, commandTransport(func(*http.Request) (*http.Response, error) { calls++; return nil, io.ErrUnexpectedEOF })))
	if !errors.Is(err, service.ErrUnknown) || calls != 0 || string(before) != string(labtest.Encode(test, attemptRunLedger(test, harness))) {
		test.Fatal("UNKNOWN replay changed history or reopened group")
	}
	if _, err := net.DialTimeout("unix", manifest.Socket, 25*time.Millisecond); err == nil {
		test.Fatal("replay enabled listener")
	}
}
func attemptCheckTrace(test *testing.T, harness *commandHarness) {
	test.Helper()
	paths, err := filepath.Glob(filepath.Join(harness.root, "trace.*"))
	if err != nil || len(paths) == 0 {
		test.Fatal("missing syscall trace")
	}
	var lines []string
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			test.Fatal(err)
		}
		lines = append(lines, strings.Split(string(raw), "\n")...)
	}
	slices.Sort(lines)
	directory := filepath.Join(harness.attempts.Root, "accounting")
	snapshot := filepath.Join(directory, "000000002.json")
	stage := 0
	for _, line := range lines {
		switch stage {
		case 0:
			if strings.Contains(line, "openat(") && strings.Contains(line, "000000002.json") && strings.Contains(line, directory) {
				if !strings.Contains(line, "O_EXCL") || !strings.Contains(line, "O_NOFOLLOW") {
					test.Fatal("snapshot is not immutable/no-follow")
				}
				stage++
			}
		case 1:
			if strings.Contains(line, "fsync(") && strings.Contains(line, snapshot+">") && strings.Contains(line, "= 0") {
				stage++
			}
		case 2:
			if strings.Contains(line, "fsync(") && strings.Contains(line, directory+">") && strings.Contains(line, "= 0") {
				stage++
			}
		case 3:
			if strings.Contains(line, "openat(") && strings.Contains(line, "head.next") && strings.Contains(line, directory) {
				if !strings.Contains(line, "O_EXCL") || !strings.Contains(line, "O_NOFOLLOW") {
					test.Fatal("head publication overwrites a pending transition")
				}
				stage++
			}
		case 4:
			if strings.Contains(line, "fsync(") && strings.Contains(line, filepath.Join(directory, "head.next")+">") && strings.Contains(line, "= 0") {
				stage++
			}
		case 5:
			if strings.Contains(line, "fsync(") && strings.Contains(line, directory+">") && strings.Contains(line, "= 0") {
				stage++
			}
		case 6:
			if strings.Contains(line, "renameat(") && strings.Contains(line, directory) && strings.Contains(line, `"head.next"`) && strings.Contains(line, `"head"`) && strings.Contains(line, "= 0") {
				stage++
			}
		case 7:
			if strings.Contains(line, "fsync(") && strings.Contains(line, directory+">") && strings.Contains(line, "= 0") {
				stage++
			}
		case 8:
			if strings.Contains(line, "write(") && strings.Contains(line, filepath.Join(harness.root, "checkpoint")+">") {
				stage++
			}
		}
	}
	if stage != 9 {
		test.Fatalf("pre-forward durable syscall ordering incomplete: stage=%d", stage)
	}
}
