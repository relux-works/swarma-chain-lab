// Run from experiments/relay. Plants alter copied module sources, never the
// checkout. Each baseline must pass and the planted run must fail its named
// assertion; setup failures, crashes and timeouts are not accepted evidence.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type plant struct {
	Name, File, Old, New, Module, Package, Test, Witness string
	Matches                                              int
}

var plants = []plant{
	{"rechallenge_inbox", "rental-gateway/gateway/relay_liveness.go", "id, until, pages = \"gw-inbox\", nil, 0", "pages = 0", "rental-gateway", "./gateway", "TestReplayRechallengeRestoresInbox", "rechallenge did not restore live inbox", 1},
	{"live_during_catchup", "rental-gateway/gateway/relay_liveness.go", "id = \"gw-catchup\"", "id = \"gw-inbox\"", "rental-gateway", "./gateway", "TestReplayKeepsLiveInbox", "catchup replaced live inbox", 1},
	{"server_ping", "relay/relay.go", "if p.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(3*time.Second)) != nil {", "if false && p.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(3*time.Second)) != nil {", "relay", ".", "TestRelayIdleLiveness", "keepalive did not survive three deadlines", 1},
	{"server_pong_refresh", "relay/relay.go", "return ws.SetReadDeadline(time.Now().Add(r.cfg.readTimeout()))", "return nil", "relay", ".", "TestRelayIdleLiveness", "keepalive did not survive three deadlines", 1},
	{"server_idle_limit", "relay/relay.go", "time.Now().Add(r.cfg.readTimeout())", "time.Now().Add(24*time.Hour)", "relay", ".", "TestRelayIdleLiveness", "silent peer was not refused", 3},
	{"ping_quota", "relay/relay.go", "ws.SetPingHandler(func(string) error {\n\t\tif !r.allow(p) {", "ws.SetPingHandler(func(string) error {\n\t\tif false && !r.allow(p) {", "relay", ".", "TestControlFrameQuota", "control quota bypass", 1},
	{"pong_quota", "relay/relay.go", "ws.SetPongHandler(func(string) error {\n\t\tif !r.allow(p) {", "ws.SetPongHandler(func(string) error {\n\t\tif false && !r.allow(p) {", "relay", ".", "TestControlFrameQuota", "control quota bypass", 1},
	{"client_ping", "rental-gateway/gateway/relay_liveness.go", "if s.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(c.pingInterval())) != nil {", "if false && s.conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(c.pingInterval())) != nil {", "rental-gateway", "./gateway", "TestClientHeartbeat", "client heartbeat did not maintain idle connection", 1},
	{"client_pong_refresh", "rental-gateway/gateway/relayclient.go", "conn.SetPongHandler(func(string) error { return conn.SetReadDeadline(time.Now().Add(c.readTimeout())) })", "conn.SetPongHandler(func(string) error { return nil })", "rental-gateway", "./gateway", "TestClientHeartbeat", "client heartbeat did not maintain idle connection", 1},
	{"client_idle_limit", "rental-gateway/gateway/relayclient.go", "time.Now().Add(c.readTimeout())", "time.Now().Add(24*time.Hour)", "rental-gateway", "./gateway", "TestClientHeartbeat", "silent relay did not trigger reconnect", 3},
	{"reconnect", "rental-gateway/gateway/relay_liveness.go", "if err != ErrRelayClosed {", "if true {", "relay", ".", "TestNativeReconnectPagination", "transport reconnect absent", 1},
	{"fatal_refusal", "rental-gateway/gateway/relay_liveness.go", "if err != ErrRelayClosed {", "if err != ErrRelayClosed && err != ErrRelayRejected {", "rental-gateway", "./gateway", "TestReconnectRefusalAndBackoff", "fatal refusal retried", 1},
	{"backoff_cap", "rental-gateway/gateway/relay_liveness.go", "if delay > maximum {", "if false && delay > maximum {", "rental-gateway", "./gateway", "TestReconnectRefusalAndBackoff", "backoff was not capped and bounded", 1},
	{"jitter_overlap", "rental-gateway/gateway/relay_liveness.go", "const replayJitter = 48 * time.Hour", "const replayJitter = 0 * time.Hour", "relay", ".", "TestNativeReconnectPagination", "backdated gap delivery lost or duplicated", 1},
	{"pagination", "rental-gateway/gateway/relay_liveness.go", "if page.count < limit {", "if true {", "relay", ".", "TestNativeReconnectPagination", "backdated gap delivery lost or duplicated", 1},
	{"inclusive_until", "rental-gateway/gateway/relay_liveness.go", "next := page.oldest", "next := page.oldest - 1", "relay", ".", "TestNativeReconnectPagination", "backdated gap delivery lost or duplicated", 1},
	{"overflow_stop", "rental-gateway/gateway/relay_liveness.go", "page.oldest == page.newest || page.oldest <= since || (until != nil && page.oldest >= *until) || pages >= maxReplayPages", "pages >= maxReplayPages", "relay", ".", "TestReplayOverflow", "equal timestamp overflow not counted", 1},
	{"overflow_counter", "rental-gateway/gateway/relay_liveness.go", "c.replayOverflows.Add(1)", "c.replayOverflows.Add(0)", "relay", ".", "TestReplayOverflow", "overflow status missing", 1},
	{"auth_before_req", "rental-gateway/gateway/relayclient.go", "if accepted == seq && (!force || accepted > after) {", "if accepted == seq || force || after >= 0 {", "rental-gateway", "./gateway", "TestPersistentAuthReconnect", "persistent REQ preceded AUTH", 1},
	{"rumor_dedup", "rental-gateway/journal/journal.go", "if s.seen[rumorID] {", "if false && s.seen[rumorID] {", "relay", ".", "TestNativeReconnectPagination", "backdated gap delivery lost or duplicated", 1},
	{"serve_reconnect", "rental-gateway/cmd/gateway/serve.go", "errs <- relay.RunGiftWraps(ctx, gw.AgentPubKey(),", "errs <- relay.SubscribeGiftWraps(ctx, gw.AgentPubKey(),", "rental-gateway", "./cmd/gateway", "TestServeExpiryDuringRelayOutage", "relay outage killed expiry worker", 1},
	{"expiry_tick", "rental-gateway/cmd/gateway/serve.go", "gw.Tick(ctx)", "_ = gw", "rental-gateway", "./cmd/gateway", "TestServeExpiryDuringRelayOutage", "relay outage starved expiry End", 1},
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	out := flag.String("out", ".temp/rk1-guards", "evidence directory")
	only := flag.String("only", "", "optional exact plant name")
	flag.Parse()
	root, e := os.Getwd()
	if e != nil {
		return e
	}
	raw, e := os.ReadFile("go.mod")
	if e != nil || !bytes.HasPrefix(raw, []byte("module github.com/relux-works/swarma-chain-lab/experiments/relay\n")) {
		return errors.New("run from relay")
	}
	evidence, e := filepath.Abs(*out)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(evidence, 0700); e != nil {
		return e
	}
	logs, e := os.MkdirTemp(evidence, "run-")
	if e != nil {
		return e
	}
	fmt.Println("evidence:", logs)
	if e = os.MkdirAll(".temp", 0700); e != nil {
		return e
	}
	work, e := os.MkdirTemp(filepath.Join(root, ".temp"), "rk1-guards-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	for _, name := range []string{"relay", "rental-gateway"} {
		if e = copyTree(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	for _, name := range []string{"station-lifecycle", "rental", "rental-booking", "single-use", "sealwatch", "payment-chain", "model-proxy", "grant-store", "signer-service"} {
		if e = os.Symlink(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	runTest := func(p plant, label string) ([]byte, int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-v", "-timeout", "30s", "-run", "^"+p.Test+"$", p.Package)
		cmd.Dir = filepath.Join(work, p.Module)
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=readonly")
		var b bytes.Buffer
		cmd.Stdout = &b
		cmd.Stderr = &b
		if e := cmd.Start(); e != nil {
			return nil, -1, e
		}
		pid := cmd.Process.Pid
		err := cmd.Wait()
		code := 0
		if err != nil {
			var x *exec.ExitError
			if !errors.As(err, &x) {
				return nil, -1, err
			}
			code = x.ExitCode()
		}
		raw := append([]byte(fmt.Sprintf("owned test-command PID %d\n", pid)), b.Bytes()...)
		if e := os.WriteFile(filepath.Join(logs, label+".log"), raw, 0600); e != nil {
			return nil, code, e
		}
		return raw, code, ctx.Err()
	}
	type result struct {
		Name          string
		Exit          int
		Detected      bool
		Before, After string
	}
	var results []result
	for _, p := range plants {
		if *only != "" && p.Name != *only {
			continue
		}
		raw, code, e := runTest(p, "baseline-"+p.Name)
		if e != nil || code != 0 || !bytes.Contains(raw, []byte("--- PASS: "+p.Test)) {
			return fmt.Errorf("baseline %s failed exit%d", p.Name, code)
		}
		file := filepath.Join(work, p.File)
		before, e := os.ReadFile(file)
		if e != nil {
			return e
		}
		if n := strings.Count(string(before), p.Old); n != p.Matches {
			return fmt.Errorf("plant %s matched%d want%d", p.Name, n, p.Matches)
		}
		after := []byte(strings.ReplaceAll(string(before), p.Old, p.New))
		if e = os.WriteFile(file, after, 0600); e != nil {
			return e
		}
		raw, code, e = runTest(p, p.Name)
		restore := os.WriteFile(file, before, 0600)
		if e != nil {
			return e
		}
		if restore != nil {
			return restore
		}
		detected := code == 1 && bytes.Contains(raw, []byte("--- FAIL: "+p.Test)) && bytes.Contains(raw, []byte(p.Witness)) && !bytes.Contains(raw, []byte("[build failed]")) && !bytes.Contains(raw, []byte("panic:"))
		results = append(results, result{p.Name, code, detected, fmt.Sprintf("%x", sha256.Sum256(before)), fmt.Sprintf("%x", sha256.Sum256(after))})
		data, _ := json.MarshalIndent(results, "", "  ")
		if e = os.WriteFile(filepath.Join(logs, "results.json"), data, 0600); e != nil {
			return e
		}
		fmt.Printf("%s detected=%v\n", p.Name, detected)
		if !detected {
			return fmt.Errorf("plant %s missed intended assertion", p.Name)
		}
	}
	if len(results) == 0 {
		return errors.New("no matching plants")
	}
	fmt.Printf("%d intended failures\n", len(results))
	return nil
}
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(src, path)
		if e != nil {
			return e
		}
		if d.IsDir() {
			if d.Name() == ".temp" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0700)
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("source symlink: %s", rel)
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0600)
	})
}
