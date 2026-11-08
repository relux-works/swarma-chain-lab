package singleuse

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Only the separate test executable accepts deterministic crash injection.
// The shipped CLI has no fault flag and always passes a nil hook.
func TestW3CrashChild(t *testing.T) {
	stage := os.Getenv("W3_CHILD_STAGE")
	if stage == "" {
		t.Skip("subprocess control only")
	}
	var p Policy
	var route Route
	for name, dst := range map[string]any{"POLICY": &p, "ROUTE": &route} {
		b, e := os.ReadFile(os.Getenv("W3_CHILD_" + name))
		if e != nil || StrictInput(b, dst) != nil {
			t.Fatal("child input")
		}
	}
	cert, e := os.ReadFile(os.Getenv("W3_CHILD_CERT"))
	if e != nil {
		t.Fatal(e)
	}
	req, e := os.ReadFile(os.Getenv("W3_CHILD_REQUEST"))
	if e != nil {
		t.Fatal(e)
	}
	node, e := NewRPC(route)
	if e != nil {
		t.Fatal(e)
	}
	code := map[string]int{"before-journal": 85, "after-journal": 86, "after-effect": 87}[stage]
	if code == 0 {
		t.Fatal("unknown fault")
	}
	r := Execute(context.Background(), node, p, cert, req, time.Now(), func(at string) {
		if at == stage {
			os.Exit(code)
		}
	})
	t.Fatalf("control was not applied: %+v", r)
}
func (l *coreLab) childInputs(p Policy, label string) (string, string, string) {
	policy := filepath.Join(l.public, label+"-policy.json")
	b, _ := json.Marshal(p)
	if e := os.WriteFile(policy, b, 0600); e != nil {
		l.t.Fatal(e)
	}
	return policy, filepath.Join(l.public, "certificate.json"), filepath.Join(l.public, "request.json")
}
func (l *coreLab) fault(p Policy, label, stage string) {
	policy, cert, request := l.childInputs(p, label)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	args := []string{"-test.run=^TestW3CrashChild$", "-test.count=1"}
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append(os.Environ(), "W3_CHILD_STAGE="+stage, "W3_CHILD_POLICY="+policy, "W3_CHILD_CERT="+cert, "W3_CHILD_REQUEST="+request, "W3_CHILD_ROUTE="+l.routePath)
	out, e := cmd.CombinedOutput()
	exit := 0
	if e != nil {
		if ee, ok := e.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			l.t.Fatal(e)
		}
	}
	expected := map[string]int{"before-journal": 85, "after-journal": 86, "after-effect": 87}[stage]
	l.rows = append(l.rows, map[string]any{"kind": "crash-child", "label": label, "argv": append([]string{os.Args[0]}, args...), "stage": stage, "policy": policy, "certificate": cert, "request": request, "route_file": l.routePath, "exit_code": exit, "expected_exit": expected, "pid": cmd.Process.Pid})
	if exit != expected {
		l.t.Fatalf("crash control exit%d expected%d: %s", exit, expected, out)
	}
}

func (l *coreLab) proxy(mode string) func() {
	node, e := NewRPC(l.route)
	if e != nil {
		l.t.Fatal(e)
	}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != l.route.Username || password != l.route.Password {
			w.WriteHeader(401)
			return
		}
		var query struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
			ID     int               `json:"id"`
		}
		if json.NewDecoder(r.Body).Decode(&query) != nil {
			w.WriteHeader(400)
			return
		}
		args := make([]any, len(query.Params))
		for i, v := range query.Params {
			args[i] = v
		}
		if query.Method == "getblockchaininfo" {
			calls++
			if mode == "tip-change" && calls == 2 {
				l.mine(1)
			}
		}
		raw, e := node.Call(r.Context(), query.Method, args...)
		if e != nil {
			w.WriteHeader(502)
			return
		}
		if query.Method == "getblockchaininfo" {
			if mode == "alias" {
				var fields map[string]json.RawMessage
				_ = json.Unmarshal(raw, &fields)
				fields["BLOCKS"] = fields["blocks"]
				delete(fields, "blocks")
				raw, _ = json.Marshal(fields)
			}
			if mode == "conflict-before" {
				raw = append([]byte(`{"BLOCKS":0,`), bytes.TrimSpace(raw)[1:]...)
			}
			if mode == "conflict-after" {
				raw = append(append([]byte(nil), bytes.TrimSpace(raw)[:len(bytes.TrimSpace(raw))-1]...), []byte(`,"BLOCKS":0}`)...)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": query.ID, "result": json.RawMessage(raw), "error": nil})
	}))
	u, _ := url.Parse(server.URL)
	host, portText, _ := net.SplitHostPort(u.Host)
	port, _ := strconv.Atoi(portText)
	route := l.route
	route.Host = host
	route.Port = port
	path := filepath.Join(l.private, "route-"+mode+".json")
	b, _ := json.Marshal(route)
	if e = os.WriteFile(path, b, 0600); e != nil {
		l.t.Fatal(e)
	}
	previous := l.routePath
	l.routePath = path
	l.rows = append(l.rows, map[string]any{"kind": "core-backed-boundary-control", "mode": mode, "node_reply_modified": mode != "tip-change", "actual_block_mined_during_observation": mode == "tip-change"})
	return func() { l.routePath = previous; server.Close() }
}

// These controls exercise real process exits, persistent state, competing
// instances and genuine Core reorgs. Transport mutations are explicitly labelled.
func (l *coreLab) lifecycleControls(run func(string, func())) {
	run("spend-of-different-seal", func() {
		p := l.state(l.newPolicy(), "other-seal")
		other := p
		funding := textValue(l.t, l.rpc("issuer", "sendtoaddress", l.sealAddress, Coins(1000000)))
		l.mine(1)
		var tx rpcTx
		_ = json.Unmarshal(l.rpc("", "getrawtransaction", funding, true), &tx)
		for _, out := range tx.Vout {
			if out.Script.Hex == p.SealScript && int64(out.Value) == 1000000 {
				other.Seal = Point{funding, out.N}
			}
		}
		if other.Seal == p.Seal {
			l.t.Fatal("other seal not prepared")
		}
		l.use(other, "grantee", "ALL", nil, true)
		r, exit := l.invoke(p, l.request, "other-seal")
		if exit != 0 || r.Status != "pending" || journalCount(l.t, p) != 0 || effectCount(l.t, p) != 0 {
			l.t.Fatal(r, exit)
		}
		l.use(p, "grantee", "ALL", nil, true)
		r, exit = l.invoke(p, l.request, "other-seal-valid")
		if exit != 0 || r.Status != "executed" || effectCount(l.t, p) != 1 {
			l.t.Fatal(r, exit)
		}
	})
	for _, stage := range []string{"before-journal", "after-journal", "after-effect"} {
		run("crash-"+stage, func() {
			p := l.state(l.newPolicy(), stage)
			l.use(p, "grantee", "ALL", nil, true)
			l.fault(p, stage, stage)
			expectedEffects := 0
			if stage == "after-effect" {
				expectedEffects = 1
			}
			if effectCount(l.t, p) != expectedEffects {
				l.t.Fatal("wrong effects at crash")
			}
			r, exit := l.invoke(p, l.request, stage+"-restart")
			expectedStatus := "already-executed"
			if stage == "before-journal" {
				expectedStatus = "executed"
				expectedEffects = 1
			}
			if exit != 0 || r.Status != expectedStatus || effectCount(l.t, p) != expectedEffects {
				l.t.Fatal(r, exit)
			}
			if stage != "before-journal" && r.JournalPhase != "reserved" {
				l.t.Fatal("lost uncertainty", r)
			}
			l.validNeighbor(stage)
		})
	}
	run("two-executors-replay", func() {
		original := l.newPolicy()
		l.use(original, "grantee", "ALL", nil, true)
		for _, label := range []string{"replica-a", "replica-b"} {
			p := l.state(original, label)
			r, exit := l.invoke(p, l.request, label+"-valid")
			if exit != 0 || r.Status != "executed" {
				l.t.Fatal(r, exit)
			}
			r, exit = l.invoke(p, l.request, label+"-replay")
			if exit != 0 || r.Status != "already-executed" || effectCount(l.t, p) != 1 {
				l.t.Fatal(r, exit)
			}
		}
	})
	run("reorg-before-effect", func() {
		p := l.state(l.newPolicy(), "reorg-before")
		id := l.use(p, "grantee", "ALL", nil, true)
		view := object(l.t, l.rpc("", "getrawtransaction", id, true))
		block := textValue(l.t, view["blockhash"])
		l.rpc("", "invalidateblock", block)
		l.save("reorg-pending-chaininfo.json", json.RawMessage(l.rpc("", "getblockchaininfo")))
		r, exit := l.invoke(p, l.request, "reorg-pending")
		if exit != 0 || r.Status != "pending" || journalCount(l.t, p) != 0 || effectCount(l.t, p) != 0 {
			l.t.Fatal(r, exit)
		}
		l.rpc("", "reconsiderblock", block)
		l.save("reorg-restored-chaininfo.json", json.RawMessage(l.rpc("", "getblockchaininfo")))
		r, exit = l.invoke(p, l.request, "reorg-restored-valid")
		if exit != 0 || r.Status != "executed" || effectCount(l.t, p) != 1 {
			l.t.Fatal(r, exit)
		}
	})
	run("reorg-after-effect", func() {
		p := l.state(l.newPolicy(), "reorg-after")
		id := l.use(p, "grantee", "ALL", nil, true)
		view := object(l.t, l.rpc("", "getrawtransaction", id, true))
		block := textValue(l.t, view["blockhash"])
		r, exit := l.invoke(p, l.request, "before-reorg-valid")
		if exit != 0 || r.Status != "executed" {
			l.t.Fatal(r, exit)
		}
		l.rpc("", "invalidateblock", block)
		r, exit = l.invoke(p, l.request, "after-reorg-replay")
		if exit != 0 || r.Status != "already-executed" || effectCount(l.t, p) != 1 || r.Calls != 0 {
			l.t.Fatal(r, exit)
		}
		l.rpc("", "reconsiderblock", block)
	})
	run("concurrent-executor-processes", func() {
		p := l.state(l.newPolicy(), "concurrent")
		l.use(p, "grantee", "ALL", nil, true)
		policy, cert, request := l.childInputs(p, "concurrent")
		args := []string{"--policy", policy, "--route", l.routePath, "--certificate", cert, "--request", request}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		var commands []*exec.Cmd
		var outputs [2]bytes.Buffer
		for i := 0; i < 2; i++ {
			cmd := exec.CommandContext(ctx, l.executor, args...)
			cmd.Stdout = &outputs[i]
			if e := cmd.Start(); e != nil {
				l.t.Fatal(e)
			}
			commands = append(commands, cmd)
		}
		executed := 0
		for i, cmd := range commands {
			e := cmd.Wait()
			exit := 0
			if e != nil {
				if x, ok := e.(*exec.ExitError); ok {
					exit = x.ExitCode()
				} else {
					l.t.Fatal(e)
				}
			}
			var r Receipt
			if json.Unmarshal(outputs[i].Bytes(), &r) != nil {
				l.t.Fatal("concurrent receipt")
			}
			if r.Status == "executed" {
				executed++
			} else if r.Status != "already-executed" && !(r.Status == "refused" && r.Reason == "EXECUTOR_BUSY") {
				l.t.Fatal(r)
			}
			l.rows = append(l.rows, map[string]any{"kind": "executor-concurrent", "argv": append([]string{l.executor}, args...), "pid": cmd.Process.Pid, "exit_code": exit, "receipt": r})
		}
		if executed != 1 || effectCount(l.t, p) != 1 {
			l.t.Fatal("concurrent duplicate/lost effect")
		}
		r, exit := l.invoke(p, l.request, "concurrent-replay")
		if exit != 0 || r.Status != "already-executed" || effectCount(l.t, p) != 1 {
			l.t.Fatal(r, exit)
		}
	})
	run("corrupt-journal", func() {
		p := l.state(l.newPolicy(), "corrupt")
		l.use(p, "grantee", "ALL", nil, true)
		j, e := openJournal(p)
		if e != nil {
			l.t.Fatal(e)
		}
		e = os.WriteFile(j.path, []byte("{"), 0600)
		j.close()
		if e != nil {
			l.t.Fatal(e)
		}
		r, exit := l.invoke(p, l.request, "corrupt-journal")
		if exit != 1 || r.Reason != "JOURNAL_CORRUPT" || journalCount(l.t, p) != 1 || effectCount(l.t, p) != 0 {
			l.t.Fatal(r, exit)
		}
		l.validNeighbor("corrupt")
	})
	run("unsafe-state-permissions", func() {
		p := l.state(l.newPolicy(), "unsafe")
		l.use(p, "grantee", "ALL", nil, true)
		if e := os.Chmod(p.StateDir, 0755); e != nil {
			l.t.Fatal(e)
		}
		l.refused(p, l.request, "unsafe-state", "PRIVATE_STATE_ROOT")
		if e := os.Chmod(p.StateDir, 0700); e != nil {
			l.t.Fatal(e)
		}
		r, exit := l.invoke(p, l.request, "safe-state-valid")
		if exit != 0 || r.Status != "executed" {
			l.t.Fatal(r, exit)
		}
	})
	run("effect-symlink-no-external-write", func() {
		p := l.state(l.newPolicy(), "symlink")
		l.use(p, "grantee", "ALL", nil, true)
		target := filepath.Join(l.private, "unrelated-sentinel")
		original := []byte("untouched\n")
		if e := os.WriteFile(target, original, 0600); e != nil {
			l.t.Fatal(e)
		}
		if e := os.Symlink(target, filepath.Join(p.StateDir, "effects.jsonl")); e != nil {
			l.t.Fatal(e)
		}
		r, exit := l.invoke(p, l.request, "symlink-effect")
		after, _ := os.ReadFile(target)
		if exit != 1 || r.Reason != "EFFECT_OPEN" || !bytes.Equal(after, original) || journalCount(l.t, p) != 1 {
			l.t.Fatal(r, exit)
		}
		r, exit = l.invoke(p, l.request, "symlink-no-retry")
		after, _ = os.ReadFile(target)
		if exit != 0 || r.Status != "already-executed" || !bytes.Equal(after, original) {
			l.t.Fatal(r, exit)
		}
		l.validNeighbor("symlink")
	})
	for _, mode := range []string{"alias", "conflict-before", "conflict-after", "tip-change"} {
		run("core-backed-"+mode, func() {
			p := l.state(l.newPolicy(), mode)
			l.use(p, "grantee", "ALL", nil, true)
			func() {
				restore := l.proxy(mode)
				defer restore()
				reason := "NODE_PROJECTION"
				if mode == "tip-change" {
					reason = "TIP_CHANGED"
				}
				l.refused(p, l.request, mode, reason)
			}()
			r, exit := l.invoke(p, l.request, mode+"-official-valid")
			if exit != 0 || r.Status != "executed" || effectCount(l.t, p) != 1 {
				l.t.Fatal(r, exit)
			}
		})
	}
	run("extra-payment-outputs-and-replay", func() {
		p := l.state(l.newPolicy(), "extra-output")
		address := textValue(l.t, l.rpc("grantee", "getnewaddress", "", "legacy"))
		info := object(l.t, l.rpc("grantee", "getaddressinfo", address))
		scriptHex := textValue(l.t, info["scriptPubKey"])
		var script []byte
		for i := 0; i < len(scriptHex); i += 2 {
			n, e := strconv.ParseUint(scriptHex[i:i+2], 16, 8)
			if e != nil {
				l.t.Fatal(e)
			}
			script = append(script, byte(n))
		}
		l.use(p, "grantee", "ALL", func(tx *Transaction) {
			tx.Outputs[0].Value -= 10000
			tx.Outputs = append(tx.Outputs, Output{10000, script})
		}, true)
		r, exit := l.invoke(p, l.request, "extra-output-valid")
		if exit != 0 || r.Status != "executed" {
			l.t.Fatal(r, exit)
		}
		r, exit = l.invoke(p, l.request, "extra-output-replay")
		if exit != 0 || r.Status != "already-executed" || effectCount(l.t, p) != 1 {
			l.t.Fatal(r, exit)
		}
	})
}
