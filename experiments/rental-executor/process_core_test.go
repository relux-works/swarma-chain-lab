package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The actual trimpath CLI uses real wall time, own-node kernel reads and both
// private socket roles. A real pay occurs once; replay and actual node outage
// cannot cause another effect. Track B grants no mint privilege on claim socket.
func TestCoreServiceProcess(t *testing.T) {
	binary := os.Getenv("M4A_BIN")
	if binary == "" {
		t.Skip("M4A_BIN required")
	}
	l := newCore(t)
	cert := testCertificate()
	cert.NotBefore = time.Now().Unix() - 60
	cert.NotAfter = cert.NotBefore + 1800
	p, c, raw, _ := l.issueFixture("process", cert)
	x, _, conf, root := l.executor(p, raw, 2)
	x.Close()
	bRoot := filepath.Join(l.root, "trackb")
	sockets := filepath.Join(l.root, "sockets")
	for _, dir := range []string{bRoot, sockets} {
		if e := os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
	}
	config := map[string]any{"executor": conf, "state_dir": root, "socket": filepath.Join(sockets, "exec.sock"), "observer": l.route, "broadcast": l.broadcastRoute, "trackb_state": bRoot, "trackb_admin_socket": filepath.Join(sockets, "admin.sock"), "trackb_claim_socket": filepath.Join(sockets, "claim.sock"), "prize_b_keys": prizes()}
	cfg := filepath.Join(l.private, "executor-config.json")
	if e := os.WriteFile(cfg, canonical(config), 0600); e != nil {
		t.Fatal(e)
	}
	log, e := os.OpenFile(filepath.Join(l.private, "executor.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, "--config", cfg)
	cmd.Stdout = log
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(l.root, "executor.pid"), []byte(fmt.Sprint(cmd.Process.Pid)), 0600); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = cmd.Process.Signal(os.Interrupt); _ = cmd.Wait(); _ = log.Close() })
	socket := filepath.Join(sockets, "exec.sock")
	ready := false
	for range 100 {
		if _, e := os.Stat(socket); e == nil {
			ready = true
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !ready {
		t.Fatal("executor did not become ready; private log retained")
	}
	client := func(name string) *http.Client {
		tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(sockets, name))
		}}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 35 * time.Second}
	}
	call := func(client *http.Client, path string, body any, want int) []byte {
		t.Helper()
		resp, e := client.Post("http://unix"+path, "application/json", strings.NewReader(string(canonical(body))))
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		data, e := io.ReadAll(resp.Body)
		if e != nil || resp.StatusCode != want {
			t.Fatalf("unexpected HTTP status %d", resp.StatusCode)
		}
		return data
	}
	event := requestFor(c, "cli", "pay", 1000)
	event.CreatedAt = time.Now().Unix()
	event = signEvent(event, testKey(2))
	q := map[string]any{"event": event, "file_base64": ""}
	execClient := client("exec.sock")
	var receipt Receipt
	if json.Unmarshal(call(execClient, "/execute", q, 200), &receipt) != nil {
		t.Fatal("receipt")
	}
	expectResult(t, receipt, "executed", "LIVE_RENTER_REQUEST")
	l.save("cli-effect.json", receipt)
	if json.Unmarshal(call(execClient, "/execute", q, 200), &receipt) != nil {
		t.Fatal("receipt")
	}
	expectResult(t, receipt, "already-executed", "DURABLE_RESERVATION_NO_RETRY")
	admin, claim := client("admin.sock"), client("claim.sock")
	slot := strings.Repeat("1", 64)
	var minted struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(call(admin, "/mint", map[string]string{"slot": slot}, 200), &minted) != nil || !hexN(minted.Token, 32) {
		t.Fatal("mint")
	}
	claimReq := map[string]string{"slot": slot, "token": minted.Token}
	var got struct {
		Key string `json:"private_key"`
	}
	if json.Unmarshal(call(claim, "/claim", claimReq, 200), &got) != nil || got.Key != prizes()[slot] {
		t.Fatal("claim")
	}
	call(claim, "/mint", map[string]string{"slot": slot}, 400)
	call(admin, "/revoke", map[string]string{"slot": slot}, 200)
	call(claim, "/claim", claimReq, 403)
	l.stop()
	event = requestFor(c, "node-down", "pay", 1000)
	event.CreatedAt = time.Now().Unix()
	event = signEvent(event, testKey(2))
	q["event"] = event
	if json.Unmarshal(call(execClient, "/execute", q, 200), &receipt) != nil {
		t.Fatal("receipt")
	}
	expectResult(t, receipt, "refused", "KERNEL_NODE_UNAVAILABLE")
	l.save("cli-node-down.json", receipt)
}
