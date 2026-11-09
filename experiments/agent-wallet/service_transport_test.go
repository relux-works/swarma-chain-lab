package wallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Actual socket framing/timeout/peer refusals never admit an action. Two frames
// on one connection produce only the first receipt; a new connection still works.
func TestCoreActionTransport(t *testing.T) {
	l := newCore(t)
	_, c := l.grant(Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}, []string{"pay"}, 1000000)
	f := coreSocket(t, l, c)
	s := f.service
	dial := func() *net.UnixConn {
		t.Helper()
		conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: s.config.Socket, Net: "unix"})
		if e != nil {
			t.Fatal(e)
		}
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		return conn
	}
	before, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	pool := string(l.rpc("", "getrawmempool"))
	for name, raw := range map[string][]byte{"zero": {0, 0, 0, 0}, "oversize": {0, 1, 0, 1}, "truncated": {0, 0, 0, 8, 123}, "header-timeout": {0}, "body-timeout": {0, 0, 0, 8, 123}} {
		t.Run(name, func(t *testing.T) {
			conn := dial()
			defer conn.Close()
			if _, e := conn.Write(raw); e != nil {
				t.Fatal(e)
			}
			if !strings.HasSuffix(name, "timeout") {
				conn.CloseWrite()
			}
			var one [1]byte
			if n, e := conn.Read(one[:]); n != 0 || e != io.EOF {
				t.Fatalf("socket frame refusal: n=%d error=%v", n, e)
			}
		})
	}
	// This second listener exercises the actual peer gate without changing a
	// running configuration or creating users. It is not a cross-UID custody test.
	other := &ActionService{config: s.config}
	other.config.PeerUID++
	path := filepath.Join(l.root, "peer.sock")
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, e := listener.AcceptUnix()
		if e != nil {
			return
		}
		defer conn.Close()
		other.serveConnection(t.Context(), conn)
	}()
	conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	started := time.Now()
	var one [1]byte
	if n, e := conn.Read(one[:]); n != 0 || e != io.EOF {
		t.Fatalf("peer gate before body: n=%d error=%v", n, e)
	}
	if time.Since(started) >= time.Second {
		t.Fatal("peer gate waited for body")
	}
	conn.Close()
	<-done
	s.mu.Lock()
	entries := len(s.state.Entries)
	s.mu.Unlock()
	after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	if entries != 0 || !bytes.Equal(before, after) || pool != string(l.rpc("", "getrawmempool")) {
		t.Fatal("transport refusal admitted or effected request")
	}
	r := actionFixture(t, "balance")
	q := actionFixture(t, "receive")
	q.Nonce = strings.Repeat("b", 32)
	var frames bytes.Buffer
	writeActionFrame(&frames, actionEnvelope(t, r))
	writeActionFrame(&frames, actionEnvelope(t, q))
	conn = dial()
	if _, e = conn.Write(frames.Bytes()); e != nil {
		t.Fatal(e)
	}
	if _, e = readActionFrame(conn); e != nil {
		t.Fatal("first frame neighbor", e)
	}
	if _, e = readActionFrame(conn); e == nil {
		t.Fatal("second frame executed")
	}
	conn.Close()
	s.mu.Lock()
	entries = len(s.state.Entries)
	s.mu.Unlock()
	if entries != 1 {
		t.Fatal("second frame admitted")
	}
	got, _ := socketRequest(t, s, q)
	expectAction(t, got, "executed", "ALLOCATED")
}

// The real default CLI signs and exchanges with the socket service. Its binary
// does not retain the daemon/Wallet/RPC constructors; legacy options and RPC
// credentials in client config refuse without changing the service journal.
func TestCoreActionClient(t *testing.T) {
	l := newCore(t)
	_, c := l.grant(Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}, []string{"pay"}, 1000000)
	f := coreSocket(t, l, c)
	s := f.service
	bin := filepath.Join(l.root, "agent-wallet")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/agent-wallet")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("client build: %v %s", e, b)
	}
	nm, e := exec.Command("go", "tool", "nm", bin).CombinedOutput()
	if e != nil {
		t.Fatal("client symbol inventory", e)
	}
	for _, symbol := range []string{".OpenActionService", ".NewWalletRPC", ".(*Wallet).Execute", ".(*Wallet).executeAuthenticated", ".(*ActionService).Serve"} {
		if bytes.Contains(nm, []byte(symbol)) {
			t.Fatal("client custody symbol", symbol)
		}
	}
	if !bytes.Contains(nm, []byte(".ExchangeAction")) {
		t.Fatal("symbol inventory positive control")
	}
	key, _ := testKey(2)
	keyPath := filepath.Join(l.private, "client.key")
	os.WriteFile(keyPath, []byte(hex.EncodeToString(key.Serialize())), 0600)
	cfg := ActionClientConfig{Version: 1, Service: WalletServiceID, Socket: s.config.Socket, ServiceUID: uint32(os.Getuid()), ReceiptKey: s.pub, KeyFile: keyPath}
	cfgPath := filepath.Join(l.root, "client.json")
	os.WriteFile(cfgPath, canonical(cfg), 0600)
	r := actionFixture(t, "balance")
	rqPath := filepath.Join(l.root, "request.json")
	os.WriteFile(rqPath, canonical(r), 0600)
	args := []string{"--config", cfgPath, "--request", rqPath}
	b, e := exec.Command(bin, args...).CombinedOutput()
	if e != nil {
		t.Fatalf("client neighbor: %v %s", e, b)
	}
	if _, e = ParseActionReceipt(bytes.TrimSpace(b), s.pub, Hash(canonical(r)), r.Grantee); e != nil {
		t.Fatal("client signed receipt", e)
	}
	before, _ := os.ReadFile(filepath.Join(s.config.StateDir, "service.json"))
	for _, flag := range []string{"--now=500", "--wallet=secret-path", "--rpc-password=do-not-echo", "--action=pay"} {
		b, e = exec.Command(bin, append(args, flag)...).CombinedOutput()
		if e == nil || string(b) != "{\"error\":\"CLI_ARGUMENTS\"}\n" {
			t.Fatalf("client legacy flag guard: %v %q", e, b)
		}
	}
	var obj map[string]any
	json.Unmarshal(canonical(cfg), &obj)
	obj["rpc_password"] = "do-not-echo"
	os.WriteFile(cfgPath, canonical(obj), 0600)
	b, e = exec.Command(bin, args...).CombinedOutput()
	if e == nil || string(b) != "{\"error\":\"CLIENT_CONFIG\"}\n" {
		t.Fatalf("client config custody guard: %v %q", e, b)
	}
	after, _ := os.ReadFile(filepath.Join(s.config.StateDir, "service.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("CLI refusal reached service")
	}
}
