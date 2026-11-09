package wallet

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type socketFixture struct {
	service *ActionService
	stop    func()
}

// Same-UID fixture uses genuine peer credentials/sockets/Core, but intentionally
// does not claim a different-OS-user custody boundary. Production Open refuses it.
func coreSocket(t *testing.T, l *coreLab, c Config) *socketFixture {
	t.Helper()
	w, e := Open(c)
	if e != nil {
		t.Fatal(e)
	}
	w.clock = func() int64 { return 500 }
	state := filepath.Join(l.private, "service-state")
	if e = os.Mkdir(state, 0700); e != nil {
		t.Fatal(e)
	}
	_, grantee := testKey(2)
	key, _ := testKey(7)
	sc := ServiceConfig{Version: 1, Service: WalletServiceID, Socket: filepath.Join(l.root, "w.sock"), SocketGID: uint32(os.Getgid()), PeerUID: uint32(os.Getuid()), Grantee: grantee, SkewSeconds: 60, TimeoutSeconds: 2, StateDir: state, WalletConfig: filepath.Join(l.private, "wallet.json"), ReceiptKeyFile: filepath.Join(l.private, "receipt.key")}
	s, e := openActionService(sc, w, key)
	if e != nil {
		w.Close()
		t.Fatal(e)
	}
	s.clock = func() int64 { return 500 }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		i, e := os.Stat(sc.Socket)
		if e == nil && i.Mode().Perm() == 0660 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("socket startup")
		}
		time.Sleep(time.Millisecond)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		if e := <-done; e != nil {
			t.Error(e)
		}
		s.Close()
	}
	t.Cleanup(stop)
	return &socketFixture{s, stop}
}
func installActionObjects(t *testing.T, c Config, raw []byte, terms Terms) string {
	t.Helper()
	id := grantID(t, raw)
	for name, b := range map[string][]byte{id: raw, Hash(canonical(terms)): canonical(terms)} {
		if e := os.WriteFile(filepath.Join(c.ObjectsDir, name+".json"), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	return id
}
func socketRaw(t *testing.T, s *ActionService, raw []byte) (SignedActionReceipt, []byte) {
	t.Helper()
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: s.config.Socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if e = writeActionFrame(c, raw); e != nil {
		t.Fatal(e)
	}
	b, e := readActionFrame(c)
	if e != nil {
		t.Fatal(e)
	}
	hash := Hash(raw)
	if v, e := ParseAction(raw, WalletServiceID); e == nil {
		hash = v.Hash
	}
	receipt, e := ParseActionReceipt(b, s.pub, hash, s.config.Grantee)
	if e != nil {
		t.Fatal("signed socket receipt", e)
	}
	return receipt, b
}
func socketRequest(t *testing.T, s *ActionService, r ActionRequest) (SignedActionReceipt, []byte) {
	t.Helper()
	return socketRaw(t, s, actionEnvelope(t, r))
}
func expectAction(t *testing.T, r SignedActionReceipt, status, reason string) {
	t.Helper()
	if r.Receipt.Verdict != status || r.Receipt.Reason != reason {
		t.Fatalf("want %s/%s got %s/%s", status, reason, r.Receipt.Verdict, r.Receipt.Reason)
	}
}

// Genuine standing payment, pinned client, immutable terminal replay past skew,
// valid reads/receive allocation replay and signature/replay/budget refusals all
// cross a real socket. Refusals do not change wallet reservations or mempool.
func TestCoreActionStanding(t *testing.T) {
	l := newCore(t)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 300000}
	raw, c := l.grant(terms, []string{"pay"}, 300000)
	id := installActionObjects(t, c, raw, terms)
	f := coreSocket(t, l, c)
	s := f.service
	r := actionFixture(t, "spend")
	r.Grant.ID = id
	first, firstBytes := socketRequest(t, s, r)
	expectAction(t, first, "executed", "EXECUTED")
	if first.Receipt.ObservedHeight < 1 || first.Receipt.Peer.UID != uint32(os.Getuid()) {
		t.Fatal("observed chain/peer absent")
	}
	s.mu.Lock()
	s.clock = func() int64 { return 2000 }
	s.wallet.clock = func() int64 { return 2000 }
	s.mu.Unlock()
	repeated, b := socketRequest(t, s, r)
	expectAction(t, repeated, "executed", "EXECUTED")
	if !bytes.Equal(b, firstBytes) {
		t.Fatal("terminal duplicate changed receipt")
	}
	s.mu.Lock()
	s.clock = func() int64 { return 500 }
	s.wallet.clock = func() int64 { return 500 }
	s.mu.Unlock()
	before, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	pool := string(l.rpc("", "getrawmempool"))
	check := func(label, want string, b []byte) {
		t.Helper()
		got, _ := socketRaw(t, s, b)
		expectAction(t, got, "refused", want)
		after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		if !bytes.Equal(before, after) || pool != string(l.rpc("", "getrawmempool")) {
			t.Fatal(label, "refusal changed wallet/effect")
		}
	}
	x := r
	x.Params = canonical(SpendParams{testAddress(3), 100001, 100000})
	check("collision", "NONCE_CONFLICT", actionEnvelope(t, x))
	x = r
	x.Nonce = strings.Repeat("b", 32)
	x.CreatedAt = 300
	check("skew", "ACTION_SKEW", actionEnvelope(t, x))
	x = r
	x.Nonce = strings.Repeat("c", 32)
	x.Params = canonical(SpendParams{testAddress(3), 200000, 100000})
	check("budget", "TOTAL_BUDGET_EXCEEDED", actionEnvelope(t, x))
	x = r
	x.Nonce = strings.Repeat("d", 32)
	x.Params = canonical(SpendParams{testAddress(4), 1, 100000})
	check("recipient", "ADDRESS_NOT_ALLOWED", actionEnvelope(t, x))
	var env ActionEnvelope
	json.Unmarshal(actionEnvelope(t, r), &env)
	env.Signature = signDigest(t, ActionDigest(r), 3)
	check("signature", "ACTION_SIGNATURE", canonical(env))
	x = r
	_, x.Grantee = testKey(3)
	env = ActionEnvelope{Request: x, Signature: signDigest(t, ActionDigest(x), 3)}
	check("grantee", "GRANTEE_MISMATCH", canonical(env))
	for i, action := range []string{"balance", "receive", "history", "budget"} {
		q := actionFixture(t, action)
		q.Nonce = strings.Repeat(string("ef89"[i]), 32)
		if action == "budget" {
			q.Grant = ActionGrant{Kind: "standing", ID: id}
		}
		got, one := socketRequest(t, s, q)
		if got.Receipt.Verdict != "executed" {
			t.Fatal("read neighbor", action, got.Receipt.Reason)
		}
		_, two := socketRequest(t, s, q)
		if !bytes.Equal(one, two) {
			t.Fatal("read/allocation replay")
		}
	}
	response, e := ExchangeAction(context.Background(), s.config.Socket, uint32(os.Getuid()), s.pub, actionEnvelope(t, r))
	if e != nil || !bytes.Equal(response, firstBytes) {
		t.Fatal("pinned client", e)
	}
	if _, e = ExchangeAction(context.Background(), s.config.Socket, uint32(os.Getuid()+1), s.pub, actionEnvelope(t, r)); e == nil {
		t.Fatal("client service UID guard")
	}
	l.save("socket-standing.json", first)
}

// Genuine grantee seal-spend commitment is over unsigned LIP bytes. Pending use
// re-observes after confirmation; changing only the unsigned locator cannot
// substitute a wrong commitment or issuer-attributed spend for authorization.
func TestCoreActionOneoff(t *testing.T) {
	l := newCore(t)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}
	_, c := l.grant(terms, []string{"pay"}, 1000000)
	f := coreSocket(t, l, c)
	s := f.service
	grant, raw := l.oneoff()
	id := Hash(raw)
	if e := os.WriteFile(filepath.Join(c.ObjectsDir, id+".json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	r := actionFixture(t, "spend")
	r.Grant = ActionGrant{Kind: "single-use", ID: id}
	use := l.use(grant, canonical(r), 2)
	var envelope ActionEnvelope
	json.Unmarshal(actionEnvelope(t, r), &envelope)
	envelope.Proof = &ActionProof{UseTxID: use}
	before, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	pool := string(l.rpc("", "getrawmempool"))
	pending, _ := socketRaw(t, s, canonical(envelope))
	expectAction(t, pending, "pending", "USE_PENDING")
	after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	if !bytes.Equal(before, after) || pool != string(l.rpc("", "getrawmempool")) {
		t.Fatal("pending socket effect")
	}
	l.mine(1)
	// Pending requests are already admitted; re-observe even after admission skew.
	s.mu.Lock()
	s.clock = func() int64 { return 700 }
	s.wallet.clock = func() int64 { return 700 }
	s.mu.Unlock()
	executed, b := socketRaw(t, s, canonical(envelope))
	expectAction(t, executed, "executed", "EXECUTED")
	_, again := socketRaw(t, s, canonical(envelope))
	if !bytes.Equal(b, again) {
		t.Fatal("single-use replay changed receipt")
	}
	s.mu.Lock()
	s.clock = func() int64 { return 500 }
	s.wallet.clock = func() int64 { return 500 }
	s.mu.Unlock()
	for _, signer := range []byte{2, 1} {
		g, raw := l.oneoff()
		id := Hash(raw)
		os.WriteFile(filepath.Join(c.ObjectsDir, id+".json"), raw, 0600)
		q := r
		q.Grant.ID = id
		q.Nonce = Hash(raw)[:32]
		committed := canonical(q)
		want := "USE_ISSUER_REVOKED"
		if signer == 2 {
			committed = []byte("wrong commitment fixture")
			want = "REQUEST_COMMITMENT"
		}
		tx := l.use(g, committed, signer)
		l.mine(1)
		var env ActionEnvelope
		json.Unmarshal(actionEnvelope(t, q), &env)
		env.Proof = &ActionProof{tx}
		before, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		pool := string(l.rpc("", "getrawmempool"))
		got, _ := socketRaw(t, s, canonical(env))
		expectAction(t, got, "refused", want)
		after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		if !bytes.Equal(before, after) || pool != string(l.rpc("", "getrawmempool")) {
			t.Fatal("oneoff refusal effect")
		}
	}
	l.save("socket-oneoff.json", executed)
}
