package kernelbind_test

// Genuine-Core gateway end-to-end for detached grants (M2-04):
// real pinned Namecoin Core regtest, two detached certificates
// under one agent name, inline presentation through the real
// kernel via kernelbind, lazy per-grantee station starts, then
// one seal is spent (revocation) and only that grantee's slot
// closes while the other keeps talking.
//
// Opt-in only (skipped otherwise, including in CI):
//
//	GW_E2E_REGTEST=1 GW_E2E_RUN_ROOT=<new abs dir>
//	GW_E2E_CORE_DAEMON=<namecoind> GW_E2E_CORE_CLI=<namecoin-cli>
//
// The node is a child of the test process and is stopped by its
// own PID.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"relux.works/swarma-chain-lab/experiments/rental"
	gw "relux.works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/journal"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernelbind"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/screen"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/station"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/stationlink"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

const e2eAgentName = "id/swarma-agent-e2e"

type coreLab struct {
	t                        *testing.T
	root, private            string
	daemon, cli, conf        string
	address, script          string
	node                     *exec.Cmd
	log                      *os.File
	observer                 su.Node
	issuer                   *btcec.PrivateKey
	issuerPub, agentNostrPub string
}

func labText(t *testing.T, b []byte) string {
	t.Helper()
	var s string
	if e := json.Unmarshal(b, &s); e != nil {
		t.Fatal(e)
	}
	return s
}

func labObject(t *testing.T, b []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if e := json.Unmarshal(b, &m); e != nil {
		t.Fatal(e)
	}
	return m
}

func (l *coreLab) rpc(wallet, method string, args ...any) json.RawMessage {
	l.t.Helper()
	argv := []string{"-regtest", "-datadir=" + l.private, "-conf=" + l.conf}
	if wallet != "" {
		argv = append(argv, "-rpcwallet="+wallet)
	}
	argv = append(argv, method)
	for _, a := range args {
		if s, ok := a.(string); ok {
			argv = append(argv, s)
		} else {
			b, _ := json.Marshal(a)
			argv = append(argv, string(b))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, l.cli, argv...)
	b, e := cmd.Output()
	if e != nil {
		if x, ok := e.(*exec.ExitError); ok {
			l.t.Fatalf("Core %s: %s", method, x.Stderr)
		}
		l.t.Fatal(e)
	}
	if !json.Valid(b) {
		b, _ = json.Marshal(strings.TrimSpace(string(b)))
	}
	return b
}

func (l *coreLab) start() {
	l.t.Helper()
	var e error
	l.log, e = os.OpenFile(filepath.Join(l.private, "node.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		l.t.Fatal(e)
	}
	l.node = exec.Command(l.daemon, "-regtest", "-datadir="+l.private, "-conf="+l.conf)
	l.node.Stdout = l.log
	l.node.Stderr = l.log
	if e = l.node.Start(); e != nil {
		l.t.Fatal(e)
	}
	pid := l.node.Process.Pid
	if e = os.WriteFile(filepath.Join(l.root, "node.pid"), []byte(fmt.Sprint(pid)), 0600); e != nil {
		l.t.Fatal(e)
	}
	l.t.Logf("namecoind started pid=%d", pid)
	for i := 0; i < 100; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		cmd := exec.CommandContext(ctx, l.cli, "-regtest", "-datadir="+l.private, "-conf="+l.conf, "getblockchaininfo")
		e := cmd.Run()
		cancel()
		if e == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	l.t.Fatal("Core startup timeout")
}

func (l *coreLab) stop() {
	if l.node == nil {
		return
	}
	pid := l.node.Process.Pid
	_ = l.node.Process.Signal(os.Interrupt)
	e := l.node.Wait()
	_ = l.log.Close()
	l.t.Logf("namecoind stopped pid=%d wait_ok=%v", pid, e == nil)
	l.node = nil
}

func (l *coreLab) mine(n int) { l.rpc("", "generatetoaddress", n, l.address) }

func (l *coreLab) send(raw string, mine bool) string {
	l.t.Helper()
	signed := labObject(l.t, l.rpc("issuer", "signrawtransactionwithwallet", raw))
	if string(signed["complete"]) != "true" {
		l.t.Fatal("incomplete signature")
	}
	id := labText(l.t, l.rpc("", "sendrawtransaction", labText(l.t, signed["hex"]), su.Coins(10000000)))
	if mine {
		l.mine(1)
	}
	return id
}

// testWIF is the public deterministic laboratory WIF for scalar n
// (same fixture as the kernel's own tests; never custody material).
func testWIF(n byte) string {
	raw := make([]byte, 34)
	raw[0] = 0xef
	raw[32] = n
	raw[33] = 1
	a := sha256.Sum256(raw)
	b := sha256.Sum256(a[:])
	raw = append(raw, b[:4]...)
	number := new(big.Int).SetBytes(raw)
	base := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	alphabet := "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	for number.Sign() > 0 {
		number.DivMod(number, base, mod)
		out = append(out, alphabet[mod.Int64()])
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func newCoreLab(t *testing.T, agentNostrPub string) *coreLab {
	t.Helper()
	if os.Getenv("GW_E2E_REGTEST") != "1" {
		t.Skip("requires explicit genuine Core GW_E2E_REGTEST=1")
	}
	root := os.Getenv("GW_E2E_RUN_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute GW_E2E_RUN_ROOT required")
	}
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	priv := make([]byte, 32)
	priv[31] = 1
	issuer, issuerPubPoint := btcec.PrivKeyFromBytes(priv)
	l := &coreLab{t: t, root: root, private: filepath.Join(root, "private"),
		daemon: os.Getenv("GW_E2E_CORE_DAEMON"), cli: os.Getenv("GW_E2E_CORE_CLI"),
		issuer: issuer, issuerPub: hex.EncodeToString(schnorr.SerializePubKey(issuerPubPoint)),
		agentNostrPub: agentNostrPub}
	if e := os.Mkdir(l.private, 0700); e != nil {
		t.Fatal(e)
	}
	for path, want := range map[string]string{
		l.daemon: "86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f",
		l.cli:    "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d"} {
		b, e := os.ReadFile(path)
		if e != nil || rental.Hash(b) != want {
			t.Fatalf("Core binary pin mismatch for %s", path)
		}
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	random := make([]byte, 32)
	if _, e = rand.Read(random); e != nil {
		t.Fatal(e)
	}
	password := hex.EncodeToString(random)
	salt := hex.EncodeToString(random[:8])
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(password))
	route := su.Route{Host: "127.0.0.1", Port: port, Username: "w3-observer", Password: password}
	l.observer, e = su.NewRPC(route)
	if e != nil {
		t.Fatal(e)
	}
	l.conf = filepath.Join(l.private, "namecoin.conf")
	cfg := fmt.Sprintf("server=1\ndeprecatedrpc=create_bdb\nlisten=0\ndnsseed=0\ndiscover=0\nnetworkactive=0\ntxindex=1\npersistmempool=0\nfallbackfee=0.002\nacceptnonstdtxn=1\nnameencoding=ascii\nvalueencoding=ascii\nrpcwhitelistdefault=0\nrpcauth=w3-observer:%s$%x\nrpcwhitelist=w3-observer:getblockchaininfo,getblockhash,getblockheader,getrawtransaction,gettxout,name_show,getrawmempool,getblock\n[regtest]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport=%d\n", salt, mac.Sum(nil), port)
	if e = os.WriteFile(l.conf, []byte(cfg), 0600); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(l.stop)
	l.start()
	l.rpc("", "createwallet", "issuer", false, false, "", false, false)
	l.address = labText(t, l.rpc("issuer", "getnewaddress", "", "legacy"))
	l.script = labText(t, labObject(t, l.rpc("issuer", "getaddressinfo", l.address))["scriptPubKey"])
	l.mine(101)
	// Register the agent name carrying the LIP-0003 key value.
	value, e := rental.AgentValue(rental.AgentKeys{Nostr: agentNostrPub, Grant: l.issuerPub})
	if e != nil {
		t.Fatal(e)
	}
	var reservation []string
	if e = json.Unmarshal(l.rpc("issuer", "name_new", e2eAgentName), &reservation); e != nil {
		t.Fatal(e)
	}
	l.mine(12)
	l.rpc("issuer", "name_firstupdate", e2eAgentName, reservation[1], reservation[0], value,
		map[string]string{"destAddress": l.address})
	l.mine(1)
	l.rpc("issuer", "importprivkey", testWIF(1), "", false)
	return l
}

// seal funds one fresh 1,000,000-sat output to the grant seal
// script (P2PKH of the issuer grant key), mines it and locks it
// against wallet coin selection.
func (l *coreLab) seal() rental.Point {
	l.t.Helper()
	descriptor := labObject(l.t, l.rpc("", "getdescriptorinfo", "pkh(02"+l.issuerPub+")"))
	var addresses []string
	if e := json.Unmarshal(l.rpc("", "deriveaddresses", labText(l.t, descriptor["descriptor"])), &addresses); e != nil || len(addresses) != 1 {
		l.t.Fatal("seal descriptor")
	}
	id := labText(l.t, l.rpc("issuer", "sendtoaddress", addresses[0], su.Coins(1000000)))
	l.mine(1)
	var tx su.TransactionView
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", id, true), &tx); e != nil {
		l.t.Fatal(e)
	}
	script, e := rental.GrantSealScript(l.issuerPub)
	if e != nil {
		l.t.Fatal(e)
	}
	for _, o := range tx.Vout {
		if o.Script.Hex == script && int64(o.Value) == 1000000 {
			point := rental.Point{TxID: id, Vout: o.N}
			l.rpc("issuer", "lockunspent", false, []rental.Point{point})
			return point
		}
	}
	l.t.Fatal("seal output absent")
	return rental.Point{}
}

// grant signs one detached certificate envelope for a renter key.
func (l *coreLab) grant(granteePub, contract string, seal rental.Point) []byte {
	l.t.Helper()
	c := rental.DetachedCertificate{
		Version: 2, Network: "regtest", Genesis: su.RegtestGenesis,
		AgentName: e2eAgentName, IssuerKey: l.issuerPub, GranteeKey: granteePub,
		ContractSHA256: contract, Scope: []string{"deliver", "pay"},
		NotBefore: 100, NotAfter: 1000, Seal: seal,
	}
	raw, e := c.Canonical()
	if e != nil {
		l.t.Fatal(e)
	}
	h, _ := hex.DecodeString(rental.Hash(raw))
	sig, e := schnorr.Sign(l.issuer, h)
	if e != nil {
		l.t.Fatal(e)
	}
	env, e := json.Marshal(rental.DetachedEnvelope{Certificate: c, Signature: hex.EncodeToString(sig.Serialize())})
	if e != nil {
		l.t.Fatal(e)
	}
	return env
}

// revoke spends a seal back to the issuer wallet (revocation).
func (l *coreLab) revoke(seal rental.Point) {
	l.t.Helper()
	unsigned := labText(l.t, l.rpc("", "createrawtransaction",
		[]rental.Point{seal}, []map[string]any{{l.address: su.Coins(950000)}}))
	l.send(unsigned, true)
}

type collectPub struct{ evs []*nostr.Event }

func (c *collectPub) Publish(ctx context.Context, ev *nostr.Event) error {
	c.evs = append(c.evs, ev)
	return nil
}

// TestGatewayDetachedCoreE2E proves the M2-04 path on genuine
// Core: two grantees present detached certificates inline, are
// routed to separate lazily-started instances, the seal of grant
// one is spent, and only that grantee's slot closes.
func TestGatewayDetachedCoreE2E(t *testing.T) {
	ctx := context.Background()
	agent, _ := nostr.GeneratePrivKey()
	l := newCoreLab(t, agent.PubKeyHex())
	seal1 := l.seal()
	seal2 := l.seal()

	renter1, _ := nostr.GeneratePrivKey()
	renter2, _ := nostr.GeneratePrivKey()
	cert1 := l.grant(renter1.PubKeyHex(), strings.Repeat("a", 64), seal1)
	cert2 := l.grant(renter2.PubKeyHex(), strings.Repeat("b", 64), seal2)

	kernelState := filepath.Join(l.root, "kernel-state")
	if e := os.Mkdir(kernelState, 0700); e != nil {
		t.Fatal(e)
	}
	adapter, err := kernelbind.New(l.observer, kernelState, e2eAgentName, l.issuerPub)
	if err != nil {
		t.Fatal(err)
	}
	store, err := journal.Open(filepath.Join(l.root, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	sockDir, err := os.MkdirTemp("", "gw-e2e")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	sock := filepath.Join(sockDir, "s.sock")
	pub := &collectPub{}
	fixed := time.Unix(500, 0)
	g, err := gw.New(gw.Config{
		AgentKey: agent, Kernel: adapter, Presenter: adapter, AgentName: e2eAgentName,
		Screener: &screen.Stub{}, Journal: store, Publisher: pub,
		Driver:   &station.LocalTestDriver{Root: filepath.Join(l.root, "stations")},
		Endpoint: sock, Now: func() time.Time { return fixed },
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = g.ServeStations(ln) }()

	for i, r := range []*nostr.PrivKey{renter1, renter2} {
		spec := gw.SlotSpec{
			ID: fmt.Sprintf("slot-%d", i+1), StationName: fmt.Sprintf("id/e2e-station-%d", i+1),
			RenterPubKey:   r.PubKeyHex(),
			ContractSHA256: strings.Repeat(string(rune('a'+i)), 64),
			NotBefore:      100, NotAfter: 1000,
		}
		if err := g.RegisterSlot(spec); err != nil {
			t.Fatal(err)
		}
	}
	dm := func(from *nostr.PrivKey, content string, cert []byte) *nostr.Event {
		var tags [][]string
		if cert != nil {
			tags = [][]string{gw.GrantCertTag(cert)}
		}
		w, _, err := nostr.WrapDM(from, agent.PubKeyHex(), content, tags, 500)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	stationClient := func(slotID, stationName, secretHex string) *stationlink.Client {
		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		c := stationlink.NewClient(conn)
		secret, _ := hex.DecodeString(secretHex)
		sys, err := c.Hello(slotID, stationName, secret)
		if err != nil || sys.Type != stationlink.TypeSystem {
			t.Fatalf("hello %s = %+v %v", slotID, sys, err)
		}
		return c
	}
	secretOf := func(slotID string) string {
		s, ok := store.Get(slotID)
		if !ok || s.ChannelSecretHex == "" {
			t.Fatalf("no channel secret for %s (started?)", slotID)
		}
		return s.ChannelSecretHex
	}

	// Untagged first: presentation required, nothing starts.
	if res := g.HandleGiftWrap(ctx, dm(renter1, "too early", nil)); !res.Refused ||
		res.Reason != "kernel_refused:presentation_required" {
		t.Fatalf("untagged first = %+v", res)
	}
	// Both grantees present inline and deliver to separate instances.
	if res := g.HandleGiftWrap(ctx, dm(renter1, "hello from one", cert1)); !res.Delivered {
		t.Fatalf("grant 1 presentation = %+v", res)
	}
	if res := g.HandleGiftWrap(ctx, dm(renter2, "hello from two", cert2)); !res.Delivered {
		t.Fatalf("grant 2 presentation = %+v", res)
	}
	s1, _ := store.Get("slot-1")
	s2, _ := store.Get("slot-2")
	if !s1.Started || !s2.Started || s1.StationHome == s2.StationHome {
		t.Fatalf("instances not separate: %q %q", s1.StationHome, s2.StationHome)
	}
	c1 := stationClient("slot-1", "id/e2e-station-1", secretOf("slot-1"))
	c2 := stationClient("slot-2", "id/e2e-station-2", secretOf("slot-2"))
	if f, err := c1.Pull(); err != nil || f.Content != "hello from one" {
		t.Fatalf("station 1 pull = %+v %v", f, err)
	}
	if f, err := c2.Pull(); err != nil || f.Content != "hello from two" {
		t.Fatalf("station 2 pull = %+v %v", f, err)
	}
	// Cached path: untagged follow-ups are Checked fresh and flow.
	if res := g.HandleGiftWrap(ctx, dm(renter1, "one again", nil)); !res.Delivered {
		t.Fatalf("grant 1 cached follow-up = %+v", res)
	}
	if f, err := c1.Pull(); err != nil || f.Content != "one again" {
		t.Fatalf("station 1 pull 2 = %+v %v", f, err)
	}

	// Revoke grant 1: spend its seal. Gift-wrap timestamps are
	// jittered, but the kernel check observes the spent seal.
	l.revoke(seal1)
	res := g.HandleGiftWrap(ctx, dm(renter1, "after revoke", nil))
	if !res.Refused || !res.SlotEnded || res.Reason != "kernel_closed:SEAL_SPENT" {
		t.Fatalf("revoked grantee = %+v, want kernel_closed:SEAL_SPENT", res)
	}
	if s, _ := store.Get("slot-1"); !s.Ended {
		t.Fatalf("slot-1 not ended after revocation: %+v", s)
	}
	// Grant 2 keeps talking.
	if res := g.HandleGiftWrap(ctx, dm(renter2, "two still here", nil)); !res.Delivered {
		t.Fatalf("grant 2 after grant-1 revocation = %+v", res)
	}
	if f, err := c2.Pull(); err != nil || f.Content != "two still here" {
		t.Fatalf("station 2 pull 2 = %+v %v", f, err)
	}
	t.Logf("genuine-Core detached e2e PASS (root %s)", l.root)
}
