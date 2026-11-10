package kernelbind_test

// Genuine-Core gateway end-to-end for K1 v3 grants (M2-05):
// real pinned Namecoin Core regtest, two grants produced by the real K1 issuer
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
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	gw "github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernelbind"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/screen"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/stationlink"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

const e2eAgentName = "id/swarma-agent-e2e"
const e2eLandlordName = "id/swarma-landlord-e2e"

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
	value, e := rental.AgentBindingValue(rental.AgentBinding{Nostr: agentNostrPub, Landlord: e2eLandlordName})
	if e != nil {
		t.Fatal(e)
	}
	landlordValue, e := rental.LandlordValue(rental.LandlordBinding{Grant: l.issuerPub})
	if e != nil {
		t.Fatal(e)
	}
	// Reserve both names together so the first name cannot expire while the
	// second waits twelve confirmations on regtest.
	reservations := map[string][]string{}
	for _, name := range []string{e2eAgentName, e2eLandlordName} {
		var res []string
		if e = json.Unmarshal(l.rpc("issuer", "name_new", name), &res); e != nil {
			t.Fatal(e)
		}
		reservations[name] = res
	}
	l.mine(12)
	for name, v := range map[string]string{e2eAgentName: value, e2eLandlordName: landlordValue} {
		res := reservations[name]
		l.rpc("issuer", "name_firstupdate", name, res[1], res[0], v, map[string]string{"destAddress": l.address})
	}
	l.mine(1)
	l.rpc("issuer", "importprivkey", testWIF(1), "", false)
	return l
}

// seal funds one fresh 1,000,000-sat output to the grant seal
// script (P2PKH of the issuer grant key), mines it and locks it
// against wallet coin selection.
// W creation explicitly spends one confirmed native funding output. Legacy
// payment/name fixtures retain their own script types.
func (l *coreLab) seal() rental.Point {
	l.t.Helper()
	nativeAddress := labText(l.t, l.rpc("issuer", "getnewaddress", "", "bech32"))
	nativeScript := labText(l.t, labObject(l.t, l.rpc("issuer", "getaddressinfo", nativeAddress))["scriptPubKey"])
	seed := labText(l.t, l.rpc("issuer", "sendtoaddress", nativeAddress, su.Coins(2000000)))
	l.mine(1)
	var view su.TransactionView
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", seed, true), &view); e != nil {
		l.t.Fatal(e)
	}
	var point su.Point
	found := false
	for _, out := range view.Vout {
		if out.Script.Hex == nativeScript && int64(out.Value) == 2000000 {
			point = su.Point{TxID: seed, Vout: out.N}
			found = true
		}
	}
	if !found {
		l.t.Fatal("native seed absent")
	}
	sealScript, e := rental.GrantSealScript(l.issuerPub)
	if e != nil {
		l.t.Fatal(e)
	}
	script, _ := hex.DecodeString(sealScript)
	change, _ := hex.DecodeString(nativeScript)
	tx := su.Transaction{Version: 2, Inputs: []su.Input{{Point: point, Sequence: 0xfffffffe}}, Outputs: []su.Output{{Value: 1000000, Script: script}, {Value: 900000, Script: change}}}
	id := l.send(hex.EncodeToString(tx.Bytes()), true)
	seal := rental.Point{TxID: id, Vout: 0}
	l.rpc("issuer", "lockunspent", false, []rental.Point{seal})
	return seal
}

func (l *coreLab) nativeFunding() (rental.Point, string) {
	address := labText(l.t, l.rpc("issuer", "getnewaddress", "", "bech32"))
	script := labText(l.t, labObject(l.t, l.rpc("issuer", "getaddressinfo", address))["scriptPubKey"])
	return l.output(address, script), script
}

// grant uses the real K1 issuer after a confirmed payment and authenticated
// booking package. The harness signs/broadcasts its returned transaction plan;
// it never constructs or signs a v3 grant itself.
func (l *coreLab) grant(grantee *nostr.PrivKey, label string, seal rental.Point, confirmed bool) []byte {
	l.t.Helper()
	booking := rental.Hash([]byte(label))
	provider, err := nostr.GeneratePrivKey()
	if err != nil {
		l.t.Fatal(err)
	}
	payment := l.output(l.address, l.script)
	funding, fundingScript := l.nativeFunding()
	var paymentTx su.TransactionView
	if err = json.Unmarshal(l.rpc("", "getrawtransaction", payment.TxID, true), &paymentTx); err != nil {
		l.t.Fatal(err)
	}
	var header su.Header
	if err = json.Unmarshal(l.rpc("", "getblockheader", paymentTx.Block), &header); err != nil {
		l.t.Fatal(err)
	}
	contract := rental.Contract{
		Version: 1, BookingID: booking, RenterPubkey: grantee.PubKeyHex(), AgentPubkey: l.agentNostrPub,
		StationName: e2eAgentName, NotBefore: 100, NotAfter: 1000,
		Allowed: []string{"deliver", "pay"}, Forbidden: []string{"publish", "repository.push", "secret.release"}, BudgetSat: 1000000,
		TemplateID: "lab-template", TemplateSHA256: strings.Repeat("1", 64), ProfileID: "lab-profile", ProfileVersion: "1", ProfileSHA256: strings.Repeat("2", 64),
		PriceUSDCents: 100, USDMicrosPerNMC: 100000000, RateAsOf: 100, PriceNMCSat: 1000000, PaymentPolicy: "advance", PaymentAddress: l.address, PrivacySHA256: strings.Repeat("3", 64),
	}
	contractID := rental.Hash(jsonBytes(l.t, contract))
	consent := signEvent(l.t, grantee, rental.Event{CreatedAt: 200, Kind: 8181, Tags: [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", contractID}, {"booking", booking}, {"privacy", contract.PrivacySHA256}}})
	pk, _ := btcec.PrivKeyFromBytes(provider.Bytes())
	pack := rental.Package{Version: 1, Contract: contract, Consent: consent, ProviderPubkey: provider.PubKeyHex(), ProviderSignature: signHash(l.t, pk, contractID), PrivacyAckAt: 100, PrivacySHA256: contract.PrivacySHA256, HoldCreatedAt: 100, HoldExpiresAt: 900}
	publication := signEvent(l.t, provider, rental.Event{CreatedAt: 300, Kind: 8182, Tags: [][]string{{"t", "swarma-rental-package-v1"}, {"contract", contractID}, {"booking", booking}, {"e", consent.ID}}, Content: string(jsonBytes(l.t, pack))})
	req := rental.IssuanceRequest{Version: 1, BookingID: booking, StationName: e2eAgentName, AgentPubkey: l.agentNostrPub, RenterPubkey: grantee.PubKeyHex(), ContractSHA256: contractID, Scope: contract.Allowed, BudgetSat: contract.BudgetSat, NotBefore: 100, NotAfter: 1000, PaymentPolicy: "advance", PaymentTxID: payment.TxID, PaymentVout: payment.Vout, PaymentHeight: header.Height, PaymentBlockHash: paymentTx.Block, ObservedTipHash: labText(l.t, l.rpc("", "getbestblockhash")), PackageEventID: publication.ID}
	issuerState := filepath.Join(l.private, "issuer-"+label)
	if err = os.Mkdir(issuerState, 0700); err != nil {
		l.t.Fatal(err)
	}
	keyPath := filepath.Join(issuerState, "grant-key")
	if err = os.WriteFile(keyPath, l.issuer.Serialize(), 0600); err != nil {
		l.t.Fatal(err)
	}
	sealScript, _ := rental.GrantSealScript(l.issuerPub)
	policy := rental.Policy{ConstructionProfile: "W", Network: "regtest", Genesis: su.RegtestGenesis, AgentName: e2eAgentName, LandlordName: e2eLandlordName, SealScript: sealScript, FundingScript: fundingScript, StateDir: issuerState}
	spec := rental.PlanSpec{Kind: "grant-issue", Inputs: []su.PlanInput{{Point: su.Point{TxID: funding.TxID, Vout: funding.Vout}, ValueSat: 1000000, Script: fundingScript, Role: "funding"}}, ChangeScript: fundingScript}
	r := rental.IssueGrant(context.Background(), l.observer, rental.IssuerPolicy{Policy: policy, ProviderPubkey: provider.PubKeyHex()}, jsonBytes(l.t, req), jsonBytes(l.t, publication), seal, spec, keyPath, 500)
	if r.Verdict != "prepared" || r.Plan == nil || r.GrantID != rental.Hash(r.SignedGrant) {
		l.t.Fatalf("K1 issuer: %s/%s", r.Verdict, r.Reason)
	}
	tx := su.Transaction{Version: r.Plan.TransactionVersion}
	for _, in := range r.Plan.Inputs {
		tx.Inputs = append(tx.Inputs, su.Input{Point: in.Point, Sequence: 0xfffffffe})
	}
	for _, out := range r.Plan.Outputs {
		script, err := hex.DecodeString(out.Script)
		if err != nil {
			l.t.Fatal(err)
		}
		tx.Outputs = append(tx.Outputs, su.Output{Value: out.ValueSat, Script: script})
	}
	id := l.send(hex.EncodeToString(tx.Bytes()), confirmed)
	proof, err := rental.PresentIssuedGrant(r.SignedGrant, id)
	if err != nil {
		l.t.Fatal(err)
	}
	// Persist only public issuance evidence; key files stay in private/.
	if err = os.WriteFile(filepath.Join(l.root, label+"-issued.json"), jsonBytes(l.t, r), 0600); err != nil {
		l.t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(l.root, label+"-presentation.json"), proof, 0600); err != nil {
		l.t.Fatal(err)
	}
	return proof
}

func (l *coreLab) output(address, script string) rental.Point {
	l.t.Helper()
	id := labText(l.t, l.rpc("issuer", "sendtoaddress", address, su.Coins(1000000)))
	l.mine(1)
	var tx su.TransactionView
	if err := json.Unmarshal(l.rpc("", "getrawtransaction", id, true), &tx); err != nil {
		l.t.Fatal(err)
	}
	for _, out := range tx.Vout {
		if out.Script.Hex == script && int64(out.Value) == 1000000 {
			point := rental.Point{TxID: id, Vout: out.N}
			l.rpc("issuer", "lockunspent", false, []rental.Point{point})
			return point
		}
	}
	l.t.Fatal("fixture output absent")
	return rental.Point{}
}

// revoke spends a seal back to the issuer wallet (revocation).
func (l *coreLab) revoke(seal rental.Point) {
	l.t.Helper()
	unsigned := labText(l.t, l.rpc("", "createrawtransaction",
		[]rental.Point{seal}, []map[string]any{{l.address: su.Coins(950000)}}))
	l.send(unsigned, true)
}

type collectPub struct {
	mu  sync.Mutex
	evs []*nostr.Event
}

func (c *collectPub) Publish(ctx context.Context, ev *nostr.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evs = append(c.evs, ev)
	return nil
}

// TestGatewayV3CoreE2E proves the M2-05 path on genuine
// Core: two grantees present issuer-produced v3 grants inline, are
// routed to separate lazily-started instances, the seal of grant
// one is spent, and only that grantee's slot closes.
func TestGatewayV3CoreE2E(t *testing.T) {
	ctx := context.Background()
	agent, _ := nostr.GeneratePrivKey()
	l := newCoreLab(t, agent.PubKeyHex())
	seal1 := l.seal()
	seal2 := l.seal()

	renter1, _ := nostr.GeneratePrivKey()
	renter2, _ := nostr.GeneratePrivKey()
	cert1 := l.grant(renter1, "one", seal1, true)
	cert2 := l.grant(renter2, "two", seal2, false)

	kernelState := filepath.Join(l.root, "kernel-state")
	if e := os.Mkdir(kernelState, 0700); e != nil {
		t.Fatal(e)
	}
	adapter, err := kernelbind.New(l.observer, kernelState, e2eAgentName, e2eLandlordName, l.issuerPub, "W")
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
	screener := &screen.Stub{}
	g, err := gw.New(gw.Config{
		AgentKey: agent, Kernel: adapter, Presenter: adapter, AgentName: e2eAgentName,
		Screener: screener, Journal: store, Publisher: pub,
		Driver:   &station.LocalTestDriver{Root: filepath.Join(l.root, "stations")},
		Endpoint: sock, PullTimeout: 10 * time.Millisecond, Now: func() time.Time { return fixed },
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
			ContractSHA256: proofGrant(t, [][]byte{cert1, cert2}[i]).Grant.ContractSHA256,
			NotBefore:      100, NotAfter: 1000,
		}
		if err := g.RegisterSlot(spec); err != nil {
			t.Fatal(err)
		}
	}
	dm := func(from *nostr.PrivKey, content string, cert []byte) *nostr.Event {
		var tags [][]string
		if cert != nil {
			tag, err := gw.GrantCertTag(cert)
			if err != nil {
				t.Fatal(err)
			}
			tags = [][]string{tag}
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
		t.Cleanup(func() { _ = conn.Close() })
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
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
	// These refusals precede any station start/screening/cache insertion.
	// Every attempt is replayed verbatim to prove its rumor id is not burned.
	refuse := func(label string, wrapped *nostr.Event, want string, sender string) {
		t.Helper()
		before := screener.Calls
		for retry := 0; retry < 2; retry++ {
			r := g.HandleGiftWrap(ctx, wrapped)
			if !r.Refused || r.Delivered || r.SlotEnded || r.Reason != want {
				t.Fatalf("%s refusal: %+v, want %s", label, r, want)
			}
			if screener.Calls != before {
				t.Fatalf("%s reached screening", label)
			}
			if _, err := adapter.CachedGrant(sender); !errors.Is(err, kernel.ErrNoPresentation) {
				t.Fatalf("%s cached refused grant: %v", label, err)
			}
			if slot, ok := store.ActiveByRenter(sender); !ok || slot.Started || slot.Ended || slot.Refusals != 0 {
				t.Fatalf("%s changed slot state", label)
			}
		}
		t.Logf("control %s PASS (%s; no screening/cache/start/strike/replay burn)", label, want)
	}
	refuse("foreign-grantee", dm(renter1, "foreign grant", cert2), "kernel_refused:GRANTEE_MISMATCH", renter1.PubKeyHex())
	signed1 := proofGrant(t, cert1)
	v2 := legacyEnvelope(t, signed1.Grant)
	if _, err := rental.ParseDetachedEnvelope(v2); err != nil {
		t.Fatal("v2 negative fixture invalid", err)
	}
	v2Receipt, err := adapter.Check(ctx, v2, e2eAgentName, renter1.PubKeyHex(), 500)
	if err != nil || v2Receipt.Verdict != kernel.Refused || v2Receipt.Reason != "CANONICAL_ENCODING" || v2Receipt.Closed {
		t.Fatalf("v2 policy refusal: %+v %v", v2Receipt, err)
	}
	rawTag := func(raw []byte, id string) *nostr.Event {
		w, _, err := nostr.WrapDM(renter1, agent.PubKeyHex(), "raw tag", [][]string{{"grant-cert", id, base64.StdEncoding.EncodeToString(raw)}}, 500)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	refuse("v2-transport", rawTag(v2, rental.Hash(v2)), "presentation_malformed", renter1.PubKeyHex())
	refuse("tag-id-mismatch", rawTag(cert1, strings.Repeat("0", 64)), "presentation_malformed", renter1.PubKeyHex())
	wrongLocator, err := rental.PresentIssuedGrant(jsonBytes(t, signed1), seal2.TxID)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := kernel.PresentationID(wrongLocator); err != nil || got != signed1.ID() {
		t.Fatal("locator changed stable id", err)
	}
	refuse("wrong-locator", dm(renter1, "wrong commitment", wrongLocator), "kernel_refused:ISSUANCE_COMMITMENT", renter1.PubKeyHex())
	unconfirmed := dm(renter2, "hello from two", cert2)
	refuse("unconfirmed-issuance", unconfirmed, "kernel_pending:ISSUANCE_UNCONFIRMED", renter2.PubKeyHex())
	l.mine(1)

	// Both grantees present inline and deliver to separate instances.
	if res := g.HandleGiftWrap(ctx, dm(renter1, "hello from one", cert1)); !res.Delivered {
		t.Fatalf("grant 1 presentation = %+v", res)
	}
	if res := g.HandleGiftWrap(ctx, unconfirmed); !res.Delivered {
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
	delivered2, pullErr := c2.Pull()
	if f, err := delivered2, pullErr; err != nil || f.Content != "hello from two" {
		t.Fatalf("station 2 pull = %+v %v", f, err)
	}
	// The actual K1 cache stores v3 proof bytes, not a live verdict. Gateway
	// receipts carry grant identity and names; no funding policy is needed.
	for _, row := range []struct {
		sender string
		raw    []byte
	}{{renter1.PubKeyHex(), cert1}, {renter2.PubKeyHex(), cert2}} {
		cached, err := adapter.CachedGrant(row.sender)
		if err != nil || !bytes.Equal(cached, row.raw) {
			t.Fatal("live presentation not cached", err)
		}
		signed := proofGrant(t, row.raw)
		receipt, err := adapter.Check(ctx, cached, e2eAgentName, row.sender, 500)
		if err != nil || !receipt.Admits() || receipt.GrantID != signed.ID() || receipt.AgentName != e2eAgentName || receipt.LandlordName != e2eLandlordName || !reflect.DeepEqual(receipt.Scope, signed.Grant.Scope) || adapter.Policy.FundingScript != "" {
			t.Fatalf("live receipt mapping: %+v %v", receipt, err)
		}
	}
	if ack, err := c2.Received(delivered2.DeliveryID); err != nil || ack.Type != stationlink.TypeAck {
		t.Fatal("receive ACK", err)
	}
	if f, err := c2.Reply(delivered2.DeliveryID, "live reply"); err != nil || f.Type != stationlink.TypeAck {
		t.Fatalf("live station reply: %+v %v", f, err)
	}
	// A bad locator cannot replace an already-live cached presentation.
	beforeReplacement := screener.Calls
	if r := g.HandleGiftWrap(ctx, dm(renter1, "bad replacement", wrongLocator)); !r.Refused || r.Delivered || r.SlotEnded || r.Reason != "kernel_refused:ISSUANCE_COMMITMENT" {
		t.Fatalf("refused replacement: %+v", r)
	}
	if raw, err := adapter.CachedGrant(renter1.PubKeyHex()); err != nil || !bytes.Equal(raw, cert1) || screener.Calls != beforeReplacement {
		t.Fatal("refused replacement changed cache or reached screening", err)
	}
	t.Log("control refused-replacement PASS (prior live cache preserved)")
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
	t.Log("control revoke-one PASS (first slot durably closed)")
	// Grant 2 keeps talking.
	if res := g.HandleGiftWrap(ctx, dm(renter2, "two still here", nil)); !res.Delivered {
		t.Fatalf("grant 2 after grant-1 revocation = %+v", res)
	}
	if f, err := c2.Pull(); err != nil || f.Content != "two still here" {
		t.Fatalf("station 2 pull 2 = %+v %v", f, err)
	}
	t.Log("control parallel-neighbour PASS (second slot still delivers)")
	// A mempool landlord rotation blocks both incoming traffic and station
	// replies without ending the surviving slot. Confirmation closes it.
	value, err := rental.LandlordValue(rental.LandlordBinding{Grant: xonly(9)})
	if err != nil {
		t.Fatal(err)
	}
	l.rpc("issuer", "name_update", e2eLandlordName, value)
	before := screener.Calls
	for i := 0; i < 2; i++ {
		r := g.HandleGiftWrap(ctx, dm(renter2, "during rotation", nil))
		if !r.Refused || r.Delivered || r.SlotEnded || r.Reason != "kernel_refused:PENDING_LANDLORD_ROTATION" {
			t.Fatalf("pending rotation: %+v", r)
		}
	}
	if slot, _ := store.Get("slot-2"); slot.Ended || slot.Refusals != 0 || screener.Calls != before {
		t.Fatal("pending rotation ended/struck/screened slot")
	}
	if f, err := c2.Pull(); err != nil || f.Type != stationlink.TypeNone {
		t.Fatalf("pending rotation leaked delivery: %+v %v", f, err)
	}
	pub.mu.Lock()
	published := len(pub.evs)
	pub.mu.Unlock()
	if f, err := c2.Reply(delivered2.DeliveryID, "must not publish"); err != nil || f.Type != stationlink.TypeError || f.Reason != "grant not live" {
		t.Fatalf("pending outbound: %+v %v", f, err)
	}
	pub.mu.Lock()
	afterPublished := len(pub.evs)
	pub.mu.Unlock()
	if afterPublished != published {
		t.Fatal("pending rotation published station reply")
	}
	t.Log("control pending-landlord-rotation PASS (refused, slot remains open)")
	l.mine(1)
	r := g.HandleGiftWrap(ctx, dm(renter2, "after rotation", nil))
	if !r.Refused || r.Delivered || !r.SlotEnded || r.Reason != "kernel_closed:LANDLORD_KEY_ROTATED" {
		t.Fatalf("confirmed rotation: %+v", r)
	}
	if slot, _ := store.Get("slot-2"); !slot.Ended {
		t.Fatal("confirmed rotation did not persist slot end")
	}
	t.Log("control confirmed-landlord-rotation PASS (slot closed)")
	t.Logf("genuine-Core v3 issuer gateway e2e PASS (root %s)", l.root)
}
