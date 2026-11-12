package wallet

// Owner S1. Production profile selection at the public service opener
// (review finding g2-profile-falls-through-to-w2, PR 76 revision 2) and the
// step-23 clock step back (S2 cross request). The unit layer opens the real
// OpenActionService with installed files and an unreachable loopback node; it
// makes no node call. The Core layer repeats the reviewer's genuine regtest
// scenario. Run the Core layer with a fresh root per invocation:
//
//	W1_REGTEST=1 W1_RUN_ROOT=FRESH_ABSOLUTE_DIRECTORY \
//	W1_CORE_CLI=ABSOLUTE_NAMECOIN_CLI W1_CORE_DAEMON=ABSOLUTE_NAMECOIND \
//	go test -count=1 -run '^TestPX1CoreService' -v .

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// px1ServiceUnitConfig provisions installed files for one OpenActionService
// without a node: the routes point at an unused loopback port and are never
// dialled during startup. It returns the service config without a g2 block.
func px1ServiceUnitConfig(t *testing.T) ServiceConfig {
	t.Helper()
	root := privateDir(t)
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(root, name)
		if e := os.Mkdir(p, mode); e != nil {
			t.Fatal(e)
		}
		if e := os.Chmod(p, mode); e != nil {
			t.Fatal(e)
		}
		return p
	}
	runtime := mk("runtime", 0750)
	installed := mk("installed", 0750)
	objects := mk("objects", 0700)
	walletState := mk("wallet-state", 0700)
	serviceState := mk("service-state", 0700)
	password := strings.Repeat("p", 24)
	route := func(user string) su.Route {
		return su.Route{Host: "127.0.0.1", Port: 9, Username: user, Password: password}
	}
	wc := Config{Version: 1, Network: "regtest", Genesis: su.RegtestGenesis, Policy: rental.Policy{ConstructionProfile: su.WitnessProfile, Network: "regtest", Genesis: su.RegtestGenesis, AgentName: "id/wallet-agent-test", LandlordName: "id/wallet-landlord-test", StateDir: filepath.Join(root, "kernel")},
		Observer: route("w3-observer"), Wallet: WalletRoute{Route: route("w1-wallet"), Wallet: "agent"}, Broadcast: route("w1-broadcast"), StateDir: walletState, ObjectsDir: objects, ChangeAddress: testAddress(6), FeeRate: 110, WalletDir: filepath.Join(root, "wallets/agent"), MemoryZone: filepath.Join(root, "memory")}
	configPath := filepath.Join(installed, "wallet.json")
	keyPath := filepath.Join(installed, "receipt.key")
	writeInstalled(t, configPath, canonical(wc))
	key, _ := testKey(9)
	writeInstalled(t, keyPath, []byte(hex.EncodeToString(key.Serialize())))
	_, grantee := testKey(2)
	return ServiceConfig{Network: "regtest", Genesis: su.RegtestGenesis, Version: 1, Service: WalletServiceID, Socket: filepath.Join(runtime, "wallet.sock"), SocketGID: uint32(os.Getgid()), PeerUID: uint32(os.Getuid() + 1), Grantee: grantee, SkewSeconds: 60, TimeoutSeconds: 2, StateDir: serviceState, WalletConfig: configPath, ReceiptKeyFile: keyPath}
}

// px1ProductDepsStubbed reports whether the S2/S3 product constructors used
// by px1Attach are still the PX1 stubs on this base.
func px1ProductDepsStubbed() bool {
	_, e := NewCanary(nil, px1Operator().Canary)
	return errors.Is(e, ErrNotImplemented)
}

// Claim: the public OpenActionService never returns a W2 wallet for a config
// with a g2 block. While the S2/S3 constructors are stubs it refuses with the
// attach error itself (PX1_NOT_IMPLEMENTED), not a substitute code; once they
// land, an opened service must be attached (wallet.g2 and its journal set).
// A refused G2 open releases the wallet lock (a W2 reopen of the same files
// succeeds), and the W2 neighbour without g2 opens unattached before and after.
// Limit: unit layer, no node call; the Core tests below cover the spend.
func TestPX1ServiceOpenG2FailClosed(t *testing.T) {
	c := px1ServiceUnitConfig(t)
	openW2 := func(label string) {
		t.Helper()
		s, e := OpenActionService(c)
		if e != nil {
			t.Fatalf("%s: W2 neighbour refused: %v", label, e)
		}
		if s.wallet.g2 != nil || s.wallet.PX1Journal() != nil {
			s.Close()
			t.Fatalf("%s: W2 neighbour attached to G2", label)
		}
		s.Close()
	}
	openW2("before")
	op := px1Operator()
	g2 := c
	g2.G2 = &op
	if e := validServiceConfig(g2); e != nil {
		t.Fatal("fixture: the g2 block must pass configuration validation", e)
	}
	s, e := OpenActionService(g2)
	switch {
	case e == nil && (s.wallet.g2 == nil || s.wallet.PX1Journal() == nil):
		s.Close()
		t.Fatal("G2_PROFILE_FALLTHROUGH: OpenActionService accepted a g2 block and returned a W2 wallet")
	case e == nil && px1ProductDepsStubbed():
		s.Close()
		t.Fatal("G2 opened although the product dependencies are stubs")
	case e == nil:
		s.Close()
	case px1ProductDepsStubbed():
		wantCode(t, "G2 stub refuses", e, ErrNotImplemented.Error())
	default:
		t.Logf("G2 startup refused with product dependencies: %v", e)
	}
	openW2("after G2 refusal")
}

// Claim: px1SelectProfile is a no-op without g2, refuses SERVICE_CONFIG for
// a g2 block without a receipt key, and otherwise returns the attach error
// unchanged with the wallet left unattached.
func TestPX1SelectProfile(t *testing.T) {
	w := &Wallet{config: Config{Network: "regtest", Genesis: su.RegtestGenesis}}
	key, _ := testKey(9)
	wantCode(t, "w2", px1SelectProfile(w, ServiceConfig{}, key), "")
	op := px1Operator()
	wantCode(t, "nil key", px1SelectProfile(w, ServiceConfig{G2: &op}, nil), "SERVICE_CONFIG")
	if px1ProductDepsStubbed() {
		wantCode(t, "stub attach", px1SelectProfile(w, ServiceConfig{G2: &op}, key), ErrNotImplemented.Error())
	}
	if w.g2 != nil {
		t.Fatal("refused selection attached the wallet")
	}
}

// Claim: a clock step back between the broadcast and the step-23 complete
// record reports CLOCK_ROLLBACK (status uncertain, debit retained, journal not
// poisoned), not JOURNAL_WRITE_UNCERTAIN; while the clock stays behind, a new
// request is refused CLOCK_ROLLBACK at the reservation with no broadcast; once
// the clock recovers a new request executes. A genuine write failure still
// reports JOURNAL_WRITE_UNCERTAIN (TestPX1WalletUncertainOutcomes).
func TestPX1WalletClockStepBack(t *testing.T) {
	l := newPX1Lab(t, px1TermsAllow(), px1Operator(), 500000, px1ExecutorKey)
	now := px1Now
	l.w.clock = func() int64 { return now }
	l.w.hook = func(point string) {
		if point == "after-broadcast" {
			now = px1Now - 1
		}
	}
	r, raw := l.request(px1AllowA, 50000, 3000, 1)
	got := l.spend(r, raw, nil)
	if got.Status != "uncertain" || got.Reason != CodeClockRollback || l.kinds() != "reserve" || len(l.chain.sent) != 1 || l.journal.Poisoned() {
		t.Fatalf("step back after broadcast: %+v kinds=%s sent=%d poisoned=%t", got, l.kinds(), len(l.chain.sent), l.journal.Poisoned())
	}
	ledger, e := l.w.PX1Ledger()
	if e != nil || ledger.SpendUsed(l.grant.ID) != 50000+l.chain.fee {
		t.Fatal("debit must stay retained", e)
	}
	l.w.hook = nil
	l.chain.coins = l.chain.coins[1:] // the broadcast spent the first coin
	r, raw = l.request(px1AllowA, 50000, 3000, 2)
	if got := l.spend(r, raw, nil); got.Status != "refused" || got.Reason != CodeClockRollback || l.kinds() != "reserve" || len(l.chain.sent) != 1 {
		t.Fatalf("clock still behind: %+v kinds=%s sent=%d", got, l.kinds(), len(l.chain.sent))
	}
	now = px1Now
	r, raw = l.request(px1AllowA, 50000, 3000, 3)
	if got := l.spend(r, raw, nil); got.Status != "executed" || l.kinds() != "reserve,reserve,complete" || len(l.chain.sent) != 2 {
		t.Fatalf("recovered clock neighbour: %+v kinds=%s", got, l.kinds())
	}
}

// Claim: with a valid g2 block (terms v2 required, transfer/day/fee ceilings
// 1000) the public opener never executes a terms-v1 spend under W2: startup
// refuses while the S2/S3 constructors are stubs; once integrated, the opened
// service carries the G2 profile at both layers, refuses every spend with
// SERVICE_STATE_UNAVAILABLE at journal_seq 0 before the first observation
// pass (S3 halt, nothing journaled), and after one pass that reads a real
// unspent canary refuses the same request TERMS_VERSION_REQUIRED. Genuine Core
// 28 regtest and the genuine K1 kernel; installedRead keeps its synthetic
// root-ownership seam and the peer metadata is injected (not a custody test).
// Adapted from the PR 76 reviewer's TestReviewG2ServiceFailClosed.
func TestPX1CoreServiceG2FailClosed(t *testing.T) { px1CoreServiceProfile(t, true) }

// Claim: without g2 the same signed terms-v1 request executes and genuine Core
// shows the 50000-atom payment, so the G2 test cannot pass by refusing every
// startup. Adapted from the reviewer's TestReviewW2ProfilePositive.
func TestPX1CoreServiceW2Positive(t *testing.T) { px1CoreServiceProfile(t, false) }

func px1CoreServiceProfile(t *testing.T, g2 bool) {
	core := newPX1Core(t)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 500000}
	budget := int64(500000)
	grant := core.px1IssueGrant(canonical(terms), &budget, 2)
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(core.root, name)
		if e := os.Mkdir(p, mode); e != nil {
			t.Fatal(e)
		}
		if e := os.Chmod(p, mode); e != nil {
			t.Fatal(e)
		}
		return p
	}
	runtime := mk("runtime", 0750)
	stateDir := mk("service-state", 0700)
	installed := mk("installed", 0750)
	configPath := filepath.Join(installed, "wallet.json")
	keyPath := filepath.Join(installed, "receipt.key")
	writeInstalled(t, configPath, canonical(grant.config))
	key, _ := testKey(9)
	writeInstalled(t, keyPath, []byte(hex.EncodeToString(key.Serialize())))
	installActionObjects(t, grant.config, grant.raw, terms)
	operator := px1Operator()
	operator.MaxTransferSat = 1000
	operator.MaxDaySat = 1000
	operator.MaxFeeSat = 1000
	if g2 {
		// A real canary: one 10000-atom output in the hot wallet, so the
		// observation pass reads it unspent (the fixture outpoint is absent).
		canary := text(t, core.rpc("issuer", "sendtoaddress", text(t, core.rpc("agent", "getnewaddress", "", "legacy")), su.Coins(10000)))
		core.mine(1)
		var view su.TransactionView
		if e := json.Unmarshal(core.rpc("", "getrawtransaction", canary, true), &view); e != nil {
			t.Fatal(e)
		}
		for i, out := range view.Vout {
			if int64(out.Value) == 10000 {
				operator.Canary = CanaryConfig{Outpoint: su.Point{TxID: canary, Vout: uint32(i)}, ValueSat: 10000}
			}
		}
		if operator.Canary.Outpoint.TxID != canary {
			t.Fatal("canary output")
		}
	}
	_, grantee := testKey(2)
	config := ServiceConfig{Network: "regtest", Genesis: su.RegtestGenesis, Version: 1, Service: WalletServiceID, Socket: filepath.Join(runtime, "wallet.sock"), SocketGID: uint32(os.Getgid()), PeerUID: uint32(os.Getuid() + 1), Grantee: grantee, SkewSeconds: 60, TimeoutSeconds: 2, StateDir: stateDir, WalletConfig: configPath, ReceiptKeyFile: keyPath}
	if g2 {
		config.G2 = &operator
	}
	service, err := OpenActionService(config)
	if err != nil {
		if !g2 {
			t.Fatal("W2 positive startup failed", err)
		}
		if px1ProductDepsStubbed() {
			wantCode(t, "G2 stub refuses", err, ErrNotImplemented.Error())
		}
		t.Logf("G2 startup refused: %v", err)
		return
	}
	defer service.Close()
	if g2 && (service.wallet.g2 == nil || service.wallet.PX1Journal() == nil) {
		t.Fatal("G2_PROFILE_FALLTHROUGH: OpenActionService accepted g2 and returned a W2 wallet")
	}
	service.clock = func() int64 { return 500 }
	service.wallet.clock = func() int64 { return 500 }
	request := actionFixture(t, "spend")
	request.Grant.ID = grant.id
	request.Params = canonical(SpendParams{To: terms.Recipients[0], Amount: 50000, FeeLimit: 30000})
	if g2 {
		// The G2 admission clock guard keeps the service clock it was opened
		// with (the real clock), so the G2 request is created now.
		request.CreatedAt = time.Now().Unix()
	}
	envelope := actionEnvelope(t, request)
	if g2 {
		if service.PX1ServiceJournal() == nil || service.PX1Profile() == nil {
			t.Fatal("G2_PROFILE_FALLTHROUGH: the service layer stayed W2")
		}
		var halted SignedActionReceipt
		if e := json.Unmarshal(service.handle(context.Background(), envelope, PeerIdentity{UID: config.PeerUID}), &halted); e != nil {
			t.Fatal(e)
		}
		if halted.Receipt.Verdict != "refused" || halted.Receipt.Reason != "SERVICE_STATE_UNAVAILABLE" || halted.Receipt.Sequence != 0 || service.PX1ServiceJournal().Usage().LastSeq != 0 {
			t.Fatalf("G2_HALT_BEFORE_PASS: want SERVICE_STATE_UNAVAILABLE at journal_seq 0, got %+v", halted.Receipt)
		}
		if e := service.PX1Tick(context.Background()); e != nil {
			t.Fatal("observation pass", e)
		}
	}
	response := service.handle(context.Background(), envelope, PeerIdentity{UID: config.PeerUID})
	var receipt SignedActionReceipt
	if err := json.Unmarshal(response, &receipt); err != nil {
		t.Fatal(err)
	}
	if g2 {
		if receipt.Receipt.Verdict != "refused" || receipt.Receipt.Reason != CodeTermsVersionRequired {
			t.Fatalf("G2_PROFILE_BYPASS: attached G2 service did not refuse terms v1: %s", response)
		}
		// T14 on the wire: the canary spent out of band (hot wallet, own
		// node mempool); the next pass halts the service, and a spend with a
		// fresh nonce refuses FLOAT_CANARY_SPENT before admission.
		raw := text(t, core.rpc("agent", "createrawtransaction", []map[string]any{{"txid": operator.Canary.Outpoint.TxID, "vout": operator.Canary.Outpoint.Vout}}, map[string]any{text(t, core.rpc("agent", "getnewaddress", "", "legacy")): su.Coins(5000)}))
		// The 10000-atom canary alone cannot pay the relay floor; the wallet
		// adds a funding input and change.
		var funded struct {
			Hex string `json:"hex"`
		}
		if e := json.Unmarshal(core.rpc("agent", "fundrawtransaction", raw), &funded); e != nil {
			t.Fatal("canary spend funding", e)
		}
		var signed struct {
			Hex      string `json:"hex"`
			Complete bool   `json:"complete"`
		}
		if e := json.Unmarshal(core.rpc("agent", "signrawtransactionwithwallet", funded.Hex), &signed); e != nil || !signed.Complete {
			t.Fatal("canary spend signature", e)
		}
		core.rpc("", "sendrawtransaction", signed.Hex)
		seqBefore := service.PX1ServiceJournal().Usage().LastSeq
		if e := service.PX1Tick(context.Background()); e != nil {
			t.Logf("observation pass after the canary spend: %v", e)
		}
		request.Nonce = strings.Repeat("e", 32)
		var spent SignedActionReceipt
		if e := json.Unmarshal(service.handle(context.Background(), actionEnvelope(t, request), PeerIdentity{UID: config.PeerUID}), &spent); e != nil {
			t.Fatal(e)
		}
		if spent.Receipt.Verdict != "refused" || spent.Receipt.Reason != CodeFloatCanarySpent || spent.Receipt.Sequence != 0 || service.PX1ServiceJournal().Usage().LastSeq != seqBefore {
			t.Fatalf("T14_WIRE: want FLOAT_CANARY_SPENT at journal_seq 0, got %+v", spent.Receipt)
		}
		return
	}
	if receipt.Receipt.Verdict != "executed" {
		t.Fatalf("unexpected W2 result: %s", response)
	}
	var effect struct {
		TxID     string `json:"txid"`
		Reserved int64  `json:"reserved_sat"`
	}
	if err := json.Unmarshal(receipt.Receipt.Effect, &effect); err != nil {
		t.Fatal(err)
	}
	var transaction su.TransactionView
	if err := json.Unmarshal(core.rpc("", "getrawtransaction", effect.TxID, true), &transaction); err != nil || len(transaction.Vout) != 2 || int64(transaction.Vout[0].Value) != 50000 {
		t.Fatal("payment not observed in genuine Core", err)
	}
	t.Logf("W2 positive neighbour executed: amount=50000 reserved=%d txid=%s", effect.Reserved, effect.TxID)
}
