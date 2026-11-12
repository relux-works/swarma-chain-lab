package wallet

// Owner S2. Core layers of T3, T5, T8, T9 and T10 (G2-PAYMENT-EXECUTOR-v1
// §3.8, PX1-INTERFACES.md "Test ids") through the public G2 service: the
// production OpenActionService with a g2 block, the product journal v2 at both
// layers, the S3 runtime (first observation pass, tracker, status), the
// genuine K1 kernel and a genuine Namecoin Core 28 regtest node. Requests enter
// at ActionService.handle (steps 1-23); T5 also drives the socket.
//
// Test seams (no product flag): the executor clock is injected into the
// service clock guard, the S3 runtime and the wallet layer, so a test never
// depends on the wall clock or crosses a real UTC midnight; installedRead
// keeps its synthetic root-ownership seam. Each G2 service gets its own Core
// hot wallet, because the S3 startup reconciler refuses a hot wallet with
// sends its journal does not know (§3.4). Run each top-level test with a fresh
// root:
//
//	W1_REGTEST=1 W1_RUN_ROOT=FRESH_ABSOLUTE_DIRECTORY \
//	W1_CORE_CLI=ABSOLUTE_NAMECOIN_CLI W1_CORE_DAEMON=ABSOLUTE_NAMECOIND \
//	go test -count=1 -run '^TestPX1CoreS2$' -v .
//
// T9 is run as the test table says: go test -race -count=50 -run
// '^TestPX1CoreS2Race$' (each iteration starts its own node under W1_RUN_ROOT).

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// px1sClock is the injected executor clock. back steps the wallet layer's
// clock behind the service clock (the step-23 clock step back that leaves a
// broadcast reservation uncertain, TestPX1WalletClockStepBack's mechanism).
type px1sClock struct{ now, back atomic.Int64 }

func (c *px1sClock) service() int64 { return c.now.Load() }
func (c *px1sClock) wallet() int64  { return c.now.Load() - c.back.Load() }

// px1sService is one G2 service under test and its installed files.
type px1sService struct {
	l      *coreLab
	grant  px1CoreGrant
	config ServiceConfig
	clock  *px1sClock
	s      *ActionService
}

// px1sEffect is the spend effect of a service receipt.
type px1sEffect struct {
	TxID     string `json:"txid"`
	Reserved int64  `json:"reserved_sat"`
	Phase    string `json:"phase"`
}

// px1sCanary creates the lab's canary: one 10000-atom output held by a Core
// wallet that never spends, so no planner can select it.
func (l *coreLab) px1sCanary() CanaryConfig {
	l.t.Helper()
	l.rpc("", "createwallet", "canary", false, false, "", false, false)
	txid := text(l.t, l.rpc("issuer", "sendtoaddress", text(l.t, l.rpc("canary", "getnewaddress", "", "legacy")), su.Coins(10000)))
	l.mine(1)
	var view su.TransactionView
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", txid, true), &view); e != nil {
		l.t.Fatal(e)
	}
	for i, out := range view.Vout {
		if int64(out.Value) == 10000 {
			return CanaryConfig{Outpoint: su.Point{TxID: txid, Vout: uint32(i)}, ValueSat: 10000}
		}
	}
	l.t.Fatal("canary output")
	return CanaryConfig{}
}

// px1sTerms are the regtest allow-mode terms with the given caps.
func px1sTerms(spend, transfer, day int64, count int) []byte {
	t := px1RegtestTerms()
	t.SpendCap, t.TransferCap, t.DayCap, t.DayCountCap = spend, transfer, day, count
	return canonical(t)
}

// px1sIssue issues a v3 standing pay grant (terms v2 bytes by contract_sha256)
// to grantee testKey(grantee), the px1IssueGrant construction with two
// parameters added: the grantee and the Core hot wallet. A non-empty hotWallet
// is created fresh (no sends) and funded with `coins` confirmed 1-NMC P2PKH
// coins; the window is [l.now-100, l.now+500).
func (l *coreLab) px1sIssue(terms []byte, budget int64, coins int, grantee byte, hotWallet string) px1CoreGrant {
	l.t.Helper()
	l.px1RenewNames()
	l.counter++
	id := fmt.Sprintf("%03d", l.counter)
	root := filepath.Join(l.root, "wallet-"+id)
	kernel := filepath.Join(l.root, "kernel-"+id)
	objects := filepath.Join(l.root, "objects-"+id)
	for _, p := range []string{root, kernel, objects} {
		if e := os.Mkdir(p, 0700); e != nil {
			l.t.Fatal(e)
		}
	}
	_, issuer := testKey(1)
	_, granteeKey := testKey(grantee)
	sealID := text(l.t, l.rpc("issuer", "sendtoaddress", testAddress(1), su.Coins(1000000)))
	l.mine(1)
	var tx su.TransactionView
	if json.Unmarshal(l.rpc("", "getrawtransaction", sealID, true), &tx) != nil {
		l.t.Fatal("seal transaction")
	}
	script, _ := rental.GrantSealScript(issuer)
	var seal rental.Point
	for _, o := range tx.Vout {
		if o.Script.Hex == script && int64(o.Value) == 1000000 {
			seal = rental.Point{TxID: sealID, Vout: o.N}
		}
	}
	if seal.TxID == "" {
		l.t.Fatal("seal absent")
	}
	l.rpc("issuer", "lockunspent", false, []rental.Point{seal})
	now := l.now
	c := rental.Grant{Version: 3, Network: "regtest", Genesis: su.RegtestGenesis, AgentName: l.agent, LandlordName: "id/wallet-landlord-test", IssuerKey: issuer, GranteeKey: granteeKey, ContractSHA256: Hash(terms), Scope: []string{"pay"}, NotBefore: now - 100, NotAfter: now + 500, Seal: seal, Budget: &budget}
	consent := Event{Pubkey: granteeKey, CreatedAt: now - 101, Kind: 8181, Tags: [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", c.ContractSHA256}, {"booking", Hash([]byte("px1s-" + id))}, {"privacy", Hash([]byte("privacy"))}}, Content: ""}
	consent.ID = consent.Digest()
	consent.Sig = signDigest(l.t, consent.ID, grantee)
	var event rental.Event
	json.Unmarshal(canonical(consent), &event)
	c.Consent = rental.GrantConsent{ContractSHA256: c.ContractSHA256, ConsentEvent: event, LandlordSig: signDigest(l.t, c.ContractSHA256, 1)}
	signingHash, e := c.SigningHash()
	if e != nil {
		l.t.Fatal(e)
	}
	raw := l.issueProof(rental.SignedGrant{Grant: c, Signature: signDigest(l.t, signingHash, 1)})
	change := testAddress(6)
	if hotWallet != "" {
		l.rpc("", "createwallet", hotWallet, false, false, "", false, false)
		change = text(l.t, l.rpc(hotWallet, "getnewaddress", "", "legacy"))
		for i := 0; i < coins; i++ {
			l.rpc("issuer", "sendtoaddress", text(l.t, l.rpc(hotWallet, "getnewaddress", "", "legacy")), su.Coins(100000000))
		}
		l.mine(1)
	}
	config := Config{Version: 1, Network: "regtest", Genesis: su.RegtestGenesis, Policy: rental.Policy{ConstructionProfile: su.WitnessProfile, Network: "regtest", Genesis: su.RegtestGenesis, AgentName: l.agent, LandlordName: "id/wallet-landlord-test", SealScript: script, StateDir: kernel}, Observer: l.routes["w3-observer"], Wallet: WalletRoute{Route: l.routes["w1-wallet"], Wallet: hotWallet}, Broadcast: l.routes["w1-broadcast"], StateDir: root, ObjectsDir: objects, ChangeAddress: change, FeeRate: 110, WalletDir: filepath.Join(l.private, "regtest/wallets", hotWallet), MemoryZone: filepath.Join(l.root, "memory")}
	return px1CoreGrant{raw: raw, terms: terms, config: config, seal: seal, id: grantID(l.t, raw)}
}

// px1sInstallObjects writes grant g's presentation and terms bytes into the
// object directory of config c (hash-addressed, as LoadGrant/LoadTerms read).
func px1sInstallObjects(t *testing.T, c Config, g px1CoreGrant) {
	t.Helper()
	for name, b := range map[string][]byte{g.id: g.raw, Hash(g.terms): g.terms} {
		if e := os.WriteFile(filepath.Join(c.ObjectsDir, name+".json"), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
}

// px1sInstall provisions the installed files of a G2 service for grant g
// (wallet config, receipt key testKey(9), objects, canary in the operator
// block) and returns it unopened. peerUID is the configured peer.
func (l *coreLab) px1sInstall(g px1CoreGrant, canary CanaryConfig, peerUID uint32, clock *px1sClock) *px1sService {
	l.t.Helper()
	root := filepath.Join(l.root, "svc-"+g.id[:12])
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(root, name)
		if e := os.MkdirAll(p, mode); e != nil {
			l.t.Fatal(e)
		}
		if e := os.Chmod(p, mode); e != nil {
			l.t.Fatal(e)
		}
		return p
	}
	// The socket directory is short (AF_UNIX paths stop at 108 bytes, and a
	// plant root nests the lab deeply); only T5 binds it.
	runtime, e := os.MkdirTemp("", "px1s-")
	if e != nil {
		l.t.Fatal(e)
	}
	l.t.Cleanup(func() { os.RemoveAll(runtime) })
	if e = os.Chmod(runtime, 0750); e != nil {
		l.t.Fatal(e)
	}
	state := mk("state", 0700)
	installed := mk("inst", 0750)
	configPath := filepath.Join(installed, "wallet.json")
	keyPath := filepath.Join(installed, "receipt.key")
	writeInstalled(l.t, configPath, canonical(g.config))
	key, _ := testKey(9)
	writeInstalled(l.t, keyPath, []byte(hex.EncodeToString(key.Serialize())))
	px1sInstallObjects(l.t, g.config, g)
	op := px1Operator()
	op.Canary = canary
	_, grantee := testKey(2)
	config := ServiceConfig{Network: "regtest", Genesis: su.RegtestGenesis, Version: 1, Service: WalletServiceID, Socket: filepath.Join(runtime, "w.sock"), SocketGID: uint32(os.Getgid()), PeerUID: peerUID, Grantee: grantee, SkewSeconds: 60, TimeoutSeconds: 2, StateDir: state, WalletConfig: configPath, ReceiptKeyFile: keyPath, G2: &op}
	return &px1sService{l: l, grant: g, config: config, clock: clock}
}

// open starts the service from its installed files (a restart when state
// exists), injects the clock and runs the first S3 observation pass (startup
// reconciliation, canary unspent), which lifts the before-first-pass halt.
// A failed pass fails the test.
func (p *px1sService) open(t *testing.T) {
	t.Helper()
	if e := p.openPass(t); e != nil {
		p.close()
		t.Fatal("first observation pass", e)
	}
}

// openPass is open that returns the first observation pass's error instead
// of failing, so a caller can report it under its own marker after the
// checks that do not depend on the pass.
func (p *px1sService) openPass(t *testing.T) error {
	t.Helper()
	s, e := OpenActionService(p.config)
	if e != nil {
		t.Fatal("G2 service open", e)
	}
	if s.g2 == nil || s.wallet.PX1Journal() == nil {
		s.Close()
		t.Fatal("G2_PROFILE_FALLTHROUGH")
	}
	s.clock = p.clock.service
	s.wallet.clock = p.clock.wallet
	guard, e := NewClockGuard(p.clock.service, s.g2.journal.Usage().LastTime)
	if e != nil {
		s.Close()
		t.Fatal("clock guard", e)
	}
	s.g2.clock = guard
	p.s = s
	t.Cleanup(p.close)
	return s.PX1Tick(context.Background())
}

func (p *px1sService) close() {
	if p.s != nil {
		p.s.Close()
		p.s = nil
	}
}

// restart closes and reopens the service on the same durable state.
func (p *px1sService) restart(t *testing.T) {
	t.Helper()
	p.close()
	p.open(t)
}

// request is a spend request of the configured grantee for grant p.grant,
// created at the injected clock.
func (p *px1sService) request(nonce int, amount, feeLimit int64) ActionRequest {
	r := actionFixture(p.l.t, "spend")
	r.Grant.ID = p.grant.id
	r.Nonce = fmt.Sprintf("%032x", nonce)
	r.CreatedAt = p.clock.now.Load()
	r.Params = canonical(SpendParams{To: px1RegtestTerms().Recipients[0], Amount: amount, FeeLimit: feeLimit})
	return r
}

// px1sEnvelope signs r with testKey(signer).
func px1sEnvelope(t *testing.T, r ActionRequest, signer byte) []byte {
	t.Helper()
	return canonical(ActionEnvelope{Request: r, Signature: signDigest(t, ActionDigest(r), signer)})
}

// send hands raw to the service as the configured peer.
func (p *px1sService) send(t *testing.T, raw []byte) (ActionReceipt, []byte) {
	t.Helper()
	return px1sSendAs(t, p.s, raw, p.config.PeerUID)
}

func px1sSendAs(t *testing.T, s *ActionService, raw []byte, uid uint32) (ActionReceipt, []byte) {
	t.Helper()
	out := s.handle(context.Background(), raw, PeerIdentity{UID: uid})
	var r SignedActionReceipt
	if e := json.Unmarshal(out, &r); e != nil {
		t.Fatal("receipt", e)
	}
	return r.Receipt, out
}

func px1sEffectOf(t *testing.T, r ActionReceipt) px1sEffect {
	t.Helper()
	var e px1sEffect
	if err := json.Unmarshal(r.Effect, &e); err != nil {
		t.Fatal("effect", err)
	}
	return e
}

// seqs is the last Seq of the service and wallet journals.
func (p *px1sService) seqs() [2]uint64 {
	return [2]uint64{p.s.PX1ServiceJournal().Usage().LastSeq, p.s.wallet.PX1Journal().Usage().LastSeq}
}

// records lists a journal's records.
func px1sRecords(t *testing.T, j JournalV2) []JournalRecordV2 {
	t.Helper()
	var out []JournalRecordV2
	if e := j.Iterate(1, func(r JournalRecordV2) error { out = append(out, r); return nil }); e != nil {
		t.Fatal("iterate", e)
	}
	return out
}

func px1sKinds(rs []JournalRecordV2) map[string]int {
	m := map[string]int{}
	for _, r := range rs {
		m[r.Kind]++
	}
	return m
}

func (p *px1sService) ledger(t *testing.T) LedgerView {
	t.Helper()
	l, e := p.s.wallet.PX1Ledger()
	if e != nil {
		t.Fatal("ledger", e)
	}
	return l
}

// sends is the number of distinct transactions the service's Core hot wallet
// sent (one "send" row per external output; the config change address is a
// receive address, so a payment lists two send rows).
func (p *px1sService) sends(t *testing.T) int {
	t.Helper()
	var rows []struct {
		Category string `json:"category"`
		TxID     string `json:"txid"`
	}
	if e := json.Unmarshal(p.l.rpc(p.grant.config.Wallet.Wallet, "listtransactions", "*", 1000, 0, false), &rows); e != nil {
		t.Fatal(e)
	}
	ids := map[string]bool{}
	for _, r := range rows {
		if r.Category == "send" {
			ids[r.TxID] = true
		}
	}
	return len(ids)
}

// inMempool reports whether txid is in the node's mempool.
func (l *coreLab) px1sInMempool(txid string) bool {
	var ids []string
	if json.Unmarshal(l.rpc("", "getrawmempool"), &ids) != nil {
		l.t.Fatal("mempool")
	}
	return slices.Contains(ids, txid)
}

// px1sStep runs f as a subtest with the lab bound to it.
func px1sStep(t *testing.T, l *coreLab, name string, f func(t *testing.T)) {
	t.Run(name, func(st *testing.T) {
		prev := l.t
		l.t = st
		defer func() { l.t = prev }()
		f(st)
	})
}

// Claim: the S2 Core layers of T3, T5 and T8 run on one genuine regtest node through the public G2 service; each step states its own claim beside its valid neighbour.
func TestPX1CoreS2(t *testing.T) {
	l := newPX1Core(t)
	canary := l.px1sCanary()
	peer := uint32(os.Getuid() + 1)

	// Claim (T3, Core): with day_cap 120000 and an uncertain 40000 reservation (broadcast, then the step-23 clock step back), one atom over the day cap refuses DAY_CAP_EXCEEDED post-plan with no record and no broadcast while the exact fill executes; a request one second before UTC midnight still refuses; at midnight the uncertain reservation is still charged in the new day (one atom over refuses again) and the exact remainder executes. With day_count_cap 2 the third spend refuses DAY_COUNT_EXCEEDED and the same spend executes after midnight.
	px1sStep(t, l, "T3-day-buckets", func(t *testing.T) {
		real := time.Now().Unix()
		midnight := (real/86400 + 1) * 86400
		l.now = midnight - 200
		clock := &px1sClock{}
		clock.now.Store(midnight - 200)
		g := l.px1sIssue(px1sTerms(500000, 100000, 120000, 3), 500000, 4, 2, "s2-t3")
		p := l.px1sInstall(g, canary, peer, clock)
		p.open(t)
		day := UTCDay(midnight - 200)
		next := UTCDay(midnight)
		fee := l.px1sQuoteFee(g.config, px1RegtestTerms().Recipients[0], 40000)
		// The uncertain reservation: broadcast, then the wallet clock steps
		// back one second before the complete record (CLOCK_ROLLBACK).
		p.s.wallet.hook = func(stage string) {
			if stage == "after-broadcast" {
				clock.back.Store(1)
			}
		}
		u, _ := p.send(t, px1sEnvelope(t, p.request(1, 40000-fee, fee), 2))
		p.s.wallet.hook = nil
		clock.back.Store(0)
		ue := px1sEffectOf(t, u)
		if u.Verdict != "uncertain" || ue.Reserved != 40000 || !l.px1sInMempool(ue.TxID) {
			t.Fatalf("T3 uncertain fixture: %+v %+v", u, ue)
		}
		if used, n := p.ledger(t).DayUsage(g.id, day); used != 40000 || n != 1 || p.ledger(t).UncertainSat(g.id) != 40000 {
			t.Fatalf("T3 uncertain charge: used=%d count=%d", used, n)
		}
		before, sends := p.seqs(), p.sends(t)
		over, _ := p.send(t, px1sEnvelope(t, p.request(2, 80000-fee+1, fee), 2))
		if over.Verdict != "refused" || over.Reason != CodeDayCapExceeded || p.seqs()[1] != before[1] || p.sends(t) != sends {
			t.Fatalf("T3 one atom over the day cap: %+v", over)
		}
		exact, _ := p.send(t, px1sEnvelope(t, p.request(3, 80000-fee, fee), 2))
		if exact.Verdict != "executed" || px1sEffectOf(t, exact).Reserved != 80000 {
			t.Fatalf("T3 exact fill neighbour: %+v", exact)
		}
		if used, n := p.ledger(t).DayUsage(g.id, day); used != 120000 || n != 2 {
			t.Fatalf("T3 day bucket after fill: used=%d count=%d", used, n)
		}
		clock.now.Store(midnight - 1)
		late, _ := p.send(t, px1sEnvelope(t, p.request(4, 10000, fee), 2))
		if late.Reason != CodeDayCapExceeded {
			t.Fatalf("T3 rollover before midnight: %+v", late)
		}
		clock.now.Store(midnight)
		if used, n := p.ledger(t).DayUsage(g.id, next); used != 40000 || n != 1 {
			t.Fatalf("T3 uncertain not carried into %s: used=%d count=%d", next, used, n)
		}
		carried, _ := p.send(t, px1sEnvelope(t, p.request(5, 80000-fee+1, fee), 2))
		if carried.Reason != CodeDayCapExceeded {
			t.Fatalf("T3 uncertain must stay charged after rollover: %+v", carried)
		}
		after, _ := p.send(t, px1sEnvelope(t, p.request(6, 80000-fee, fee), 2))
		if after.Verdict != "executed" {
			t.Fatalf("T3 rollover neighbour: %+v", after)
		}
		if used, n := p.ledger(t).DayUsage(g.id, next); used != 120000 || n != 2 {
			t.Fatalf("T3 new day bucket: used=%d count=%d", used, n)
		}
		p.close()
		// Day count cap 2 on a second grant, same clock scheme.
		l.now = midnight - 200
		cc := &px1sClock{}
		cc.now.Store(midnight - 100)
		gc := l.px1sIssue(px1sTerms(500000, 100000, 300000, 2), 500000, 4, 2, "s2-t3c")
		pc := l.px1sInstall(gc, canary, peer, cc)
		pc.open(t)
		for i := 1; i <= 2; i++ {
			if r, _ := pc.send(t, px1sEnvelope(t, pc.request(i, 20000, fee), 2)); r.Verdict != "executed" {
				t.Fatalf("T3 count %d: %+v", i, r)
			}
		}
		seq := pc.seqs()[1]
		third := pc.request(3, 20000, fee)
		if r, _ := pc.send(t, px1sEnvelope(t, third, 2)); r.Reason != CodeDayCountExceeded || pc.seqs()[1] != seq {
			t.Fatalf("T3 day count: %+v", r)
		}
		cc.now.Store(midnight)
		if r, _ := pc.send(t, px1sEnvelope(t, pc.request(4, 20000, fee), 2)); r.Verdict != "executed" {
			t.Fatalf("T3 day count after rollover: %+v", r)
		}
		l.mine(1)
	})

	// Claim (T5, Core): a request signed by another key refuses GRANTEE_MISMATCH and a grant naming another grantee refuses GRANT_GRANTEE_MISMATCH, neither with a wallet record or a broadcast (the first not even admitted); a peer with another UID gets a silent close on the socket and a SERVICE_PEER refusal at the handler, nothing journaled; the same signed request from the configured peer executes. Limit: configuration validation refuses a peer UID equal to the service UID (Q9), so the configured peer cannot dial the socket from this process; its neighbour enters at the handler.
	px1sStep(t, l, "T5-grantee", func(t *testing.T) {
		l.now = time.Now().Unix() - 1000
		clock := &px1sClock{}
		clock.now.Store(l.now)
		g := l.px1sIssue(px1sTerms(500000, 100000, 300000, 5), 500000, 2, 2, "s2-t5")
		other := l.px1sIssue(px1sTerms(500000, 100000, 300000, 5), 500000, 0, 4, "s2-t5o")
		px1sInstallObjects(t, g.config, other)
		// The socket's kernel peer check first: a service (own state, unfunded
		// hot wallet, grant g installed) configured for a UID this process
		// does not have.
		gw := l.px1sIssue(px1sTerms(500000, 100000, 300000, 5), 500000, 0, 2, "s2-t5w")
		px1sInstallObjects(t, gw.config, g)
		wrong := l.px1sInstall(gw, canary, uint32(os.Getuid()+1), clock)
		wrong.open(t)
		request := wrong.request(1, 50000, 30000)
		request.Grant.ID = g.id
		raw := px1sEnvelope(t, request, 2)
		stop := runExistingSocket(t, wrong.s)
		c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: wrong.config.Socket, Net: "unix"})
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		writeActionFrame(c, raw)
		reply, e := io.ReadAll(c)
		c.Close()
		if len(reply) != 0 || (e != nil && !errors.Is(e, io.EOF) && !strings.Contains(e.Error(), "reset")) {
			t.Fatalf("T5 wrong peer: want a silent close, got %d bytes (%v)", len(reply), e)
		}
		if seqs := wrong.seqs(); seqs != [2]uint64{0, 0} {
			t.Fatalf("T5 wrong peer journaled: %v", seqs)
		}
		// The handler's own peer check (defence in depth) refuses SERVICE_PEER.
		if r, _ := px1sSendAs(t, wrong.s, raw, uint32(os.Getuid()+2)); r.Reason != "SERVICE_PEER" || r.Sequence != 0 || wrong.seqs() != [2]uint64{0, 0} {
			t.Fatalf("T5 handler peer: %+v", r)
		}
		stop()
		wrong.s = nil
		// The service of grant g. Configuration validation refuses a peer UID
		// equal to the service's own (Q9), so the configured peer is another
		// UID and the positive neighbour enters at the handler as that peer.
		p := l.px1sInstall(g, canary, peer, clock)
		p.open(t)
		sends := p.sends(t)
		_, foreign := testKey(4)
		forged := p.request(2, 50000, 30000)
		forged.Grantee = foreign
		if r, _ := p.send(t, px1sEnvelope(t, forged, 4)); r.Verdict != "refused" || r.Reason != "GRANTEE_MISMATCH" || r.Sequence != 0 || p.seqs() != [2]uint64{0, 0} {
			t.Fatalf("T5 request of another grantee: %+v seqs=%v", r, p.seqs())
		}
		cross := p.request(3, 50000, 30000)
		cross.Grant.ID = other.id
		r, _ := p.send(t, px1sEnvelope(t, cross, 2))
		svc := px1sKinds(px1sRecords(t, p.s.PX1ServiceJournal()))
		if r.Verdict != "refused" || r.Reason != "GRANT_GRANTEE_MISMATCH" || r.Sequence != 1 || svc[RecordAdmit] != 1 || svc[RecordTerminal] != 1 || p.seqs()[1] != 0 || p.sends(t) != sends {
			t.Fatalf("T5 grant of another grantee: %+v service=%v wallet=%d", r, svc, p.seqs()[1])
		}
		ok, _ := p.send(t, raw)
		if ok.Verdict != "executed" || !l.px1sInMempool(px1sEffectOf(t, ok).TxID) {
			t.Fatalf("T5 configured peer neighbour: %+v", ok)
		}
		l.mine(1)
	})

	// Claim (T8, Core): a replay of an executed request returns the stored receipt byte-identically with no record and no broadcast, before and after a restart; the same nonce with other bytes refuses NONCE_CONFLICT with nothing written; after the spend that exhausts the total budget exactly (it executes), a new nonce refuses TOTAL_BUDGET_EXCEEDED with no wallet record and no broadcast.
	px1sStep(t, l, "T8-replay", func(t *testing.T) {
		l.now = time.Now().Unix() - 1000
		clock := &px1sClock{}
		clock.now.Store(l.now)
		g := l.px1sIssue(px1sTerms(100000, 100000, 100000, 5), 100000, 3, 2, "s2-t8")
		p := l.px1sInstall(g, canary, peer, clock)
		p.open(t)
		fee := l.px1sQuoteFee(g.config, px1RegtestTerms().Recipients[0], 50000)
		first := p.request(1, 50000-fee, fee)
		raw := px1sEnvelope(t, first, 2)
		r1, b1 := p.send(t, raw)
		if r1.Verdict != "executed" || px1sEffectOf(t, r1).Reserved != 50000 {
			t.Fatalf("T8 first spend: %+v", r1)
		}
		seqs, sends := p.seqs(), p.sends(t)
		if _, b := p.send(t, raw); string(b) != string(b1) || p.seqs() != seqs || p.sends(t) != sends {
			t.Fatal("T8 replay after success: not the stored receipt, or an effect")
		}
		conflict := first
		conflict.Params = canonical(SpendParams{To: px1RegtestTerms().Recipients[0], Amount: 50000 - fee - 1, FeeLimit: fee})
		if r, _ := p.send(t, px1sEnvelope(t, conflict, 2)); r.Reason != "NONCE_CONFLICT" || r.Sequence != 0 || p.seqs() != seqs || p.sends(t) != sends {
			t.Fatalf("T8 same nonce, other bytes: %+v", r)
		}
		p.restart(t)
		if _, b := p.send(t, raw); string(b) != string(b1) || p.seqs() != seqs || p.sends(t) != sends {
			t.Fatal("T8 replay after restart: not the stored receipt, or an effect")
		}
		if r, _ := p.send(t, px1sEnvelope(t, p.request(2, 50000-fee, fee), 2)); r.Verdict != "executed" {
			t.Fatalf("T8 exhausting neighbour: %+v", r)
		}
		seqs, sends = p.seqs(), p.sends(t)
		if r, _ := p.send(t, px1sEnvelope(t, p.request(3, 546, fee), 2)); r.Reason != CodeTotalBudgetExceeded || p.seqs()[1] != seqs[1] || p.sends(t) != sends {
			t.Fatalf("T8 new nonce after exhaustion: %+v", r)
		}
		if p.ledger(t).SpendUsed(g.id) != 100000 {
			t.Fatal("T8 ledger after exhaustion")
		}
		l.mine(1)
	})
}

// px1sRaceRun numbers TestPX1CoreS2Race iterations (go test -count=N reruns
// the function in one process); each iteration gets a fresh node root.
var px1sRaceRun atomic.Int64

// Claim (T9, Core, race): 32 parallel distinct-nonce spends of 60000 atoms each (fee-inclusive) against day_cap 300000 execute exactly 5 times, every other request refuses DAY_CAP_EXCEEDED, the wallet journal holds exactly 5 reserve and 5 complete records on distinct inputs, the fold charges exactly 300000 in the day (count 5), and each executed txid is in the mempool once; 2 parallel requests with one nonce and different bytes give exactly one executed and one NONCE_CONFLICT with one admit and one wallet reservation, and 2 parallel identical requests give byte-identical receipts and one transaction. Run with -race -count=50; the assertions do not depend on the interleaving.
func TestPX1CoreS2Race(t *testing.T) {
	if os.Getenv("W1_REGTEST") == "1" {
		parent := os.Getenv("W1_RUN_ROOT")
		if !filepath.IsAbs(parent) {
			t.Fatal("absolute W1_RUN_ROOT required")
		}
		if e := os.MkdirAll(parent, 0700); e != nil {
			t.Fatal(e)
		}
		root := filepath.Join(parent, fmt.Sprintf("run-%03d", px1sRaceRun.Add(1)))
		t.Setenv("W1_RUN_ROOT", root)
		// Registered before the node's own cleanup, so it runs after the node
		// stopped; a failed iteration keeps its root for diagnosis.
		t.Cleanup(func() {
			if !t.Failed() {
				os.RemoveAll(root)
			}
		})
	}
	l := newPX1Core(t)
	canary := l.px1sCanary()
	peer := uint32(os.Getuid() + 1)
	l.now = time.Now().Unix() - 1000
	clock := &px1sClock{}
	clock.now.Store(l.now)
	g := l.px1sIssue(px1sTerms(500000, 100000, 300000, 10), 500000, 7, 2, "s2-t9")
	p := l.px1sInstall(g, canary, peer, clock)
	p.open(t)
	fee := l.px1sQuoteFee(g.config, px1RegtestTerms().Recipients[0], 50000)
	const parallel, cost, dayCap = 32, int64(60000), int64(300000)
	want := int(dayCap / cost)
	raws := make([][]byte, parallel)
	for i := range raws {
		raws[i] = px1sEnvelope(t, p.request(100+i, cost-fee, fee), 2)
	}
	receipts := make([]ActionReceipt, parallel)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range raws {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			out := p.s.handle(context.Background(), raws[i], PeerIdentity{UID: peer})
			var r SignedActionReceipt
			if json.Unmarshal(out, &r) == nil {
				receipts[i] = r.Receipt
			}
		}(i)
	}
	close(start)
	wg.Wait()
	executed, txids := 0, map[string]bool{}
	for i, r := range receipts {
		switch {
		case r.Verdict == "executed":
			executed++
			e := px1sEffectOf(t, r)
			if e.Reserved != cost || txids[e.TxID] || !l.px1sInMempool(e.TxID) {
				t.Fatalf("T9_RACE executed %d: %+v", i, e)
			}
			txids[e.TxID] = true
		case r.Verdict == "refused" && r.Reason == CodeDayCapExceeded:
		default:
			t.Fatalf("T9_RACE request %d: want executed or %s, got %+v", i, CodeDayCapExceeded, r)
		}
	}
	if executed != want {
		t.Fatalf("T9_RACE day cap overshoot: want exactly %d executed, got %d", want, executed)
	}
	wallet := px1sRecords(t, p.s.wallet.PX1Journal())
	kinds := px1sKinds(wallet)
	inputs := map[su.Point]bool{}
	for _, r := range wallet {
		if r.Kind != RecordReserve {
			continue
		}
		for _, in := range r.Inputs {
			if inputs[in] {
				t.Fatalf("T9_RACE input reserved twice: %v", in)
			}
			inputs[in] = true
		}
		if !txids[r.TxID] {
			t.Fatalf("T9_RACE reservation without an executed receipt: %s", r.TxID)
		}
	}
	service := px1sKinds(px1sRecords(t, p.s.PX1ServiceJournal()))
	if len(wallet) != 2*want || kinds[RecordReserve] != want || kinds[RecordComplete] != want || service[RecordAdmit] != parallel || service[RecordServiceReserve] != want || service[RecordTerminal] != parallel {
		t.Fatalf("T9_RACE journals disagree: wallet=%v service=%v", kinds, service)
	}
	used, count := p.ledger(t).DayUsage(g.id, UTCDay(clock.now.Load()))
	if used != int64(want)*cost || count != want || p.ledger(t).SpendUsed(g.id) != int64(want)*cost || p.sends(t) != want {
		t.Fatalf("T9_RACE ledger: used=%d count=%d spend=%d sends=%d", used, count, p.ledger(t).SpendUsed(g.id), p.sends(t))
	}
	p.close()

	// Same nonce on a fresh grant: different bytes, then identical bytes.
	gn := l.px1sIssue(px1sTerms(500000, 100000, 300000, 10), 500000, 3, 2, "s2-t9n")
	pn := l.px1sInstall(gn, canary, peer, clock)
	pn.open(t)
	pair := func(a, b []byte) [2][]byte {
		var out [2][]byte
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i, raw := range [][]byte{a, b} {
			wg.Add(1)
			go func(i int, raw []byte) {
				defer wg.Done()
				<-start
				out[i] = pn.s.handle(context.Background(), raw, PeerIdentity{UID: peer})
			}(i, raw)
		}
		close(start)
		wg.Wait()
		return out
	}
	x := pn.request(7, 20000, fee)
	y := x
	y.Params = canonical(SpendParams{To: px1RegtestTerms().Recipients[0], Amount: 20001, FeeLimit: fee})
	out := pair(px1sEnvelope(t, x, 2), px1sEnvelope(t, y, 2))
	verdicts := []string{}
	for _, b := range out {
		var r SignedActionReceipt
		if e := json.Unmarshal(b, &r); e != nil {
			t.Fatal(e)
		}
		verdicts = append(verdicts, r.Receipt.Verdict+"/"+r.Receipt.Reason)
	}
	slices.Sort(verdicts)
	svc := px1sKinds(px1sRecords(t, pn.s.PX1ServiceJournal()))
	wk := px1sKinds(px1sRecords(t, pn.s.wallet.PX1Journal()))
	if verdicts[0] != "executed/EXECUTED" || verdicts[1] != "refused/NONCE_CONFLICT" || svc[RecordAdmit] != 1 || svc[RecordTerminal] != 1 || wk[RecordReserve] != 1 || pn.sends(t) != 1 {
		t.Fatalf("T9_RACE same nonce, other bytes: %v service=%v wallet=%v", verdicts, svc, wk)
	}
	same := px1sEnvelope(t, pn.request(8, 20000, fee), 2)
	out = pair(same, same)
	var r SignedActionReceipt
	if e := json.Unmarshal(out[0], &r); e != nil || string(out[0]) != string(out[1]) || r.Receipt.Verdict != "executed" {
		t.Fatalf("T9_RACE same nonce, same bytes: %s | %s", out[0], out[1])
	}
	svc = px1sKinds(px1sRecords(t, pn.s.PX1ServiceJournal()))
	wk = px1sKinds(px1sRecords(t, pn.s.wallet.PX1Journal()))
	if svc[RecordAdmit] != 2 || wk[RecordReserve] != 2 || pn.sends(t) != 2 {
		t.Fatalf("T9_RACE same nonce, same bytes wrote twice: service=%v wallet=%v", svc, wk)
	}
}

// px1sCrashFixture is what the T10 child process needs to serve one request.
type px1sCrashFixture struct {
	Service  ServiceConfig `json:"service"`
	Stage    string        `json:"stage"`
	Now      int64         `json:"now"`
	Envelope []byte        `json:"envelope"`
}

// Child-only process for T10: it opens the G2 service from installed files,
// runs the first observation pass and serves one spend; at the named stage it
// is killed with SIGKILL (no deferred code, no flush). Without
// PX1_T10_CHILD it skips; no production variable or flag installs the hook.
func TestPX1T10Child(t *testing.T) {
	path := os.Getenv("PX1_T10_CHILD")
	if path == "" {
		t.Skip("T10 crash child process only")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("fixture")
	}
	var f px1sCrashFixture
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal("fixture schema")
	}
	clock := &px1sClock{}
	clock.now.Store(f.Now)
	p := &px1sService{l: &coreLab{t: t}, config: f.Service, clock: clock}
	p.open(t)
	kill := func(stage string) {
		if stage == f.Stage {
			syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
	}
	switch f.Stage {
	case "after-service-reservation":
		p.s.hook = kill
	case "after-reservation", "after-broadcast":
		p.s.wallet.hook = kill
	default:
		t.Fatal("stage")
	}
	out := p.s.handle(context.Background(), f.Envelope, PeerIdentity{UID: f.Service.PeerUID})
	os.WriteFile(path+".reply", out, 0600)
	os.Exit(3) // the crash point was not reached
}

// Claim (T10, Core subprocess): a real process killed (SIGKILL) after the wallet reservation, after the service reservation, or after the broadcast leaves a retained debit; after a restart the replay answers uncertain DURABLE_RESERVATION_NO_RETRY and then byte-identically, never broadcasts again, and the status shows the debit as uncertain. A crash before the broadcast leaves no transaction: the tracker marks it conflicted and one operator release (receipt-key signed, evidence absent) frees it exactly once, a second release refuses. A crash after the broadcast leaves exactly the planned transaction: the tracker later shows it confirmed while it stays uncertain (debit retained, nothing released). Each crash point has its valid neighbour: the same request with no crash executes, completes and is tracked confirmed.
func TestPX1CoreS2Crash(t *testing.T) {
	l := newPX1Core(t)
	canary := l.px1sCanary()
	peer := uint32(os.Getuid() + 1)
	for i, stage := range []string{"after-reservation", "after-service-reservation", "after-broadcast"} {
		px1sStep(t, l, stage, func(t *testing.T) {
			l.now = time.Now().Unix() - 3000
			clock := &px1sClock{}
			clock.now.Store(l.now)
			g := l.px1sIssue(px1sTerms(500000, 100000, 300000, 5), 500000, 2, 2, fmt.Sprintf("s2-t10-%d", i))
			p := l.px1sInstall(g, canary, peer, clock)
			fee := l.px1sQuoteFee(g.config, px1RegtestTerms().Recipients[0], 50000)
			request := p.request(1, 50000-fee, fee)
			raw := px1sEnvelope(t, request, 2)
			fixture := filepath.Join(l.root, fmt.Sprintf("t10-%d.json", i))
			if e := os.WriteFile(fixture, canonical(px1sCrashFixture{Service: p.config, Stage: stage, Now: clock.now.Load(), Envelope: raw}), 0600); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestPX1T10Child$", "-test.count=1")
			cmd.Env = append(os.Environ(), "PX1_T10_CHILD="+fixture)
			log, _ := os.Create(fixture + ".log")
			cmd.Stdout, cmd.Stderr = log, log
			e := cmd.Run()
			log.Close()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || !exit.Sys().(syscall.WaitStatus).Signaled() || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("T10 %s: the child was not killed at the crash point: %v (see %s.log)", stage, e, fixture)
			}
			// Restart on the crashed state. The S2 checks below do not depend on
			// the observation pass; its error is reported under its own marker.
			pass := p.openPass(t)
			if pass != nil && p.s.px1oHalted() != "" {
				t.Fatalf("T10 %s: restarted service halted after the first pass: %v / %s", stage, pass, p.s.px1oHalted())
			}
			wallet := px1sRecords(t, p.s.wallet.PX1Journal())
			if len(wallet) != 1 || wallet[0].Kind != RecordReserve || wallet[0].Reserved != 50000 {
				t.Fatalf("T10 %s: wallet journal after the crash: %+v", stage, wallet)
			}
			reserve := wallet[0]
			broadcast := stage == "after-broadcast"
			if l.px1sInMempool(reserve.TxID) != broadcast || p.sends(t) != map[bool]int{false: 0, true: 1}[broadcast] {
				t.Fatalf("T10 %s: broadcast state after the crash", stage)
			}
			wantService := map[string]int{RecordAdmit: 1}
			if stage != "after-reservation" {
				wantService[RecordServiceReserve] = 1
			}
			if got := px1sKinds(px1sRecords(t, p.s.PX1ServiceJournal())); !mapsEqual(got, wantService) {
				t.Fatalf("T10 %s: service journal after the crash: %v", stage, got)
			}
			// The replay after the restart: uncertain, never re-sent.
			r, first := p.send(t, raw)
			if r.Verdict != "uncertain" || r.Reason != "DURABLE_RESERVATION_NO_RETRY" || r.Sequence != 1 {
				t.Fatalf("T10 %s: replay after restart: %+v", stage, r)
			}
			if stage != "after-reservation" && string(r.Effect) != "{}" {
				t.Fatalf("T10 %s: the service must answer its own reservation, got effect %s", stage, r.Effect)
			}
			if _, again := p.send(t, raw); string(again) != string(first) {
				t.Fatal("T10 replay is not byte-identical")
			}
			if p.sends(t) != map[bool]int{false: 0, true: 1}[broadcast] || len(px1sRecords(t, p.s.wallet.PX1Journal())) != 1 {
				t.Fatalf("T10 %s: the replay re-applied the reservation", stage)
			}
			ledger := p.ledger(t)
			if ledger.SpendUsed(g.id) != 50000 || ledger.UncertainSat(g.id) != 50000 || !ledger.InputReserved(reserve.Inputs[0]) {
				t.Fatalf("T10 %s: debit not retained", stage)
			}
			status, e := p.s.PX1Status()
			if e != nil || len(status.Grants) != 1 || status.Grants[0].UncertainSat != 50000 || status.Grants[0].ReservedSat != 50000 || status.Grants[0].ReleasedSat != 0 {
				t.Fatalf("T10 %s: status %+v %v", stage, status.Grants, e)
			}
			if broadcast {
				if pass != nil {
					t.Fatalf("T10 after-broadcast: first observation pass after restart: %v", pass)
				}
				l.mine(DefaultConfirmationsK)
				if e := p.s.PX1Tick(context.Background()); e != nil {
					t.Fatal("tick", e)
				}
				status, _ = p.s.PX1Status()
				ledger = p.ledger(t)
				if status.Payments.Confirmed != 1 || status.Grants[0].UncertainSat != 50000 || ledger.UncertainSat(g.id) != 50000 || ledger.SpendUsed(g.id) != 50000 {
					t.Fatalf("T10 after-broadcast: want tracker confirmed and the debit still uncertain: payments=%+v grants=%+v", status.Payments, status.Grants)
				}
				if _, again := p.send(t, raw); string(again) != string(first) || p.sends(t) != 1 {
					t.Fatal("T10 after-broadcast: confirmation changed the replay or re-sent")
				}
			} else {
				// The S3 tracker must keep observing after the restart: the
				// never-broadcast reservation is absent from mempool and chain,
				// so after ConflictBlocksN blocks it is conflicted (the operator
				// alert that leads to the release below).
				l.mine(DefaultConflictBlocksN + 1)
				tick := p.s.PX1Tick(context.Background())
				status, _ = p.s.PX1Status()
				if pass != nil || tick != nil || status.Payments.Conflicted != 1 {
					t.Errorf("T10_TRACKER_UNKNOWN_TX %s: the observation pass must succeed and mark the never-broadcast payment conflicted: first pass %v, later pass %v, payments %+v", stage, pass, tick, status.Payments)
				}
				if status.Grants[0].UncertainSat != 50000 {
					t.Fatalf("T10 %s: debit not retained after the observation pass: %+v", stage, status.Grants)
				}
				j := p.s.wallet.PX1Journal()
				at := j.Usage().LastTime + 1
				release := func(at int64) error {
					rec := px1jFollowRec(reserve, RecordReconcile, "released", at)
					rec.Reconcile = &ReconcileRecordV2{TargetSeq: reserve.Seq, Evidence: "absent", Height: int64(l.px1sHeight()), BlockHash: px1jHex(9), ReleasedSat: reserve.Reserved, NoteSHA256: px1jHex(5)}
					_, e := j.Append(px1jSignNext(t, j, rec, px1jReceiptKeyN))
					return e
				}
				if e := release(at); e != nil {
					t.Fatalf("T10 %s: operator release: %v", stage, e)
				}
				if e := release(at + ReconcileMinIntervalSeconds); e == nil {
					t.Fatalf("T10 %s: a second release of the same reservation was accepted", stage)
				}
				ledger = p.ledger(t)
				status, _ = p.s.PX1Status()
				if ledger.SpendUsed(g.id) != 0 || ledger.UncertainSat(g.id) != 0 || ledger.InputReserved(reserve.Inputs[0]) || status.Grants[0].ReleasedSat != 50000 || status.Grants[0].ReservedSat != 0 {
					t.Fatalf("T10 %s: release not applied exactly once: %+v", stage, status.Grants)
				}
			}
			p.close()

			// Valid neighbour: the same request with no crash (fresh grant,
			// state and hot wallet) executes, completes and is confirmed.
			cv := &px1sClock{}
			cv.now.Store(l.now)
			gv := l.px1sIssue(px1sTerms(500000, 100000, 300000, 5), 500000, 2, 2, fmt.Sprintf("s2-t10v-%d", i))
			pv := l.px1sInstall(gv, canary, peer, cv)
			pv.open(t)
			ok, _ := pv.send(t, px1sEnvelope(t, pv.request(1, 50000-fee, fee), 2))
			if ok.Verdict != "executed" || px1sKinds(px1sRecords(t, pv.s.wallet.PX1Journal()))[RecordComplete] != 1 {
				t.Fatalf("T10 %s neighbour: %+v", stage, ok)
			}
			l.mine(DefaultConfirmationsK)
			if e := pv.s.PX1Tick(context.Background()); e != nil {
				t.Fatal("tick", e)
			}
			if st, _ := pv.s.PX1Status(); st.Payments.Confirmed != 1 || st.Grants[0].UncertainSat != 0 || st.Grants[0].SpentSat != 50000 {
				t.Fatalf("T10 %s neighbour status: %+v %+v", stage, st.Payments, st.Grants)
			}
		})
	}
}

// px1sQuoteFee is px1QuoteFee against the grant's own Core hot wallet: the
// fee fundrawtransaction charges for a one-output payment at the config fee
// rate (no effect: nothing is signed or locked).
func (l *coreLab) px1sQuoteFee(c Config, to string, amount int64) int64 {
	l.t.Helper()
	script, e := addressScriptForNetwork(to, "regtest", su.RegtestGenesis)
	if e != nil {
		l.t.Fatal(e)
	}
	tx := wire.NewMsgTx(2)
	tx.AddTxOut(wire.NewTxOut(amount, script))
	opts := map[string]any{"changeAddress": c.ChangeAddress, "changePosition": 1, "fee_rate": c.FeeRate, "minconf": 1, "include_unsafe": false, "includeWatching": false, "lockUnspents": false, "replaceable": false}
	var funded struct {
		Fee json.Number `json:"fee"`
	}
	if json.Unmarshal(l.rpc(c.Wallet.Wallet, "fundrawtransaction", rawTx(tx), opts), &funded) != nil {
		l.t.Fatal("fee quote")
	}
	fee, e := su.ParseCoins(funded.Fee.String())
	if e != nil {
		l.t.Fatal(e)
	}
	return fee
}

// px1sHeight is the node's block count.
func (l *coreLab) px1sHeight() int {
	var n int
	if json.Unmarshal(l.rpc("", "getblockcount"), &n) != nil {
		l.t.Fatal("height")
	}
	return n
}

func mapsEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
