package wallet

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// F6 reuses coreLab's production grant/wallet helpers and isolated bootstrap.
// This task-specific bootstrap adds explicit private ports and a sanitized CLI
// command recorder without changing the existing shared/frozen test helpers.
func newF6Core(t *testing.T) *coreLab {
	t.Helper()
	if os.Getenv("W1_REGTEST") != "1" {
		t.Skip("requires W1_REGTEST=1 genuine isolated Core")
	}
	root := os.Getenv("W1_RUN_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute fresh W1_RUN_ROOT required")
	}
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	l := &coreLab{t: t, root: root, private: filepath.Join(root, "private"), public: filepath.Join(root, "public"), cli: os.Getenv("W1_CORE_CLI"), daemon: os.Getenv("W1_CORE_DAEMON"), agent: "id/wallet-agent-test", routes: map[string]su.Route{}}
	for _, p := range []string{l.private, l.public} {
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	if !coreBinariesPinned(l.daemon, l.cli) {
		t.Fatal("Core binary pin")
	}
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if port <= 28000 {
		t.Fatal("F6 requires a private port above 28000")
	}
	ln.Close()
	conf := "server=1\ndeprecatedrpc=create_bdb\nlisten=0\ndnsseed=0\ndiscover=0\nnetworkactive=0\ntxindex=1\npersistmempool=0\nfallbackfee=0.002\nacceptnonstdtxn=1\nnameencoding=ascii\nvalueencoding=ascii\nrpcwhitelistdefault=0\naddresstype=bech32\nchangetype=bech32\n"
	sets := map[string]string{"w3-observer": "getblockchaininfo,getblockhash,getblockheader,getrawtransaction,gettxout,name_show,getrawmempool,getblock", "w1-wallet": "getbalances,getnewaddress,listtransactions,fundrawtransaction,signrawtransactionwithwallet", "w1-broadcast": "sendrawtransaction"}
	for user, methods := range sets {
		b := make([]byte, 32)
		if _, e = rand.Read(b); e != nil {
			t.Fatal(e)
		}
		password := hex.EncodeToString(b)
		salt := hex.EncodeToString(b[:8])
		mac := hmac.New(sha256.New, []byte(salt))
		mac.Write([]byte(password))
		l.routes[user] = su.Route{Host: "127.0.0.1", Port: port, Username: user, Password: password}
		conf += fmt.Sprintf("rpcauth=%s:%s$%x\nrpcwhitelist=%s:%s\n", user, salt, mac.Sum(nil), user, methods)
	}
	conf += fmt.Sprintf("[regtest]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport=%d\n", port)
	l.conf = filepath.Join(l.private, "namecoin.conf")
	if e = os.WriteFile(l.conf, []byte(conf), 0600); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.stop(); l.save("commands.json", l.commands) })
	l.cli = f6Recorder(t, l.cli, l.private, l.public)
	f6Start(l, port, f6Port(t))
	l.rpc("", "createwallet", "issuer", false, false, "", false, false)
	l.rpc("", "createwallet", "agent", false, false, "", false, false)
	l.rpc("", "createwallet", "oneoff", false, false, "", false, false)
	l.address = text(t, l.rpc("issuer", "getnewaddress", "", "bech32"))
	l.mine(101)
	// Legacy coins for one-off seals (oneoff), confirmed by the blocks below.
	l.rpc("issuer", "sendtoaddress", text(t, l.rpc("oneoff", "getnewaddress", "", "legacy")), su.Coins(1000000000))
	_, issuer := testKey(1)
	_, nostr := testKey(3)
	value, e := rental.AgentBindingValue(rental.AgentBinding{Landlord: "id/wallet-landlord-test", Nostr: nostr})
	if e != nil {
		t.Fatal(e)
	}
	var reservation []string
	if json.Unmarshal(l.rpc("issuer", "name_new", l.agent), &reservation) != nil {
		t.Fatal("name_new fixture")
	}
	l.mine(12)
	l.rpc("issuer", "name_firstupdate", l.agent, reservation[1], reservation[0], value)
	l.mine(1)
	landlordValue, e := rental.LandlordValue(rental.LandlordBinding{Grant: issuer})
	if e != nil {
		t.Fatal(e)
	}
	var landlordReservation []string
	if json.Unmarshal(l.rpc("issuer", "name_new", "id/wallet-landlord-test"), &landlordReservation) != nil {
		t.Fatal("landlord fixture")
	}
	l.mine(12)
	l.rpc("issuer", "name_firstupdate", "id/wallet-landlord-test", landlordReservation[1], landlordReservation[0], landlordValue)
	l.mine(1)
	k, _ := testKey(1)
	wif, _ := btcutil.NewWIF(k, &chaincfg.RegressionNetParams, true)
	l.rpc("issuer", "importprivkey", wif.String(), "", false)
	return l
}

func f6Port(t *testing.T) int {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	p := ln.Addr().(*net.TCPAddr).Port
	if p <= 28000 {
		t.Fatal("F6 port bound")
	}
	return p
}
func f6Start(l *coreLab, rpc, p2p int) {
	l.t.Helper()
	var e error
	l.log, e = os.OpenFile(filepath.Join(l.private, "node.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		l.t.Fatal(e)
	}
	args := []string{"-regtest", "-datadir=" + l.private, "-conf=" + l.conf, "-port=" + fmt.Sprint(p2p), "-rpcport=" + fmt.Sprint(rpc), "-listen=0"}
	l.node = exec.Command(l.daemon, args...)
	l.node.Stdout = l.log
	l.node.Stderr = l.log
	if e = l.node.Start(); e != nil {
		l.t.Fatal(e)
	}
	l.save("node-start.json", map[string]any{"binary": l.daemon, "argv": args, "pid": l.node.Process.Pid, "rpcport": rpc, "port": p2p})
	os.WriteFile(filepath.Join(l.root, "node.pid"), []byte(fmt.Sprint(l.node.Process.Pid)), 0600)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		e = exec.CommandContext(ctx, l.cli, "-regtest", "-datadir="+l.private, "-conf="+l.conf, "getblockchaininfo").Run()
		cancel()
		if e == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	l.t.Fatal("F6 private node startup timeout")
}
func f6Recorder(t *testing.T, real, data, public string) string {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	records := filepath.Join(public, "rpc-commands")
	if e = os.Mkdir(records, 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("F6_RPC_BINARY", real)
	t.Setenv("F6_RPC_DATA", data)
	t.Setenv("F6_RPC_RECORDS", records)
	return exe
}

// Test-only recorder dispatch: actual pinned namecoin-cli always runs with the
// fresh explicit regtest datadir. Credential/key-bearing fixture arguments are
// never written to evidence, and no live-node configuration is consulted.
func init() {
	real, data, records := os.Getenv("F6_RPC_BINARY"), os.Getenv("F6_RPC_DATA"), os.Getenv("F6_RPC_RECORDS")
	if real == "" || records == "" || len(os.Args) < 2 || os.Args[1] != "-regtest" {
		return
	}
	args := append([]string{}, os.Args[1:]...)
	bound := false
	method := ""
	index := -1
	for i, a := range args {
		if a == "-datadir="+data {
			bound = true
		}
		if !strings.HasPrefix(a, "-") && method == "" {
			method = a
			index = i
		}
	}
	if !bound || method == "" {
		os.Exit(91)
	}
	cmd := exec.Command(real, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	started := time.Now()
	e := cmd.Start()
	pid := 0
	if e == nil {
		pid = cmd.Process.Pid
		e = cmd.Wait()
	}
	code := 0
	if e != nil {
		code = 1
		if ee, ok := e.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}
	safe := append([]string{}, args...)
	output := stdout.String()
	if method == "importprivkey" {
		if index+1 < len(safe) {
			safe[index+1] = "REDACTED-FIXTURE-KEY"
		}
		output = "REDACTED-KEY-OPERATION"
	}
	if method == "name_new" {
		output = "REDACTED-FIXTURE-COMMITMENT"
	}
	if method == "name_firstupdate" && index+2 < len(safe) {
		safe[index+2] = "REDACTED-FIXTURE-COMMITMENT"
	}
	errOutput := stderr.String()
	if method == "importprivkey" || method == "name_new" || method == "name_firstupdate" {
		errOutput = "REDACTED-FIXTURE-SECRET-OPERATION"
	}
	record := map[string]any{"binary": real, "argv": safe, "pid": pid, "exit": code, "stdout": output, "stderr": errOutput, "started": started.UTC().Format(time.RFC3339Nano), "elapsed_ms": time.Since(started).Milliseconds()}
	raw, _ := json.MarshalIndent(record, "", "  ")
	file, e2 := os.CreateTemp(records, "rpc-*.json")
	if e2 != nil {
		os.Exit(92)
	}
	file.Write(raw)
	file.Close()
	fmt.Fprint(os.Stdout, stdout.String())
	if code != 0 {
		fmt.Fprintln(os.Stderr, "F6_CLI_REFUSED")
	}
	os.Exit(code)
}

// Claim (private Core, no host-custody claim): production spends become uncertain
// when the own node rejects broadcast; a distinct mined input conflict remains
// charged at k=5 and permits the operator core at k=6. Real action socket requests
// never append reconcile records. This is an optional function-only diagnostic;
// Infra performs native CLI qualification in the signed draft-6 install fixture.
// No local native-CLI fallback or DK5 admission override is provided.
func TestF6CoreRehearsal(t *testing.T) {
	l := newF6Core(t)
	l.now = time.Now().Unix()
	canary := l.px1sCanary()
	clock := &px1sClock{}
	clock.now.Store(l.now)
	g := l.px1sIssue(px1sTerms(500000, 100000, 300000, 5), 500000, 2, 2, "f6-hot")
	p := l.px1sInstall(g, canary, uint32(os.Getuid()+1), clock)
	p.config.TimeoutSeconds = 30
	p.open(t)
	// The environment has one UID. Only the test fixture accepts its real peer;
	// installed config keeps the required distinct peer for production validation.
	p.s.config.PeerUID = uint32(os.Getuid())
	socketCtx, cancelSocket := context.WithCancel(context.Background())
	socketDone := make(chan error, 1)
	go func() { socketDone <- p.s.Serve(socketCtx) }()
	awaitActionSocket(t, p.s.config.Socket)
	socketStopped := false
	stopSocket := func() {
		if !socketStopped {
			socketStopped = true
			cancelSocket()
			if e := <-socketDone; e != nil {
				t.Error(e)
			}
		}
	}
	defer stopSocket()
	fee := l.px1sQuoteFee(g.config, px1RegtestTerms().Recipients[0], 50000)
	p.s.wallet.hook = func(stage string) {
		if stage == "after-reservation" {
			rs := px1sRecords(t, p.s.wallet.PX1Journal())
			l.rpc("", "prioritisetransaction", rs[len(rs)-1].TxID, 0, -100000000)
		}
	}
	for i := 1; i <= 1; i++ {
		receipt, raw := f6CoreWire(t, p.s, px1sEnvelope(t, p.request(i, 50000-fee, fee), 2))
		l.save(fmt.Sprintf("uncertain-%d.json", i), json.RawMessage(raw))
		if receipt.Receipt.Verdict != "uncertain" || receipt.Receipt.Reason != "BROADCAST_UNCERTAIN" {
			t.Fatal("F6_UNCERTAIN_PATH", receipt.Receipt)
		}
	}
	p.s.wallet.hook = nil
	records := px1sRecords(t, p.s.wallet.PX1Journal())
	reserves := []JournalRecordV2{}
	for _, r := range records {
		if r.Kind == RecordReserve {
			reserves = append(reserves, r)
		}
	}
	if len(reserves) != 1 {
		t.Fatal("F6_RESERVES", len(reserves))
	}
	l.save("wallet-before.json", records)
	before := p.seqs()
	for _, action := range []string{"reconcile", "unknown", "status"} {
		q := p.request(10, 1, 1)
		q.Action = action
		q.Params = json.RawMessage(`{}`)
		reply, raw := f6CoreWire(t, p.s, px1sEnvelope(t, q, 2))
		l.save("row20-"+action+".json", json.RawMessage(raw))
		if reply.Receipt.Reason != "ACTION_UNSUPPORTED" || p.seqs() != before {
			t.Fatal("F6_CORE_WIRE_RECONCILE", reply.Receipt)
		}
	}
	for i, action := range []string{"balance", "history", "receive", "budget"} {
		q := p.request(20+i, 1, 1)
		q.Action = action
		q.Params = json.RawMessage(`{}`)
		if action != "budget" {
			q.Grant = ActionGrant{Kind: "none"}
		}
		reply, raw := f6CoreWire(t, p.s, px1sEnvelope(t, q, 2))
		l.save("row20-valid-"+action+".json", json.RawMessage(raw))
		if reply.Receipt.Verdict != "executed" {
			t.Fatal("F6_CORE_VALID_WIRE", action, reply.Receipt.Reason)
		}
	}
	for _, journal := range []JournalV2{p.s.wallet.PX1Journal(), p.s.PX1ServiceJournal()} {
		journal.Iterate(1, func(r JournalRecordV2) error {
			if r.Kind == RecordReconcile {
				t.Fatal("F6_CORE_WIRE_RELEASE")
			}
			return nil
		})
	}
	l.save("row20-verdict.json", map[string]any{"negative": "ACTION_UNSUPPORTED", "valid_actions": []string{"spend", "balance", "history", "receive", "budget"}, "reconcile_records": 0, "custody": "same-UID test fixture; T18 unqualified"})
	inputs := []su.Point{}
	total := int64(0)
	for _, r := range reserves {
		for _, in := range r.Inputs {
			inputs = append(inputs, in)
			var out struct {
				Value json.Number `json:"value"`
			}
			if json.Unmarshal(l.rpc("", "gettxout", in.TxID, in.Vout, true), &out) != nil {
				t.Fatal("input value")
			}
			amount, err := su.ParseCoins(out.Value.String())
			if err != nil {
				t.Fatal(err)
			}
			total += amount
		}
	}
	unsigned := text(t, l.rpc("", "createrawtransaction", inputs, map[string]any{l.address: su.Coins(total - 100000)}))
	var signed struct {
		Hex      string `json:"hex"`
		Complete bool   `json:"complete"`
	}
	if json.Unmarshal(l.rpc("f6-hot", "signrawtransactionwithwallet", unsigned), &signed) != nil || !signed.Complete {
		t.Fatal("conflict sign")
	}
	conflict := text(t, l.rpc("", "sendrawtransaction", signed.Hex))
	l.mine(5)
	node, e := su.NewRPC(g.config.Observer)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = reconcileConflict(context.Background(), node, reserves[0], conflict, "regtest", su.RegtestGenesis); e == nil || e.Error() != CodeReconcileEvidence {
		t.Fatal("F6_K5_RELEASED", e)
	}
	l.save("evidence-k5.json", json.RawMessage(l.rpc("", "getrawtransaction", conflict, true)))
	l.mine(1)
	l.save("evidence-k6.json", json.RawMessage(l.rpc("", "getrawtransaction", conflict, true)))
	l.save("tip-k6.json", json.RawMessage(l.rpc("", "getblockchaininfo")))
	// Stop the action listener and release the production service locks.
	stopSocket()
	p.close()
	if e = os.Remove(filepath.Dir(p.config.Socket)); e != nil {
		t.Fatal(e)
	}
	configPath := filepath.Join(filepath.Dir(p.config.WalletConfig), "service.json")
	writeInstalled(t, configPath, canonical(p.config))
	note := filepath.Join(l.root, "public-operator-note.txt")
	os.WriteFile(note, []byte("Private regtest fixture: distinct input conflict confirmed at six; no external node or funds."), 0600)
	// Function-only diagnostic. Native installed CLI rehearsal belongs to Infra's
	// draft-6 install fixture and must not use this synthetic installed reader.
	q := ReconcileRequest{TargetSeq: reserves[0].Seq, ReleasedSat: reserves[0].Reserved, Evidence: "conflict", ConflictTxID: conflict, NotePath: note}
	result, e := ReconcileWallet(context.Background(), configPath, q)
	if e != nil {
		t.Fatal("F6_CORE_OPERATOR_ENTRY", e)
	}
	l.save("signed-reconcile.json", result)
	if result.Record == nil || !result.Verified {
		t.Fatal("F6_RECORD_MISSING")
	}
	if result.Record.Reconcile.NoteSHA256 != "4a28089845105667b855abc627b9781ce791fc7ef348dafdc529dc8cc22ab924" || result.Record.Reconcile.ConflictTxID != conflict {
		t.Fatal("F6_NOTE_OR_EVIDENCE_BINDING")
	}
	// Repeating the invocation inside the hour refuses before signing/write.
	q.TargetSeq = reserves[0].Seq
	q.ReleasedSat = reserves[0].Reserved
	second, e := ReconcileWallet(context.Background(), configPath, q)
	if e == nil || e.Error() != CodeReconcileRateLimited || second.MayHaveWritten {
		t.Fatal("F6_CORE_HOURLY", e)
	}
	l.save("hourly-refusal.json", map[string]any{"reason": e.Error(), "may_have_written": second.MayHaveWritten})
	// Reopen and independently verify the signed record and retained accounting.
	wc, e2 := LoadInstalledWalletConfig(p.config.WalletConfig)
	if e2 != nil {
		t.Fatal(e2)
	}
	key, e2 := loadReceiptKey(p.config.ReceiptKeyFile)
	if e2 != nil {
		t.Fatal(e2)
	}
	wallet, e2 := px1OpenServiceWallet(wc, p.config, key)
	if e2 != nil {
		t.Fatal(e2)
	}
	defer wallet.Close()
	j := wallet.PX1Journal()
	if e2 = VerifyReconcileV2(j.Header(), *result.Record); e2 != nil {
		t.Fatal(e2)
	}
	ledger, e2 := FoldLedgerV2(j)
	if e2 != nil || ledger.SpendUsed(reserves[0].GrantID) != 0 {
		t.Fatal("F6_LEDGER_AFTER", e2)
	}
	reconciler, _ := NewStartupReconciler(startupReconcileRoute{Node: wallet.wallet, observer: wallet.px1Observer(), network: wc.Network, genesis: wc.Genesis})
	if e2 = reconciler.Reconcile(context.Background(), j); e2 != nil {
		t.Fatal("F6_STARTUP_VERIFIED_CONFLICT", e2)
	}
	l.save("wallet-after.json", px1sRecords(t, j))
	l.save("verified-reopen.json", map[string]any{"signature": "verified", "retained_sat": ledger.SpendUsed(reserves[0].GrantID), "startup": "verified named conflict accepted"})
}

func f6CoreWire(t *testing.T, s *ActionService, raw []byte) (SignedActionReceipt, []byte) {
	t.Helper()
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: s.config.Socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(45 * time.Second))
	if e = writeActionFrame(c, raw); e != nil {
		t.Fatal(e)
	}
	reply, e := readActionFrame(c)
	if e != nil {
		t.Fatal(e)
	}
	hash := Hash(raw)
	if action, e := ParseAction(raw, WalletServiceID); e == nil {
		hash = action.Hash
	}
	receipt, e := ParseActionReceipt(reply, s.pub, hash, s.config.Grantee)
	if e != nil {
		t.Fatal(e)
	}
	return receipt, reply
}
