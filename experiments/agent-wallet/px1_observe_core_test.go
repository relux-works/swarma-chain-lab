package wallet

// Owner S3. Core layer of T11, T13 and T14 against a genuine Namecoin Core 28
// regtest node (W1_REGTEST=1, W1_RUN_ROOT, W1_CORE_CLI, W1_CORE_DAEMON). The
// S3 observers run on the real observer and w1-wallet routes; the journals
// are fakes of the frozen JournalV2 interface, because S1/S2 have not landed.
// The end-to-end service layer (a spend refused FLOAT_CANARY_SPENT, startup
// of agent-walletd refused STATE_RECONCILE_REQUIRED) is pending S1/S2.
// All keys and wallets here are regtest fixtures, never live custody.

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

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Accepted Core 28 binary pins: the existing harness pins, and the Linux
// x86_64 namecoin-28.0 release build (namecoind, namecoin-cli).
var px1CorePins = map[string]bool{
	"86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f": true, "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d": true,
	"dc7430676e445af3992430e036f7c1a17bea44f757e9cf25b69205e39625f2f7": true, "318b6c881c8071abbafd984550172369c3498b4c65c389797350f2d458f085b1": true,
}

type px1Core struct {
	t                      *testing.T
	data, conf, cli, miner string
	node                   *exec.Cmd
	routes                 map[string]su.Route
}

func px1StartCore(t *testing.T) *px1Core {
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
	c := &px1Core{t: t, data: filepath.Join(root, "private"), cli: os.Getenv("W1_CORE_CLI"), routes: map[string]su.Route{}}
	daemon := os.Getenv("W1_CORE_DAEMON")
	for _, p := range []string{daemon, c.cli} {
		b, e := os.ReadFile(p)
		if e != nil || !px1CorePins[Hash(b)] {
			t.Fatal("Core binary pin")
		}
	}
	if e := os.Mkdir(c.data, 0700); e != nil {
		t.Fatal(e)
	}
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	conf := "server=1\nlisten=0\ndnsseed=0\ndiscover=0\nnetworkactive=0\ntxindex=1\npersistmempool=0\nfallbackfee=0.002\nrpcwhitelistdefault=0\n"
	for user, methods := range map[string]string{"w3-observer": "getblockchaininfo,getblockhash,getblockheader,getrawtransaction,gettxout,name_show,getrawmempool,getblock", "w1-wallet": "getbalances,getnewaddress,listtransactions,fundrawtransaction,signrawtransactionwithwallet"} {
		b := make([]byte, 32)
		if _, e = rand.Read(b); e != nil {
			t.Fatal(e)
		}
		password, salt := hex.EncodeToString(b), hex.EncodeToString(b[:8])
		mac := hmac.New(sha256.New, []byte(salt))
		mac.Write([]byte(password))
		c.routes[user] = su.Route{Host: "127.0.0.1", Port: port, Username: user, Password: password}
		conf += fmt.Sprintf("rpcauth=%s:%s$%x\nrpcwhitelist=%s:%s\n", user, salt, mac.Sum(nil), user, methods)
	}
	conf += fmt.Sprintf("[regtest]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport=%d\n", port)
	c.conf = filepath.Join(c.data, "namecoin.conf")
	if e = os.WriteFile(c.conf, []byte(conf), 0600); e != nil {
		t.Fatal(e)
	}
	log, e := os.OpenFile(filepath.Join(root, "node.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	c.node = exec.Command(daemon, "-regtest", "-datadir="+c.data, "-conf="+c.conf)
	c.node.Stdout, c.node.Stderr = log, log
	if e = c.node.Start(); e != nil {
		t.Fatal(e)
	}
	pid := c.node.Process.Pid
	os.WriteFile(filepath.Join(root, "node.pid"), []byte(fmt.Sprint(pid)), 0600)
	t.Cleanup(func() {
		// Stop exactly the node this test started, by its PID.
		c.node.Process.Signal(os.Interrupt)
		c.node.Wait()
		log.Close()
	})
	for i := 0; ; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		e = exec.CommandContext(ctx, c.cli, "-regtest", "-datadir="+c.data, "-conf="+c.conf, "getblockchaininfo").Run()
		cancel()
		if e == nil {
			break
		}
		if i == 150 {
			t.Fatal("Core startup timeout")
		}
		time.Sleep(100 * time.Millisecond)
	}
	c.rpc("", "createwallet", "issuer")
	c.rpc("", "createwallet", "agent")
	c.miner = c.str("issuer", "getnewaddress")
	c.mine(101)
	return c
}

// rpc is the admin route (cookie); it is never given to the S3 observers.
func (c *px1Core) rpc(wallet, method string, args ...any) json.RawMessage {
	c.t.Helper()
	argv := []string{"-regtest", "-datadir=" + c.data, "-conf=" + c.conf}
	if wallet != "" {
		argv = append(argv, "-rpcwallet="+wallet)
	}
	argv = append(argv, method)
	for _, v := range args {
		if s, ok := v.(string); ok {
			argv = append(argv, s)
		} else {
			argv = append(argv, string(canonical(v)))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, c.cli, argv...).Output()
	if e != nil {
		c.t.Fatalf("Core %s failed", method)
	}
	if !json.Valid(b) {
		b = canonical(strings.TrimSpace(string(b)))
	}
	return b
}
func (c *px1Core) str(wallet, method string, args ...any) string {
	c.t.Helper()
	var s string
	if json.Unmarshal(c.rpc(wallet, method, args...), &s) != nil {
		c.t.Fatalf("%s: expected a string", method)
	}
	return s
}
func (c *px1Core) mine(n int) { c.rpc("", "generatetoaddress", n, c.miner) }
func (c *px1Core) height() int64 {
	var info struct {
		Blocks int64 `json:"blocks"`
	}
	json.Unmarshal(c.rpc("", "getblockchaininfo"), &info)
	return info.Blocks
}

type px1CoreTx struct {
	Vin []struct {
		TxID string `json:"txid"`
		Vout uint32 `json:"vout"`
	} `json:"vin"`
	Vout []struct {
		Value json.Number `json:"value"`
		N     uint32      `json:"n"`
	} `json:"vout"`
}

func (c *px1Core) tx(txid string) px1CoreTx {
	var tx px1CoreTx
	if json.Unmarshal(c.rpc("", "getrawtransaction", txid, true), &tx) != nil {
		c.t.Fatal("transaction view")
	}
	return tx
}

// spend signs, with the agent wallet, a raw transaction moving p (worth
// value atoms) to the miner minus fee. It is the out-of-band admin route.
func (c *px1Core) spend(p su.Point, value, fee int64) string {
	c.t.Helper()
	raw := c.str("", "createrawtransaction", []map[string]any{{"txid": p.TxID, "vout": p.Vout}}, map[string]any{c.miner: json.RawMessage(su.Coins(value - fee))})
	var signed struct {
		Hex      string `json:"hex"`
		Complete bool   `json:"complete"`
	}
	if json.Unmarshal(c.rpc("agent", "signrawtransactionwithwallet", raw), &signed) != nil || !signed.Complete {
		c.t.Fatal("out-of-band spend not signed")
	}
	return signed.Hex
}

func (c *px1Core) outpointTo(txid, address string) (su.Point, int64) {
	var tx struct {
		Vout []struct {
			Value  json.Number `json:"value"`
			N      uint32      `json:"n"`
			Script struct {
				Address string `json:"address"`
			} `json:"scriptPubKey"`
		} `json:"vout"`
	}
	json.Unmarshal(c.rpc("", "getrawtransaction", txid, true), &tx)
	for _, o := range tx.Vout {
		if o.Script.Address == address {
			v, _ := su.ParseCoins(o.Value.String())
			return su.Point{TxID: txid, Vout: o.N}, v
		}
	}
	c.t.Fatal("output absent")
	return su.Point{}, 0
}

// Claim (T11, T13, T14 Core): on genuine Core 28 regtest the S3 observers
//   - T13: accept a hot wallet whose sends the wallet journal carries, and
//     refuse STATE_RECONCILE_REQUIRED for a restored older journal that lacks
//     the payment (valid neighbour first);
//   - T14: read the canary unspent, then spent after an out-of-band spend in
//     the mempool, and the runtime pass poisons the service with exactly one
//     ALERT_CANARY_SPENT and a spent canary in the status projection;
//   - T11: confirm the payment at depth k=2, return it to pending after
//     invalidateblock without a record, and mark it conflicted, citing the
//     conflicting spend of its input mined from the admin route.
//
// Limit: the journals are fakes of the frozen JournalV2; the service-layer
// refusal codes on the spend path are pending S1/S2.
func TestPX1CoreObserve(t *testing.T) {
	c := px1StartCore(t)
	ctx := context.Background()
	observer, e := su.NewRPC(c.routes["w3-observer"])
	if e != nil {
		t.Fatal(e)
	}
	walletRoute, e := NewWalletRPC(WalletRoute{Route: c.routes["w1-wallet"], Wallet: "agent"})
	if e != nil {
		t.Fatal(e)
	}
	agentAddress := c.str("agent", "getnewaddress")
	c.str("issuer", "sendtoaddress", agentAddress, json.RawMessage(su.Coins(100000000)))
	c.mine(1)
	// The payment: an agent-wallet send, journaled as reserve + complete.
	payment := c.str("agent", "sendtoaddress", c.miner, json.RawMessage(su.Coins(10000000)))
	view := c.tx(payment)
	inputs := []su.Point{}
	for _, in := range view.Vin {
		inputs = append(inputs, su.Point{TxID: in.TxID, Vout: in.Vout})
	}
	journal := px1Journal(JournalLayerWallet)
	reserve := journal.add(px1Reserve(px1G, px1N1, payment, 10100000, px1StatusDay(time.Now().Unix()), inputs...))
	journal.add(px1Follow(RecordComplete, "complete", reserve))

	// T13: positive with the full journal, refusal with an older journal.
	reconciler, e := NewStartupReconciler(walletRoute)
	if e != nil {
		t.Fatal(e)
	}
	if e := reconciler.Reconcile(ctx, journal); e != nil {
		t.Fatalf("T13: journaled send refused: %v", e)
	}
	if e := reconciler.Reconcile(ctx, px1Journal(JournalLayerWallet)); e == nil || e.Error() != CodeStateReconcileRequired {
		t.Fatalf("T13: restored older journal accepted: %v", e)
	}

	// T11 part 1: pending in the mempool, confirmed at depth 2.
	tracker, e := NewTracker(observer, TrackerConfig{ConfirmationsK: DefaultConfirmationsK, ConflictBlocksN: DefaultConflictBlocksN}, journal)
	if e != nil {
		t.Fatal(e)
	}
	if out := px1Tick(t, tracker); len(out) != 0 || tracker.Snapshot()[0].State != TrackPending {
		t.Fatal("T11: mempool payment not pending")
	}
	c.mine(1)
	mined := c.height()
	if out := px1Tick(t, tracker); len(out) != 0 || tracker.Snapshot()[0].Confirmations != 1 {
		t.Fatal("T11: depth 1 must stay pending")
	}
	c.mine(1)
	out := px1Tick(t, tracker)
	if len(out) != 1 || out[0].Record.State != TrackConfirmed || out[0].Record.Confirmations != 2 || out[0].Record.Height != mined+1 {
		t.Fatalf("T11: not confirmed at depth 2: %+v", out)
	}

	// T14: a canary in the hot wallet, watched by the runtime pass.
	canaryTx := c.str("issuer", "sendtoaddress", agentAddress, json.RawMessage(su.Coins(100000)))
	c.mine(1)
	outpoint, value := c.outpointTo(canaryTx, agentAddress)
	op := px1Operator()
	op.Canary = CanaryConfig{Outpoint: outpoint, ValueSat: value}
	op.MaxFloatSat, op.LowFloatSat = 1000000000, 1000000
	service := px1Journal(JournalLayerService)
	service.usage = JournalUsageV2{SpendCapacity: 2048}
	poisons := 0
	lines := []string{}
	runtime := &px1Runtime{sink: NewLogAlertSink(func(s string) { lines = append(lines, s) })}
	env := px1Env{profile: &op, service: service, wallet: journal, observer: observer, walletRoute: walletRoute, receiptKey: px1ExecutorKey, network: "regtest", now: time.Now().Unix(), poison: func() { poisons++ }}
	if e := runtime.tick(ctx, env); e != nil || poisons != 0 || runtime.canaryLast.State != CanaryUnspent || runtime.floatLast.State != "ok" {
		t.Fatalf("T14: unspent canary pass: %v poisons=%d canary=%s float=%+v", e, poisons, runtime.canaryLast.State, runtime.floatLast)
	}
	canary, e := NewCanary(observer, op.Canary)
	if e != nil {
		t.Fatal(e)
	}
	if s, e := canary.Check(ctx); s != CanaryUnspent || e != nil {
		t.Fatalf("T14: canary read %s %v", s, e)
	}
	c.str("", "sendrawtransaction", c.spend(outpoint, value, 50000))
	if s, e := canary.Check(ctx); s != CanarySpent || e != nil {
		t.Fatalf("T14: mempool spend of the canary read %s %v", s, e)
	}
	env.now = time.Now().Unix()
	if e := runtime.tick(ctx, env); e != nil {
		t.Fatal(e)
	}
	if e := runtime.tick(ctx, env); e != nil {
		t.Fatal(e)
	}
	status, e := runtime.status(env)
	if e != nil || poisons != 2 || len(lines) != 1 || !strings.HasPrefix(lines[0], "PX1_ALERT code=ALERT_CANARY_SPENT") || !status.Poisoned || status.Canary.State != CanarySpent || status.Payments.Confirmed != 1 {
		t.Fatalf("T14: spent canary pass: %v poisons=%d lines=%q status=%+v", e, poisons, lines, status)
	}

	// T11 part 2: invalidateblock returns the payment to the mempool.
	c.rpc("", "invalidateblock", c.str("", "getblockhash", mined))
	if out := px1Tick(t, tracker); len(out) != 0 || tracker.Snapshot()[0].State != TrackPending || tracker.Snapshot()[0].Confirmations != 0 {
		t.Fatalf("T11: reorged payment must be pending without a record: %+v", tracker.Snapshot())
	}
	// A conflicting spend of the payment's input, mined from the admin route.
	parent := c.tx(inputs[0].TxID)
	inputValue, _ := su.ParseCoins(parent.Vout[inputs[0].Vout].Value.String())
	conflictHex := c.spend(inputs[0], inputValue, 100000)
	var conflictTx struct {
		TxID string `json:"txid"`
	}
	json.Unmarshal(c.rpc("", "decoderawtransaction", conflictHex), &conflictTx)
	c.rpc("", "generateblock", c.miner, []string{conflictHex})
	out = px1Tick(t, tracker)
	if len(out) != 1 || out[0].Record.State != TrackConflicted || out[0].Record.ConflictTxID != conflictTx.TxID {
		t.Fatalf("T11: conflicting spend not detected: %+v", out)
	}
	// The conflicting send is out of band: startup reconciliation refuses.
	if e := reconciler.Reconcile(ctx, journal); e == nil || e.Error() != CodeStateReconcileRequired {
		t.Fatalf("T13: out-of-band send accepted: %v", e)
	}
}
