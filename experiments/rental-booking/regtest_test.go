package booking

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	singleuse "relux.works/swarma-chain-lab/experiments/single-use"
)

type coreLab struct {
	t                                               *testing.T
	root, private, public, cli, daemon, conf, miner string
	node                                            *exec.Cmd
	log                                             *os.File
	route                                           singleuse.Route
	read                                            Node
	pids                                            []int
	commands                                        []string
}

func textValue(t *testing.T, b json.RawMessage) string {
	t.Helper()
	var s string
	if e := json.Unmarshal(b, &s); e != nil {
		t.Fatal(e)
	}
	return s
}
func obj(t *testing.T, b json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if e := json.Unmarshal(b, &m); e != nil {
		t.Fatal(e)
	}
	return m
}
func (l *coreLab) rpc(wallet, method string, args ...any) json.RawMessage {
	l.t.Helper()
	ctx, c := context.WithTimeout(context.Background(), 20*time.Second)
	defer c()
	argv := []string{"-regtest", "-datadir=" + l.private, "-conf=" + l.conf}
	if wallet != "" {
		argv = append(argv, "-rpcwallet="+wallet)
	}
	argv = append(argv, method)
	for _, a := range args {
		if s, ok := a.(string); ok {
			argv = append(argv, s)
		} else {
			argv = append(argv, string(canonical(a)))
		}
	}
	cmd := exec.CommandContext(ctx, l.cli, argv...)
	raw, e := cmd.Output()
	l.commands = append(l.commands, method)
	if e != nil {
		if x, ok := e.(*exec.ExitError); ok {
			l.t.Fatalf("Core %s: %s", method, x.Stderr)
		}
		l.t.Fatalf("Core %s failed", method)
	}
	if !json.Valid(raw) {
		raw = canonical(strings.TrimSpace(string(raw)))
	}
	return raw
}
func (l *coreLab) save(name string, v any) {
	l.t.Helper()
	if e := os.WriteFile(filepath.Join(l.public, name+".json"), canonical(v), 0600); e != nil {
		l.t.Fatal(e)
	}
}
func (l *coreLab) start() {
	l.t.Helper()
	var e error
	l.log, e = os.OpenFile(filepath.Join(l.private, "node.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		l.t.Fatal(e)
	}
	l.node = exec.Command(l.daemon, "-regtest", "-datadir="+l.private, "-conf="+l.conf, "-persistmempool=0")
	l.node.Stdout = l.log
	l.node.Stderr = l.log
	if e = l.node.Start(); e != nil {
		l.t.Fatal(e)
	}
	l.pids = append(l.pids, l.node.Process.Pid)
	if e = os.WriteFile(filepath.Join(l.root, "node-pids.json"), canonical(l.pids), 0600); e != nil {
		l.t.Fatal(e)
	}
	for i := 0; i < 100; i++ {
		cmd := exec.Command(l.cli, "-regtest", "-datadir="+l.private, "-conf="+l.conf, "getblockchaininfo")
		if cmd.Run() == nil {
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
	_ = l.node.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- l.node.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = l.node.Process.Kill()
		<-done
	}
	_ = l.log.Close()
	l.node = nil
}
func newCoreLab(t *testing.T) *coreLab {
	t.Helper()
	if os.Getenv("M3_REGTEST") != "1" {
		t.Skip("set M3_REGTEST=1 and explicit isolated Core paths")
	}
	root := os.Getenv("M3_RUN_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute M3_RUN_ROOT required")
	}
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	l := &coreLab{t: t, root: root, private: filepath.Join(root, "private"), public: filepath.Join(root, "public"), cli: os.Getenv("M3_CORE_CLI"), daemon: os.Getenv("M3_CORE_DAEMON")}
	for _, p := range []string{l.private, l.public} {
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	for path, want := range map[string]string{l.cli: "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d", l.daemon: "86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f"} {
		b, e := os.ReadFile(path)
		if e != nil || Hash(b) != want {
			t.Fatal("Core binary pin")
		}
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	var entropy [32]byte
	if _, e = rand.Read(entropy[:]); e != nil {
		t.Fatal(e)
	}
	password := hex.EncodeToString(entropy[:])
	salt := hex.EncodeToString(entropy[:8])
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(password))
	l.route = singleuse.Route{Host: "127.0.0.1", Port: port, Username: "w3-observer", Password: password}
	methods := "getblockchaininfo,getblockhash,getblockheader,getrawtransaction,gettxout,name_show,getrawmempool,getblock"
	conf := fmt.Sprintf("server=1\ndeprecatedrpc=create_bdb\nlisten=0\ndnsseed=0\ndiscover=0\nnetworkactive=0\ntxindex=1\nfallbackfee=0.002\nwalletbroadcast=0\nacceptnonstdtxn=1\nnameencoding=ascii\nvalueencoding=ascii\nrpcwhitelistdefault=0\nrpcauth=w3-observer:%s$%x\nrpcwhitelist=w3-observer:%s\n[regtest]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport=%d\n", salt, mac.Sum(nil), methods, port)
	l.conf = filepath.Join(l.private, "namecoin.conf")
	if e = os.WriteFile(l.conf, []byte(conf), 0600); e != nil {
		t.Fatal(e)
	}
	l.start()
	t.Cleanup(func() {
		l.stop()
		l.save("lifecycle", map[string]any{"pids": l.pids, "stopped": true, "regtest": true, "no_peers": true, "methods": l.commands})
	})
	l.read, e = singleuse.NewRPC(l.route)
	if e != nil {
		t.Fatal(e)
	}
	l.rpc("", "createwallet", "lab", false, false, "", false, false)
	l.miner = textValue(t, l.rpc("lab", "getnewaddress", "", "legacy"))
	l.mine(110)
	return l
}
func (l *coreLab) mine(n int) string {
	var hashes []string
	if e := json.Unmarshal(l.rpc("", "generatetoaddress", n, l.miner), &hashes); e != nil {
		l.t.Fatal(e)
	}
	return hashes[len(hashes)-1]
}
func amountJSON(sat int64) json.Number {
	return json.Number(fmt.Sprintf("%d.%08d", sat/100000000, sat%100000000))
}
func (l *coreLab) pay(address string, sat int64) string {
	l.t.Helper()
	id := textValue(l.t, l.rpc("lab", "sendtoaddress", address, amountJSON(sat), "", "", false, false))
	raw := textValue(l.t, obj(l.t, l.rpc("lab", "gettransaction", id))["hex"])
	got := textValue(l.t, l.rpc("", "sendrawtransaction", raw))
	if got != id {
		l.t.Fatal("payment id")
	}
	return id
}
func (l *coreLab) fixture(t *testing.T, policy string) *fixture {
	t.Helper()
	f := newFixture(t)
	f.s.Close()
	f.now = time.Now().Unix()
	f.cfg.RateAsOf = f.now
	f.cfg.Slots = []Slot{{"one", "id/station-one", f.now + 3600, f.now + 7200, policy}, {"two", "id/station-two", f.now + 3600, f.now + 7200, policy}}
	seed := sha256.Sum256([]byte(t.Name()))
	master, _ := hdkeychain.NewMaster(seed[:], &chaincfg.RegressionNetParams)
	pub, _ := master.Neuter()
	f.cfg.PublicBranch = pub.String()
	f.cfg.PublicBranchSHA256 = Hash([]byte(pub.String()))
	f.cfg.StateDir = filepath.Join(l.private, strings.ReplaceAll(t.Name(), "/", "-"))
	if e := os.Mkdir(f.cfg.StateDir, 0700); e != nil {
		t.Fatal(e)
	}
	relayDir := f.cfg.StateDir + "-relay"
	if e := os.Mkdir(relayDir, 0700); e != nil {
		t.Fatal(e)
	}
	relay, e := NewLocalRelay(relayDir)
	if e != nil {
		t.Fatal(e)
	}
	srv := httptest.NewServer(relay)
	t.Cleanup(func() { srv.Close(); relay.Close() })
	publisher, e := NewRelayPublisher("ws" + strings.TrimPrefix(srv.URL, "http"))
	if e != nil {
		t.Fatal(e)
	}
	f.s, e = NewService(f.cfg, f.profile, f.provider, l.read, publisher, func() time.Time { return time.Unix(f.now, 0) })
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func readyBooking(t *testing.T, f *fixture) Booking {
	t.Helper()
	b := f.book(t, "one")
	b, e := f.s.AcceptConsent(context.Background(), b.Contract.BookingID, f.consent(t, b))
	if e != nil || !b.Published {
		t.Fatalf("package: %v", e)
	}
	return b
}
func refresh(t *testing.T, f *fixture, id string) Booking {
	t.Helper()
	ctx, c := context.WithTimeout(context.Background(), 60*time.Second)
	defer c()
	if e := f.s.Refresh(ctx); e != nil {
		t.Fatal(e)
	}
	b, e := f.s.Get(id)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// All chain verdicts below run against hash-pinned Namecoin Core 28 with a
// whitelist-only service credential. Valid neighbours share that real node.
func TestGenuineCorePayments(t *testing.T) {
	l := newCoreLab(t)
	t.Run("advance_pending_then_confirmed_duplicate_restart", func(t *testing.T) {
		l.t = t
		f := l.fixture(t, "advance")
		b := readyBooking(t, f)
		id := l.pay(b.Contract.PaymentAddress, b.Contract.PriceNMCSat)
		pending := refresh(t, f, b.Contract.BookingID)
		if pending.Status != "pending" || pending.Issuance != nil {
			t.Fatal("mempool admitted advance")
		}
		l.mine(1)
		paid := refresh(t, f, b.Contract.BookingID)
		if paid.Status != "paid" || paid.Issuance == nil || paid.Payment.TxID != id {
			t.Fatal("confirmed payment not admitted")
		}
		initial := string(canonical(paid.Issuance))
		l.pay(b.Contract.PaymentAddress, b.Contract.PriceNMCSat)
		l.mine(1)
		again := refresh(t, f, b.Contract.BookingID)
		if string(canonical(again.Issuance)) != initial || len(again.Receipts) != 2 {
			t.Fatal("duplicate issued again")
		}
		refund := 0
		for _, r := range again.Receipts {
			if r.Disposition == "refund_review" {
				refund++
			}
		}
		if refund != 1 {
			t.Fatal("duplicate not marked refund")
		}
		f.s.Close()
		var e error
		f.s, e = NewService(f.cfg, f.profile, f.provider, l.read, f.s.relay, func() time.Time { return time.Unix(f.now, 0) })
		if e != nil {
			t.Fatal(e)
		}
		after := refresh(t, f, b.Contract.BookingID)
		if string(canonical(after.Issuance)) != initial {
			t.Fatal("restart reissued")
		}
		l.save("advance-confirmed", after)
	})
	t.Run("underpayment_and_wrong_address", func(t *testing.T) {
		l.t = t
		f := l.fixture(t, "advance")
		b := readyBooking(t, f)
		other := f.book(t, "two")
		l.pay(b.Contract.PaymentAddress, b.Contract.PriceNMCSat-1)
		l.pay(other.Contract.PaymentAddress, b.Contract.PriceNMCSat)
		l.mine(1)
		bad := refresh(t, f, b.Contract.BookingID)
		if bad.Issuance != nil || bad.Status != "pending" {
			t.Fatal("under/wrong payment admitted")
		}
		l.pay(b.Contract.PaymentAddress, b.Contract.PriceNMCSat)
		l.mine(1)
		good := refresh(t, f, b.Contract.BookingID)
		if good.Issuance == nil {
			t.Fatal("valid neighbour refused")
		}
		l.save("under-and-wrong", good)
	})
	t.Run("late_payment_expiry_reallocation", func(t *testing.T) {
		l.t = t
		f := l.fixture(t, "advance")
		old := readyBooking(t, f)
		f.now = old.HoldExpiresAt
		newer := readyBooking(t, f)
		l.pay(old.Contract.PaymentAddress, old.Contract.PriceNMCSat)
		l.pay(newer.Contract.PaymentAddress, newer.Contract.PriceNMCSat)
		l.mine(1)
		bad := refresh(t, f, old.Contract.BookingID)
		good, _ := f.s.Get(newer.Contract.BookingID)
		if bad.Issuance != nil || bad.Status != "expired" || good.Issuance == nil {
			t.Fatal("late allocation verdict")
		}
		l.save("late-expired", bad)
		l.save("expiry-neighbour", good)
	})
	t.Run("confirmed_reorg", func(t *testing.T) {
		l.t = t
		f := l.fixture(t, "advance")
		b := readyBooking(t, f)
		l.pay(b.Contract.PaymentAddress, b.Contract.PriceNMCSat)
		block := l.mine(1)
		paid := refresh(t, f, b.Contract.BookingID)
		if paid.Issuance == nil {
			t.Fatal("positive missing")
		}
		l.rpc("", "invalidateblock", block)
		defer l.rpc("", "reconsiderblock", block)
		l.save("invalidated-chaininfo", l.rpc("", "getblockchaininfo"))
		pending := refresh(t, f, b.Contract.BookingID)
		if pending.Payment != nil || pending.Revoke == nil || pending.Revoke.Reason != "payment_reorged" {
			t.Fatal("reorg did not revoke")
		}
		l.rpc("", "reconsiderblock", block)
		l.save("restored-chaininfo", l.rpc("", "getblockchaininfo"))
		again := refresh(t, f, b.Contract.BookingID)
		if again.Revoke == nil || string(canonical(again.Issuance)) != string(canonical(paid.Issuance)) {
			t.Fatal("reorg silently reissued")
		}
		l.save("reorg", again)
	})
	t.Run("start_now_replacement", func(t *testing.T) {
		l.t = t
		f := l.fixture(t, "start_now")
		b := readyBooking(t, f)
		id := l.pay(b.Contract.PaymentAddress, b.Contract.PriceNMCSat)
		paid := refresh(t, f, b.Contract.BookingID)
		if paid.Issuance == nil || paid.Issuance.PaymentHeight != 0 {
			t.Fatal("start-now missing")
		}
		tx := obj(t, l.rpc("", "getrawtransaction", id, true))
		var inputs []map[string]json.RawMessage
		if e := json.Unmarshal(tx["vin"], &inputs); e != nil {
			t.Fatal(e)
		}
		var points []map[string]any
		for _, in := range inputs {
			var vout, seq uint32
			_ = json.Unmarshal(in["vout"], &vout)
			_ = json.Unmarshal(in["sequence"], &seq)
			if seq < 0xfffffffe {
				t.Fatal("original unexpectedly signals RBF")
			}
			points = append(points, map[string]any{"txid": textValue(t, in["txid"]), "vout": vout, "sequence": uint32(0xffffffff)})
		}
		var outs []map[string]json.RawMessage
		_ = json.Unmarshal(tx["vout"], &outs)
		var total int64
		for _, v := range outs {
			a, e := amountSat(v["value"])
			if e != nil {
				t.Fatal(e)
			}
			total += a
		}
		raw := textValue(t, l.rpc("", "createrawtransaction", points, map[string]any{l.miner: amountJSON(total - 1000000)}))
		signed := obj(t, l.rpc("lab", "signrawtransactionwithwallet", raw))
		if string(signed["complete"]) != "true" {
			t.Fatal("replacement not signed")
		}
		replacement := textValue(t, l.rpc("", "sendrawtransaction", textValue(t, signed["hex"])))
		revoked := refresh(t, f, b.Contract.BookingID)
		if revoked.Revoke == nil || revoked.Revoke.Reason != "payment_disappeared" || revoked.Payment != nil || revoked.Issuance.PaymentTxID != id {
			t.Fatal("replacement not revoked")
		}
		l.save("replacement", map[string]any{"original": id, "replacement": replacement, "original_signals_rbf": false, "booking": revoked})
		l.mine(1)
	})
	t.Run("start_now_dropped", func(t *testing.T) {
		l.t = t
		f := l.fixture(t, "start_now")
		b := readyBooking(t, f)
		id := l.pay(b.Contract.PaymentAddress, b.Contract.PriceNMCSat)
		paid := refresh(t, f, b.Contract.BookingID)
		if paid.Issuance == nil {
			t.Fatal("positive missing")
		}
		before := string(canonical(f.s.state))
		l.stop()
		if e := f.s.Refresh(context.Background()); e == nil || e.Error() != "NODE_UNAVAILABLE" || string(canonical(f.s.state)) != before {
			t.Fatalf("outage mutated state: %v", e)
		}
		l.start()
		var pool []string
		_ = json.Unmarshal(l.rpc("", "getrawmempool"), &pool)
		for _, p := range pool {
			if p == id {
				t.Fatal("drop not applied")
			}
		}
		revoked := refresh(t, f, b.Contract.BookingID)
		if revoked.Revoke == nil || revoked.Revoke.Reason != "payment_disappeared" {
			t.Fatal("drop not revoked")
		}
		l.save("dropped", revoked)
	})
	l.t = t
}

// Genuine unrelated witness, 65-input and 257-transaction mempool traffic must
// preserve both an admitted payment and a neighbouring underpayment refusal.
func TestGenuineCoreNoise(t *testing.T) {
	l := newCoreLab(t)
	f := l.fixture(t, "advance")
	paid := readyBooking(t, f)
	unpaid := f.book(t, "two")
	if _, e := f.s.AcceptConsent(context.Background(), unpaid.Contract.BookingID, f.consent(t, unpaid)); e != nil {
		t.Fatal(e)
	}
	l.pay(paid.Contract.PaymentAddress, paid.Contract.PriceNMCSat)
	l.pay(unpaid.Contract.PaymentAddress, unpaid.Contract.PriceNMCSat-1)
	l.mine(1)
	check := func(label string) {
		t.Helper()
		p := refresh(t, f, paid.Contract.BookingID)
		u, _ := f.s.Get(unpaid.Contract.BookingID)
		if p.Status != "paid" || p.Issuance == nil || p.Revoke != nil || u.Status != "pending" || u.Issuance != nil {
			t.Fatalf("noise verdict changed at %s", label)
		}
		l.save(label, map[string]any{"paid": p, "underpaid": u})
	}
	check("clean-neighbours")
	noiseSeed := func(count int, witness bool) []singleuse.Point {
		t.Helper()
		kind := "legacy"
		if witness {
			kind = "bech32"
		}
		address := textValue(t, l.rpc("lab", "getnewaddress", "noise", kind))
		scriptHex := textValue(t, obj(t, l.rpc("lab", "getaddressinfo", address))["scriptPubKey"])
		script, _ := hex.DecodeString(scriptHex)
		tx := singleuse.Transaction{Version: 2}
		for i := 0; i < count; i++ {
			tx.Outputs = append(tx.Outputs, singleuse.Output{Value: 1000000, Script: script})
		}
		funded := obj(t, l.rpc("lab", "fundrawtransaction", hex.EncodeToString(tx.Bytes()), map[string]any{"fee_rate": 200, "changePosition": count}))
		signed := obj(t, l.rpc("lab", "signrawtransactionwithwallet", textValue(t, funded["hex"])))
		if string(signed["complete"]) != "true" {
			t.Fatal("seed sign")
		}
		id := textValue(t, l.rpc("", "sendrawtransaction", textValue(t, signed["hex"])))
		l.mine(1)
		points := make([]singleuse.Point, count)
		for i := range points {
			points[i] = singleuse.Point{TxID: id, Vout: uint32(i)}
		}
		l.rpc("lab", "lockunspent", false, points)
		return points
	}
	spend := func(points []singleuse.Point, witness bool) string {
		t.Helper()
		scriptHex := textValue(t, obj(t, l.rpc("lab", "getaddressinfo", l.miner))["scriptPubKey"])
		script, _ := hex.DecodeString(scriptHex)
		tx := singleuse.Transaction{Version: 2, Outputs: []singleuse.Output{{Value: int64(len(points)) * 800000, Script: script}}}
		for _, p := range points {
			tx.Inputs = append(tx.Inputs, singleuse.Input{Point: p, Sequence: 0xfffffffd})
		}
		signed := obj(t, l.rpc("lab", "signrawtransactionwithwallet", hex.EncodeToString(tx.Bytes())))
		if string(signed["complete"]) != "true" {
			t.Fatal("noise sign")
		}
		raw := textValue(t, signed["hex"])
		if (len(raw) > 12 && raw[8:12] == "0001") != witness {
			t.Fatal("witness control not applied")
		}
		return textValue(t, l.rpc("", "sendrawtransaction", raw))
	}
	witness := noiseSeed(1, true)
	many := noiseSeed(65, false)
	pool := noiseSeed(257, false)
	witnessID := spend(witness, true)
	check("witness-mempool")
	manyID := spend(many, false)
	view := obj(t, l.rpc("", "getrawtransaction", manyID, true))
	var vin []json.RawMessage
	_ = json.Unmarshal(view["vin"], &vin)
	if len(vin) != 65 {
		t.Fatal("65-input plant not applied")
	}
	check("many-input-mempool")
	for _, p := range pool {
		spend([]singleuse.Point{p}, false)
	}
	var mempool []string
	_ = json.Unmarshal(l.rpc("", "getrawmempool"), &mempool)
	if len(mempool) < 259 {
		t.Fatal("large mempool not applied")
	}
	check("large-mempool")
	l.mine(1)
	check("all-noise-confirmed")
	l.save("noise-shapes", map[string]any{"witness_txid": witnessID, "many_input_txid": manyID, "many_input_count": len(vin), "mempool_count": len(mempool), "preserved_admit_and_refusal": true})
	if _, e := l.read.Call(context.Background(), "sendrawtransaction", "00"); e == nil {
		t.Fatal("service route allowed write")
	}
	// Exercise the subprocess adapter used by the service binary as well.
	route := singleuse.OperatorRoute{Network: "regtest", Genesis: singleuse.RegtestGenesis, NodeCLI: l.cli, NodeCLISHA256: "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d", NodeConfig: filepath.Join(l.private, "observer.conf"), NodeDataDir: l.private}
	observerConfig := fmt.Sprintf("rpcuser=%s\nrpcpassword=%s\n[regtest]\nrpcconnect=127.0.0.1\nrpcport=%d\n", l.route.Username, l.route.Password, l.route.Port)
	if e := os.WriteFile(route.NodeConfig, []byte(observerConfig), 0600); e != nil {
		t.Fatal(e)
	}
	operator, e := singleuse.NewOperatorRPC(route, "regtest", singleuse.RegtestGenesis, f.cfg.StateDir)
	if e != nil {
		t.Fatal(e)
	}
	f.s.node = operator
	check("operator-route")
}

// Optional renter names are checked against the actual active Namecoin value;
// another key cannot book under that name, while its real key can.
func TestGenuineCoreRenterName(t *testing.T) {
	l := newCoreLab(t)
	f := l.fixture(t, "advance")
	name := "id/m3-renter"
	var reservation []string
	if e := json.Unmarshal(l.rpc("lab", "name_new", name), &reservation); e != nil {
		t.Fatal(e)
	}
	raw := textValue(t, obj(t, l.rpc("lab", "gettransaction", reservation[0]))["hex"])
	l.rpc("", "sendrawtransaction", raw)
	l.mine(12)
	id := textValue(t, l.rpc("lab", "name_firstupdate", name, reservation[1], reservation[0], string(canonical(map[string]any{"swarma": map[string]string{"nostr_pubkey": keyHex(f.renter)}}))))
	raw = textValue(t, obj(t, l.rpc("lab", "gettransaction", id))["hex"])
	l.rpc("", "sendrawtransaction", raw)
	l.mine(1)
	before := string(canonical(f.s.state))
	if _, e := f.s.Book(context.Background(), BookInput{"one", keyHex(testKey(5)), name, true}); e == nil || e.Error() != "RENTER_NAME_KEY" || string(canonical(f.s.state)) != before {
		t.Fatalf("name key refusal: %v", e)
	}
	b, e := f.s.Book(context.Background(), BookInput{"one", keyHex(f.renter), name, true})
	if e != nil || b.Contract.RenterName != name {
		t.Fatalf("named neighbour: %v", e)
	}
	l.save("named-booking", b)
}

// The built trimpath service runs its real CLI/OperatorRPC/HTTP/polling path:
// book, sign consent, publish to the local relay, confirm on Core, emit once.
func TestGenuineCoreServiceProcess(t *testing.T) {
	if os.Getenv("M3_BOOKING_BIN") == "" {
		t.Skip("M3_BOOKING_BIN required for the actual CLI control")
	}
	l := newCoreLab(t)
	f := l.fixture(t, "advance")
	publisher := f.s.relay.(*RelayPublisher)
	f.s.Close()
	configPath := filepath.Join(l.private, "service-config.json")
	profilePath := filepath.Join(l.private, "service-profile.bin")
	keyPath := filepath.Join(l.private, "service-provider.hex")
	routePath := filepath.Join(l.private, "service-route.json")
	observerConf := filepath.Join(l.private, "service-observer.conf")
	route := singleuse.OperatorRoute{Network: "regtest", Genesis: singleuse.RegtestGenesis, NodeCLI: l.cli, NodeCLISHA256: "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d", NodeConfig: observerConf, NodeDataDir: l.private}
	files := map[string][]byte{configPath: canonical(f.cfg), profilePath: f.profile, keyPath: []byte(hex.EncodeToString(f.provider.Serialize())), routePath: canonical(route), observerConf: []byte(fmt.Sprintf("rpcuser=%s\nrpcpassword=%s\n[regtest]\nrpcconnect=127.0.0.1\nrpcport=%d\n", l.route.Username, l.route.Password, l.route.Port))}
	for path, raw := range files {
		if e := os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	binary := os.Getenv("M3_BOOKING_BIN")
	binaryBytes, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, "-config", configPath, "-profile", profilePath, "-provider-key", keyPath, "-route", routePath, "-listen", "127.0.0.1:0", "-relay", publisher.url, "-poll", "1s")
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	diag, e := os.Create(filepath.Join(l.private, "service.log"))
	if e != nil {
		t.Fatal(e)
	}
	cmd.Stderr = diag
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	pid := cmd.Process.Pid
	if e = os.WriteFile(filepath.Join(l.root, "service.pid"), []byte(fmt.Sprint(pid)), 0600); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		diag.Close()
		l.save("service-process", map[string]any{"pid": pid, "stopped": true, "binary_sha256": Hash(binaryBytes)})
	})
	first := make(chan string, 1)
	go func() {
		scan := bufio.NewScanner(stdout)
		if scan.Scan() {
			first <- scan.Text()
		} else {
			first <- ""
		}
	}()
	var origin string
	select {
	case line := <-first:
		origin = strings.TrimPrefix(line, "listening ")
	case <-time.After(10 * time.Second):
		t.Fatal("service startup timeout")
	}
	if !strings.HasPrefix(origin, "http://127.0.0.1:") {
		t.Fatal("service failed to start; private diagnostic log retained")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	post := func(path string, v any) []byte {
		t.Helper()
		req, _ := http.NewRequest("POST", origin+path, strings.NewReader(string(canonical(v))))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		r, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Body.Close()
		raw, _ := io.ReadAll(r.Body)
		if r.StatusCode >= 400 {
			t.Fatalf("service %s: %d %s", path, r.StatusCode, raw)
		}
		return raw
	}
	var response struct {
		Booking Booking `json:"booking"`
	}
	if e = json.Unmarshal(post("/book", BookInput{"one", keyHex(f.renter), "", true}), &response); e != nil {
		t.Fatal(e)
	}
	b := response.Booking
	consent := Consent(b.Contract, time.Now().Unix())
	if e = consent.Sign(f.renter); e != nil {
		t.Fatal(e)
	}
	post("/consent", map[string]any{"booking_id": b.Contract.BookingID, "event": consent})
	l.pay(b.Contract.PaymentAddress, b.Contract.PriceNMCSat)
	l.mine(1)
	deadline := time.Now().Add(10 * time.Second)
	var final Booking
	for time.Now().Before(deadline) {
		r, e := client.Get(origin + "/booking?id=" + b.Contract.BookingID)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if e = json.Unmarshal(raw, &final); e != nil {
			t.Fatal(e)
		}
		if final.Issuance != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if final.Issuance == nil || !final.Published || final.Status != "paid" {
		t.Fatal("actual service did not issue")
	}
	l.save("service-booking", final)
}

// A payment observed before expiry cannot cause a late first issuance after
// relay recovery. The expired hold releases capacity to a new valid neighbour.
func TestGenuineCoreLateRelay(t *testing.T) {
	l := newCoreLab(t)
	f := l.fixture(t, "advance")
	realRelay := f.s.relay
	f.s.relay = &memoryRelay{fail: true}
	b := f.book(t, "one")
	if _, e := f.s.AcceptConsent(context.Background(), b.Contract.BookingID, f.consent(t, b)); e == nil || e.Error() != "RELAY_UNAVAILABLE" {
		t.Fatalf("relay outage: %v", e)
	}
	l.pay(b.Contract.PaymentAddress, b.Contract.PriceNMCSat)
	l.mine(1)
	before := refresh(t, f, b.Contract.BookingID)
	if before.Status != "paid" || before.Issuance != nil {
		t.Fatal("pre-expiry payment/package state")
	}
	f.now = b.HoldExpiresAt
	f.s.relay = realRelay
	if e := f.s.PublishPending(context.Background()); e != nil {
		t.Fatal(e)
	}
	late := refresh(t, f, b.Contract.BookingID)
	if late.Status != "expired" || late.Issuance != nil || late.Payment != nil || len(late.Receipts) != 1 || late.Receipts[0].Disposition != "refund_review" {
		t.Fatal("late relay retained paid/issued state")
	}
	next := readyBooking(t, f)
	l.pay(next.Contract.PaymentAddress, next.Contract.PriceNMCSat)
	l.mine(1)
	good := refresh(t, f, next.Contract.BookingID)
	if good.Issuance == nil {
		t.Fatal("valid neighbour refused")
	}
	l.save("late-relay", late)
	l.save("late-relay-neighbour", good)
}
