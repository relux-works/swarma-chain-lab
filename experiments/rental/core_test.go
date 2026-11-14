package rental

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

type coreLab struct {
	t                                                                  *testing.T
	root, private, public, daemon, cli, conf, address, script, station string
	node                                                               *exec.Cmd
	log                                                                *os.File
	route                                                              su.Route
	observer                                                           su.Node
	counter                                                            int
	rows                                                               []any
	noWalletBroadcast                                                  bool
}

func text(t *testing.T, b []byte) string {
	t.Helper()
	var s string
	if e := json.Unmarshal(b, &s); e != nil {
		t.Fatal(e)
	}
	return s
}
func object(t *testing.T, b []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if e := json.Unmarshal(b, &m); e != nil {
		t.Fatal(e)
	}
	return m
}
func (l *coreLab) save(name string, v any) {
	l.t.Helper()
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		l.t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(l.public, name), append(b, '\n'), 0600); e != nil {
		l.t.Fatal(e)
	}
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
	l.rows = append(l.rows, map[string]any{"method": method, "exit_ok": e == nil})
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
	if l.noWalletBroadcast {
		l.node.Args = append(l.node.Args, "-walletbroadcast=0")
	}
	l.node.Stdout = l.log
	l.node.Stderr = l.log
	if e = l.node.Start(); e != nil {
		l.t.Fatal(e)
	}
	pid := l.node.Process.Pid
	if e = os.WriteFile(filepath.Join(l.root, "node.pid"), []byte(fmt.Sprint(pid)), 0600); e != nil {
		l.t.Fatal(e)
	}
	l.rows = append(l.rows, map[string]any{"start_pid": pid})
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
	l.rows = append(l.rows, map[string]any{"stopped_pid": pid, "wait_ok": e == nil})
	l.node = nil
}
func newCore(t *testing.T) *coreLab {
	t.Helper()
	if os.Getenv("M1_REGTEST") != "1" {
		t.Skip("requires explicit genuine Core M1_REGTEST=1")
	}
	root := os.Getenv("M1_RUN_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute M1_RUN_ROOT required")
	}
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	l := &coreLab{t: t, root: root, private: filepath.Join(root, "private"), public: filepath.Join(root, "public"), daemon: os.Getenv("M1_CORE_DAEMON"), cli: os.Getenv("M1_CORE_CLI"), station: "id/swarma-station-test"}
	for _, d := range []string{l.private, l.public} {
		if e := os.Mkdir(d, 0700); e != nil {
			t.Fatal(e)
		}
	}
	// Complete upstream Core 28.0 release pairs; never accept mixed binaries.
	daemonBytes, daemonErr := os.ReadFile(l.daemon)
	cliBytes, cliErr := os.ReadFile(l.cli)
	accepted := map[[2]string]bool{
		{"86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f", "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d"}: true,
		{"dc7430676e445af3992430e036f7c1a17bea44f757e9cf25b69205e39625f2f7", "318b6c881c8071abbafd984550172369c3498b4c65c389797350f2d458f085b1"}: true,
	}
	if daemonErr != nil || cliErr != nil || !accepted[[2]string{Hash(daemonBytes), Hash(cliBytes)}] {
		t.Fatal("Core binary pair pin mismatch")
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
	l.route = su.Route{Host: "127.0.0.1", Port: port, Username: "w3-observer", Password: password}
	l.observer, e = su.NewRPC(l.route)
	if e != nil {
		t.Fatal(e)
	}
	l.conf = filepath.Join(l.private, "namecoin.conf")
	cfg := fmt.Sprintf("server=1\ndeprecatedrpc=create_bdb\nlisten=0\ndnsseed=0\ndiscover=0\nnetworkactive=0\ntxindex=1\npersistmempool=0\nfallbackfee=0.002\nacceptnonstdtxn=1\nnameencoding=ascii\nvalueencoding=ascii\nrpcwhitelistdefault=0\nrpcauth=w3-observer:%s$%x\nrpcwhitelist=w3-observer:getblockchaininfo,getblockhash,getblockheader,getrawtransaction,gettxout,name_show,getrawmempool,getblock\n[regtest]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport=%d\n", salt, mac.Sum(nil), port)
	if e = os.WriteFile(l.conf, []byte(cfg), 0600); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.stop(); l.save("commands.json", l.rows) })
	l.start()
	l.rpc("", "createwallet", "issuer", false, false, "", false, false)
	l.address = text(t, l.rpc("issuer", "getnewaddress", "", "legacy"))
	l.script = text(t, object(t, l.rpc("issuer", "getaddressinfo", l.address))["scriptPubKey"])
	l.mine(101)
	var reservation []string
	if e = json.Unmarshal(l.rpc("issuer", "name_new", l.station), &reservation); e != nil {
		t.Fatal(e)
	}
	l.mine(12)
	l.rpc("issuer", "name_firstupdate", l.station, reservation[1], reservation[0], "{}", map[string]string{"destAddress": l.address})
	l.mine(1)
	return l
}
func (l *coreLab) mine(n int) { l.rpc("", "generatetoaddress", n, l.address) }
func (l *coreLab) policy(label string) Policy {
	l.t.Helper()
	l.counter++
	c := testCertificate()
	root := filepath.Join(l.root, fmt.Sprintf("state-%03d-%s", l.counter, label))
	if e := os.Mkdir(root, 0700); e != nil {
		l.t.Fatal(e)
	}
	return Policy{Network: "regtest", Genesis: su.RegtestGenesis, IssuerPubkey: c.IssuerPubkey, AgentPubkey: c.AgentPubkey, StationName: l.station, StationScript: l.script, StateDir: root}
}
func (l *coreLab) fund() su.PlanInput {
	l.t.Helper()
	var list []struct {
		TxID   string      `json:"txid"`
		Vout   uint32      `json:"vout"`
		Amount json.Number `json:"amount"`
		Script string      `json:"scriptPubKey"`
	}
	if e := json.Unmarshal(l.rpc("issuer", "listunspent", 1, 9999999, []string{l.address}), &list); e != nil {
		l.t.Fatal(e)
	}
	for _, u := range list {
		n, e := su.ParseCoins(string(u.Amount))
		if e == nil && n > 10000000 && u.Script == l.script {
			return su.PlanInput{Point: su.Point{TxID: u.TxID, Vout: u.Vout}, ValueSat: n, Script: u.Script, Role: "funding"}
		}
	}
	l.t.Fatal("funding absent")
	return su.PlanInput{}
}
func (l *coreLab) send(raw string, mine bool, burn ...int64) string {
	l.t.Helper()
	signed := object(l.t, l.rpc("issuer", "signrawtransactionwithwallet", raw))
	if string(signed["complete"]) != "true" {
		l.t.Fatal("incomplete signature")
	}
	signedHex := text(l.t, signed["hex"])
	maxBurn := int64(0)
	if len(burn) == 1 {
		maxBurn = burn[0]
	}
	id := text(l.t, l.rpc("", "sendrawtransaction", signedHex, su.Coins(10000000), su.Coins(maxBurn)))
	if mine {
		l.mine(1)
	}
	return id
}
func (l *coreLab) sendPlan(p Plan, mine bool, burn ...int64) string {
	l.t.Helper()
	tx := su.Transaction{Version: p.TransactionVersion}
	for _, i := range p.Inputs {
		tx.Inputs = append(tx.Inputs, su.Input{Point: i.Point, Sequence: 0xfffffffe})
	}
	for _, o := range p.Outputs {
		b, e := hex.DecodeString(o.Script)
		if e != nil {
			l.t.Fatal(e)
		}
		tx.Outputs = append(tx.Outputs, su.Output{Value: o.ValueSat, Script: b})
	}
	return l.send(hex.EncodeToString(tx.Bytes()), mine, burn...)
}
func (l *coreLab) pool(p Policy, mine bool) PoolOutput {
	l.t.Helper()
	plan, e := MakeLegacyPlan(IssuerPolicy{Policy: p}, PlanSpec{Kind: "refill", Inputs: []su.PlanInput{l.fund()}, ChangeScript: l.script, Count: 2, ValueSat: 1000000}, nil, nil, nil, 500)
	if e != nil {
		l.t.Fatal(e)
	}
	id := l.sendPlan(plan, mine)
	l.rpc("issuer", "lockunspent", false, []Point{{id, 0}, {id, 1}})
	pool := PoolOutput{Point: Point{id, 0}, ValueSat: 1000000, Script: l.script}
	if mine {
		v := object(l.t, l.rpc("", "getrawtransaction", id, true))
		pool.Block = text(l.t, v["blockhash"])
		h := object(l.t, l.rpc("", "getblockheader", pool.Block))
		if e = json.Unmarshal(h["height"], &pool.Height); e != nil {
			l.t.Fatal(e)
		}
	}
	l.save(fmt.Sprintf("refill-%03d.json", l.counter), plan)
	return pool
}
func (l *coreLab) anchor(c Certificate, raw []byte, value string, mutate func(*su.Transaction), mine bool) string {
	l.t.Helper()
	n := object(l.t, l.rpc("", "name_show", l.station))
	var vout uint32
	if e := json.Unmarshal(n["vout"], &vout); e != nil {
		l.t.Fatal(e)
	}
	if value == "" {
		var e error
		value, e = NameValue(c, Hash(raw))
		if e != nil {
			l.t.Fatal(e)
		}
	}
	unsigned := text(l.t, l.rpc("", "createrawtransaction", []Point{{text(l.t, n["txid"]), vout}}, []map[string]any{{l.address: su.Coins(1000000)}, {"data": Hash(raw)}}))
	named := object(l.t, l.rpc("", "namerawtransaction", unsigned, 0, map[string]any{"op": "name_update", "name": l.station, "value": value}))
	funded := object(l.t, l.rpc("issuer", "fundrawtransaction", text(l.t, named["hex"]), map[string]any{"fee_rate": 200}))
	unsigned = text(l.t, funded["hex"])
	if mutate != nil {
		b, _ := hex.DecodeString(unsigned)
		tx, e := su.DecodeTransaction(b)
		if e != nil {
			l.t.Fatal(e)
		}
		mutate(tx)
		unsigned = hex.EncodeToString(tx.Bytes())
	}
	return l.send(unsigned, mine)
}
func (l *coreLab) fixture(label string) (Policy, Certificate, []byte, PoolOutput) {
	p := l.policy(label)
	pool := l.pool(p, true)
	c := testCertificate()
	c.Seal = pool.Point
	raw := signTest(l.t, c, 1)
	l.anchor(c, raw, "", nil, true)
	return p, c, raw, pool
}

func (l *coreLab) issueFixture(label string) (Policy, Certificate, []byte, PoolOutput) {
	l.t.Helper()
	p := l.policy(label)
	pool := l.pool(p, true)
	c := testCertificate()
	c.Seal = pool.Point
	id := text(l.t, l.rpc("issuer", "sendtoaddress", l.address, su.Coins(1000000)))
	l.mine(1)
	var payment su.TransactionView
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", id, true), &payment); e != nil {
		l.t.Fatal(e)
	}
	var point Point
	for _, v := range payment.Vout {
		if v.Script.Hex == l.script && int64(v.Value) == 1000000 {
			point = Point{id, v.N}
			break
		}
	}
	if point.TxID == "" {
		l.t.Fatal("payment absent")
	}
	var header su.Header
	if e := json.Unmarshal(l.rpc("", "getblockheader", payment.Block), &header); e != nil {
		l.t.Fatal(e)
	}
	c, req, event := packageFixture(l.t, c, l.address, point, header.Height, payment.Block, "advance")
	raw := signTest(l.t, c, 1)
	request, _ := json.Marshal(req)
	_, provider := testKey(4)
	ip := IssuerPolicy{p, provider}
	a := AdmitIssuance(context.Background(), l.observer, ip, request, eventBytes(event), 500)
	l.save("issuance-admission.json", a)
	if a.Verdict != "admit" {
		l.t.Fatal(a)
	}
	var name su.NameView
	if e := json.Unmarshal(l.rpc("", "name_show", l.station), &name); e != nil {
		l.t.Fatal(e)
	}
	var previous su.TransactionView
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", name.TxID, true), &previous); e != nil {
		l.t.Fatal(e)
	}
	in := previous.Vout[name.Vout]
	spec := PlanSpec{Kind: "issue", Inputs: []su.PlanInput{{Point: su.Point{TxID: name.TxID, Vout: name.Vout}, ValueSat: int64(in.Value), Script: in.Script.Hex, Role: "name"}, l.fund()}, ChangeScript: l.script, Pool: pool}
	plan, e := MakeLegacyPlan(ip, spec, raw, request, eventBytes(event), 500)
	if e != nil {
		l.t.Fatal(e)
	}
	l.save("issue-plan.json", plan)
	l.save("issuance-request.json", req)
	l.save("package-event.json", event)
	l.save("certificate.json", json.RawMessage(raw))
	l.sendPlan(plan, true)
	return p, c, raw, pool
}
func (l *coreLab) check(label string, node su.Node, p Policy, raw []byte, sender string, now int64, want, reason string, closed bool) Receipt {
	l.t.Helper()
	r := CheckLegacy(context.Background(), node, p, raw, l.station, sender, now)
	l.save(label+".json", r)
	if r.Verdict != want || r.Reason != reason || r.Closed != closed {
		l.t.Fatalf("%s: want %s/%s closed%v; %+v", label, want, reason, closed, r)
	}
	return r
}

// The lifecycle uses genuine pinned Core 28 transactions, an isolated wallet,
// and the read-only route. It proves mempool spend closure survives mining,
// kernel reinvocation and node restart; no mainnet or production effect exists.
func TestCoreLifecycle(t *testing.T) {
	l := newCore(t)
	p, c, raw, pool := l.issueFixture("lifecycle")
	l.check("live", l.observer, p, raw, c.GranteePubkey, 500, "live", "LIVE", false)
	plan, e := MakeLegacyPlan(IssuerPolicy{Policy: p}, PlanSpec{Kind: "revoke", Inputs: []su.PlanInput{{Point: su.Point{TxID: pool.Point.TxID, Vout: pool.Point.Vout}, ValueSat: pool.ValueSat, Script: pool.Script, Role: "seal"}}, ChangeScript: l.script, Pool: pool}, nil, nil, nil, 500)
	if e != nil {
		t.Fatal(e)
	}
	l.save("revoke-plan.json", plan)
	l.sendPlan(plan, false)
	l.check("mempool-closed", l.observer, p, raw, c.GranteePubkey, 500, "refused", "SEAL_SPENT", true)
	l.mine(1)
	l.check("mined-closed", l.observer, p, raw, c.GranteePubkey, 500, "refused", "SEAL_SPENT", true)
	l.stop()
	l.start()
	r := l.check("restart-closed", nil, p, raw, c.GranteePubkey, 500, "refused", "SEAL_SPENT", true)
	if r.Calls != 0 {
		t.Fatal("closure reread node")
	}
	l.save("result.json", map[string]any{"status": "PASS", "regtest": true, "closed_survives_restart": true})
}
