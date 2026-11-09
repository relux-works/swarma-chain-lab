package signerservice

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	gs "github.com/relux-works/swarma-chain-lab/experiments/grant-store"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type coreLab struct {
	t                                                 *testing.T
	root, private, public, cli, conf, address, script string
	node                                              *exec.Cmd
	log                                               *os.File
	read, send                                        su.Route
	observer                                          su.Node
	events                                            []any
	cfg                                               Config
	sink                                              *S1Store
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
	var v map[string]json.RawMessage
	if e := json.Unmarshal(b, &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func (l *coreLab) rpc(wallet, method string, args ...any) json.RawMessage {
	l.t.Helper()
	argv := []string{"-regtest", "-datadir=" + l.private, "-conf=" + l.conf}
	if wallet != "" {
		argv = append(argv, "-rpcwallet="+wallet)
	}
	argv = append(argv, method)
	for _, v := range args {
		if s, ok := v.(string); ok {
			argv = append(argv, s)
		} else {
			argv = append(argv, string(encode(v)))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, l.cli, argv...)
	var out, errbuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errbuf
	if e := cmd.Start(); e != nil {
		l.t.Fatal("fixture CLI start", e)
	}
	pid := cmd.Process.Pid
	e := cmd.Wait()
	l.events = append(l.events, map[string]any{"method": method, "pid": pid, "exit_ok": e == nil})
	if e != nil {
		l.t.Fatalf("fixture %s failed: %s", method, errbuf.Bytes())
	}
	b := out.Bytes()
	if !json.Valid(b) {
		b = encode(strings.TrimSpace(string(b)))
	}
	return b
}
func (l *coreLab) mine(n int)              { l.rpc("", "generatetoaddress", n, l.address) }
func (l *coreLab) save(name string, v any) { write(l.t, filepath.Join(l.public, name), encode(v)) }
func newCore(t *testing.T) *coreLab {
	t.Helper()
	if os.Getenv("SG1_REGTEST") != "1" {
		t.Skip("explicit genuine Core SG1_REGTEST=1 required")
	}
	root := os.Getenv("SG1_RUN_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute SG1_RUN_ROOT required")
	}
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	l := &coreLab{t: t, root: root, private: filepath.Join(root, "private"), public: filepath.Join(root, "public"), cli: os.Getenv("SG1_CORE_CLI")}
	for _, d := range []string{l.private, l.public} {
		if e := os.Mkdir(d, 0700); e != nil {
			t.Fatal(e)
		}
	}
	daemon := os.Getenv("SG1_CORE_DAEMON")
	for p, want := range map[string]string{daemon: "86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f", l.cli: "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d"} {
		b, e := os.ReadFile(p)
		if e != nil || hash(b) != want {
			t.Fatal("Core binary pin")
		}
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	rpcAuth := func(user string) (su.Route, string) {
		random := make([]byte, 32)
		if _, e := rand.Read(random); e != nil {
			t.Fatal(e)
		}
		pass := hex.EncodeToString(random)
		salt := hex.EncodeToString(random[:8])
		mac := hmac.New(sha256.New, []byte(salt))
		mac.Write([]byte(pass))
		return su.Route{Host: "127.0.0.1", Port: port, Username: user, Password: pass}, fmt.Sprintf("rpcauth=%s:%s$%x\n", user, salt, mac.Sum(nil))
	}
	var ra, sa string
	l.read, ra = rpcAuth("w3-observer")
	l.send, sa = rpcAuth("sg1-broadcaster")
	l.conf = filepath.Join(l.private, "namecoin.conf")
	conf := "server=1\ndeprecatedrpc=create_bdb\nlisten=0\ndnsseed=0\ndiscover=0\nnetworkactive=0\ntxindex=1\npersistmempool=0\nfallbackfee=0.002\nacceptnonstdtxn=1\nnameencoding=ascii\nvalueencoding=ascii\nrpcwhitelistdefault=0\n" + ra + sa + "rpcwhitelist=w3-observer:getblockchaininfo,getblockhash,getblockheader,getrawtransaction,gettxout,name_show,getrawmempool,getblock\nrpcwhitelist=sg1-broadcaster:sendrawtransaction\n" + fmt.Sprintf("[regtest]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport=%d\n", port)
	write(t, l.conf, []byte(conf))
	l.log, e = os.OpenFile(filepath.Join(l.private, "node.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	l.node = exec.Command(daemon, "-regtest", "-datadir="+l.private, "-conf="+l.conf)
	l.node.Stdout = l.log
	l.node.Stderr = l.log
	if e = l.node.Start(); e != nil {
		t.Fatal(e)
	}
	pid := l.node.Process.Pid
	write(t, filepath.Join(root, "node.pid"), []byte(fmt.Sprint(pid)))
	l.events = append(l.events, map[string]any{"start_pid": pid})
	t.Cleanup(func() {
		_ = l.node.Process.Signal(os.Interrupt)
		e := l.node.Wait()
		l.log.Close()
		l.events = append(l.events, map[string]any{"stopped_pid": pid, "wait_ok": e == nil})
		l.save("commands.json", l.events)
	})
	l.observer, e = su.NewRPC(l.read)
	if e != nil {
		t.Fatal(e)
	}
	ready := false
	for j := 0; j < 100; j++ {
		if _, e = l.observer.Call(context.Background(), "getblockchaininfo"); e == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Core startup")
	}
	l.rpc("", "createwallet", "lab", false, false, "", false, false)
	l.address = text(t, l.rpc("lab", "getnewaddress", "", "legacy"))
	l.script = text(t, object(t, l.rpc("lab", "getaddressinfo", l.address))["scriptPubKey"])
	l.mine(101)
	// These keys are fixture-only. Grant/funding keys are never imported into
	// the node wallet; only the service can sign the enrolled P2PKH outputs.
	l.cfg = config(t)
	landlord, _ := rental.LandlordValue(rental.LandlordBinding{Grant: l.cfg.Policy.Policy.IssuerPubkey})
	agent, _ := rental.AgentBindingValue(rental.AgentBinding{Nostr: l.cfg.Policy.Policy.AgentPubkey, Landlord: l.cfg.Policy.Policy.LandlordName})
	reservations := map[string][]string{}
	for _, name := range []string{l.cfg.Policy.Policy.LandlordName, l.cfg.Policy.Policy.AgentName} {
		var r []string
		json.Unmarshal(l.rpc("lab", "name_new", name), &r)
		reservations[name] = r
	}
	l.mine(12)
	for _, v := range []struct{ name, value string }{{l.cfg.Policy.Policy.LandlordName, landlord}, {l.cfg.Policy.Policy.AgentName, agent}} {
		r := reservations[v.name]
		l.rpc("lab", "name_firstupdate", v.name, r[1], r[0], v.value)
	}
	l.mine(1)
	// The actual S1 server and signed HTTP client are part of the fixture.
	signerBytes, _ := os.ReadFile(l.cfg.GrantKeyPath)
	signer, e := nostr.PrivKeyFromBytes(signerBytes)
	clear(signerBytes)
	if e != nil {
		t.Fatal(e)
	}
	var server *gs.Server
	httpServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { server.ServeHTTP(w, r) }))
	publicURL := "http://" + httpServer.Listener.Addr().String()
	server, e = gs.Open(gs.Config{Root: dir(t), PublicURL: publicURL, Writers: []string{signer.PubKeyHex()}})
	if e != nil {
		t.Fatal(e)
	}
	httpServer.Start()
	t.Cleanup(func() { httpServer.Close(); server.Close() })
	l.sink, e = NewS1Store(publicURL, signer, l.cfg.Policy.Policy.IssuerPubkey, l.cfg.Policy.Policy.AgentPubkey)
	if e != nil {
		t.Fatal(e)
	}
	return l
}
func (l *coreLab) fund(role string, value int64) su.PlanInput {
	l.t.Helper()
	pub := l.cfg.Policy.Policy.IssuerPubkey
	script := l.cfg.Policy.Policy.SealScript
	if role == "funding" {
		_, pub, script = testKey(7)
	}
	info := object(l.t, l.rpc("", "getdescriptorinfo", "pkh(02"+pub+")"))
	var addresses []string
	json.Unmarshal(l.rpc("", "deriveaddresses", text(l.t, info["descriptor"])), &addresses)
	if len(addresses) != 1 {
		l.t.Fatal("descriptor")
	}
	id := text(l.t, l.rpc("lab", "sendtoaddress", addresses[0], su.Coins(value)))
	l.mine(1)
	var tx su.TransactionView
	json.Unmarshal(l.rpc("", "getrawtransaction", id, true), &tx)
	for _, out := range tx.Vout {
		if out.Script.Hex == script && int64(out.Value) == value {
			return su.PlanInput{Point: su.Point{TxID: id, Vout: out.N}, Role: role, ValueSat: value, Script: script}
		}
	}
	l.t.Fatal("fund output")
	return su.PlanInput{}
}
func eventBytes(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.Encode(v)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
func signature(t *testing.T, h string, n byte) string {
	t.Helper()
	k, _, _ := testKey(n)
	b, _ := hex.DecodeString(h)
	s, e := schnorr.Sign(k, b)
	if e != nil {
		t.Fatal(e)
	}
	return hex.EncodeToString(s.Serialize())
}
func event(t *testing.T, e rental.Event, n byte) rental.Event {
	_, e.Pubkey, _ = testKey(n)
	e.ID = hash(eventBytes([]any{0, e.Pubkey, e.CreatedAt, e.Kind, e.Tags, e.Content}))
	e.Sig = signature(t, e.ID, n)
	return e
}
func (l *coreLab) item(label string, confirmed bool) Item {
	l.t.Helper()
	id := text(l.t, l.rpc("lab", "sendtoaddress", l.address, su.Coins(1000000)))
	if confirmed {
		l.mine(1)
	}
	var tx su.TransactionView
	json.Unmarshal(l.rpc("", "getrawtransaction", id, true), &tx)
	var vout uint32
	found := false
	for _, o := range tx.Vout {
		if o.Script.Hex == l.script && int64(o.Value) == 1000000 {
			vout = o.N
			found = true
			break
		}
	}
	if !found {
		l.t.Fatal("payment output")
	}
	var h su.Header
	if confirmed {
		json.Unmarshal(l.rpc("", "getblockheader", tx.Block), &h)
	}
	_, renter, _ := testKey(2)
	_, provider, _ := testKey(4)
	booking := hash([]byte(label))
	p := l.cfg.Policy.Policy
	c := rental.Contract{Version: 1, BookingID: booking, RenterPubkey: renter, AgentPubkey: p.AgentPubkey, StationName: p.AgentName, NotBefore: 100, NotAfter: 1000, Allowed: []string{"pay"}, Forbidden: []string{"deliver", "publish", "repository.push", "secret.release"}, BudgetSat: 1000000, TemplateID: "lab", TemplateSHA256: hash([]byte("template")), ProfileID: "lab", ProfileVersion: "1", ProfileSHA256: hash([]byte("profile")), PriceUSDCents: 100, USDMicrosPerNMC: 100000000, RateAsOf: 100, PriceNMCSat: 1000000, PaymentPolicy: "advance", PaymentAddress: l.address, PrivacySHA256: hash([]byte("privacy"))}
	ch := hash(eventBytes(c))
	consent := event(l.t, rental.Event{CreatedAt: 200, Kind: 8181, Tags: [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", ch}, {"booking", booking}, {"privacy", c.PrivacySHA256}}}, 2)
	pack := rental.Package{Version: 1, Contract: c, Consent: consent, ProviderPubkey: provider, ProviderSignature: signature(l.t, ch, 4), PrivacyAckAt: 100, PrivacySHA256: c.PrivacySHA256, HoldCreatedAt: 100, HoldExpiresAt: 900}
	pub := event(l.t, rental.Event{CreatedAt: 300, Kind: 8182, Tags: [][]string{{"t", "swarma-rental-package-v1"}, {"contract", ch}, {"booking", booking}, {"e", consent.ID}}, Content: string(eventBytes(pack))}, 4)
	req := rental.IssuanceRequest{Version: 1, BookingID: booking, StationName: p.AgentName, AgentPubkey: p.AgentPubkey, RenterPubkey: renter, ContractSHA256: ch, Scope: c.Allowed, BudgetSat: c.BudgetSat, NotBefore: 100, NotAfter: 1000, PaymentPolicy: "advance", PaymentTxID: id, PaymentVout: vout, PaymentHeight: h.Height, PaymentBlockHash: tx.Block, ObservedTipHash: text(l.t, l.rpc("", "getbestblockhash")), PackageEventID: pub.ID}
	return Item{ID: hash([]byte("item/" + label)), Kind: "grant-issue", Request: string(eventBytes(req)), Publication: string(eventBytes(pub))}
}
func (l *coreLab) engine() *Engine {
	l.t.Helper()
	b, e := NewRPCBroadcast(l.send, l.read)
	if e != nil {
		l.t.Fatal(e)
	}
	x, e := Open(l.cfg, V1Issuer{l.cfg.Policy, l.observer, l.cfg.GrantKeyPath}, l.observer, b, l.sink)
	if e != nil {
		l.t.Fatal(e)
	}
	return x
}

// The real private outbox -> K1 -> local P2PKH signer -> own Core broadcast ->
// actual S1 HTTP put path yields a live grant only after commitment mining.
// Its seal is unchanged by issuance, spent once by revoke, and refill creates
// confirmed seals using a funding input whose key is absent from the wallet.
func TestCoreService(t *testing.T) {
	coreService(t, false)
}

// The same real issue/revoke/refill lifecycle additionally exercises configured
// movement/exposure accounting through actual signatures, broadcasts and replay.
// This is isolated regtest, not a live-main admission or custody qualification.
func TestCoreSpending(t *testing.T) {
	coreService(t, true)
}

func coreService(t *testing.T, spending bool) {
	l := newCore(t)
	if spending {
		l.cfg.Spending = &SpendingCaps{MovedPerTx: 1000000, MovedDay: 10000000, EnrolledHot: 2200000}
		l.cfg.Policy.Policy.FeeRate = 200
	}
	ctx := context.Background()
	seal := l.fund("seal", 200000)
	fund := l.fund("funding", 2000000)
	item := l.item("lifecycle", true)
	x := l.engine()
	defer x.Close()
	if e := x.Enroll(ctx, []su.PlanInput{seal, fund}, 500); e != nil {
		t.Fatal(e)
	}
	outbox := dir(t)
	appendItem(t, outbox, nil, item)
	source, e := OpenFileSource(outbox)
	if e != nil {
		t.Fatal(e)
	}
	if e = x.Pull(ctx, source, BookingSource, 500); e != nil {
		t.Fatal(e)
	}
	rows := x.Step(ctx, 500)
	l.save("issue.json", rows)
	if len(rows) != 1 || rows[0].Phase != "stored" || rows[0].Reason != "" {
		t.Fatal("issue", rows)
	}
	op := x.state.Operations[0]
	record, e := x.readRecord(op)
	if e != nil {
		t.Fatal(e)
	}
	proof := append([]byte(nil), record.Presentation...)
	p := l.cfg.Policy.Policy
	p.StateDir = dir(t)
	_, renter, _ := testKey(2)
	before := rental.Check(ctx, l.observer, p, proof, p.AgentName, renter, 500)
	if before.Reason != "ISSUANCE_UNCONFIRMED" {
		t.Fatal("unconfirmed commitment", before)
	}
	l.mine(1)
	live := rental.Check(ctx, l.observer, p, proof, p.AgentName, renter, 500)
	l.save("live.json", live)
	if live.Verdict != "live" {
		t.Fatal("live", live)
	}
	again, e := x.Process(ctx, encode(item), BookingSource, 500)
	if e != nil || again.TxID != record.TxID || len(x.state.Operations) != 1 {
		t.Fatal("exact replay", again, e)
	}
	if e = x.observe(ctx, []su.PlanInput{seal}); e != nil {
		t.Fatal("issuance spent seal", e)
	}
	req := rental.IssuanceRequest{}
	json.Unmarshal([]byte(item.Request), &req)
	revoke := Item{ID: hash([]byte("revoke")), Kind: "revoke", Revoke: &Revoke{Version: 2, BookingID: req.BookingID, ContractSHA256: req.ContractSHA256, Reason: "operator"}}
	revoked, e := x.Process(ctx, encode(revoke), OperatorSource, 501)
	if e != nil || revoked.Phase != "broadcast" {
		t.Fatal("revoke", revoked, e)
	}
	replay, e := x.Process(ctx, encode(revoke), OperatorSource, 501)
	if e != nil || replay.TxID != revoked.TxID || len(x.state.Operations) != 2 {
		t.Fatal("revoke replay", replay, e)
	}
	closed := rental.Check(ctx, l.observer, p, proof, p.AgentName, renter, 501)
	l.save("closed.json", closed)
	if closed.Reason != "SEAL_SPENT" || !closed.Closed {
		t.Fatal("revoke seal", closed)
	}
	l.mine(1)
	refill, e := x.Refill(ctx, 502)
	if e != nil || refill.Phase != "broadcast" {
		t.Fatal("refill", refill, e)
	}
	l.mine(1)
	var outputs []su.PlanInput
	for _, v := range x.state.Inventory {
		if v.Input.Point.TxID == refill.TxID && v.Input.Role == "seal" {
			outputs = append(outputs, v.Input)
		}
	}
	if len(outputs) != l.cfg.Caps.RefillCount {
		t.Fatal("refill count")
	}
	if e = x.observe(ctx, outputs); e != nil {
		t.Fatal("refill outputs", e)
	}
	l.save("result.json", map[string]any{"issuance": rows[0], "revoke": revoked, "refill": refill, "seal_outputs": len(outputs), "status": "PASS"})
	if spending {
		var used, fees int64
		for _, op := range x.state.Operations {
			r, err := x.readRecord(op)
			if err != nil || !terminalSpend(r) || op.SpendAt < op.At {
				t.Fatal("real movement accounting", err)
			}
			used += op.MovedAtoms
			fees += r.Plan.FeeSat
		}
		if used != fees+int64(l.cfg.Caps.RefillCount)*l.cfg.Caps.SealValue {
			t.Fatal("issue/refill/revoke charged amount")
		}
		// Narrow only the in-memory checker after the genuine effects. Its exact
		// boundary permits no further movement, and refusal preserves the ledger.
		x.cfg.Spending.MovedDay = used
		before := encode(x.state)
		wantError(t, x.capSpending(1, 1000, ""), "MOVED_DAY_CAP")
		if !bytes.Equal(before, encode(x.state)) {
			t.Fatal("movement denial changed real ledger")
		}
		l.save("spending.json", map[string]any{"movement_atoms": used, "fees_atoms": fees, "operations": len(x.state.Operations), "replay_operations": 3, "status": "PASS"})
	}
	// Corrupt only this fixture's durable record while recomputing its txid and
	// content hash. Recovery must verify signatures/template, not trust those IDs.
	corrupt := record
	raw, _ := hex.DecodeString(corrupt.RawTx)
	tx, e := su.DecodeTransaction(raw)
	if e != nil {
		t.Fatal(e)
	}
	tx.Outputs[0].Value++
	corrupt.RawTx = hex.EncodeToString(tx.Bytes())
	corrupt.TxID = tx.ID()
	corrupt.Presentation, e = rental.PresentIssuedGrant(corrupt.SignedGrant, corrupt.TxID)
	if e != nil {
		t.Fatal(e)
	}
	if e = x.save(0, corrupt); e != nil {
		t.Fatal(e)
	}
	if _, e = x.readRecord(x.state.Operations[0]); e == nil || e.Error() != "RECORD_TRANSACTION" {
		t.Fatal("corrupt durable transaction accepted", e)
	}

}

// A genuine mempool payment refuses before any grant/reservation and succeeds
// after mining. Expiry during fsync-boundary latency permits no chain signature;
// recovery remains uncertain instead of signing with an old admission result.
func TestCoreAdmissionBoundaries(t *testing.T) {
	l := newCore(t)
	ctx := context.Background()
	seal, fund := l.fund("seal", 200000), l.fund("funding", 2000000)
	item := l.item("unconfirmed", false)
	x := l.engine()
	if e := x.Enroll(ctx, []su.PlanInput{seal, fund}, 500); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(l.cfg.StateDir, "ledger.json"))
	_, e := x.Process(ctx, encode(item), BookingSource, 500)
	wantError(t, e, "payment_unconfirmed")
	after, _ := os.ReadFile(filepath.Join(l.cfg.StateDir, "ledger.json"))
	if !bytes.Equal(before, after) || len(x.state.Operations) != 0 || len(snapshot(t, l.cfg.Policy.Policy.StateDir)) != 0 {
		t.Fatal("unconfirmed payment signed or reserved")
	}
	l.mine(1)
	r, e := x.Process(ctx, encode(item), BookingSource, 500)
	if e != nil || r.Phase != "stored" {
		t.Fatal("confirmed neighbor", r, e)
	}
	x.Close()
	l.renew()
	l.cfg.StateDir = dir(t)
	l.cfg.Policy.Policy.StateDir = dir(t)
	seal, fund = l.fund("seal", 200000), l.fund("funding", 2000000)
	item = l.item("late-admission", true)
	x = l.engine()
	defer x.Close()
	if e = x.Enroll(ctx, []su.PlanInput{seal, fund}, 899); e != nil {
		t.Fatal(e)
	}
	x.boundary = func(stage string) {
		if stage == "signing_uncertain" {
			time.Sleep(1100 * time.Millisecond)
		}
	}
	r, e = x.Process(ctx, encode(item), BookingSource, 899)
	wantError(t, e, "hold_expired_at_admission")
	rec, e := x.readRecord(x.state.Operations[0])
	if e != nil || rec.Phase != "signing_uncertain" || rec.RawTx != "" {
		t.Fatal("expired admission signed tx", r, e)
	}
	x.boundary = nil
	_, e = x.Process(ctx, encode(item), BookingSource, 901)
	wantError(t, e, "SIGNING_UNCERTAIN")
	l.save("admission-boundaries.json", map[string]any{"unconfirmed_no_effect": true, "confirmed_neighbor": true, "expired_before_chain_signature": true, "uncertain_retry_refused": true})
	x.Close()
	l.cfg.StateDir = dir(t)
	l.cfg.Policy.Policy.StateDir = dir(t)
	y := l.engine()
	_, newPub, _ := testKey(9)
	value, _ := rental.LandlordValue(rental.LandlordBinding{Grant: newPub})
	l.rpc("lab", "name_update", l.cfg.Policy.Policy.LandlordName, value)
	l.mine(1)
	wantError(t, y.identity(ctx), "CUSTODY_KEY_ROTATED")
	y.Close()
	value, _ = rental.LandlordValue(rental.LandlordBinding{Grant: l.cfg.Policy.Policy.IssuerPubkey})
	l.rpc("lab", "name_update", l.cfg.Policy.Policy.LandlordName, value)
	l.mine(1)
	y = l.engine()
	defer y.Close()
	wantError(t, y.ready(902), "CUSTODY_KEY_ROTATED")

}
