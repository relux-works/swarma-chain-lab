// Isolated Core bootstrap adapted from rental/core_test.go at 87ff2c02.
// All keys here are deterministic public regtest fixtures, never live custody.
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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type coreLab struct {
	t                                                        *testing.T
	root, private, public, cli, daemon, conf, address, agent string
	node                                                     *exec.Cmd
	log                                                      *os.File
	routes                                                   map[string]su.Route
	commands                                                 []any
	counter                                                  int
	now                                                      int64
}

func text(t *testing.T, b []byte) string {
	t.Helper()
	var s string
	if json.Unmarshal(b, &s) != nil {
		t.Fatal("expected public string")
	}
	return s
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
			argv = append(argv, string(canonical(v)))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, l.cli, argv...).Output()
	l.commands = append(l.commands, map[string]any{"method": method, "ok": e == nil})
	if e != nil {
		l.t.Fatalf("Core %s failed; diagnostics withheld", method)
	}
	if !json.Valid(b) {
		b = canonical(strings.TrimSpace(string(b)))
	}
	return b
}
func (l *coreLab) save(name string, v any) {
	l.t.Helper()
	b, _ := json.MarshalIndent(v, "", "  ")
	if e := os.WriteFile(filepath.Join(l.public, name), append(b, '\n'), 0600); e != nil {
		l.t.Fatal(e)
	}
}
func (l *coreLab) mine(n int) { l.rpc("", "generatetoaddress", n, l.address) }
func (l *coreLab) stop() {
	if l.node == nil {
		return
	}
	pid := l.node.Process.Pid
	l.node.Process.Signal(os.Interrupt)
	e := l.node.Wait()
	l.log.Close()
	l.node = nil
	l.commands = append(l.commands, map[string]any{"stopped_pid": pid, "exit_ok": e == nil})
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
	os.WriteFile(filepath.Join(l.root, "node.pid"), []byte(fmt.Sprint(pid)), 0600)
	l.commands = append(l.commands, map[string]any{"start_pid": pid})
	for i := 0; i < 100; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		e = exec.CommandContext(ctx, l.cli, "-regtest", "-datadir="+l.private, "-conf="+l.conf, "getblockchaininfo").Run()
		cancel()
		if e == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	l.t.Fatal("Core startup timeout")
}
func newCore(t *testing.T) *coreLab {
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
	for p, want := range map[string]string{l.daemon: "86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f", l.cli: "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d"} {
		b, e := os.ReadFile(p)
		if e != nil || Hash(b) != want {
			t.Fatal("Core binary pin")
		}
	}
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	conf := "server=1\ndeprecatedrpc=create_bdb\nlisten=0\ndnsseed=0\ndiscover=0\nnetworkactive=0\ntxindex=1\npersistmempool=0\nfallbackfee=0.002\nacceptnonstdtxn=1\nnameencoding=ascii\nvalueencoding=ascii\nrpcwhitelistdefault=0\n"
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
	l.start()
	l.rpc("", "createwallet", "issuer", false, false, "", false, false)
	l.rpc("", "createwallet", "agent", false, false, "", false, false)
	l.address = text(t, l.rpc("issuer", "getnewaddress", "", "legacy"))
	l.mine(101)
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
func (l *coreLab) grant(t Terms, scope []string, budget int64) ([]byte, Config) {
	l.t.Helper()
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
	_, grantee := testKey(2)
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
	sort.Strings(scope)
	now := l.now
	if now == 0 {
		now = 500
	}
	c := rental.Grant{Version: 3, Network: "regtest", Genesis: su.RegtestGenesis, AgentName: l.agent, LandlordName: "id/wallet-landlord-test", IssuerKey: issuer, GranteeKey: grantee, ContractSHA256: Hash(canonical(t)), Scope: scope, NotBefore: now - 100, NotAfter: now + 500, Seal: seal, Budget: &budget}
	consent := Event{Pubkey: grantee, CreatedAt: now - 101, Kind: 8181, Tags: [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", c.ContractSHA256}, {"booking", Hash([]byte(id))}, {"privacy", Hash([]byte("privacy"))}}, Content: ""}
	consent.ID = consent.Digest()
	consent.Sig = signDigest(l.t, consent.ID, 2)
	var event rental.Event
	json.Unmarshal(canonical(consent), &event)
	c.Consent = rental.GrantConsent{ContractSHA256: c.ContractSHA256, ConsentEvent: event, LandlordSig: signDigest(l.t, c.ContractSHA256, 1)}
	signingHash, e := c.SigningHash()
	if e != nil {
		l.t.Fatal(e)
	}
	signed := rental.SignedGrant{Grant: c, Signature: signDigest(l.t, signingHash, 1)}
	raw := l.issueProof(signed)
	change := text(l.t, l.rpc("agent", "getnewaddress", "", "legacy"))
	l.rpc("issuer", "sendtoaddress", change, su.Coins(100000000))
	l.mine(1)
	config := Config{Version: 1, Network: "regtest", Genesis: su.RegtestGenesis, Policy: rental.Policy{Network: "regtest", Genesis: su.RegtestGenesis, AgentName: l.agent, LandlordName: "id/wallet-landlord-test", SealScript: script, StateDir: kernel}, Observer: l.routes["w3-observer"], Wallet: WalletRoute{Route: l.routes["w1-wallet"], Wallet: "agent"}, Broadcast: l.routes["w1-broadcast"], StateDir: root, ObjectsDir: objects, ChangeAddress: change, FeeRate: 200, WalletDir: filepath.Join(l.private, "regtest/wallets/agent"), MemoryZone: filepath.Join(l.root, "memory")}
	return raw, config
}

// Genuine Core + the actual K1 kernel: a signed in-scope request produces one
// actual wallet transaction with charged fees; replay is durable across reopen.
// Snapshot evidence remains development-only until its dependency is signed/reviewed.
func TestCoreWalletSpend(t *testing.T) {
	l := newCore(t)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 10000000, NameCap: 0, NameCount: 0}
	raw, c := l.grant(terms, []string{"pay"}, 10000000)
	w, e := Open(c)
	if e != nil {
		t.Fatal(e)
	}
	w.clock = func() int64 { return 500 }
	defer func() {
		if w != nil {
			w.Close()
		}
	}()
	r := testRequest()
	r.GrantID = grantID(t, raw)
	r.Amount = 100000
	r.FeeLimit = 100000
	request := signRequest(t, r, 2)
	got := w.Execute(context.Background(), raw, canonical(terms), request, "")
	l.save("spend.json", got)
	if got.Status != "executed" {
		t.Fatalf("want executed got %+v", got)
	}
	if got.Reserved <= r.Amount || got.Reserved > r.Amount+r.FeeLimit {
		t.Fatal("fee-inclusive debit")
	}
	var view su.TransactionView
	if json.Unmarshal(l.rpc("", "getrawtransaction", got.TxID, true), &view) != nil {
		t.Fatal("effect transaction")
	}
	if len(view.Vout) != 2 {
		t.Fatal("effect shape")
	}
	before, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	w.Close()
	w = nil
	w, e = Open(c)
	if e != nil {
		t.Fatal(e)
	}
	w.clock = func() int64 { return 500 }
	again := w.Execute(context.Background(), raw, canonical(terms), request, "")
	if again.Status != "already-executed" || again.TxID != got.TxID {
		t.Fatalf("replay %+v", again)
	}
	after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	if string(before) != string(after) {
		t.Fatal("replay changed journal")
	}
	l.save("replay.json", again)
}

func signDigest(t *testing.T, id string, key byte) string {
	t.Helper()
	k, _ := testKey(key)
	b, _ := hex.DecodeString(id)
	s, e := schnorr.Sign(k, b)
	if e != nil {
		t.Fatal(e)
	}
	return hex.EncodeToString(s.Serialize())
}
func grantID(t *testing.T, raw []byte) string {
	t.Helper()
	p, e := rental.ParseGrantPresentation(raw)
	if e != nil {
		t.Fatal(e)
	}
	return p.SignedGrant.ID()
}
func (l *coreLab) issueProof(s rental.SignedGrant) []byte {
	l.t.Helper()
	commitment, e := rental.IssuanceCommitment(s)
	if e != nil {
		l.t.Fatal(e)
	}
	tx := text(l.t, l.rpc("", "createrawtransaction", []any{}, []map[string]any{{"data": commitment}}))
	var funded struct {
		Hex string `json:"hex"`
	}
	if json.Unmarshal(l.rpc("issuer", "fundrawtransaction", tx, map[string]any{"fee_rate": 200}), &funded) != nil {
		l.t.Fatal("issuance fund")
	}
	var sig struct {
		Hex      string `json:"hex"`
		Complete bool   `json:"complete"`
	}
	if json.Unmarshal(l.rpc("issuer", "signrawtransactionwithwallet", funded.Hex), &sig) != nil || !sig.Complete {
		l.t.Fatal("issuance sign")
	}
	id := text(l.t, l.rpc("", "sendrawtransaction", sig.Hex))
	l.mine(1)
	raw, e := rental.PresentIssuedGrant(canonical(s), id)
	if e != nil {
		l.t.Fatal(e)
	}
	return raw
}
