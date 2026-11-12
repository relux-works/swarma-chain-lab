package wallet

// PX1 shared G2 test helpers (owner S1; other streams call them, never edit
// them). Unit layer: in-memory fakes of the frozen S2/S3 interfaces, a fake
// authority and a fake wallet node that funds and signs genuine P2PKH
// transactions. Fakes never establish real-Core acceptance; they only let the
// S1 path run before S2/S3 land.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// px1MainParams are the Namecoin mainnet address parameters used by wire.go.
func px1MainParams() *chaincfg.Params {
	p := chaincfg.MainNetParams
	p.PubKeyHashAddrID, p.ScriptHashAddrID, p.PrivateKeyID = 52, 13, 180
	p.Bech32HRPSegwit = "nc"
	return &p
}

// px1MainAddress is testKey(n)'s mainnet P2PKH address.
func px1MainAddress(n byte) string {
	k, _ := testKey(n)
	a, _ := btcutil.NewAddressPubKeyHash(btcutil.Hash160(k.PubKey().SerializeCompressed()), px1MainParams())
	return a.EncodeAddress()
}

// px1TestDay is the test stand-in for S2's UTCDay (same frozen definition).
func px1TestDay(unix int64) string { return time.Unix(unix, 0).UTC().Format(time.DateOnly) }

// fakeJournal is an in-memory JournalV2: Seq assignment, LastTime
// monotonicity (CLOCK_ROLLBACK) and injected append failures that poison it.
type fakeJournal struct {
	header   JournalHeaderV2
	records  []JournalRecordV2
	failKind string // Append of this kind fails and poisons
	poisoned bool
	closed   bool
}

func (j *fakeJournal) Header() JournalHeaderV2 { return j.header }
func (j *fakeJournal) Append(r JournalRecordV2) (JournalRecordV2, error) {
	if j.poisoned {
		return r, fail("JOURNAL_WRITE_UNCERTAIN")
	}
	if n := len(j.records); n > 0 && r.LastTime < j.records[n-1].LastTime {
		return r, fail(CodeClockRollback)
	}
	if r.Kind == j.failKind {
		j.poisoned = true
		return r, fail("JOURNAL_WRITE_UNCERTAIN")
	}
	r.Seq = uint64(len(j.records) + 1)
	r.Inputs = append([]su.Point{}, r.Inputs...)
	j.records = append(j.records, r)
	return r, nil
}
func (j *fakeJournal) Iterate(from uint64, fn func(JournalRecordV2) error) error {
	for _, r := range j.records {
		if r.Seq >= from {
			if e := fn(r); e != nil {
				return e
			}
		}
	}
	return nil
}
func (j *fakeJournal) Usage() JournalUsageV2 {
	u := JournalUsageV2{Segments: 1}
	if n := len(j.records); n > 0 {
		u.LastSeq, u.LastTime = j.records[n-1].Seq, j.records[n-1].LastTime
	}
	return u
}
func (j *fakeJournal) Poisoned() bool { return j.poisoned }
func (j *fakeJournal) Close()         { j.closed = true }

// fakeLedger folds a fakeJournal with the frozen LedgerView rules: the last
// record of each (grant, nonce) decides; reserve, uncertain, refuse-retained,
// complete and track retain the debit; reconcile releases it; a retained
// record counts toward day D if it is reserved or uncertain, or its day is D.
type fakeLedger struct{ last map[[2]string]JournalRecordV2 }

func fakeFold(j JournalV2) (LedgerView, error) {
	l := fakeLedger{last: map[[2]string]JournalRecordV2{}}
	e := j.Iterate(1, func(r JournalRecordV2) error {
		l.last[[2]string{r.GrantID, r.Nonce}] = r
		return nil
	})
	return l, e
}
func (l fakeLedger) retained(r JournalRecordV2) bool { return r.Kind != RecordReconcile }
func (l fakeLedger) SpendUsed(g string) (n int64) {
	for k, r := range l.last {
		if k[0] == g && l.retained(r) {
			n += r.Reserved
		}
	}
	return
}
func (l fakeLedger) DayUsage(g, day string) (used int64, count int) {
	for k, r := range l.last {
		if k[0] == g && l.retained(r) && (r.Phase == "reserved" || r.Phase == "uncertain" || r.Day == day) {
			used += r.Reserved
			count++
		}
	}
	return
}
func (l fakeLedger) UncertainSat(g string) (n int64) {
	for k, r := range l.last {
		if k[0] == g && r.Phase == "uncertain" {
			n += r.Reserved
		}
	}
	return
}
func (l fakeLedger) InputReserved(p su.Point) bool {
	for _, r := range l.last {
		if l.retained(r) && containsPoint(r.Inputs, p) {
			return true
		}
	}
	return false
}

// fixedLedger is a static LedgerView for pure cap-checker tests.
type fixedLedger struct {
	spent, dayUsed, uncertain int64
	dayCount                  int
	day                       string
	inputs                    []su.Point
}

func (l fixedLedger) SpendUsed(string) int64 { return l.spent }
func (l fixedLedger) DayUsage(_, day string) (int64, int) {
	if day != l.day {
		return 0, 0
	}
	return l.dayUsed, l.dayCount
}
func (l fixedLedger) UncertainSat(string) int64     { return l.uncertain }
func (l fixedLedger) InputReserved(p su.Point) bool { return containsPoint(l.inputs, p) }

// fakeCanary excludes exactly its configured outpoint.
type fakeCanary struct{ point su.Point }

func (c fakeCanary) Excluded(p su.Point) bool              { return p == c.point }
func (c fakeCanary) Check(context.Context) (string, error) { return CanaryUnspent, nil }

// px1FakeDeps are the unit-layer stand-ins for the S2/S3 constructors.
func px1FakeDeps(j *fakeJournal) px1Deps {
	return px1Deps{
		openJournal: func(dir, lock string, h JournalHeaderV2, l JournalLimitsV2) (JournalV2, error) {
			if j.header == (JournalHeaderV2{}) {
				j.header = h
			}
			return j, nil
		},
		fold:   fakeFold,
		day:    px1TestDay,
		canary: func(_ su.Node, c CanaryConfig) (Canary, error) { return fakeCanary{c.Outpoint}, nil },
	}
}

// fakeAuthority returns one fixed grant and scripted kernel verdicts: the
// n-th Check returns checks[n] (nil when the script is exhausted).
type fakeAuthority struct {
	grant  Grant
	checks []error
	calls  int
}

func (a *fakeAuthority) Parse([]byte) (Grant, error) { return a.grant, nil }
func (a *fakeAuthority) Check(context.Context, []byte, string, int64) error {
	a.calls++
	if a.calls <= len(a.checks) {
		return a.checks[a.calls-1]
	}
	return nil
}

// fakeChain is a wallet node double: fundrawtransaction picks the first
// offered coin, signing produces genuine P2PKH SIGHASH_ALL signatures, and
// broadcasts are recorded. Every RPC method name is logged in calls.
type fakeChain struct {
	t       *testing.T
	coins   []fakeCoin
	fee     int64
	change  []byte
	sent    []string
	calls   []string
	sendErr error
}
type fakeCoin struct {
	point su.Point
	value int64
	key   *btcec.PrivateKey
}

func fakePoint(n byte) su.Point {
	return su.Point{TxID: strings.Repeat(hex.EncodeToString([]byte{n}), 32), Vout: uint32(n % 4)}
}
func (c *fakeChain) coin(p su.Point) (fakeCoin, bool) {
	for _, x := range c.coins {
		if x.point == p {
			return x, true
		}
	}
	return fakeCoin{}, false
}
func p2pkh(k *btcec.PrivateKey) []byte {
	a, _ := btcutil.NewAddressPubKeyHash(btcutil.Hash160(k.PubKey().SerializeCompressed()), px1MainParams())
	s, _ := txscript.PayToAddrScript(a)
	return s
}
func (c *fakeChain) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	c.calls = append(c.calls, method)
	switch method {
	case "gettxout":
		p := su.Point{TxID: args[0].(string), Vout: args[1].(uint32)}
		x, ok := c.coin(p)
		if !ok {
			return json.RawMessage("null"), nil
		}
		return canonical(map[string]any{"confirmations": 6, "value": su.Coins(x.value), "coinbase": false, "scriptPubKey": map[string]string{"hex": hex.EncodeToString(p2pkh(x.key))}}), nil
	case "fundrawtransaction":
		// An input-less template must be read without the witness marker
		// heuristic (Core does the same).
		b, e := hex.DecodeString(args[0].(string))
		tx := wire.NewMsgTx(2)
		if e == nil {
			e = tx.DeserializeNoWitness(bytes.NewReader(b))
		}
		if e != nil || len(c.coins) == 0 {
			return nil, fail("RPC_FUND")
		}
		x := c.coins[0]
		h, _ := chainhash.NewHashFromStr(x.point.TxID)
		tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(h, x.point.Vout), nil, nil))
		left := x.value - tx.TxOut[0].Value - c.fee
		pos := -1
		if left >= 546 {
			tx.AddTxOut(wire.NewTxOut(left, c.change))
			pos = 1
		}
		return canonical(map[string]any{"hex": rawTx(tx), "fee": su.Coins(c.fee), "changepos": pos}), nil
	case "signrawtransactionwithwallet":
		tx, e := decodeWire(args[0].(string))
		if e != nil {
			return nil, fail("RPC_SIGN")
		}
		for i, in := range tx.TxIn {
			x, ok := c.coin(su.Point{TxID: in.PreviousOutPoint.Hash.String(), Vout: in.PreviousOutPoint.Index})
			if !ok {
				return nil, fail("RPC_SIGN")
			}
			sig, e := txscript.SignatureScript(tx, i, p2pkh(x.key), txscript.SigHashAll, x.key, true)
			if e != nil {
				c.t.Fatal(e)
			}
			tx.TxIn[i].SignatureScript = sig
		}
		return canonical(map[string]any{"hex": rawTx(tx), "complete": true}), nil
	case "sendrawtransaction":
		if c.sendErr != nil {
			return nil, c.sendErr
		}
		tx, e := decodeWire(args[0].(string))
		if e != nil {
			return nil, fail("RPC_SEND")
		}
		c.sent = append(c.sent, tx.TxHash().String())
		return canonical(tx.TxHash().String()), nil
	}
	return nil, errors.New("RPC_METHOD")
}
func (c *fakeChain) called(method string) int {
	n := 0
	for _, m := range c.calls {
		if m == method {
			n++
		}
	}
	return n
}

// px1Lab is one unit-layer G2 wallet: fixture terms and operator block, a
// standing grant committing to the allow fixture, the executor key testKey(9).
type px1Lab struct {
	w       *Wallet
	chain   *fakeChain
	auth    *fakeAuthority
	journal *fakeJournal
	grant   Grant
	terms   []byte
	now     int64
}

const px1Now int64 = 1794000000 // 2026-11-06T21:20:00Z, inside the fixture grant window

// px1Grant is a standing v3-shaped grant that commits to terms bytes.
func px1Grant(terms []byte, budget int64) Grant {
	_, issuer := testKey(1)
	_, grantee := testKey(2)
	return Grant{ID: strings.Repeat("a1", 32), Agent: "id/wallet-agent-test", Landlord: "id/wallet-landlord-test", Grantee: grantee, Issuer: issuer, Contract: Hash(terms), Scope: []string{"pay"}, Budget: budget, NotBefore: px1Now - 86400, NotAfter: px1Now + 30*86400, Seal: fakePoint(0xee)}
}

// newPX1Lab attaches a G2 wallet to the fakes. receipt is the instance's
// receipt x-only key; the fixture terms name px1ExecutorKey.
func newPX1Lab(t *testing.T, terms TermsV2, op G2OperatorConfig, budget int64, receipt string) *px1Lab {
	t.Helper()
	raw := canonical(terms)
	g := px1Grant(raw, budget)
	changeKey, _ := testKey(6)
	chain := &fakeChain{t: t, fee: 2260, change: p2pkh(changeKey)}
	for i := byte(1); i <= 3; i++ {
		k, _ := testKey(10 + i)
		chain.coins = append(chain.coins, fakeCoin{point: fakePoint(i), value: 1000000, key: k})
	}
	auth := &fakeAuthority{grant: g}
	w := &Wallet{config: Config{Version: 1, Network: "main", Genesis: su.MainGenesis, ChangeAddress: px1MainAddress(6), FeeRate: 110, StateDir: "/state/wallet"}, node: chain, wallet: chain, broadcast: chain, authority: auth, clock: func() int64 { return px1Now }}
	w.state = state{Version: 1, Binding: Hash([]byte("px1-unit-wallet")), Records: []Record{}}
	j := &fakeJournal{}
	if e := w.px1AttachWith(op, receipt, px1FakeDeps(j)); e != nil {
		t.Fatal("attach", e)
	}
	return &px1Lab{w: w, chain: chain, auth: auth, journal: j, grant: g, terms: raw, now: px1Now}
}

// request builds a pay request of this lab's grant to address.
func (l *px1Lab) request(address string, amount, feeLimit int64, nonce byte) (Request, []byte) {
	r := Request{Version: 1, GrantID: l.grant.ID, Action: "pay", Nonce: strings.Repeat(hex.EncodeToString([]byte{nonce}), 32), Address: address, Amount: amount, FeeLimit: feeLimit}
	return r, canonical(r)
}

// spend runs the wallet layer of one G2 spend, as the service does.
func (l *px1Lab) spend(r Request, raw []byte, before func(Record) error) Receipt {
	l.w.mu.Lock()
	defer l.w.mu.Unlock()
	return l.w.executeAuthenticated(context.Background(), []byte("grant"), l.terms, r, l.grant.Grantee, l.now-10, raw, "", before)
}

// kinds lists the journal record kinds in Seq order.
func (l *px1Lab) kinds() string {
	var out []string
	for _, r := range l.journal.records {
		out = append(out, r.Kind)
	}
	return strings.Join(out, ",")
}

// noEffect asserts that no reservation and no broadcast happened.
func (l *px1Lab) noEffect(t *testing.T, label string) {
	t.Helper()
	if len(l.journal.records) != 0 || len(l.chain.sent) != 0 || l.chain.called("sendrawtransaction") != 0 {
		t.Fatalf("%s: effect after refusal: records=%s sent=%d", label, l.kinds(), len(l.chain.sent))
	}
}

// ---- Core layer (genuine Namecoin Core 28 regtest, genuine K1 kernel) ----

// px1CorePins are the accepted Core 28.0 executables: the macOS pair the W2
// harness pins (core_test.go) and the Linux x86_64 release pair. A binary
// outside this table never runs.
var px1CorePins = map[[2]string]bool{
	{"86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f", "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d"}: true,
	{"dc7430676e445af3992430e036f7c1a17bea44f757e9cf25b69205e39625f2f7", "318b6c881c8071abbafd984550172369c3498b4c65c389797350f2d458f085b1"}: true,
}

// newPX1Core starts a fresh private regtest node for the G2 Core layer. It is
// the W2 harness (core_test.go) with two differences: witness-ready coins
// (mining and wallet change are native P2WPKH, so seal creation and grant
// issuance satisfy the rental W construction profile), and the binary pin
// table above. Requires W1_REGTEST=1, a fresh absolute W1_RUN_ROOT and
// absolute W1_CORE_CLI / W1_CORE_DAEMON. The node PID is recorded and the
// node is stopped on cleanup.
func newPX1Core(t *testing.T) *coreLab {
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
	d, e1 := os.ReadFile(l.daemon)
	c, e2 := os.ReadFile(l.cli)
	if e1 != nil || e2 != nil || !px1CorePins[[2]string{Hash(d), Hash(c)}] {
		t.Fatal("Core binary pin")
	}
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := ln.Addr().(*net.TCPAddr).Port
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
	l.start()
	l.rpc("", "createwallet", "issuer", false, false, "", false, false)
	l.rpc("", "createwallet", "agent", false, false, "", false, false)
	l.address = text(t, l.rpc("issuer", "getnewaddress", "", "bech32"))
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

// px1CoreGrant is one issued G2 grant on the Core lab.
type px1CoreGrant struct {
	raw    []byte // grant presentation
	terms  []byte // terms v2 bytes committed by contract_sha256
	config Config // wallet config with fresh state, kernel and object dirs
	seal   rental.Point
	id     string
}

// px1RegtestTerms are the smoke-value allow-mode terms on regtest, naming the
// fixture executor key and the regtest addresses of testKey(3) and testKey(5).
func px1RegtestTerms() TermsV2 {
	t := px1TermsAllow()
	t.Network, t.Genesis = "regtest", su.RegtestGenesis
	t.Recipients = []string{testAddress(3), testAddress(5)}
	slices.Sort(t.Recipients)
	return t
}

// px1IssueGrant issues a v3 standing pay grant under the rental W construction
// profile whose contract_sha256 commits to terms (terms v2 bytes). budget nil
// issues a budget-absent grant. The agent wallet receives `coins` P2PKH
// coins of 1 NMC each (confirmed) for spends. The window is [now-100, now+500)
// on the lab clock (l.now, default 500).
func (l *coreLab) px1IssueGrant(terms []byte, budget *int64, coins int) px1CoreGrant {
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
	now := l.now
	if now == 0 {
		now = 500
	}
	c := rental.Grant{Version: 3, Network: "regtest", Genesis: su.RegtestGenesis, AgentName: l.agent, LandlordName: "id/wallet-landlord-test", IssuerKey: issuer, GranteeKey: grantee, ContractSHA256: Hash(terms), Scope: []string{"pay"}, NotBefore: now - 100, NotAfter: now + 500, Seal: seal, Budget: budget}
	consent := Event{Pubkey: grantee, CreatedAt: now - 101, Kind: 8181, Tags: [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", c.ContractSHA256}, {"booking", Hash([]byte("px1-" + id))}, {"privacy", Hash([]byte("privacy"))}}, Content: ""}
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
	for i := 0; i < coins; i++ {
		l.rpc("issuer", "sendtoaddress", text(l.t, l.rpc("agent", "getnewaddress", "", "legacy")), su.Coins(100000000))
	}
	l.mine(1)
	config := Config{Version: 1, Network: "regtest", Genesis: su.RegtestGenesis, Policy: rental.Policy{ConstructionProfile: su.WitnessProfile, Network: "regtest", Genesis: su.RegtestGenesis, AgentName: l.agent, LandlordName: "id/wallet-landlord-test", SealScript: script, StateDir: kernel}, Observer: l.routes["w3-observer"], Wallet: WalletRoute{Route: l.routes["w1-wallet"], Wallet: "agent"}, Broadcast: l.routes["w1-broadcast"], StateDir: root, ObjectsDir: objects, ChangeAddress: change, FeeRate: 110, WalletDir: filepath.Join(l.private, "regtest/wallets/agent"), MemoryZone: filepath.Join(l.root, "memory")}
	return px1CoreGrant{raw: raw, terms: terms, config: config, seal: seal, id: grantID(l.t, raw)}
}

// px1RenewNames re-registers the agent and landlord names with unchanged
// values. Regtest names expire after 30 blocks; without renewal a long Core
// run turns every kernel check into GRANT_NODE_UNAVAILABLE (name_show fails).
func (l *coreLab) px1RenewNames() {
	l.t.Helper()
	_, issuer := testKey(1)
	_, nostr := testKey(3)
	agentValue, e := rental.AgentBindingValue(rental.AgentBinding{Landlord: "id/wallet-landlord-test", Nostr: nostr})
	if e != nil {
		l.t.Fatal(e)
	}
	landlordValue, e := rental.LandlordValue(rental.LandlordBinding{Grant: issuer})
	if e != nil {
		l.t.Fatal(e)
	}
	l.rpc("issuer", "name_update", l.agent, agentValue)
	l.rpc("issuer", "name_update", "id/wallet-landlord-test", landlordValue)
	l.mine(1)
}

// px1OpenG2 opens the genuine wallet of grant g and attaches the G2 profile
// with receipt key `receipt`. Until S2/S3 land, the journal, fold, day and
// canary come from the unit fakes (journal returned for inspection); the
// node, wallet RPC, broadcast route and K1 kernel are genuine.
func (l *coreLab) px1OpenG2(g px1CoreGrant, op G2OperatorConfig, receipt string) (*Wallet, *fakeJournal) {
	l.t.Helper()
	j := &fakeJournal{}
	return l.px1OpenG2With(g, op, receipt, px1FakeDeps(j)), j
}

// px1OpenG2With is px1OpenG2 with explicit S2/S3 constructors: pass
// px1ProductDeps() once S2/S3 land, or fakes of the frozen interfaces.
func (l *coreLab) px1OpenG2With(g px1CoreGrant, op G2OperatorConfig, receipt string, deps px1Deps) *Wallet {
	l.t.Helper()
	w, e := Open(g.config)
	if e != nil {
		l.t.Fatal(e)
	}
	l.t.Cleanup(w.Close)
	now := l.now
	if now == 0 {
		now = 500
	}
	w.clock = func() int64 { return now }
	if e = w.px1AttachWith(op, receipt, deps); e != nil {
		l.t.Fatal("attach", e)
	}
	return w
}

// px1Spend runs the wallet layer of one G2 spend on the Core lab.
func (l *coreLab) px1Spend(w *Wallet, g px1CoreGrant, to string, amount, feeLimit int64, nonce byte, created int64) (Receipt, []byte) {
	l.t.Helper()
	_, grantee := testKey(2)
	r := Request{Version: 1, GrantID: g.id, Action: "pay", Nonce: strings.Repeat(hex.EncodeToString([]byte{nonce}), 32), Address: to, Amount: amount, FeeLimit: feeLimit}
	raw := canonical(r)
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.executeAuthenticated(context.Background(), g.raw, g.terms, r, grantee, created, raw, "", func(Record) error { return nil }), raw
}

// px1QuoteFee asks the agent wallet what fee fundrawtransaction charges for a
// one-output payment at the config fee rate (no effect: nothing is signed).
func (l *coreLab) px1QuoteFee(c Config, to string, amount int64) int64 {
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
	if json.Unmarshal(l.rpc("agent", "fundrawtransaction", rawTx(tx), opts), &funded) != nil {
		l.t.Fatal("fee quote")
	}
	fee, e := su.ParseCoins(funded.Fee.String())
	if e != nil {
		l.t.Fatal(e)
	}
	return fee
}

// px1Mempool is the number of mempool transactions.
func (l *coreLab) px1Mempool() int {
	l.t.Helper()
	var ids []string
	if json.Unmarshal(l.rpc("", "getrawmempool"), &ids) != nil {
		l.t.Fatal("mempool")
	}
	return len(ids)
}

// px1Revoke spends grant g's seal from the issuer wallet (landlord revoke)
// into the mempool, without mining.
func (l *coreLab) px1Revoke(g px1CoreGrant) string {
	l.t.Helper()
	l.rpc("issuer", "lockunspent", true, []rental.Point{g.seal})
	raw := text(l.t, l.rpc("", "createrawtransaction", []map[string]any{{"txid": g.seal.TxID, "vout": g.seal.Vout}}, []map[string]any{{l.address: su.Coins(950000)}}))
	var signed struct {
		Hex      string `json:"hex"`
		Complete bool   `json:"complete"`
	}
	if json.Unmarshal(l.rpc("issuer", "signrawtransactionwithwallet", raw), &signed) != nil || !signed.Complete {
		l.t.Fatal("revoke sign")
	}
	// Core's refusal text is regtest-only diagnostics; it stays in private/.
	cmd := exec.Command(l.cli, "-regtest", "-datadir="+l.private, "-conf="+l.conf, "sendrawtransaction", signed.Hex)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, e := cmd.Output()
	if e != nil {
		os.WriteFile(filepath.Join(l.private, "revoke-error.log"), stderr.Bytes(), 0600)
		l.t.Fatal("revoke broadcast refused; see private/revoke-error.log")
	}
	l.commands = append(l.commands, map[string]any{"method": "sendrawtransaction", "ok": true})
	return strings.TrimSpace(string(out))
}
