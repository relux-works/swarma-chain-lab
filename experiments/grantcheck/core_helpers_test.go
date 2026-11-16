package grantcheck

// Test-only laboratory helpers adapted from landed kernelbind/core_e2e_test.go.
// Grants are produced by rental.IssueGrant, never by a synthetic signing shortcut.
import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const coreEpoch int64 = 1700000000

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
	if os.Getenv("CG1_REGTEST") != "1" {
		t.Skip("requires explicit genuine Core CG1_REGTEST=1")
	}
	root := os.Getenv("CG1_RUN_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute CG1_RUN_ROOT required")
	}
	root = filepath.Join(root, strings.ReplaceAll(t.Name(), "/", "-"))
	if e := os.MkdirAll(filepath.Dir(root), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	priv := make([]byte, 32)
	priv[31] = 1
	issuer, issuerPubPoint := btcec.PrivKeyFromBytes(priv)
	l := &coreLab{t: t, root: root, private: filepath.Join(root, "private"),
		daemon: os.Getenv("CG1_CORE_DAEMON"), cli: os.Getenv("CG1_CORE_CLI"),
		issuer: issuer, issuerPub: hex.EncodeToString(schnorr.SerializePubKey(issuerPubPoint)),
		agentNostrPub: agentNostrPub}
	if e := os.Mkdir(l.private, 0700); e != nil {
		t.Fatal(e)
	}
	// Pin complete release pairs; mixed, unlisted or modified executables never start.
	daemonBytes, daemonErr := os.ReadFile(l.daemon)
	cliBytes, cliErr := os.ReadFile(l.cli)
	pair := [2]string{rental.Hash(daemonBytes), rental.Hash(cliBytes)}
	accepted := map[[2]string]bool{
		{"86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f", "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d"}: true,
		{"dc7430676e445af3992430e036f7c1a17bea44f757e9cf25b69205e39625f2f7", "318b6c881c8071abbafd984550172369c3498b4c65c389797350f2d458f085b1"}: true,
	}
	if daemonErr != nil || cliErr != nil || !accepted[pair] {
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
	route := su.Route{Host: "127.0.0.1", Port: port, Username: "w3-observer", Password: su.NewRPCPassword(password)}
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
	l.rpc("", "setmocktime", coreEpoch+500)
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

// grant uses the real terms-v2 issuer and issuance planner on isolated Core.
// The earlier-consent not-before fixture is explicitly re-signed before anchoring.
func (l *coreLab) grant(grantee *nostr.PrivKey, label string, seal rental.Point, confirmed bool, executor ...string) []byte {
	l.t.Helper()
	granteeKey, _ := btcec.PrivKeyFromBytes(grantee.Bytes())
	var terms rental.PayTermsV2
	if err := json.Unmarshal(unitTerms(l.t), &terms); err != nil {
		l.t.Fatal(err)
	}
	if len(executor) > 0 {
		terms.ExecutorKey = executor[0]
	}
	issued, err := rental.IssuePayGrantV2(context.Background(), rental.PayGrantV2Input{
		Network: "regtest", Genesis: su.RegtestGenesis, AgentName: e2eAgentName, LandlordName: e2eLandlordName,
		IssuerKey: l.issuerPub, GranteeKey: grantee.PubKeyHex(), NotBefore: coreEpoch + 200, NotAfter: coreEpoch + 1000,
		Seal: seal, BudgetSat: 1000000, Terms: terms, ConsentCreatedAt: coreEpoch + 200, PrivacyNoticeSHA256: rental.Hash([]byte("regtest privacy")),
	}, labSigner{granteeKey}, labSigner{l.issuer})
	if err != nil {
		l.t.Fatal(err)
	}
	signed, err := rental.ParseSignedGrant(issued.SignedGrant)
	if err != nil {
		l.t.Fatal(err)
	}
	signed.Grant.NotBefore = coreEpoch + 300
	digest, err := signed.Grant.SigningHash()
	if err != nil {
		l.t.Fatal(err)
	}
	signed.Signature = signHash(l.t, l.issuer, digest)
	raw := jsonBytes(l.t, signed)
	funding, fundingScript := l.nativeFunding()
	sealScript, _ := rental.GrantSealScript(l.issuerPub)
	policy := rental.Policy{ConstructionProfile: "W", Network: "regtest", Genesis: su.RegtestGenesis, AgentName: e2eAgentName, LandlordName: e2eLandlordName, SealScript: sealScript, FundingScript: fundingScript, StateDir: l.private}
	spec := rental.PlanSpec{Kind: "grant-issue", Inputs: []su.PlanInput{{Point: su.Point{TxID: funding.TxID, Vout: funding.Vout}, ValueSat: 1000000, Script: fundingScript, Role: "funding"}}, ChangeScript: fundingScript}
	plan, err := rental.MakeGrantIssuancePlan(policy, spec, raw)
	if err != nil {
		l.t.Fatal(err)
	}
	tx := su.Transaction{Version: plan.TransactionVersion}
	for _, in := range plan.Inputs {
		tx.Inputs = append(tx.Inputs, su.Input{Point: in.Point, Sequence: 0xfffffffe})
	}
	for _, out := range plan.Outputs {
		script, err := hex.DecodeString(out.Script)
		if err != nil {
			l.t.Fatal(err)
		}
		tx.Outputs = append(tx.Outputs, su.Output{Value: out.ValueSat, Script: script})
	}
	id := l.send(hex.EncodeToString(tx.Bytes()), confirmed)
	proof, err := rental.PresentIssuedGrant(raw, id)
	if err != nil {
		l.t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(l.root, label+"-presentation.json"), proof, 0600); err != nil {
		l.t.Fatal(err)
	}
	return proof
}

type labSigner struct{ key *btcec.PrivateKey }

func (s labSigner) XOnlyKey() string {
	return hex.EncodeToString(schnorr.SerializePubKey(s.key.PubKey()))
}
func (s labSigner) Sign(ctx context.Context, r rental.PayGrantSigningRequest) (rental.PayGrantSignature, error) {
	if err := ctx.Err(); err != nil {
		return rental.PayGrantSignature{}, err
	}
	if _, err := rental.VerifyPayGrantSigningRequest(r); err != nil {
		return rental.PayGrantSignature{}, err
	}
	digest, err := hex.DecodeString(r.Digest)
	if err != nil {
		return rental.PayGrantSignature{}, err
	}
	sig, err := schnorr.Sign(s.key, digest)
	if err != nil {
		return rental.PayGrantSignature{}, err
	}
	return rental.PayGrantSignature{Version: 1, Purpose: r.Purpose, SignerKey: s.XOnlyKey(), Digest: r.Digest, Signature: hex.EncodeToString(sig.Serialize())}, nil
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
	l.send(unsigned, false)
}
