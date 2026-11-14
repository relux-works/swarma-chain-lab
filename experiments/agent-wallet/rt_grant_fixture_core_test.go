package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type rtFixtureResult struct {
	GrantID        string          `json:"grant_id"`
	ContractSHA256 string          `json:"contract_sha256"`
	IssuerKey      string          `json:"issuer_key"`
	GranteeKey     string          `json:"grantee_key"`
	ExecutorKey    string          `json:"executor_key"`
	Seal           rental.Point    `json:"seal"`
	AgentName      string          `json:"agent_name"`
	LandlordName   string          `json:"landlord_name"`
	SealScript     string          `json:"seal_script"`
	BudgetSat      int64           `json:"budget_sat"`
	AllowanceSat   int64           `json:"allowance_sat"`
	FeeLimitSat    int64           `json:"fee_limit_sat"`
	Terms          json.RawMessage `json:"terms"`
	Presentation   json.RawMessage `json:"presentation"`
}

// Claim: the built rehearsal CLI creates real names, a locked W seal and a product-valid standing grant; the installed G2 service spends 20000 sat and refuses over-budget and off-list neighbours without a broadcast. Root ownership uses the existing installedRead test seam.
func TestRTGrantFixtureCore(t *testing.T) {
	l := newPX1Core(t)
	canary := l.px1sCanary()
	bin := filepath.Join(l.root, "rt-grant-fixture")
	build := exec.Command("go", "build", "-trimpath", "-o", bin, "./cmd/rt-grant-fixture")
	build.Dir = "../rental"
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("fixture build: %v %s", e, b)
	}
	outDir := filepath.Join(l.root, "fixture")
	_, executor := testKey(9)
	recipient := testAddress(5)
	route := l.routes["w3-observer"]
	args := []string{"--rpc-host", "127.0.0.1", "--rpc-port", fmt.Sprint(route.Port), "--rpc-cookie", filepath.Join(l.private, "regtest", ".cookie"), "--wallet", "issuer", "--out-dir", outDir, "--executor-key", executor, "--recipient", recipient}
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if e := cmd.Run(); e != nil {
		t.Fatalf("fixture exit nonzero: %s", stderr.String())
	}
	var f rtFixtureResult
	raw, e := os.ReadFile(filepath.Join(outDir, "fixture.json"))
	if e != nil || json.Unmarshal(raw, &f) != nil {
		t.Fatal("fixture JSON")
	}
	if stdout.String() != "RT_GRANT_ID "+f.GrantID+"\n" || stderr.Len() != 0 || len(f.GrantID) != 64 {
		t.Fatal("fixture public output")
	}
	if f.AgentName != "id/rt-agent" || f.LandlordName != "id/rt-landlord" || f.ExecutorKey != executor || f.AllowanceSat != 20000 || f.FeeLimitSat != 30000 || f.BudgetSat != 50000 {
		t.Fatal("fixture pins/default parameters")
	}
	if Hash(f.Terms) != f.ContractSHA256 {
		t.Fatal("contract hash")
	}
	for _, name := range []string{f.GrantID, f.ContractSHA256} {
		b, e := os.ReadFile(filepath.Join(outDir, name+".json"))
		if e != nil || (name == f.GrantID && !bytes.Equal(b, f.Presentation)) || (name == f.ContractSHA256 && !bytes.Equal(b, f.Terms)) {
			t.Fatal("object bytes")
		}
	}
	for _, name := range []string{"issuer.key", "grantee.key"} {
		info, e := os.Stat(filepath.Join(outDir, name))
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatal("private key permissions")
		}
		b, e := os.ReadFile(filepath.Join(outDir, name))
		if e != nil {
			t.Fatal("key read")
		}
		// Compare without ever emitting a generated secret in failure diagnostics.
		secret := bytes.TrimSpace(b)
		if bytes.Contains(stdout.Bytes(), secret) || bytes.Contains(stderr.Bytes(), secret) || bytes.Contains(raw, secret) {
			t.Fatal("secret disclosed")
		}
	}
	info, e := os.Stat(outDir)
	if e != nil || info.Mode().Perm() != 0700 {
		t.Fatal("output directory permissions")
	}
	var locks []rental.Point
	if json.Unmarshal(l.rpc("issuer", "listlockunspent"), &locks) != nil {
		t.Fatal("locks")
	}
	found := false
	for _, p := range locks {
		if p == f.Seal {
			found = true
		}
	}
	if !found {
		t.Fatal("seal not locked")
	}
	for _, name := range []string{f.AgentName, f.LandlordName} {
		var n su.NameView
		if json.Unmarshal(l.rpc("", "name_show", name, map[string]string{"nameEncoding": "ascii", "valueEncoding": "ascii"}), &n) != nil || n.ExpiresIn <= 0 {
			t.Fatal("registered name")
		}
		if name == f.AgentName {
			b, e := rental.ParseAgentBinding(n.Value)
			if e != nil || b.Nostr != f.GranteeKey || b.Landlord != f.LandlordName {
				t.Fatal("agent binding")
			}
		} else {
			b, e := rental.ParseLandlordValue(n.Value)
			if e != nil || b.Grant != f.IssuerKey {
				t.Fatal("landlord binding")
			}
		}
	}
	root := filepath.Join(l.root, "consumer")
	mk := func(name string) string {
		p := filepath.Join(root, name)
		if e := os.MkdirAll(p, 0700); e != nil {
			t.Fatal(e)
		}
		return p
	}
	l.rpc("", "createwallet", "rt-hot", false, false, "", false, false)
	change := text(t, l.rpc("rt-hot", "getnewaddress", "", "legacy"))
	for i := 0; i < 2; i++ {
		l.rpc("issuer", "sendtoaddress", text(t, l.rpc("rt-hot", "getnewaddress", "", "legacy")), su.Coins(100000000))
	}
	l.mine(1)
	config := Config{Version: 1, Network: "regtest", Genesis: su.RegtestGenesis, Policy: rental.Policy{ConstructionProfile: su.WitnessProfile, Network: "regtest", Genesis: su.RegtestGenesis, AgentName: f.AgentName, LandlordName: f.LandlordName, SealScript: f.SealScript, StateDir: mk("kernel")}, Observer: l.routes["w3-observer"], Wallet: WalletRoute{Route: l.routes["w1-wallet"], Wallet: "rt-hot"}, Broadcast: l.routes["w1-broadcast"], StateDir: mk("wallet"), ObjectsDir: mk("objects"), ChangeAddress: change, FeeRate: 110, WalletDir: filepath.Join(l.private, "regtest/wallets/rt-hot"), MemoryZone: filepath.Join(l.root, "memory")}
	node, e := su.NewRPC(config.Observer)
	if e != nil {
		t.Fatal(e)
	}
	authority := KernelAuthority{Node: node, Policy: config.Policy}
	now := time.Now().Unix()
	if e = authority.Check(context.Background(), f.Presentation, f.GranteeKey, now); e != nil {
		t.Fatal("KernelAuthority acceptance", e)
	}
	g := px1CoreGrant{raw: f.Presentation, terms: f.Terms, config: config, seal: f.Seal, id: f.GrantID}
	clock := &px1sClock{}
	clock.now.Store(now)
	p := l.px1sInstall(g, canary, uint32(os.Getuid()+1), clock)
	p.config.Grantee = f.GranteeKey
	p.open(t)
	keyBytes, e := os.ReadFile(filepath.Join(outDir, "grantee.key"))
	if e != nil {
		t.Fatal("grantee key read")
	}
	secret, e := hex.DecodeString(strings.TrimSpace(string(keyBytes)))
	if e != nil {
		t.Fatal("grantee key encoding")
	}
	key, _ := btcec.PrivKeyFromBytes(secret)
	send := func(nonce int, to string, amount, feeLimit int64) ActionReceipt {
		r := p.request(nonce, amount, feeLimit)
		r.Grantee = f.GranteeKey
		r.Params = canonical(SpendParams{To: to, Amount: amount, FeeLimit: feeLimit})
		digest, _ := hex.DecodeString(ActionDigest(r))
		sig, e := schnorr.Sign(key, digest)
		if e != nil {
			t.Fatal("request signature")
		}
		receipt, _ := p.send(t, canonical(ActionEnvelope{Request: r, Signature: hex.EncodeToString(sig.Serialize())}))
		return receipt
	}
	before := l.px1Mempool()
	refused := send(1, testAddress(3), 20000, 30000)
	if refused.Verdict != "refused" || refused.Reason != "ADDRESS_NOT_ALLOWED" || l.px1Mempool() != before || p.seqs()[1] != 0 {
		t.Fatal("off-list request changed state", refused.Verdict, refused.Reason)
	}
	valid := send(2, recipient, 20000, 30000)
	if valid.Verdict != "executed" {
		t.Fatal("fixture payment", valid.Verdict, valid.Reason)
	}
	effect := px1sEffectOf(t, valid)
	if !l.px1sInMempool(effect.TxID) || effect.Reserved <= 20000 || effect.Reserved > 50000 {
		t.Fatal("payment effect/fee-inclusive reservation")
	}
	seqs := p.seqs()
	before = l.px1Mempool()
	refused = send(3, recipient, 50000-effect.Reserved+1, effect.Reserved-20000)
	if refused.Verdict != "refused" || refused.Reason != CodeTotalBudgetExceeded || l.px1Mempool() != before || p.seqs()[1] != seqs[1] {
		t.Fatal("over-budget request changed state", refused.Verdict, refused.Reason)
	}
	// The same output dir is a fail-closed rerun and leaves height/mempool unchanged.
	height := l.px1sHeight()
	before = l.px1Mempool()
	again := exec.Command(bin, args...)
	stdout.Reset()
	stderr.Reset()
	again.Stdout = &stdout
	again.Stderr = &stderr
	if e = again.Run(); e == nil || stdout.Len() != 0 || stderr.String() != "rt-grant-fixture: OUT_DIR_EXISTS_OR_UNAVAILABLE\n" || l.px1sHeight() != height || l.px1Mempool() != before {
		t.Fatal("existing-dir rerun wrote")
	}
	// A new output directory cannot take over the already registered fixed names.
	freshArgs := append([]string(nil), args...)
	for i := range freshArgs {
		if freshArgs[i] == outDir {
			freshArgs[i] = filepath.Join(l.root, "second-fixture")
		}
	}
	again = exec.Command(bin, freshArgs...)
	stdout.Reset()
	stderr.Reset()
	again.Stdout = &stdout
	again.Stderr = &stderr
	if e = again.Run(); e == nil || stdout.Len() != 0 || stderr.String() != "rt-grant-fixture: FRESH_NAMES_REQUIRED\n" || l.px1sHeight() != height || l.px1Mempool() != before {
		t.Fatal("fixed-name rerun wrote")
	}
}
