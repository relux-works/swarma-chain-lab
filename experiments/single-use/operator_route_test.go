package singleuse

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The actual subprocess adapter uses only fixed read argv, literal path refs,
// bounded lifetime and a cleared environment. This offline child is not Core;
// genuine Core coverage is a separate explicitly gated test below.
func TestOperatorRouteSubprocess(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "node-cli")
	cmd := exec.Command("go", "build", "-trimpath", "-o", binary, "./testdata/operator-cli")
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("fixture build %v: %s", e, out)
	}
	b, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	r := OperatorRoute{Network: "main", Genesis: MainGenesis, NodeCLI: binary, NodeCLISHA256: Hash(b), NodeConfig: dir + "/ABSENT-CONFIG", NodeDataDir: dir + "/ABSENT-DATA"}
	n, e := NewOperatorRPC(r, "main", MainGenesis, dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Setenv("W3_OPERATOR_SECRET_CONTROL", "test-only-inheritance-control")
	raw, e := n.Call(context.Background(), "getblockchaininfo")
	if e != nil {
		t.Fatal(e)
	}
	var got struct {
		Argv       []string
		Home, Path string
		Unexpected string `json:"unexpected_env"`
	}
	if e = json.Unmarshal(raw, &got); e != nil {
		t.Fatal(e)
	}
	want := []string{"-conf=" + r.NodeConfig, "-datadir=" + r.NodeDataDir, "-chain=main", "-rpcclienttimeout=2", "getblockchaininfo"}
	if !reflect.DeepEqual(got.Argv, want) || filepath.Dir(got.Home) != dir || got.Path != "/nonexistent" || got.Unexpected != "" {
		t.Fatal(got)
	}
	for _, path := range []string{r.NodeConfig, r.NodeDataDir, got.Home} {
		if _, e = os.Stat(path); !os.IsNotExist(e) {
			t.Fatal("reference accessed/child root retained", path)
		}
	}
	raw, e = n.Call(context.Background(), "getblockhash", 0)
	if e != nil || string(raw) != `"`+MainGenesis+`"` {
		t.Fatal(string(raw), e)
	}
	raw, e = n.Call(context.Background(), "gettxout", "public-tx", 0, true)
	if e != nil || string(raw) != "null" {
		t.Fatal(string(raw), e)
	}
	for _, method := range []string{"sendrawtransaction", "signrawtransactionwithwallet", "getwalletinfo", "stop", "getindexinfo"} {
		if _, e = n.Call(context.Background(), method); publicError(e) != "READ_ONLY_METHOD" {
			t.Fatal(method, e)
		}
	}
	if _, e = n.Call(context.Background(), "name_show", "-rpcwallet=forbidden"); publicError(e) != "RPC_INPUT" {
		t.Fatal(e)
	}
	started := time.Now()
	if _, e = n.Call(context.Background(), "getblock", "slow"); publicError(e) != "RPC_UNAVAILABLE" || time.Since(started) > 3500*time.Millisecond {
		t.Fatal("timeout", e, time.Since(started))
	}
	for _, change := range []func(*OperatorRoute){func(r *OperatorRoute) { r.Genesis = RegtestGenesis }, func(r *OperatorRoute) { r.Network = "" }, func(r *OperatorRoute) { r.NodeCLISHA256 = RegtestGenesis }, func(r *OperatorRoute) { r.NodeConfig = "relative" }} {
		bad := r
		change(&bad)
		if _, e := NewOperatorRPC(bad, "main", MainGenesis, dir); publicError(e) != "OPERATOR_ROUTE" {
			t.Fatal(e)
		}
	}
	if e = os.Chmod(binary, 0777); e != nil {
		t.Fatal(e)
	}
	if _, e = n.Call(context.Background(), "getblockchaininfo"); publicError(e) != "NODE_CLI_PIN" {
		t.Fatal("writable executable", e)
	}
}

// Real Core regtest exercises the same operator subprocess route through a
// complete confirmed use. Mainnet pins/selection are tested offline only.
func TestGenuineCoreOperatorRoute(t *testing.T) {
	l := newCoreLab(t)
	p := l.state(l.newPolicy(), "operator-route")
	l.use(p, "grantee", "ALL", nil, true)
	binary, e := os.ReadFile(l.cli)
	if e != nil {
		t.Fatal(e)
	}
	route := OperatorRoute{Network: "regtest", Genesis: RegtestGenesis, NodeCLI: l.cli, NodeCLISHA256: Hash(binary), NodeConfig: l.conf, NodeDataDir: l.private}
	node, e := NewOperatorRPC(route, p.Network, p.Genesis, p.StateDir)
	if e != nil {
		t.Fatal(e)
	}
	r := Execute(context.Background(), node, p, l.certificate, l.request, time.Now(), nil)
	l.save("operator-route-receipt.json", r)
	if r.Status != "executed" || r.JournalPhase != "complete" || effectCount(t, p) != 1 {
		t.Fatal(r)
	}
	r = Execute(context.Background(), node, p, l.certificate, l.request, time.Now(), nil)
	l.save("operator-route-replay.json", r)
	if r.Status != "already-executed" || r.Calls != 0 || effectCount(t, p) != 1 {
		t.Fatal(r)
	}
	l.save("result.json", map[string]any{"status": "PASS", "scope": "genuine Core operator CLI transport on regtest only", "mainnet_calls": 0})
}

// Mainnet library use is bound to the same operator capability and state root
// as the CLI. HTTP/custom nodes, crossed pins and crossed roots are not routes.
// This checks the capability boundary only, not any mainnet observation.
func TestMainnetCapabilityBinding(t *testing.T) {
	p := Policy{Network: "main", Genesis: MainGenesis, StateDir: "/private/state"}
	good := &OperatorRPC{route: OperatorRoute{Network: "main", Genesis: MainGenesis}, root: p.StateDir}
	if !mainnetRouteBound(good, p) {
		t.Fatal("matching capability refused")
	}
	var nilRoute *OperatorRPC
	for _, bad := range []Node{nilRoute, admissionNode{"main", MainGenesis}, &RPC{}, &OperatorRPC{route: OperatorRoute{Network: "regtest", Genesis: RegtestGenesis}, root: p.StateDir}, &OperatorRPC{route: good.route, root: "/different/state"}} {
		if mainnetRouteBound(bad, p) {
			t.Fatal("crossed or non-operator route admitted")
		}
	}
}

// Execute itself rejects a non-operator mainnet capability before creating any
// journal state. A bound capability reaches the separate public-verifier gate;
// this uses public placeholders and performs no node calls or signing.
func TestExecuteMainnetRouteGate(t *testing.T) {
	s := exampleSpec(t, "use")
	_, script, e := SealScript(s.IssuerKey, s.GranteeKey)
	if e != nil {
		t.Fatal(e)
	}
	cert, req := []byte("public certificate"), []byte("public request")
	p := Policy{Network: "main", Genesis: MainGenesis, Seal: s.Seal, SealScript: hexString(script), IssuerKey: s.IssuerKey, GranteeKey: s.GranteeKey, Anchor: Anchor{TxID: strings.Repeat("44", 32), Block: strings.Repeat("55", 32), Height: 2}, OwnerName: "id/test", OwnerPaymentScript: s.ChangeScript, OwnerSPKI: "owner", RequesterSPKI: "requester", CertificateHash: Hash(cert), VerifierPath: "/ABSENT-PUBLIC-VERIFIER", VerifierHash: strings.Repeat("66", 32), StateDir: t.TempDir()}
	if e := os.Chmod(p.StateDir, 0700); e != nil {
		t.Fatal(e)
	}
	r := Execute(context.Background(), admissionNode{"main", MainGenesis}, p, cert, req, time.Now(), nil)
	entries, e := os.ReadDir(p.StateDir)
	if r.Status != "refused" || r.Reason != "MAINNET_OPERATOR_ROUTE" || r.Calls != 0 || e != nil || len(entries) != 0 {
		t.Fatalf("route must refuse before state: receipt%+v state_entries%d read_error%v", r, len(entries), e)
	}
	bound := &OperatorRPC{route: OperatorRoute{Network: "main", Genesis: MainGenesis}, root: p.StateDir}
	r = Execute(context.Background(), bound, p, cert, req, time.Now(), nil)
	if r.Reason != "VERIFIER_PIN" || r.Calls != 0 {
		t.Fatal("bound capability did not reach next gate", r)
	}
}
