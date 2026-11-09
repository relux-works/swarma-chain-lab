package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	rental "relux.works/swarma-chain-lab/experiments/rental"
)

func modifyGrant(t *testing.T, raw []byte, f func(*rental.Grant)) []byte {
	t.Helper()
	env, e := rental.ParseGrantPresentation(raw)
	if e != nil {
		t.Fatal(e)
	}
	f(&env.SignedGrant.Grant)
	hash, e := env.SignedGrant.Grant.SigningHash()
	if e != nil {
		t.Fatal(e)
	}
	k, _ := testKey(1)
	digest, _ := hex.DecodeString(hash)
	sig, e := schnorr.Sign(k, digest)
	if e != nil {
		t.Fatal(e)
	}
	env.SignedGrant.Signature = hex.EncodeToString(sig.Serialize())
	return canonical(env)
}

// Real Core and the actual kernel supply the valid authority/transaction
// neighbor. Each negative asserts its exact refusal and unchanged wallet state;
// an unavailable wallet endpoint is a genuine Core RPC failure.
func TestCoreWalletControls(t *testing.T) {
	l := newCore(t)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 300000}
	raw, c := l.grant(terms, []string{"pay"}, 300000)
	w, e := Open(c)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	w.clock = func() int64 { return 500 }
	r := testRequest()
	r.GrantID = grantID(t, raw)
	r.Amount = 100000
	r.FeeLimit = 100000
	good := signRequest(t, r, 2)
	ctx := context.Background()
	first := w.Execute(ctx, raw, canonical(terms), good, "")
	if first.Status != "executed" {
		t.Fatalf("positive control %+v", first)
	}
	before, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	pool := string(l.rpc("", "getrawmempool"))
	cases := []struct {
		name, want            string
		grant, terms, request []byte
		now                   int64
	}{
		{"no-grant", "GRANT_INVALID", nil, canonical(terms), good, 500},
		{"malformed-grant", "GRANT_INVALID", []byte("{}"), canonical(terms), good, 500},
		{"contract-mismatch", "CONTRACT_HASH", raw, []byte("{}"), good, 500},
		{"bad-request", "REQUEST_SCHEMA", raw, canonical(terms), []byte("{}"), 500},
		{"unsigned", "REQUEST_SCHEMA", raw, canonical(terms), nil, 500},
	}
	add := func(name, want string, edit func(*Request), signer byte) {
		x := r
		x.Nonce = strings.Repeat("c", 64)
		edit(&x)
		cases = append(cases, struct {
			name, want            string
			grant, terms, request []byte
			now                   int64
		}{name, want, raw, canonical(terms), signRequest(t, x, signer), 500})
	}
	add("other-grantee", "REQUEST_GRANTEE_BINDING", func(*Request) {}, 4)
	add("recipient", "ADDRESS_NOT_ALLOWED", func(x *Request) { x.Address = testAddress(4) }, 2)
	add("amount-cap", "TOTAL_BUDGET_EXCEEDED", func(x *Request) { x.Amount = 300001 }, 2)
	add("cumulative", "TOTAL_BUDGET_EXCEEDED", func(x *Request) { x.Amount = 200000 }, 2)
	add("nonce-conflict", "NONCE_CONFLICT", func(x *Request) { x.Nonce = r.Nonce; x.Amount++ }, 2)
	add("missing-nonce", "REQUEST_FIELDS", func(x *Request) { x.Nonce = "" }, 2)
	add("wrong-grant-id", "REQUEST_GRANTEE_BINDING", func(x *Request) { x.GrantID = strings.Repeat("f", 64) }, 2)
	add("zero-amount", "REQUEST_PAY", func(x *Request) { x.Amount = 0 }, 2)
	add("negative-amount", "REQUEST_PAY", func(x *Request) { x.Amount = -1 }, 2)
	add("huge-fee", "REQUEST_FIELDS", func(x *Request) { x.FeeLimit = MaxFee + 1 }, 2)
	for _, caze := range []struct {
		name, want string
		edit       func(*rental.Grant)
	}{
		{"other-agent", "GRANT_GRANT_POLICY", func(c *rental.Grant) { c.AgentName = "id/other-wallet" }},
		{"empty-scope", "GRANT_SCOPE", func(c *rental.Grant) { c.Scope = []string{} }},
		{"zero-budget", "CONTRACT_BUDGET", func(c *rental.Grant) { n := int64(0); c.Budget = &n }},
	} {
		g := modifyGrant(t, raw, caze.edit)
		x := r
		x.GrantID = grantID(t, g)
		x.Nonce = strings.Repeat("e", 64)
		cases = append(cases, struct {
			name, want            string
			grant, terms, request []byte
			now                   int64
		}{caze.name, caze.want, g, canonical(terms), signRequest(t, x, 2), 500})
	}
	x := r
	x.Nonce = strings.Repeat("e", 64)
	cases = append(cases, struct {
		name, want            string
		grant, terms, request []byte
		now                   int64
	}{"expired", "GRANT_EXPIRED", raw, canonical(terms), signRequest(t, x, 2), 1000})
	for _, caze := range cases {
		t.Run(caze.name, func(t *testing.T) {
			w.clock = func() int64 { return caze.now }
			got := w.Execute(ctx, caze.grant, caze.terms, caze.request, "")
			if got.Status != "refused" || got.Reason != caze.want {
				t.Fatalf("want %s got %+v", caze.want, got)
			}
			after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
			if string(after) != string(before) {
				t.Fatal("refusal mutated wallet journal")
			}
			if string(l.rpc("", "getrawmempool")) != pool {
				t.Fatal("refusal broadcast a transaction")
			}
		})
	}
	w.clock = func() int64 { return 500 }
	real := w.wallet
	missing := c.Wallet
	missing.Wallet = "missing-wallet-fixture"
	w.wallet, e = NewWalletRPC(missing)
	if e != nil {
		t.Fatal(e)
	}
	x.Amount = 1000
	got := w.Execute(ctx, raw, canonical(terms), signRequest(t, x, 2), "")
	w.wallet = real
	if got.Reason != "RPC_RESPONSE" {
		t.Fatalf("wallet outage %+v", got)
	}
	after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	if string(before) != string(after) || pool != string(l.rpc("", "getrawmempool")) {
		t.Fatal("wallet outage changed journal/effects")
	}
	balance, e := w.Balance(ctx)
	if e != nil || balance.Confirmed <= 0 {
		t.Fatal("balance positive", e)
	}
	if _, e = w.Receive(ctx); e != nil {
		t.Fatal(e)
	}
	if rows, e := w.History(ctx); e != nil || len(rows) == 0 {
		t.Fatal("history positive", e)
	}
	l.save("controls.json", map[string]any{"negative_cases": len(cases) + 1, "positive_spend": first, "balance": balance})
}

// Child code is test-only and exits after a genuine durable reservation. No
// production clock or fault-injection environment variable is implemented.
func TestCrashChild(t *testing.T) {
	path := os.Getenv("W1_CRASH_FIXTURE")
	if path == "" {
		t.Skip("process crash child only")
	}
	b, e := os.ReadFile(filepath.Join(path, "config.json"))
	if e != nil {
		t.Fatal(e)
	}
	var c Config
	if json.Unmarshal(b, &c) != nil {
		t.Fatal("config")
	}
	raw, _ := os.ReadFile(filepath.Join(path, "grant.json"))
	terms, _ := os.ReadFile(filepath.Join(path, "terms.json"))
	request, _ := os.ReadFile(filepath.Join(path, "request.json"))
	w, e := Open(c)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	w.clock = func() int64 { return 500 }
	w.hook = func(stage string) {
		if stage == "after-reservation" {
			os.Exit(73)
		}
	}
	w.Execute(context.Background(), raw, terms, request, "")
	t.Fatal("crash hook not reached")
}

// An actual exited process leaves a reservation before any broadcast. Reopening
// returns that reservation and preserves mempool/journal bytes; no retry occurs.
func TestCoreWalletCrash(t *testing.T) {
	l := newCore(t)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}
	raw, c := l.grant(terms, []string{"pay"}, 1000000)
	r := testRequest()
	r.GrantID = grantID(t, raw)
	r.FeeLimit = 100000
	request := signRequest(t, r, 2)
	fixture := filepath.Join(l.private, "crash")
	if e := os.Mkdir(fixture, 0700); e != nil {
		t.Fatal(e)
	}
	for name, b := range map[string][]byte{"config.json": canonical(c), "grant.json": raw, "terms.json": canonical(terms), "request.json": request} {
		if e := os.WriteFile(filepath.Join(fixture, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	beforePool := string(l.rpc("", "getrawmempool"))
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, "-test.run", "^TestCrashChild$")
	cmd.Env = append(os.Environ(), "W1_CRASH_FIXTURE="+fixture)
	e = cmd.Run()
	exit, ok := e.(*exec.ExitError)
	if !ok || exit.ExitCode() != 73 {
		t.Fatal("expected intended process exit73")
	}
	before, e := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	if e != nil {
		t.Fatal("reservation missing after exit73")
	}
	if beforePool != string(l.rpc("", "getrawmempool")) {
		t.Fatal("crash already broadcast")
	}
	w, e := Open(c)
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	w.clock = func() int64 { return 500 }
	got := w.Execute(context.Background(), raw, canonical(terms), request, "")
	if got.Status != "already-executed" || got.Phase != "reserved" {
		t.Fatalf("crash replay %+v", got)
	}
	after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	if string(before) != string(after) || beforePool != string(l.rpc("", "getrawmempool")) {
		t.Fatal("crash replay changed effects")
	}
	l.save("crash-replay.json", got)
}
