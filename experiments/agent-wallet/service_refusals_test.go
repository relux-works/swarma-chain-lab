package wallet

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// W1 grant/contract/time/scope/plan boundaries are exercised through the signed
// socket frontend with actual Core. Admission telemetry may persist, but refused
// requests leave wallet reservations and chain effects unchanged.
func TestCoreActionRefusals(t *testing.T) {
	l := newCore(t)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}
	raw, c := l.grant(terms, []string{"pay"}, 1000000)
	id := installActionObjects(t, c, raw, terms)
	f := coreSocket(t, l, c)
	s := f.service
	base := actionFixture(t, "spend")
	base.Grant.ID = id
	serial := 0
	fresh := func() ActionRequest { serial++; r := base; r.Nonce = Hash([]byte{byte(serial)})[:32]; return r }
	check := func(label, want string, r ActionRequest) {
		t.Helper()
		before, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		pool := string(l.rpc("", "getrawmempool"))
		got, _ := socketRequest(t, s, r)
		expectAction(t, got, "refused", want)
		after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		if !bytes.Equal(before, after) || pool != string(l.rpc("", "getrawmempool")) {
			t.Fatal(label, "socket refusal changed wallet/effect")
		}
	}
	object := filepath.Join(c.ObjectsDir, id+".json")
	os.WriteFile(object, []byte(`{}`), 0600)
	check("malformed-grant", "OBJECT_HASH", fresh())
	os.WriteFile(object, raw, 0600)
	termPath := filepath.Join(c.ObjectsDir, Hash(canonical(terms))+".json")
	os.WriteFile(termPath, []byte(`{}`), 0600)
	check("contract-hash", "CONTRACT_HASH", fresh())
	os.WriteFile(termPath, canonical(terms), 0600)
	r := fresh()
	r.Grant.Kind = "single-use"
	check("kind", "GRANT_KIND", r)
	for _, tc := range []struct {
		name, want string
		edit       func(*rental.Grant)
	}{
		{"other-agent", "GRANT_GRANT_POLICY", func(g *rental.Grant) { g.AgentName = "id/other" }},
		{"scope", "GRANT_SCOPE", func(g *rental.Grant) { g.Scope = []string{} }},
		{"zero-budget", "CONTRACT_BUDGET", func(g *rental.Grant) { n := int64(0); g.Budget = &n }},
	} {
		altered := modifyGrant(t, raw, tc.edit)
		newID := grantID(t, altered)
		os.WriteFile(filepath.Join(c.ObjectsDir, newID+".json"), altered, 0600)
		r := fresh()
		r.Grant.ID = newID
		check(tc.name, tc.want, r)
	}
	r = fresh()
	r.CreatedAt = 950
	s.mu.Lock()
	s.clock = func() int64 { return 1000 }
	s.wallet.clock = func() int64 { return 1000 }
	s.mu.Unlock()
	check("expired", "GRANT_EXPIRED", r)
	s.mu.Lock()
	s.clock = func() int64 { return 500 }
	s.wallet.clock = func() int64 { return 500 }
	s.mu.Unlock()
	r = fresh()
	r.CreatedAt = 501
	check("future-within-skew", "REQUEST_TIME", r)
	for _, tc := range []struct{ action, want string }{{"name-register", "ACTION_UNSUPPORTED"}, {"name-update", "ACTION_UNSUPPORTED"}, {"dump-wallet", "ACTION_UNSUPPORTED"}} {
		r := fresh()
		r.Action = tc.action
		check(tc.action, tc.want, r)
	}
	for _, tc := range []struct{ mode, want string }{{"target", "PLAN_TARGET"}, {"change", "PLAN_CHANGE"}, {"version", "PLAN_SHAPE"}, {"fee-quote", "FEE_LIMIT"}, {"signed-output", "SIGNED_PLAN_CHANGED"}, {"signature", "SIGNED_INPUT_INVALID"}} {
		r := fresh()
		s.mu.Lock()
		original := s.wallet.wallet
		s.wallet.wallet = corruptWallet{node: original, mode: tc.mode}
		s.mu.Unlock()
		check(tc.mode, tc.want, r)
		s.mu.Lock()
		s.wallet.wallet = original
		s.mu.Unlock()
	}
	r = fresh()
	r.Params = canonical(SpendParams{testAddress(3), 100000, 1})
	check("fee-limit", "FEE_LIMIT", r)
	r = fresh()
	s.mu.Lock()
	original := s.wallet.wallet
	missing := c.Wallet
	missing.Wallet = "missing-wallet-fixture"
	var e error
	s.wallet.wallet, e = NewWalletRPC(missing)
	s.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	check("wallet-outage", "RPC_RESPONSE", r)
	s.mu.Lock()
	s.wallet.wallet = original
	s.mu.Unlock()
	got, _ := socketRequest(t, s, fresh())
	expectAction(t, got, "executed", "EXECUTED")
	// A well-signed single-use grant for a different grantee is still not ours.
	one, oneRaw := l.oneoff()
	_, one.Grant.Grantee = testKey(4)
	one.Signature = signDigest(t, OneoffDigest(one.Grant), 1)
	oneRaw = canonical(one)
	oneID := Hash(oneRaw)
	os.WriteFile(filepath.Join(c.ObjectsDir, oneID+".json"), oneRaw, 0600)
	r = fresh()
	r.Grant = ActionGrant{"single-use", oneID}
	check("grant-grantee", "GRANT_GRANTEE_MISMATCH", r)
	l.save("socket-refusals.json", map[string]any{"admitted_controls": serial, "positive": got})
}

// Signed one-off amount, recipient and fee limits cannot be widened by a socket
// request; public locators remain required and the legacy domain stays distinct.
func TestCoreActionOneoffBindings(t *testing.T) {
	l := newCore(t)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}
	_, c := l.grant(terms, []string{"pay"}, 1000000)
	f := coreSocket(t, l, c)
	s := f.service
	env, raw := l.oneoff()
	id := Hash(raw)
	os.WriteFile(filepath.Join(c.ObjectsDir, id+".json"), raw, 0600)
	r := actionFixture(t, "spend")
	r.Grant = ActionGrant{"single-use", id}
	for i, p := range []SpendParams{{testAddress(3), 100001, 100000}, {testAddress(4), 100000, 100000}, {testAddress(3), 100000, 100001}} {
		q := r
		q.Nonce = Hash([]byte{byte(i)})[:32]
		q.Params = canonical(p)
		got, _ := socketRequest(t, s, q)
		expectAction(t, got, "refused", "ONEOFF_REQUEST_BINDING")
	}
	q := r
	q.Nonce = strings.Repeat("b", 32)
	got, _ := socketRequest(t, s, q)
	expectAction(t, got, "refused", "USE_PROOF_REQUIRED")
	bad := env
	bad.Signature = signDigest(t, Hash(canonical(env.Grant)), 1)
	badRaw := canonical(bad)
	badID := Hash(badRaw)
	os.WriteFile(filepath.Join(c.ObjectsDir, badID+".json"), badRaw, 0600)
	q = r
	q.Nonce = strings.Repeat("c", 32)
	q.Grant.ID = badID
	got, _ = socketRequest(t, s, q)
	expectAction(t, got, "refused", "OBJECT_HASH")
	if _, e := os.Stat(filepath.Join(c.StateDir, "wallet.json")); !os.IsNotExist(e) {
		t.Fatal("binding refusal reserved wallet")
	}
	tx := l.use(env, canonical(r), 2)
	l.mine(1)
	var action ActionEnvelope
	json.Unmarshal(actionEnvelope(t, r), &action)
	action.Proof = &ActionProof{tx}
	got, _ = socketRaw(t, s, canonical(action))
	expectAction(t, got, "executed", "EXECUTED")
	l.save("socket-oneoff-bindings.json", got)
}
