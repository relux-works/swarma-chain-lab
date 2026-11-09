package wallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// The socket frontend retains W1's seal-input exclusion even if the isolated
// fixture wallet holds the public test issuer key; ordinary funding still works.
func TestCoreActionSealFunding(t *testing.T) {
	l := newCore(t)
	k, _ := testKey(1)
	wif, _ := btcutil.NewWIF(k, &chaincfg.RegressionNetParams, true)
	l.rpc("agent", "importprivkey", wif.String(), "", false)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}
	raw, c := l.grant(terms, []string{"pay"}, 1000000)
	id := installActionObjects(t, c, raw, terms)
	f := coreSocket(t, l, c)
	s := f.service
	g, e := s.wallet.Grant(raw)
	if e != nil {
		t.Fatal(e)
	}
	l.rpc("agent", "lockunspent", false, []su.Point{g.Seal})
	txid := text(t, l.rpc("issuer", "sendtoaddress", testAddress(1), su.Coins(1000000)))
	l.mine(1)
	var tx su.TransactionView
	json.Unmarshal(l.rpc("", "getrawtransaction", txid, true), &tx)
	script, _ := addressScript(testAddress(1))
	stray := su.Point{}
	for _, o := range tx.Vout {
		if o.Script.Hex == hex.EncodeToString(script) && int64(o.Value) == 1000000 {
			stray = su.Point{TxID: txid, Vout: o.N}
		}
	}
	if stray.TxID == "" {
		t.Fatal("fixture seal output absent")
	}
	l.rpc("agent", "lockunspent", false, []su.Point{stray})
	r := actionFixture(t, "spend")
	r.Grant.ID = id
	real := s.wallet.wallet
	for i, tc := range []struct {
		point su.Point
		want  string
	}{{g.Seal, "PLAN_RESERVED_INPUT"}, {stray, "PLAN_SEAL_SCRIPT_INPUT"}} {
		r.Nonce = fmt.Sprintf("%032x", i)
		before, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		pool := string(l.rpc("", "getrawmempool"))
		s.mu.Lock()
		s.wallet.wallet = corruptWallet{node: real, mode: "seal-funding", point: tc.point}
		s.mu.Unlock()
		got, _ := socketRequest(t, s, r)
		expectAction(t, got, "refused", tc.want)
		after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		if !bytes.Equal(before, after) || pool != string(l.rpc("", "getrawmempool")) {
			t.Fatal("socket seal refusal effect")
		}
	}
	s.mu.Lock()
	s.wallet.wallet = real
	s.mu.Unlock()
	r.Nonce = fmt.Sprintf("%032x", 2)
	got, _ := socketRequest(t, s, r)
	expectAction(t, got, "executed", "EXECUTED")
}

// A real landlord rotation closes a previously admitted generation across the
// socket, including rollback/restart and rotate-back. Fresh-observer mismatch
// remains distinct. Each refused request has a fresh nonce (terminal replay is
// intentionally stable); the earlier valid single-use payment is a control.
func TestCoreActionRotation(t *testing.T) {
	l := newCore(t)
	_, c := l.grant(Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}, []string{"pay"}, 1000000)
	f := coreSocket(t, l, c)
	s := f.service
	put := func(raw []byte) string {
		id := Hash(raw)
		if e := os.WriteFile(filepath.Join(c.ObjectsDir, id+".json"), raw, 0600); e != nil {
			t.Fatal(e)
		}
		return id
	}
	env, raw := l.oneoff()
	r := actionFixture(t, "spend")
	r.Grant = ActionGrant{"single-use", put(raw)}
	use := l.use(env, canonical(r), 2)
	l.mine(1)
	key, _ := testKey(2)
	b, e := SignAction(r, key, &ActionProof{use})
	if e != nil {
		t.Fatal(e)
	}
	got, _ := socketRaw(t, s, b)
	expectAction(t, got, "executed", "EXECUTED")
	env, raw = l.oneoff()
	id := put(raw)
	sequence := 1
	check := func(id, want string) {
		t.Helper()
		q := r
		q.Grant.ID = id
		q.Nonce = fmt.Sprintf("%032x", sequence)
		sequence++
		before, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		pool := string(l.rpc("", "getrawmempool"))
		got, _ := socketRequest(t, s, q)
		expectAction(t, got, "refused", want)
		after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		if !bytes.Equal(before, after) || pool != string(l.rpc("", "getrawmempool")) {
			t.Fatal("socket rotation refusal effect")
		}
	}
	check(id, "USE_PROOF_REQUIRED")
	_, other := testKey(4)
	value, e := rental.LandlordValue(rental.LandlordBinding{Grant: other})
	if e != nil {
		t.Fatal(e)
	}
	l.rpc("issuer", "name_update", env.Grant.Landlord, value)
	check(id, "PENDING_LANDLORD_ROTATION")
	l.mine(1)
	check(id, "GRANT_KEY_ROTATED")
	block := text(t, l.rpc("", "getbestblockhash"))
	l.rpc("", "invalidateblock", block)
	f.stop()
	w, e := Open(c)
	if e != nil {
		t.Fatal(e)
	}
	w.clock = func() int64 { return 500 }
	receiptKey, _ := testKey(7)
	s, e = openActionService(s.config, w, receiptKey)
	if e != nil {
		w.Close()
		t.Fatal(e)
	}
	s.clock = func() int64 { return 500 }
	stop := runExistingSocket(t, s)
	defer stop()
	check(id, "GRANT_KEY_ROTATED")
	l.rpc("", "reconsiderblock", block)
	_, fresh := l.oneoff()
	freshID := put(fresh)
	check(freshID, "GRANT_KEY_MISMATCH")
	value, e = rental.LandlordValue(rental.LandlordBinding{Grant: env.Grant.Issuer})
	if e != nil {
		t.Fatal(e)
	}
	l.rpc("issuer", "name_update", env.Grant.Landlord, value)
	l.mine(1)
	check(id, "GRANT_KEY_ROTATED")
	check(freshID, "USE_PROOF_REQUIRED")
}
