package wallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func (l *coreLab) oneoff() (OneoffEnvelope, []byte) {
	l.t.Helper()
	_, issuer := testKey(1)
	_, grantee := testKey(2)
	redeem, payment, e := su.SealScript("02"+issuer, "02"+grantee)
	if e != nil {
		l.t.Fatal(e)
	}
	a, e := btcutil.NewAddressScriptHash(redeem, &chaincfg.RegressionNetParams)
	if e != nil {
		l.t.Fatal(e)
	}
	// The one-off seal is a legacy W3 construction: its funding transaction must
	// carry no witness. It is funded from the legacy-only oneoff wallet with
	// legacy change, never from the witness-ready issuer coins (newCore).
	unfunded := text(l.t, l.rpc("", "createrawtransaction", []any{}, []map[string]any{{a.EncodeAddress(): su.Coins(1000000)}}))
	var funded struct {
		Hex string `json:"hex"`
	}
	if json.Unmarshal(l.rpc("oneoff", "fundrawtransaction", unfunded, map[string]any{"fee_rate": 200, "change_type": "legacy"}), &funded) != nil {
		l.t.Fatal("oneoff fund")
	}
	var signed struct {
		Hex      string `json:"hex"`
		Complete bool   `json:"complete"`
	}
	if json.Unmarshal(l.rpc("oneoff", "signrawtransactionwithwallet", funded.Hex), &signed) != nil || !signed.Complete {
		l.t.Fatal("oneoff sign")
	}
	id := text(l.t, l.rpc("", "sendrawtransaction", signed.Hex))
	l.mine(1)
	var tx su.TransactionView
	if json.Unmarshal(l.rpc("", "getrawtransaction", id, true), &tx) != nil {
		l.t.Fatal("oneoff funding")
	}
	seal := su.Point{}
	for _, o := range tx.Vout {
		if o.Script.Hex == hex.EncodeToString(payment) {
			seal = su.Point{TxID: id, Vout: o.N}
		}
	}
	if seal.TxID == "" {
		l.t.Fatal("seal absent")
	}
	g := OneoffGrant{Version: 1, Network: "regtest", Genesis: su.RegtestGenesis, Agent: l.agent, Landlord: "id/wallet-landlord-test", Issuer: issuer, Grantee: grantee, Address: testAddress(3), Amount: 100000, FeeLimit: 100000, NotBefore: 400, NotAfter: 1000, Seal: seal}
	env := OneoffEnvelope{Grant: g, Signature: signDigest(l.t, OneoffDigest(g), 1)}
	return env, canonical(env)
}
func (l *coreLab) use(env OneoffEnvelope, request []byte, signer byte) string {
	l.t.Helper()
	g := env.Grant
	redeem, _, e := su.SealScript("02"+g.Issuer, "02"+g.Grantee)
	if e != nil {
		l.t.Fatal(e)
	}
	h, e := chainhash.NewHashFromStr(g.Seal.TxID)
	if e != nil {
		l.t.Fatal(e)
	}
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(h, g.Seal.Vout), nil, nil))
	commit, _ := hex.DecodeString(Hash(request))
	data, _ := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN).AddData(commit).Script()
	payment := l.payoutScript()
	tx.AddTxOut(wire.NewTxOut(0, data))
	tx.AddTxOut(wire.NewTxOut(970000, payment))
	k, _ := testKey(signer)
	if k.PubKey().SerializeCompressed()[0] != 2 {
		l.t.Fatal("fixture requires even key")
	}
	sig, e := txscript.RawTxInSignature(tx, 0, redeem, txscript.SigHashAll, k)
	if e != nil {
		l.t.Fatal(e)
	}
	tx.TxIn[0].SignatureScript, e = txscript.NewScriptBuilder().AddOp(txscript.OP_0).AddData(sig).AddData(redeem).Script()
	if e != nil {
		l.t.Fatal(e)
	}
	return text(l.t, l.rpc("", "sendrawtransaction", rawTx(tx)))
}

// Real W3 seal signatures/commitments and K1 landlord resolution gate an actual
// wallet payment. Mempool, wrong request, issuer revocation and repeats cause
// no new wallet effect; standalone accounting does not debit the rental grant.
func TestCoreOneoff(t *testing.T) {
	l := newCore(t)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}
	rentalRaw, c := l.grant(terms, []string{"pay"}, 1000000)
	w, e := Open(c)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { w.Close() }()
	w.clock = func() int64 { return 500 }
	ctx := context.Background()
	env, raw := l.oneoff()
	r := testRequest()
	r.GrantID = Hash(raw)
	r.Amount = env.Grant.Amount
	r.FeeLimit = env.Grant.FeeLimit
	request := signRequest(t, r, 2)
	check := func(label string, g, req []byte, txid, status, reason string) {
		t.Helper()
		before, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		pool := string(l.rpc("", "getrawmempool"))
		got := w.Execute(ctx, g, nil, req, txid)
		if got.Status != status || got.Reason != reason {
			t.Fatalf("%s want %s/%s got %+v", label, status, reason, got)
		}
		after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		if string(before) != string(after) || pool != string(l.rpc("", "getrawmempool")) {
			t.Fatal(label, "mutated journal/effects")
		}
		l.save(label+".json", got)
	}
	check("missing-use", raw, request, "", "refused", "USE_PROOF_REQUIRED")
	untagged := env
	untagged.Signature = signDigest(t, Hash(canonical(env.Grant)), 1)
	check("oneoff-untagged", canonical(untagged), request, "", "refused", "ONEOFF_SIGNATURE")
	x := r
	x.Amount++
	check("oneoff-exact-amount", raw, signRequest(t, x, 2), "", "refused", "ONEOFF_REQUEST_BINDING")
	x = r
	x.Address = testAddress(4)
	check("oneoff-exact-recipient", raw, signRequest(t, x, 2), "", "refused", "ONEOFF_REQUEST_BINDING")
	x = r
	x.FeeLimit++
	check("oneoff-fee-limit", raw, signRequest(t, x, 2), "", "refused", "ONEOFF_REQUEST_BINDING")
	use := l.use(env, request, 2)
	check("mempool-use", raw, request, use, "pending", "USE_PENDING")
	l.mine(1)
	x = r
	x.Nonce = strings.Repeat("c", 64)
	check("wrong-commitment", raw, signRequest(t, x, 2), use, "refused", "REQUEST_COMMITMENT")
	got := w.Execute(ctx, raw, nil, request, use)
	if got.Status != "executed" {
		t.Fatalf("confirmed use %+v", got)
	}
	l.save("oneoff-executed.json", got)
	check("oneoff-replay", raw, request, use, "already-executed", "DURABLE_RESERVATION_NO_RETRY")
	check("second-request", raw, signRequest(t, x, 2), use, "refused", "REQUEST_COMMITMENT")
	b, e := w.Budget(ctx, rentalRaw, canonical(terms))
	if e != nil || b.SpendReserved != 0 || b.NameReserved != 0 || b.TotalRemaining != 1000000 {
		t.Fatalf("independent rental allowance %+v %v", b, e)
	}
	env2, raw2 := l.oneoff()
	x = r
	x.GrantID = Hash(raw2)
	x.Nonce = strings.Repeat("d", 64)
	req2 := signRequest(t, x, 2)
	revoke := l.use(env2, req2, 1)
	l.mine(1)
	check("issuer-revoked", raw2, req2, revoke, "refused", "USE_ISSUER_REVOKED")
	// Admit a fresh grant generation, then observe a pending and confirmed
	// landlord rotation. Returning to the old key cannot reopen the grant.
	env3, raw3 := l.oneoff()
	x.GrantID = Hash(raw3)
	req3 := signRequest(t, x, 2)
	check("rotation-admit", raw3, req3, "", "refused", "USE_PROOF_REQUIRED")
	_, other := testKey(4)
	value, e := rental.LandlordValue(rental.LandlordBinding{Grant: other})
	if e != nil {
		t.Fatal(e)
	}
	l.rpc("issuer", "name_update", env3.Grant.Landlord, value)
	check("rotation-pending", raw3, req3, "", "refused", "PENDING_LANDLORD_ROTATION")
	l.mine(1)
	check("rotation-confirmed", raw3, req3, "", "refused", "GRANT_KEY_ROTATED")
	rotationBlock := text(t, l.rpc("", "getbestblockhash"))
	l.rpc("", "invalidateblock", rotationBlock)
	w.Close()
	w, e = Open(c)
	if e != nil {
		t.Fatal(e)
	}
	w.clock = func() int64 { return 500 }
	check("rotation-rollback-reopen", raw3, req3, "", "refused", "GRANT_KEY_ROTATED")
	l.rpc("", "reconsiderblock", rotationBlock)
	// A first observation of the wrong current key is a refusal, not invented
	// historical evidence of a previously admitted generation's rotation.
	_, raw4 := l.oneoff()
	x.GrantID = Hash(raw4)
	req4 := signRequest(t, x, 2)
	check("first-observer-mismatch", raw4, req4, "", "refused", "GRANT_KEY_MISMATCH")
	value, e = rental.LandlordValue(rental.LandlordBinding{Grant: env3.Grant.Issuer})
	if e != nil {
		t.Fatal(e)
	}
	l.rpc("issuer", "name_update", env3.Grant.Landlord, value)
	l.mine(1)
	check("rotation-stays-closed", raw3, req3, "", "refused", "GRANT_KEY_ROTATED")
	check("first-observer-current-key", raw4, req4, "", "refused", "USE_PROOF_REQUIRED")
}
