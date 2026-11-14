package wallet

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

func freshFixtureSignature(t *testing.T, digest, original string, key byte) string {
	t.Helper()
	k, pub := testKey(key)
	h, err := hex.DecodeString(digest)
	if err != nil {
		t.Fatal(err)
	}
	var aux [32]byte
	if _, err = rand.Read(aux[:]); err != nil {
		t.Fatal(err)
	}
	sig, err := schnorr.Sign(k, h, schnorr.CustomNonce(aux))
	if err != nil {
		t.Fatal(err)
	}
	second := hex.EncodeToString(sig.Serialize())
	if second == original || !rental.VerifySignature(pub, digest, original) || !rental.VerifySignature(pub, digest, second) {
		t.Fatal("two distinct valid fixture signatures required")
	}
	return second
}

func secondRequestSignature(t *testing.T, raw []byte) []byte {
	t.Helper()
	a, err := ParseRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	e := a.Event
	e.Sig = freshFixtureSignature(t, e.ID, e.Sig, 2)
	second := canonical(e)
	b, err := ParseRequest(second)
	if err != nil || a.Event.ID != b.Event.ID || !bytes.Equal(canonical(a.Request), canonical(b.Request)) || Hash(raw) == Hash(second) {
		t.Fatal("same logical request with different signed-byte hash required", err)
	}
	return second
}

// The actual W1 executor reserves, charges and broadcasts once. A fresh valid
// signature over identical request content is a nonce conflict before any RPC,
// journal write or extra debit. The node/authority are explicit unit doubles;
// genuine Core is covered by TestCoreSignatureIdentities below.
func TestW1SecondSignatureChargedOnce(t *testing.T) {
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}
	g := px1Grant(canonical(terms), 1000000)
	g.NotBefore, g.NotAfter = 100, 1000
	change, _ := testKey(6)
	funding, _ := testKey(11)
	chain := &fakeChain{t: t, fee: 2260, change: p2pkh(change), coins: []fakeCoin{{point: fakePoint(1), value: 1000000, key: funding}}}
	root := privateDir(t)
	store, err := durable.Open(root, "wallet.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	w := &Wallet{config: Config{Network: "regtest", Genesis: su.RegtestGenesis, ChangeAddress: testAddress(6), FeeRate: 110}, node: chain, wallet: chain, broadcast: chain, authority: &fakeAuthority{grant: g}, store: store, clock: func() int64 { return 500 }, state: state{Version: 1, Binding: Hash([]byte("signature-identity-fixture")), Records: []Record{}}}
	r := testRequest()
	r.GrantID = g.ID
	original := signRequest(t, r, 2)
	second := secondRequestSignature(t, original)
	got := w.Execute(context.Background(), []byte("fixture-grant"), canonical(terms), original, "")
	if got.Status != "executed" || len(chain.sent) != 1 || len(w.state.Records) != 1 {
		t.Fatalf("valid original must execute once: %+v", got)
	}
	before, err := os.ReadFile(filepath.Join(root, "wallet.json"))
	if err != nil {
		t.Fatal(err)
	}
	spent, names, count := w.used(g.ID)
	calls := len(chain.calls)
	// Offer an unused funded input, so a missing logical dedup cannot hide behind
	// the separate input-reservation gate or an exhausted wallet balance.
	chain.coins = []fakeCoin{{point: fakePoint(2), value: 1000000, key: funding}}
	denied := w.Execute(context.Background(), []byte("fixture-grant"), canonical(terms), second, "")
	after, err := os.ReadFile(filepath.Join(root, "wallet.json"))
	if err != nil {
		t.Fatal(err)
	}
	afterSpent, afterNames, afterCount := w.used(g.ID)
	if len(chain.sent) != 1 || len(w.state.Records) != 1 || !bytes.Equal(before, after) || spent != afterSpent || names != afterNames || count != afterCount || len(chain.calls) != calls {
		t.Error("SECOND_SIGNATURE_DOUBLE_EFFECT: journal, debit or execution changed")
	}
	if denied.Status != "refused" || denied.Reason != "NONCE_CONFLICT" {
		t.Errorf("SECOND_SIGNATURE_LOGICAL_DEDUP: %+v", denied)
	}
	replay := w.Execute(context.Background(), []byte("fixture-grant"), canonical(terms), original, "")
	if replay.Status != "already-executed" || len(chain.sent) != 1 {
		t.Fatal("original replay", replay)
	}
}

// Genuine Core and the real grant kernel: signed-grant IDs and wallet grant /
// nonce keys change with an issuer re-sign, but the uncommitted ID cannot gain
// admission. A request re-sign is the same logical request and has no second
// payment, debit, durable record or mempool entry, including after reopening.
func TestCoreSignatureIdentities(t *testing.T) {
	l := newCore(t)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}
	raw, c := l.grant(terms, []string{"pay"}, 1000000)
	p, err := rental.ParseGrantPresentation(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := p.SignedGrant.Grant.SigningHash()
	if err != nil {
		t.Fatal(err)
	}
	p.SignedGrant.Signature = freshFixtureSignature(t, digest, p.SignedGrant.Signature, 1)
	alternate := canonical(p)
	a := KernelAuthority{Policy: c.Policy}
	originalGrant, err := a.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	secondGrant, err := a.Parse(alternate)
	if err != nil || originalGrant.ID == secondGrant.ID {
		t.Fatal("grant IDs must be signature dependent", err)
	}
	w, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if w != nil {
			w.Close()
		}
	}()
	w.clock = func() int64 { return 500 }
	r := testRequest()
	r.GrantID, r.FeeLimit = secondGrant.ID, 100000
	denied := w.Execute(context.Background(), alternate, canonical(terms), signRequest(t, r, 2), "")
	if denied.Status != "refused" || denied.Reason != "GRANT_ISSUANCE_COMMITMENT" || len(w.state.Records) != 0 {
		t.Fatalf("uncommitted grant gained wallet admission: %+v", denied)
	}
	r.GrantID = originalGrant.ID
	original := signRequest(t, r, 2)
	second := secondRequestSignature(t, original)
	paid := w.Execute(context.Background(), raw, canonical(terms), original, "")
	if paid.Status != "executed" {
		t.Fatal("committed original", paid)
	}
	before, err := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	if err != nil {
		t.Fatal(err)
	}
	pool := string(l.rpc("", "getrawmempool"))
	spent, names, count := w.used(originalGrant.ID)
	check := func() {
		t.Helper()
		denied := w.Execute(context.Background(), raw, canonical(terms), second, "")
		after, err := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
		afterSpent, afterNames, afterCount := w.used(originalGrant.ID)
		if err != nil || !bytes.Equal(before, after) || pool != string(l.rpc("", "getrawmempool")) || len(w.state.Records) != 1 || spent != afterSpent || names != afterNames || count != afterCount {
			t.Error("SECOND_SIGNATURE_DOUBLE_EFFECT: Core payment/journal/debit changed", err)
		}
		if denied.Status != "refused" || denied.Reason != "NONCE_CONFLICT" {
			t.Errorf("SECOND_SIGNATURE_LOGICAL_DEDUP: %+v", denied)
		}
	}
	check()
	w.Close()
	w, err = Open(c)
	if err != nil {
		t.Fatal(err)
	}
	w.clock = func() int64 { return 500 }
	check()
}

// One-off envelope IDs also include the signature. A new issuer signature
// changes the request's grant ID, so the confirmed seal spend for the original
// request cannot authorize the alternate. Only one payment/debit is retained.
func TestCoreOneoffSecondSignatureCommitment(t *testing.T) {
	l := newCore(t)
	terms := Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}
	_, c := l.grant(terms, []string{"pay"}, 1000000)
	w, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	w.clock = func() int64 { return 500 }
	env, raw := l.oneoff()
	twin := env
	twin.Signature = freshFixtureSignature(t, OneoffDigest(env.Grant), env.Signature, 1)
	alternate := canonical(twin)
	if _, err = parseOneoff(alternate); err != nil || Hash(raw) == Hash(alternate) {
		t.Fatal("oneoff twin fixture", err)
	}
	r := testRequest()
	r.GrantID, r.Amount, r.FeeLimit = Hash(raw), env.Grant.Amount, env.Grant.FeeLimit
	original := signRequest(t, r, 2)
	use := l.use(env, original, 2)
	l.mine(1)
	r.GrantID = Hash(alternate)
	denied := w.Execute(context.Background(), alternate, nil, signRequest(t, r, 2), use)
	if denied.Status != "refused" || denied.Reason != "REQUEST_COMMITMENT" || len(w.state.Records) != 0 {
		t.Fatal("alternate oneoff reused original commitment", denied)
	}
	paid := w.Execute(context.Background(), raw, nil, original, use)
	if paid.Status != "executed" {
		t.Fatal("committed original", paid)
	}
	before, err := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	if err != nil {
		t.Fatal(err)
	}
	pool := string(l.rpc("", "getrawmempool"))
	denied = w.Execute(context.Background(), alternate, nil, signRequest(t, r, 2), use)
	after, err := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	if err != nil {
		t.Fatal(err)
	}
	if denied.Status != "refused" || denied.Reason != "REQUEST_COMMITMENT" || !bytes.Equal(before, after) || len(w.state.Records) != 1 || pool != string(l.rpc("", "getrawmempool")) {
		t.Fatal("oneoff second signature changed effects", denied)
	}
}

// The G2 wallet's separate journal lookup also deduplicates W1 signatures by
// grant/nonce before consulting signed-byte conflict hashes. Unit doubles supply
// the node and journal; assertions cover retained debit, records and broadcasts.
func TestG2SecondSignatureChargedOnce(t *testing.T) {
	l := newPX1Lab(t, px1RegtestTerms(), px1Operator(), 500000, px1ExecutorKey)
	l.w.config.Network, l.w.config.Genesis = "regtest", su.RegtestGenesis
	l.w.config.ChangeAddress = testAddress(6)
	l.w.g2.checker = NewCapCheckerFor("regtest", su.RegtestGenesis)
	r := testRequest()
	r.GrantID = l.grant.ID
	original := signRequestAt(t, r, 2, l.now-10)
	second := secondRequestSignature(t, original)
	paid := l.w.Execute(context.Background(), []byte("fixture-grant"), l.terms, original, "")
	if paid.Status != "executed" || len(l.chain.sent) != 1 {
		t.Fatal("valid G2 original", paid)
	}
	before := canonical(l.journal.records)
	ledger, err := l.w.PX1Ledger()
	if err != nil {
		t.Fatal(err)
	}
	debit := ledger.SpendUsed(l.grant.ID)
	if debit <= r.Amount {
		t.Fatal("G2 original did not retain fee-inclusive debit")
	}
	calls := len(l.chain.calls)
	l.chain.coins = append([]fakeCoin(nil), l.chain.coins[1:]...)
	denied := l.w.Execute(context.Background(), []byte("fixture-grant"), l.terms, second, "")
	ledger, err = l.w.PX1Ledger()
	if err != nil {
		t.Fatal(err)
	}
	if len(l.chain.sent) != 1 || len(l.chain.calls) != calls || !bytes.Equal(before, canonical(l.journal.records)) || debit != ledger.SpendUsed(l.grant.ID) {
		t.Error("SECOND_SIGNATURE_G2_DOUBLE_EFFECT: debit, journal or broadcast changed")
	}
	if denied.Status != "refused" || denied.Reason != "NONCE_CONFLICT" {
		t.Errorf("SECOND_SIGNATURE_G2_LOGICAL_DEDUP: %+v", denied)
	}
}
