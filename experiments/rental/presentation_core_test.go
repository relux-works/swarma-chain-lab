package rental

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	su "relux.works/swarma-chain-lab/experiments/single-use"
)

func (l *coreLab) detachedPoolMany(count int) []Point {
	l.t.Helper()
	if count < 1 || count > 16 {
		l.t.Fatal("fixture output bound")
	}
	l.rpc("issuer", "importprivkey", testWIF(1), "", false)
	_, key := testKey(1)
	script, e := GrantSealScript(key)
	if e != nil {
		l.t.Fatal(e)
	}
	funding := l.fund()
	tx := su.Transaction{Version: 2, Inputs: []su.Input{{Point: funding.Point, Sequence: 0xfffffffe}}}
	for i := 0; i < count; i++ {
		tx.Outputs = append(tx.Outputs, su.Output{Value: 1000000, Script: mustDecodeKey(script)})
	}
	// Reserve above Core regtest's 100 sat/vB floor for all sixteen outputs.
	tx.Outputs = append(tx.Outputs, su.Output{Value: funding.ValueSat - int64(count)*1000000 - 200000, Script: mustDecodeKey(l.script)})
	id := l.send(hex.EncodeToString(tx.Bytes()), true)
	points := make([]Point, count)
	for i := range points {
		points[i] = Point{id, uint32(i)}
	}
	l.rpc("issuer", "lockunspent", false, points)
	return points
}

// Genuine Core admission precedes caching. Wrong id, sender and expired
// replacement preserve the admitted cache; a live replacement succeeds. A
// full 64-sender cache refuses a 65th entry without changing its contents.
func TestCoreDetachedPresentation(t *testing.T) {
	l := newCore(t)
	l.agentValue(1, 3, true)
	var seals []Point
	for i := 0; i < 4; i++ {
		seals = append(seals, l.detachedPoolMany(16)...)
	}
	p, c, raw := l.detached("presentation", seals[0], 10)
	present := func(bytes []byte, id, sender string) Receipt {
		return Present(context.Background(), l.observer, p, bytes, id, p.AgentName, sender, 500)
	}
	if r := present(raw, Hash(raw), c.GranteeKey); r.Verdict != "live" {
		t.Fatal(r)
	}
	before := cacheBytes(t, p)
	for _, mode := range []string{"wrong-id", "wrong-sender", "expired-replacement"} {
		t.Run(mode, func(t *testing.T) {
			input := raw
			id := Hash(raw)
			sender := c.GranteeKey
			want := ""
			switch mode {
			case "wrong-id":
				id = Hash([]byte("wrong"))
				want = "PRESENTATION_ID"
			case "wrong-sender":
				_, sender = testKey(11)
				want = "GRANTEE_MISMATCH"
			case "expired-replacement":
				other := c
				other.Seal = seals[1] // Isolate expiry from the one-seal-ever guard.
				other.NotAfter = 500
				input = signDetachedTest(t, other, 1)
				id = Hash(input)
				want = "EXPIRED"
			}
			if r := present(input, id, sender); r.Verdict != "refused" || r.Reason != want {
				t.Fatal(r)
			}
			if !bytes.Equal(before, cacheBytes(t, p)) {
				t.Fatal("refusal changed cache")
			}
			if r := present(raw, Hash(raw), c.GranteeKey); r.Verdict != "live" {
				t.Fatal("valid neighbor", r)
			}
		})
	}
	for i := 1; i < PresentationCapacity; i++ {
		next := c
		next.Seal = seals[i]
		_, next.GranteeKey = testKey(byte(10 + i))
		b := signDetachedTest(t, next, 1)
		if r := present(b, Hash(b), next.GranteeKey); r.Verdict != "live" {
			t.Fatalf("cache fill %d: %+v", i, r)
		}
	}
	before = cacheBytes(t, p)
	extra := c
	extra.Seal = l.detachedPool(1, true)
	_, extra.GranteeKey = testKey(90)
	extraRaw := signDetachedTest(t, extra, 1)
	if r := present(extraRaw, Hash(extraRaw), extra.GranteeKey); r.Reason != "PRESENTATION_CACHE_FULL" || r.Verdict != "refused" {
		t.Fatal(r)
	}
	if !bytes.Equal(before, cacheBytes(t, p)) {
		t.Fatal("full cache changed")
	}
	replacement := c
	replacement.Seal = l.detachedPool(1, true)
	replacementRaw := signDetachedTest(t, replacement, 1)
	if r := present(replacementRaw, Hash(replacementRaw), c.GranteeKey); r.Verdict != "live" {
		t.Fatal("live replacement at capacity", r)
	}
	cached, id, e := CachedCertificate(p, c.GranteeKey)
	if e != nil || id != Hash(replacementRaw) || !bytes.Equal(cached, replacementRaw) {
		t.Fatal("replacement lookup", e)
	}
	l.revokeDetached(replacement.Seal, false)
	if r := present(replacementRaw, id, c.GranteeKey); r.Reason != "SEAL_SPENT" || !r.Closed {
		t.Fatal("cache bypassed fresh revocation", r)
	}
	l.save("presentation-result.json", map[string]any{"status": "PASS", "real_live_senders": PresentationCapacity, "rejected_extra_sender": true, "fresh_check_on_cache_hit": true})
}

// Genuine Core accepts an optional root-only batch transaction. Its exact
// commitment and valid proof verify; another leaf does not. The grant remains
// live before and after, proving the anchor is not a verification prerequisite.
func TestCoreDetachedBatch(t *testing.T) {
	l := newCore(t)
	l.agentValue(1, 3, true)
	seal := l.detachedPool(1, true)
	p, c, raw := l.detached("batch", seal, 2)
	l.checkDetached("without-anchor", p, c, raw, 500, "live", "LIVE", false)
	fund := l.detachedPool(1, true)
	spec := PlanSpec{Kind: "batch-anchor", Inputs: []su.PlanInput{{Point: su.Point{TxID: fund.TxID, Vout: fund.Vout}, ValueSat: 1000000, Script: p.SealScript, Role: "funding"}}, ChangeScript: p.SealScript}
	ids := []string{Hash(raw), Hash([]byte("other-one")), Hash([]byte("other-two"))}
	if _, e := MakeBatchAnchorPlan(p, spec, ids, false); e == nil || e.Error() != "BATCH_DISABLED" {
		t.Fatal("batch enabled by default")
	}
	batch, e := MakeBatchAnchorPlan(p, spec, ids, true)
	if e != nil {
		t.Fatal(e)
	}
	id := l.sendPlan(batch.Plan, true)
	var view su.TransactionView
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", id, true), &view); e != nil {
		t.Fatal(e)
	}
	rootScript := "6a20" + batch.Batch.Commitment
	commits := 0
	for _, output := range view.Vout {
		if output.Script.Hex == rootScript {
			commits++
			if int64(output.Value) != 0 {
				t.Fatal("nonzero root output")
			}
		}
	}
	if commits != 1 {
		t.Fatal("root commitment cardinality")
	}
	index := -1
	for i, id := range batch.Batch.IDs {
		if id == Hash(raw) {
			index = i
		}
	}
	if index < 0 || !VerifyBatchProof(Hash(raw), batch.Batch.Commitment, batch.Batch.Proofs[index]) {
		t.Fatal("valid batch proof")
	}
	if VerifyBatchProof(Hash([]byte("wrong-leaf")), batch.Batch.Commitment, batch.Batch.Proofs[index]) {
		t.Fatal("wrong leaf accepted")
	}
	wrongCount := batch.Batch.Proofs[index]
	wrongCount.Count++
	if VerifyBatchProof(Hash(raw), batch.Batch.Commitment, wrongCount) {
		t.Fatal("wrong count accepted")
	}
	l.checkDetached("with-optional-anchor", p, c, raw, 500, "live", "LIVE", false)
	l.save("batch-plan.json", batch)
	l.save("batch-result.json", map[string]any{"status": "PASS", "txid": id, "root": batch.Batch.Root, "commitment": batch.Batch.Commitment})
}
