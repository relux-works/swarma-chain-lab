package singleuse

import (
	"context"
	"testing"
	"time"
)

// Invalidate the actual spend block at the pre-reservation seam. The final
// chain check must reject before journal/effect; restoring the block is a valid
// neighboring use. It does not prove atomicity after the final RPC returns.
func TestGenuineCoreLateReorg(t *testing.T) {
	l := newCoreLab(t)
	p := l.state(l.newPolicy(), "late-reorg")
	id := l.use(p, "grantee", "ALL", nil, true)
	view := object(t, l.rpc("", "getrawtransaction", id, true))
	block := textValue(t, view["blockhash"])
	node, e := NewRPC(l.route)
	if e != nil {
		t.Fatal(e)
	}
	applied := false
	r := Execute(context.Background(), node, p, l.certificate, l.request, time.Now(), func(stage string) {
		if stage == "before-journal" {
			applied = true
			l.rpc("", "invalidateblock", block)
		}
	})
	l.save("late-reorg-receipt.json", r)
	if !applied || r.Status != "refused" || r.Reason != "TIP_CHANGED" || journalCount(t, p) != 0 || effectCount(t, p) != 0 {
		t.Fatalf("late reorg must refuse before reservation: applied%v %+v journal%d effect%d", applied, r, journalCount(t, p), effectCount(t, p))
	}
	l.rpc("", "reconsiderblock", block)
	r, exit := l.invoke(p, l.request, "restored-valid")
	if exit != 0 || r.Status != "executed" || effectCount(t, p) != 1 {
		t.Fatal(r, exit)
	}
	l.save("result.json", map[string]any{"status": "PASS", "late_reorg_applied": true, "refused_before_journal_effect": true, "restored_positive": true})
}
