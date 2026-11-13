package gateway_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/stationlink"
)

// TestEndSlotIdempotent proves same-id repeats return the recorded
// result, a different id for a completed end conflicts, and lookup
// answers for the closer.
func TestEndSlotIdempotent(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	ctx := context.Background()
	rec, err := h.gw.EndSlot(ctx, "slot-1", "op-end-1", "closer")
	if err != nil || rec.State != journal.OpStateDone {
		t.Fatalf("EndSlot = %+v %v", rec, err)
	}
	again, err := h.gw.EndSlot(ctx, "slot-1", "op-end-1", "closer")
	if err != nil || again.State != journal.OpStateDone || again.OpID != rec.OpID {
		t.Fatalf("repeat EndSlot = %+v %v", again, err)
	}
	if _, err := h.gw.EndSlot(ctx, "slot-1", "op-end-2", "closer"); !errors.Is(err, gateway.ErrOperationConflict) {
		t.Fatalf("conflicting id err = %v, want ErrOperationConflict", err)
	}
	got, found := h.gw.LookupOperation("slot-1", "op-end-1")
	if !found || got.State != journal.OpStateDone {
		t.Fatalf("lookup = %+v found=%v", got, found)
	}
	if _, found := h.gw.LookupOperation("slot-1", "op-nope"); found {
		t.Fatal("lookup found a nonexistent operation")
	}
	slot, _ := h.store.Get("slot-1")
	if !slot.Ended || slot.ChannelSecretHex.Reveal() != "" {
		t.Fatalf("slot after EndSlot: ended=%v secret=%q", slot.Ended, slot.ChannelSecretHex.Reveal())
	}
}

// TestFinalMessageExactlyOneEvent proves: repeat after success
// publishes nothing new; a crash-leftover started record (event
// persisted, publish already happened) completes by re-publishing
// the identical event, so exactly one final event id ever reaches
// the renter; different content under the same or a new id is a
// conflict.
func TestFinalMessageExactlyOneEvent(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	ctx := context.Background()
	if _, err := h.gw.EndSlot(ctx, "slot-1", "op-end", "closer"); err != nil {
		t.Fatal(err)
	}
	before := h.pub.count()
	rec, err := h.gw.SendFinalMessage(ctx, "slot-1", "op-final", "final summary")
	if err != nil || rec.State != journal.OpStateDone || rec.EventID == "" {
		t.Fatalf("SendFinalMessage = %+v %v", rec, err)
	}
	if h.pub.count() != before+1 {
		t.Fatalf("published %d events, want exactly 1 new", h.pub.count()-before)
	}
	if _, err := h.gw.SendFinalMessage(ctx, "slot-1", "op-final", "final summary"); err != nil {
		t.Fatal(err)
	}
	if h.pub.count() != before+1 {
		t.Fatal("repeat after success published again")
	}
	if _, err := h.gw.SendFinalMessage(ctx, "slot-1", "op-final", "DIFFERENT"); !errors.Is(err, gateway.ErrOperationConflict) {
		t.Fatalf("different content same id err = %v", err)
	}
	if _, err := h.gw.SendFinalMessage(ctx, "slot-1", "op-final-2", "final summary"); !errors.Is(err, gateway.ErrOperationConflict) {
		t.Fatalf("new id after done err = %v", err)
	}

	// Crash simulation on a fresh slot: started record with the
	// persisted event, publish already happened once, then retry.
	h2 := newHarness(t, harnessOpts{})
	if _, err := h2.gw.EndSlot(ctx, "slot-1", "op-end", "closer"); err != nil {
		t.Fatal(err)
	}
	wrap, _, err := nostr.WrapDM(h2.agent, h2.renter.PubKeyHex(), "crash final", nil, nowMid)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(wrap)
	sum := sha256.Sum256([]byte("crash final"))
	if _, _, err := h2.store.BeginOperation("slot-1", journal.OpFinalMessage, "op-crash", "", nowMid); err != nil {
		t.Fatal(err)
	}
	if _, err := h2.store.AttachOperationEvent("slot-1", "op-crash", wrap.ID,
		base64.StdEncoding.EncodeToString(raw), hex.EncodeToString(sum[:]), nowMid); err != nil {
		t.Fatal(err)
	}
	_ = h2.pub.Publish(ctx, wrap) // the pre-crash publish
	done, err := h2.gw.SendFinalMessage(ctx, "slot-1", "op-crash", "crash final")
	if err != nil || done.State != journal.OpStateDone {
		t.Fatalf("crash retry = %+v %v", done, err)
	}
	ids := map[string]bool{}
	for _, ev := range h2.pub.evsSnapshot() {
		if u, err := nostr.UnwrapDM(ev, h2.renter); err == nil && u.Rumor.Content == "crash final" {
			ids[ev.ID] = true
		}
	}
	if len(ids) != 1 || !ids[wrap.ID] {
		t.Fatalf("distinct final event ids at relay = %v, want exactly {%s}", ids, wrap.ID)
	}
}

// TestDestroyIdempotentAcrossRestart proves Destroy works from
// durable state after a gateway restart (no in-memory handle),
// repeats return the recorded report, and a crash-leftover started
// destroy completes on retry.
func TestDestroyIdempotentAcrossRestart(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	home := filepath.Join(h.stationDir, "slot-1")
	if _, err := os.Stat(home); err != nil {
		t.Fatalf("station home missing before destroy: %v", err)
	}
	h.rebuild() // fresh gateway: stations map empty, journal from disk
	ctx := context.Background()
	report, rec, err := h.gw.DestroySlot(ctx, "slot-1", "op-destroy")
	if err != nil || rec.State != journal.OpStateDone {
		t.Fatalf("Destroy after restart = %+v %v", rec, err)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("home survives destroy after restart: %v", err)
	}
	report2, _, err := h.gw.DestroySlot(ctx, "slot-1", "op-destroy")
	if err != nil || len(report2.Removed) != len(report.Removed) {
		t.Fatalf("repeat destroy = %+v %v, want recorded report %+v", report2, err, report)
	}
	if _, _, err := h.gw.DestroySlot(ctx, "slot-1", "op-destroy-2"); !errors.Is(err, gateway.ErrOperationConflict) {
		t.Fatalf("conflicting destroy id err = %v", err)
	}

	// Crash-leftover: started destroy record completes on retry.
	h2 := newHarness(t, harnessOpts{})
	if _, _, err := h2.store.BeginOperation("slot-1", journal.OpDestroy, "op-crash-d", "destroyed", nowMid); err != nil {
		t.Fatal(err)
	}
	if _, rec, err := h2.gw.DestroySlot(ctx, "slot-1", "op-crash-d"); err != nil || rec.State != journal.OpStateDone {
		t.Fatalf("crash destroy retry = %+v %v", rec, err)
	}
	if _, err := os.Stat(filepath.Join(h2.stationDir, "slot-1")); !os.IsNotExist(err) {
		t.Fatalf("home survives crash-retry destroy: %v", err)
	}
}

// TestEndSlotStartedCompletesOnRetry proves a crash-leftover
// started EndSlot completes instead of stranding in uncertain.
func TestEndSlotStartedCompletesOnRetry(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	if _, _, err := h.store.BeginOperation("slot-1", journal.OpEndSlot, "op-crash-e", "closer", nowMid); err != nil {
		t.Fatal(err)
	}
	rec, err := h.gw.EndSlot(context.Background(), "slot-1", "op-crash-e", "closer")
	if err != nil || rec.State != journal.OpStateDone {
		t.Fatalf("started EndSlot retry = %+v %v", rec, err)
	}
	slot, _ := h.store.Get("slot-1")
	if !slot.Ended {
		t.Fatal("slot not ended after retry-completed EndSlot")
	}
}

// TestReplyRequiresLiveGrant proves outbound agent signing happens
// only for a current grantee: a fresh kernel check gates every
// reply (no outbound screening anywhere in this path).
func TestReplyRequiresLiveGrant(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c, conn := h.stationClient()
	defer conn.Close()
	deliveryID := h.deliverValid(c, "question")
	if ack, err := c.Reply(deliveryID, "answer while live"); err != nil || ack.Type != stationlink.TypeAck {
		t.Fatalf("live reply = %+v %v", ack, err)
	}
	h.kern.Verdict, h.kern.Reason = kernel.Refused, "ANCHOR_INACTIVE"
	before := h.pub.count()
	ack, err := c.Reply(deliveryID, "must not be signed")
	if err != nil {
		t.Fatal(err)
	}
	if ack.Type == stationlink.TypeAck || h.pub.count() != before {
		t.Fatalf("reply signed despite non-live grant: ack=%+v published=%d", ack, h.pub.count()-before)
	}
	h.kern.Verdict, h.kern.Reason = kernel.Live, ""
	deliveryID = h.deliverValid(c, "second question")
	if ack, err := c.Reply(deliveryID, "live again"); err != nil || ack.Type != stationlink.TypeAck {
		t.Fatalf("live-again reply = %+v %v", ack, err)
	}
}

// TestConcurrentDuplicateOps proves RM2-03 C1: eight concurrent
// callers with one operation id coalesce — exactly one effect runs
// per kind; the final message reaches the publisher as exactly one
// distinct event id. Run under -race.
func TestConcurrentDuplicateOps(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	ctx := context.Background()
	const n = 8

	run := func(fn func() error) []error {
		errs := make([]error, n)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				errs[i] = fn()
			}(i)
		}
		close(start)
		wg.Wait()
		return errs
	}
	for i, err := range run(func() error {
		_, err := h.gw.EndSlot(ctx, "slot-1", "op-end-c", "closer")
		return err
	}) {
		if err != nil {
			t.Fatalf("concurrent EndSlot %d: %v", i, err)
		}
	}
	before := h.pub.count()
	for i, err := range run(func() error {
		_, err := h.gw.SendFinalMessage(ctx, "slot-1", "op-final-c", "concurrent final")
		return err
	}) {
		if err != nil {
			t.Fatalf("concurrent SendFinalMessage %d: %v", i, err)
		}
	}
	ids := map[string]bool{}
	for _, ev := range h.pub.evsSnapshot()[before:] {
		if u, err := nostr.UnwrapDM(ev, h.renter); err == nil && u.Rumor.Content == "concurrent final" {
			ids[ev.ID] = true
		}
	}
	if len(ids) != 1 {
		t.Fatalf("concurrent final produced %d distinct event ids, want 1 (%v)", len(ids), ids)
	}
	for i, err := range run(func() error {
		_, _, err := h.gw.DestroySlot(ctx, "slot-1", "op-destroy-c")
		return err
	}) {
		if err != nil {
			t.Fatalf("concurrent DestroySlot %d: %v", i, err)
		}
	}
	if _, err := os.Stat(filepath.Join(h.stationDir, "slot-1")); !os.IsNotExist(err) {
		t.Fatalf("home survives concurrent destroy: %v", err)
	}
}

// TestConcurrentDifferentIDsConflict proves two different op ids
// for one slot+kind race to exactly one winner and one conflict.
func TestConcurrentDifferentIDsConflict(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	ctx := context.Background()
	if _, err := h.gw.EndSlot(ctx, "slot-1", "op-end-x", "closer"); err != nil {
		t.Fatal(err)
	}
	errs := make([]error, 2)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, id := range []string{"op-final-a", "op-final-b"} {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			<-start
			_, errs[i] = h.gw.SendFinalMessage(ctx, "slot-1", id, "race final")
		}(i, id)
	}
	close(start)
	wg.Wait()
	wins, conflicts := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, gateway.ErrOperationConflict):
			conflicts++
		default:
			t.Fatalf("unexpected err: %v", err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("wins=%d conflicts=%d, want 1/1 (errs %v)", wins, conflicts, errs)
	}
	count := 0
	for _, dm := range h.pub.dmsTo(h.renter) {
		if dm == "race final" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("race final delivered %d times, want 1", count)
	}
}
