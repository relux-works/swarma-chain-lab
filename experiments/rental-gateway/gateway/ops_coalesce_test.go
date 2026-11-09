package gateway

// RM2-04 F1/F2 white-box controls for closer-operation
// coalescing: the in-flight key includes the operation kind, and
// waiters honour their own context.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/journal"
)

func coalesceGateway(t *testing.T) *Gateway {
	t.Helper()
	store, err := journal.Open(filepath.Join(t.TempDir(), "journal"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(&journal.Slot{ID: "slot-1", RenterPubKey: "renter"}); err != nil {
		t.Fatal(err)
	}
	return &Gateway{
		cfg:      Config{Journal: store, Now: func() time.Time { return time.Unix(1500, 0) }},
		inFlight: map[string]*opCall{},
	}
}

// TestOpCoalescingKeyIncludesKind proves F1: the same op id under
// two different kinds does not share one in-flight call.
func TestOpCoalescingKeyIncludesKind(t *testing.T) {
	g := coalesceGateway(t)
	_, endCall, owner := g.opEnter("slot-1", journal.OpEndSlot, "op-x")
	if !owner {
		t.Fatal("first enter not owner")
	}
	_, destroyCall, owner := g.opEnter("slot-1", journal.OpDestroy, "op-x")
	if !owner || destroyCall == endCall {
		t.Fatal("same op id, different kind coalesced into one call")
	}
	_, again, owner := g.opEnter("slot-1", journal.OpEndSlot, "op-x")
	if owner || again != endCall {
		t.Fatal("same slot+kind+op id did not coalesce")
	}
}

// TestOpWaiterHonoursCtx proves F2: a coalesced waiter with a
// cancelled context returns promptly with the ctx error while the
// owner is still running, and the owner then completes and
// records the operation exactly once.
func TestOpWaiterHonoursCtx(t *testing.T) {
	g := coalesceGateway(t)
	release := make(chan struct{})
	entered := make(chan struct{})
	effect := func(ctx context.Context, slot *journal.Slot, rec journal.OpRecord) ([]string, []string, error) {
		close(entered)
		<-release
		return nil, nil, nil
	}
	ownerDone := make(chan error, 1)
	go func() {
		_, err := g.runOperation(context.Background(), "slot-1", journal.OpEndSlot, "op-ctx", "test", effect)
		ownerDone <- err
	}()
	<-entered

	ctx, cancel := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		_, err := g.runOperation(ctx, "slot-1", journal.OpEndSlot, "op-ctx", "test", effect)
		waiterDone <- err
	}()
	cancel()
	select {
	case err := <-waiterDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled waiter did not return")
	}

	close(release)
	if err := <-ownerDone; err != nil {
		t.Fatalf("owner err = %v", err)
	}
	rec, found := g.LookupOperation("slot-1", "op-ctx")
	if !found || rec.State != journal.OpStateDone {
		t.Fatalf("recorded op = %+v found=%v, want done", rec, found)
	}
	// A late waiter now replays the recorded result without an effect.
	rec2, err := g.runOperation(context.Background(), "slot-1", journal.OpEndSlot, "op-ctx", "test",
		func(ctx context.Context, slot *journal.Slot, rec journal.OpRecord) ([]string, []string, error) {
			t.Error("effect ran for a completed operation")
			return nil, nil, nil
		})
	if err != nil || rec2.State != journal.OpStateDone {
		t.Fatalf("replay = %+v %v", rec2, err)
	}
}
