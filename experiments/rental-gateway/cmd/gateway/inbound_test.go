package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/testrelay"
)

// Four blocked startup handlers plus a full bounded queue cannot occupy the
// actual relay ACK pump. Saturation/cancellation refuse more work, and close
// waits for all admitted handlers to observe cancellation.
func TestInboundDoesNotBlockRelayACK(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, 4)
	exited := make(chan struct{}, 4)
	q := newInbound(ctx, 1, func(ctx context.Context, _ *nostr.Event) { entered <- struct{}{}; <-ctx.Done(); exited <- struct{}{} })
	defer q.close()
	for range 4 {
		if !q.offer(&nostr.Event{}) {
			t.Fatal("worker admission")
		}
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("worker not started")
		}
	}
	if !q.offer(&nostr.Event{}) || q.offer(&nostr.Event{}) {
		t.Fatal("queue bound")
	}
	relay, e := testrelay.Start()
	if e != nil {
		t.Fatal(e)
	}
	defer relay.Close()
	sender := &gateway.RelayClient{URL: relay.URL}
	defer sender.Close()
	agent, _ := nostr.GeneratePrivKey()
	renter, _ := nostr.GeneratePrivKey()
	wrap, _, e := nostr.WrapDM(renter, agent.PubKeyHex(), "test queue pressure", nil, time.Now().Unix())
	if e != nil {
		t.Fatal(e)
	}
	if e = sender.Publish(ctx, wrap); e != nil {
		t.Fatal(e)
	}
	client := &gateway.RelayClient{URL: relay.URL}
	defer client.Close()
	callback := make(chan bool, 1)
	done := make(chan error, 1)
	go func() {
		done <- client.SubscribeGiftWraps(ctx, agent.PubKeyHex(), func(_ context.Context, ev *nostr.Event) { callback <- q.offer(ev) })
	}()
	select {
	case accepted := <-callback:
		if accepted {
			t.Fatal("full queue accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("callback blocked")
	}
	reply, _, e := nostr.WrapDM(agent, renter.PubKeyHex(), "independent ACK", nil, time.Now().Unix())
	if e != nil {
		t.Fatal(e)
	}
	ackctx, ackcancel := context.WithTimeout(ctx, time.Second)
	defer ackcancel()
	if e = client.Publish(ackctx, reply); e != nil {
		t.Fatal("blocked ACK", e)
	}
	cancel()
	q.close()
	if q.offer(wrap) || len(exited) != 4 || len(entered) != 0 {
		t.Fatal("cancelled queue executed pending work")
	}
	if s := q.status(); s.Admitted != 5 || s.DroppedFull != 2 || s.Capacity != 1 || s.WorkerLimit != 4 {
		t.Fatalf("ACK path accounting: %+v", s)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("subscriber leaked")
	}
}

// At min, typical and max configured capacity, four blocked handlers plus
// capacity queued events admit no more work. Concurrent overflow is counted
// exactly; nil/cancelled refusals are excluded and a freed slot admits again.
func TestInboundStatusBounds(t *testing.T) {
	for _, capacity := range []int{1, 8, 128} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			entered := make(chan struct{}, capacity+4)
			release := make(chan struct{})
			q := newInbound(context.Background(), capacity, func(ctx context.Context, _ *nostr.Event) {
				entered <- struct{}{}
				select {
				case <-ctx.Done():
				case <-release:
				}
			})
			defer q.close()
			if s := q.status(); s.Admitted != 0 || s.DroppedFull != 0 || s.Queued != 0 || s.Capacity != capacity || s.WorkerLimit != 4 {
				t.Fatalf("initial status: %+v", s)
			}
			waitEntered := func() {
				t.Helper()
				select {
				case <-entered:
				case <-time.After(time.Second):
					t.Fatal("worker did not enter")
				}
			}
			for range 4 {
				if !q.offer(&nostr.Event{}) {
					t.Fatal("worker refused")
				}
				waitEntered()
			}
			for range capacity {
				if !q.offer(&nostr.Event{}) {
					t.Fatal("capacity refused")
				}
			}
			var offers sync.WaitGroup
			for range 100 {
				offers.Go(func() {
					if q.offer(&nostr.Event{}) {
						t.Error("overflow admitted")
					}
					_ = q.status()
				})
			}
			offers.Wait()
			if q.offer(nil) {
				t.Fatal("nil admitted")
			}
			if s := q.status(); s.Admitted != uint64(capacity+4) || s.DroppedFull != 100 || s.Queued != capacity {
				t.Fatalf("saturation accounting: %+v", s)
			}
			release <- struct{}{}
			waitEntered()
			if !q.offer(&nostr.Event{}) {
				t.Fatal("freed capacity refused")
			}
			q.close()
			if q.offer(&nostr.Event{}) || q.offer(nil) {
				t.Fatal("closed admitted")
			}
			if s := q.status(); s.Admitted != uint64(capacity+5) || s.DroppedFull != 100 {
				t.Fatalf("closed accounting: %+v", s)
			}
		})
	}
}

// A blocked status sink cannot block queue admission/refusal. JSON snapshots
// expose cumulative drops at startup/tick/shutdown without per-event writes.
func TestInboundStatusReporting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	entered := make(chan struct{}, 4)
	q := newInbound(ctx, 1, func(ctx context.Context, _ *nostr.Event) { entered <- struct{}{}; <-ctx.Done() })
	defer q.close()
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	ticks := make(chan time.Time)
	done := make(chan struct{})
	go func() { q.reportStatus(w, ticks); close(done) }()
	// Bound the test even if a regression blocks a write; this is not success.
	stop := context.AfterFunc(ctx, func() { r.CloseWithError(ctx.Err()); w.CloseWithError(ctx.Err()) })
	defer stop()
	for range 4 {
		if !q.offer(&nostr.Event{}) {
			t.Fatal("worker refused")
		}
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("blocked admission")
		}
	}
	if !q.offer(&nostr.Event{}) || q.offer(&nostr.Event{}) {
		t.Fatal("queue bound")
	}
	dec := json.NewDecoder(r)
	var s inboundStatus
	if e := dec.Decode(&s); e != nil || s.Kind != "inbound_status" {
		t.Fatal("startup status", e)
	}
	go func() {
		select {
		case ticks <- time.Now():
		case <-ctx.Done():
		}
	}()
	if e := dec.Decode(&s); e != nil || s.Admitted != 5 || s.DroppedFull != 1 || s.Queued != 1 || s.Capacity != 1 || s.WorkerLimit != 4 {
		t.Fatalf("tick status: %+v %v", s, e)
	}
	q.close()
	if e := dec.Decode(&s); e != nil || s.Admitted != 5 || s.DroppedFull != 1 {
		t.Fatal("shutdown status", s, e)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("reporter did not stop")
	}
	if ctx.Err() != nil {
		t.Fatal("status test deadline", ctx.Err())
	}
}

// Invalid symlink ancestry refuses before creating anything in its target;
// existing broad permissions are preserved rather than silently changed.
func TestPrivateDirNoRedirectedEffects(t *testing.T) {
	root := testRoot(t)
	target := testRoot(t)
	link := filepath.Join(root, "link")
	if e := os.Symlink(target, link); e != nil {
		t.Fatal(e)
	}
	if e := privateDir(filepath.Join(link, "new", "nested")); e != errConfig {
		t.Fatal("symlink accepted")
	}
	entries, e := os.ReadDir(target)
	if e != nil || len(entries) != 0 {
		t.Fatal("refusal wrote target")
	}
	broad := filepath.Join(root, "broad")
	if e = os.Mkdir(broad, 0755); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(broad, 0755); e != nil {
		t.Fatal(e)
	}
	if e = privateDir(broad); e != errConfig {
		t.Fatal("broad state accepted")
	}
	st, e := os.Stat(broad)
	if e != nil || st.Mode().Perm() != 0755 {
		t.Fatal("existing permissions changed")
	}
	valid := filepath.Join(root, "new", "nested")
	if e = privateDir(valid); e != nil {
		t.Fatal("valid neighbour", e)
	}
}
