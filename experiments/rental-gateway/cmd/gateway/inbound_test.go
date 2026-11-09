package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/testrelay"
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
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("subscriber leaked")
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
