package relay

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/screen"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type discardPublisher struct{}

func (discardPublisher) Publish(context.Context, *nostr.Event) error { return nil }
func awaitRK(t *testing.T, claim string, f func() bool) {
	t.Helper()
	end := time.Now().Add(4 * time.Second)
	for !f() {
		if time.Now().After(end) {
			t.Fatal(claim)
		}
		time.Sleep(time.Millisecond)
	}
}

// Re-encrypt only the outer wrapper with an owned ephemeral key so the fixture
// can choose worst-case backdating/timestamp ties without changing the rumor.
func datedWrap(t *testing.T, from, to *nostr.PrivKey, text string, at int64) (*nostr.Event, string) {
	t.Helper()
	w, rumor, e := nostr.WrapDM(from, to.PubKeyHex(), text, nil, time.Now().Unix())
	if e != nil {
		t.Fatal(e)
	}
	old, e := nostr.ConversationKey(to, w.PubKey)
	if e != nil {
		t.Fatal(e)
	}
	seal, e := nostr.DecryptNIP44(w.Content, old)
	if e != nil {
		t.Fatal(e)
	}
	ephemeral := key(t)
	shared, e := nostr.ConversationKey(ephemeral, to.PubKeyHex())
	if e != nil {
		t.Fatal(e)
	}
	w.Content, e = nostr.EncryptNIP44(seal, shared, [32]byte{})
	if e != nil {
		t.Fatal(e)
	}
	w.CreatedAt = at
	if e = ephemeral.SignEvent(w); e != nil {
		t.Fatal(e)
	}
	return w, rumor.ID
}

// Actual native relay, fresh required AUTH and real gateway journal dedup recover
// seven backdated gap wraps across pages. Overlap must not duplicate deliveries.
// Kernel and host execution are explicit stubs; no Core/model/host claim.
func TestNativeReconnectPagination(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.Backlog = 3
	cfg.RequireReadAuth = true
	cfg.RequireWriteAuth = true
	cfg.RestrictGiftWrapReads = true
	var blocked atomic.Bool
	var r *Relay
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if blocked.Load() {
			http.Error(w, "unavailable", 503)
			return
		}
		r.ServeHTTP(w, q)
	}))
	cfg.PublicURL = "ws" + strings.TrimPrefix("http://"+server.Listener.Addr().String(), "http")
	var e error
	r, e = New(cfg, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	server.Start()
	defer server.Close()
	defer r.Close()
	agent, renter := key(t), key(t)
	sender := &gateway.RelayClient{URL: cfg.PublicURL, Auth: gateway.RelayAuthRequired, AgentKey: renter}
	defer sender.Close()
	first, firstID := datedWrap(t, renter, agent, "before", time.Now().Unix()-5)
	if e = sender.Publish(context.Background(), first); e != nil {
		t.Fatal(e)
	}
	store, e := journal.Open(filepath.Join(t.TempDir(), "journal"))
	if e != nil {
		t.Fatal(e)
	}
	gw, e := gateway.New(gateway.Config{AgentKey: agent, Kernel: &kernel.Stub{Verdict: kernel.Live}, Screener: screen.Off{}, Journal: store, Publisher: discardPublisher{}, Driver: &station.LocalTestDriver{Root: filepath.Join(t.TempDir(), "stations")}})
	if e != nil {
		t.Fatal(e)
	}
	if e = gw.RegisterSlot(gateway.SlotSpec{ID: "reconnect", StationName: "fixture", RenterPubKey: renter.PubKeyHex(), Certificate: []byte("explicit kernel stub"), NotBefore: time.Now().Unix() - 60, NotAfter: time.Now().Unix() + 3600}); e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	deliveries := map[string]int{}
	callbacks := 0
	var live atomic.Int32
	client := &gateway.RelayClient{URL: cfg.PublicURL, Auth: gateway.RelayAuthRequired, AgentKey: agent, ReplayLimit: 3, ReconnectMin: 10 * time.Millisecond, ReconnectMax: 40 * time.Millisecond, OnStatus: func(s gateway.RelayStatus) {
		if s.Reason == "RELAY_LIVE" {
			live.Add(1)
		}
	}}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- client.RunGiftWraps(ctx, agent.PubKeyHex(), func(ctx context.Context, ev *nostr.Event) {
			u, err := nostr.UnwrapDM(ev, agent)
			if err != nil {
				t.Error("invalid recovered wrapper")
				return
			}
			res := gw.HandleGiftWrap(ctx, ev)
			mu.Lock()
			callbacks++
			if res.Delivered {
				deliveries[u.Rumor.ID]++
			}
			mu.Unlock()
		})
	}()
	defer func() {
		cancel()
		client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("persistent subscriber leaked")
		}
	}()
	awaitRK(t, "initial live subscription", func() bool { return live.Load() == 1 })
	blocked.Store(true)
	r.mu.Lock()
	for p := range r.peers {
		if p.auth[agent.PubKeyHex()] {
			p.stop()
		}
	}
	r.mu.Unlock()
	awaitRK(t, "transport reconnect absent", func() bool { return client.Status().Reconnects > 0 })
	ids := []string{firstID}
	// Keep exact two-event timestamp ties even if publication crosses a second.
	gapTime := time.Now().Unix() - 172790
	for i := range 7 {
		w, id := datedWrap(t, renter, agent, fmt.Sprintf("gap-%d", i), gapTime+int64(i/2))
		ids = append(ids, id)
		if e = sender.Publish(ctx, w); e != nil {
			t.Fatal(e)
		}
	}
	blocked.Store(false)
	awaitRK(t, "gap pagination did not complete", func() bool { return live.Load() >= 2 })
	mu.Lock()
	defer mu.Unlock()
	for _, id := range ids {
		if deliveries[id] != 1 {
			t.Fatal("backdated gap delivery lost or duplicated")
		}
	}
	if callbacks <= len(ids) {
		t.Fatal("inclusive replay overlap was not exercised")
	}
	if client.Status().ReplayOverflows != 0 {
		t.Fatal("distinct pages reported overflow")
	}
	s, _ := store.Get("reconnect")
	if len(s.SeenRumorIDs) != len(ids) {
		t.Fatal("durable rumor dedup mismatch")
	}
}

// An unpageable equal-timestamp group reports one counted overflow and continues
// live traffic. It must neither loop nor pretend all retained history arrived.
func TestReplayOverflow(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.Backlog = 3
	r, url := serve(t, cfg)
	_ = r
	agent, renter := key(t), key(t)
	sender := &gateway.RelayClient{URL: url}
	defer sender.Close()
	at := time.Now().Unix() - 100
	for i := range 4 {
		w, _ := datedWrap(t, renter, agent, fmt.Sprintf("tie-%d", i), at)
		if e := sender.Publish(context.Background(), w); e != nil {
			t.Fatal(e)
		}
	}
	var overflow, live atomic.Int32
	got := make(chan string, 16)
	client := &gateway.RelayClient{URL: url, ReplayLimit: 3, OnStatus: func(s gateway.RelayStatus) {
		if s.Reason == "REPLAY_OVERFLOW" {
			overflow.Add(1)
		}
		if s.Reason == "RELAY_LIVE" {
			live.Add(1)
		}
	}}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- client.RunGiftWraps(ctx, agent.PubKeyHex(), func(_ context.Context, e *nostr.Event) { got <- e.ID })
	}()
	defer func() {
		cancel()
		client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("overflow subscriber leaked")
		}
	}()
	awaitRK(t, "equal timestamp overflow not counted", func() bool { return overflow.Load() == 1 && live.Load() == 1 })
	w, _ := datedWrap(t, renter, agent, "live-after-overflow", at+1)
	if e := sender.Publish(ctx, w); e != nil {
		t.Fatal(e)
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case id := <-got:
			if id == w.ID {
				if client.Status().ReplayOverflows != 1 {
					t.Fatal("overflow status missing")
				}
				return
			}
		case <-timer.C:
			t.Fatal("overflow disabled live subscription")
		}
	}
}
