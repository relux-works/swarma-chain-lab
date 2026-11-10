package relay

import (
	"context"
	hexenc "encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/screen"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/stationlink"
)

// The actual gateway outbox and websocket publisher drive the unchanged native
// relay default. A fitting reply is stored, a 32768-byte plain reply becomes one
// stored terminal notice, then the next delivery progresses. Kernel/host are
// explicit stubs; the relay, wrapping, journal and HMAC channel are real.
func TestDeliveryDefaultRelaySize(t *testing.T) {
	cfg := fixtureConfig(t)
	if cfg.MaxEventBytes != 65536 {
		t.Fatal("default relay cap changed")
	}
	r, url := serve(t, cfg)
	agent, renter := key(t), key(t)
	publisher := &gateway.RelayClient{URL: url}
	defer publisher.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Independent negative control: actual wrapping succeeds but this actual
	// relay refuses the full wire. This proves the relay bound matters.
	oversized, _, e := nostr.WrapDM(agent, renter.PubKeyHex(), strings.Repeat("a", 32768), [][]string{{"e", strings.Repeat("d", 64)}}, time.Now().Unix())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(oversized)
	if len(raw) <= 65536 {
		t.Fatal("oversize relay witness invalid")
	}
	if _, e = validEvent(raw, cfg); e == nil || e.Error() != "EVENT_SIZE" {
		t.Fatal("relay event size guard missing", e)
	}
	if e = publisher.Publish(ctx, oversized); !errors.Is(e, gateway.ErrRelayClosed) {
		t.Fatal("oversize frame did not close publisher", e)
	}
	r.mu.Lock()
	stored := len(r.store.events)
	r.mu.Unlock()
	if stored != 0 {
		t.Fatal("oversize control changed store")
	}
	j, e := journal.Open(filepath.Join(t.TempDir(), "journal"))
	if e != nil {
		t.Fatal(e)
	}
	gw, e := gateway.New(gateway.Config{RelayMaxEventBytes: 65536, AgentKey: agent, Kernel: &kernel.Stub{Verdict: kernel.Live}, Screener: screen.Off{}, Journal: j, Publisher: publisher, Driver: &station.LocalTestDriver{Root: filepath.Join(t.TempDir(), "stations")}})
	if e != nil {
		t.Fatal(e)
	}
	if e = gw.RegisterSlot(gateway.SlotSpec{ID: "size", StationName: "id/size", RenterPubKey: renter.PubKeyHex(), Certificate: []byte("explicit kernel stub"), ContractSHA256: strings.Repeat("a", 64), NotBefore: time.Now().Unix() - 60, NotAfter: time.Now().Unix() + 3600}); e != nil {
		t.Fatal(e)
	}
	if e = gw.StartSlot(ctx, "size"); e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	initial := len(r.store.events)
	r.mu.Unlock()
	if initial != 1 {
		t.Fatal("startup ready notice missing")
	}
	slot, _ := j.Get("size")
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); gw.HandleStationConn(b) }()
	defer func() {
		a.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("station connection leaked")
		}
	}()
	a.SetDeadline(time.Now().Add(10 * time.Second))
	client := stationlink.NewClient(a)
	secret, e := hexenc.DecodeString(slot.ChannelSecretHex)
	if e != nil {
		t.Fatal(e)
	}
	system, e := client.Hello("size", "id/size", secret)
	if e != nil || system.Type != stationlink.TypeSystem || system.RelayMaxEventBytes != 65536 {
		t.Fatal("authenticated relay cap missing", e)
	}
	for _, text := range []string{"fitting", "oversize", "following"} {
		w, _, e := nostr.WrapDM(renter, agent.PubKeyHex(), text, nil, time.Now().Unix())
		if e != nil {
			t.Fatal(e)
		}
		if res := gw.HandleGiftWrap(ctx, w); !res.Delivered {
			t.Fatal("input admission", res.Reason)
		}
	}
	for i, reply := range []string{strings.Repeat("a", 24000), strings.Repeat("a", 32768), "next answer"} {
		f, e := client.Pull()
		if e != nil || f.Type != stationlink.TypeDeliver {
			t.Fatal("size outcome wedged next delivery", e)
		}
		ack, e := client.Received(f.DeliveryID)
		if e != nil || ack.Type != stationlink.TypeAck {
			t.Fatal("receive", e)
		}
		ack, e = client.Reply(f.DeliveryID, reply)
		if e != nil || ack.Type != stationlink.TypeAck {
			t.Fatal("default relay terminal reply failed", e)
		}
		want := reply
		if i == 1 {
			want = "reply exceeded deliverable size"
		}
		d, ok := j.Delivery("size", f.DeliveryID)
		if !ok || d.Phase != journal.DeliveryAccepted || d.Reply != want || len(d.Wire) > 65536 {
			t.Fatal("relay size result not terminal")
		}
		ev, e := nostr.ParseEvent(d.Wire)
		if e != nil {
			t.Fatal(e)
		}
		r.mu.Lock()
		v := r.store.events[ev.ID]
		count := len(r.store.events)
		r.mu.Unlock()
		if v == nil || count != initial+i+1 {
			t.Fatal("terminal reply not stored once")
		}
		dm, e := nostr.UnwrapDM(v, renter)
		if e != nil || dm.Rumor.Content != want {
			t.Fatal("stored reply mismatch", e)
		}
	}
	if _, pending := j.PendingDelivery("size", nil); pending {
		t.Fatal("completed delivery remained pending")
	}
	// The default relay persisted the same accepted events, not only memory.
	data, e := os.ReadFile(filepath.Join(cfg.StateDir, "events.json"))
	if e != nil {
		t.Fatal(e)
	}
	var snap snapshot
	if json.Unmarshal(data, &snap) != nil || len(snap.Events) != initial+3 {
		t.Fatal("relay disk snapshot mismatch")
	}
}
