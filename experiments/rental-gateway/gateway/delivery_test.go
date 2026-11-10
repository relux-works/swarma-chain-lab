package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/stationlink"
)

// This publisher models only the acknowledged/unacknowledged boundary. Actual
// relay duplicate suppression is qualified separately by its real websocket tests.
type deliveryPublisher struct {
	mu        sync.Mutex
	attempts  [][]byte
	accepted  map[string][]byte
	before    bool
	after     bool
	afterSend func()
}

func (p *deliveryPublisher) Publish(_ context.Context, e *nostr.Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, _ := json.Marshal(e)
	p.attempts = append(p.attempts, raw)
	if p.before {
		p.before = false
		return errors.New("unsent")
	}
	if p.accepted == nil {
		p.accepted = map[string][]byte{}
	}
	p.accepted[e.ID] = raw
	if p.afterSend != nil {
		p.afterSend()
		p.afterSend = nil
	}
	if p.after {
		p.after = false
		return errors.New("ack lost")
	}
	return nil
}
func deliveryGateway(t *testing.T, h *harness, p gateway.Publisher) *gateway.Gateway {
	t.Helper()
	g, e := gateway.New(gateway.Config{AgentKey: h.agent, Kernel: h.kern, Screener: h.scr, Journal: h.store, Publisher: p, Driver: h.driver, Now: h.clock.Now, PullTimeout: 20 * time.Millisecond})
	if e != nil {
		t.Fatal(e)
	}
	h.gw = g
	return g
}
func deliveryConn(t *testing.T, h *harness, g *gateway.Gateway) (*stationlink.Client, func()) {
	t.Helper()
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); g.HandleStationConn(b) }()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	c := stationlink.NewClient(a)
	if f, e := c.Hello("slot-1", "id/swarma-station-1", h.slotSecret("slot-1")); e != nil || f.Type != stationlink.TypeSystem {
		t.Fatal("hello", e)
	}
	close := func() {
		a.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("connection leaked")
		}
	}
	return c, close
}
func receiveDelivery(t *testing.T, c *stationlink.Client) *stationlink.Frame {
	t.Helper()
	f, e := c.Pull()
	if e != nil || f.Type != stationlink.TypeDeliver {
		t.Fatal("pull", e)
	}
	ack, e := c.Received(f.DeliveryID)
	if e != nil || ack.Type != stationlink.TypeAck || ack.DeliveryID != f.DeliveryID {
		t.Fatal("receive ACK", e)
	}
	return f
}

// Restart after durable input, after remote acceptance with lost ACK, or after
// failed local acceptance marking always reuses the identical signed event.
func TestDeliveryCrashRetry(t *testing.T) {
	for _, phase := range []string{"input-recorded", "before-send", "ack-lost", "mark-failed"} {
		t.Run(phase, func(t *testing.T) {
			h := newHarness(t, harnessOpts{})
			p := &deliveryPublisher{}
			g := deliveryGateway(t, h, p)
			wrap := h.renterDM("question", nowMid)
			if r := h.handle(wrap); !r.Delivered {
				t.Fatal("input", r)
			}
			var previous []byte
			if phase != "input-recorded" {
				c, close := deliveryConn(t, h, g)
				f := receiveDelivery(t, c)
				p.before = phase == "before-send"
				p.after = phase == "ack-lost"
				if phase == "mark-failed" {
					p.afterSend = func() {
						if e := os.Chmod(h.journalDir, 0500); e != nil {
							panic(e)
						}
					}
				}
				ack, e := c.Reply(f.DeliveryID, "immutable answer")
				if e != nil || ack.Type != stationlink.TypeError {
					t.Fatal("uncertain reply not refused", e)
				}
				close()
				previous = append([]byte(nil), p.attempts[0]...)
				if e = os.Chmod(h.journalDir, 0700); e != nil {
					t.Fatal(e)
				}
			}
			var e error
			h.store, e = journal.Open(h.journalDir)
			if e != nil {
				t.Fatal(e)
			}
			g = deliveryGateway(t, h, p)
			c, close := deliveryConn(t, h, g)
			defer close()
			f := receiveDelivery(t, c)
			if f.Content != "question" {
				t.Fatal("durable input lost")
			}
			if ack, e := c.Reply(f.DeliveryID, "immutable answer"); e != nil || ack.Type != stationlink.TypeAck || ack.DeliveryID != f.DeliveryID {
				t.Fatal("retry", e)
			}
			if len(p.accepted) != 1 {
				t.Fatal("more than one logical event")
			}
			if previous != nil && !bytes.Equal(previous, p.attempts[len(p.attempts)-1]) {
				t.Fatal("retry regenerated signed bytes")
			}
			before := len(p.attempts)
			if ack, e := c.Reply(f.DeliveryID, "immutable answer"); e != nil || ack.Type != stationlink.TypeAck {
				t.Fatal("accepted replay", e)
			}
			if len(p.attempts) != before {
				t.Fatal("accepted reply published again")
			}
			if ack, e := c.Reply(f.DeliveryID, "different answer"); e != nil || ack.Type != stationlink.TypeError || len(p.attempts) != before {
				t.Fatal("different reply admitted", e)
			}
			if r := h.handle(wrap); r.Reason != "replayed_rumor" {
				t.Fatal("input replay admitted")
			}
		})
	}
}

// Unknown/unreceived replies and post-authority attempts have no publication;
// a valid receipt-bound live reply provides the positive neighbor.
func TestDeliveryRefusals(t *testing.T) {
	for _, mode := range []string{"unknown", "unreceived", "revoked", "expired"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, harnessOpts{})
			p := &deliveryPublisher{}
			g := deliveryGateway(t, h, p)
			if !h.handle(h.renterDM("question", nowMid)).Delivered {
				t.Fatal("input")
			}
			c, close := deliveryConn(t, h, g)
			defer close()
			f, e := c.Pull()
			if e != nil {
				t.Fatal(e)
			}
			if mode != "unreceived" {
				if ack, e := c.Received(f.DeliveryID); e != nil || ack.Type != stationlink.TypeAck {
					t.Fatal("receive", e)
				}
			}
			id := f.DeliveryID
			switch mode {
			case "unknown":
				id = strings.Repeat("f", 64)
			case "revoked":
				h.kern.Verdict = kernel.Refused
			case "expired":
				h.clock.Set(slotNotAfter)
			}
			ack, e := c.Reply(id, "answer")
			if e != nil || ack.Type != stationlink.TypeError || len(p.attempts) != 0 {
				t.Fatal("forbidden reply published", e)
			}
			if mode == "expired" {
				return
			} // terminal slot; other table rows exercise the live neighbor
			h.kern.Verdict = kernel.Live
			if mode == "unreceived" {
				if ack, e := c.Received(f.DeliveryID); e != nil || ack.Type != stationlink.TypeAck {
					t.Fatal("receipt neighbor", e)
				}
			}
			if ack, e := c.Reply(f.DeliveryID, "answer"); e != nil || ack.Type != stationlink.TypeAck || len(p.accepted) != 1 {
				t.Fatal("valid reply neighbor", e)
			}
		})
	}
}

// A corrupt ready outbox prevents reopening; neither the persisted bytes nor
// the publication count changes. Restoring the valid file re-enables exact retry.
func TestDeliveryCorruptOutbox(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	p := &deliveryPublisher{before: true}
	g := deliveryGateway(t, h, p)
	if !h.handle(h.renterDM("question", nowMid)).Delivered {
		t.Fatal("input")
	}
	c, close := deliveryConn(t, h, g)
	f := receiveDelivery(t, c)
	if ack, e := c.Reply(f.DeliveryID, "answer"); e != nil || ack.Type != stationlink.TypeError {
		t.Fatal("prepare", e)
	}
	close()
	file := filepath.Join(h.journalDir, "slot-slot-1.json")
	raw, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	bad := bytes.Replace(raw, []byte(`"reply":"answer"`), []byte(`"reply":"changed"`), 1)
	if bytes.Equal(raw, bad) {
		t.Fatal("plant not applied")
	}
	if e = os.WriteFile(file, bad, 0600); e != nil {
		t.Fatal(e)
	}
	before := len(p.attempts)
	if _, e = journal.Open(h.journalDir); e == nil {
		t.Fatal("corrupt outbox admitted")
	}
	after, _ := os.ReadFile(file)
	if !bytes.Equal(bad, after) || len(p.attempts) != before {
		t.Fatal("corrupt state had effects")
	}
	if e = os.WriteFile(file, raw, 0600); e != nil {
		t.Fatal(e)
	}
	h.store, e = journal.Open(h.journalDir)
	if e != nil {
		t.Fatal(e)
	}
	g = deliveryGateway(t, h, p)
	c, close = deliveryConn(t, h, g)
	defer close()
	f = receiveDelivery(t, c)
	if ack, e := c.Reply(f.DeliveryID, "answer"); e != nil || ack.Type != stationlink.TypeAck {
		t.Fatal("valid neighbor", e)
	}
}

// A failed durable input write cannot acknowledge or expose a delivery. Restart
// after repairing this isolated filesystem permits the original input once.
func TestDeliveryInputWriteRefusal(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	p := &deliveryPublisher{}
	g := deliveryGateway(t, h, p)
	file := filepath.Join(h.journalDir, "slot-slot-1.json")
	before, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	wrap := h.renterDM("question", nowMid)
	if e = os.Chmod(h.journalDir, 0500); e != nil {
		t.Fatal(e)
	}
	r := h.handle(wrap)
	if !r.Refused || r.Reason != "journal_error" || r.Delivered || len(p.attempts) != 0 {
		t.Fatal("write failure acknowledged")
	}
	after, _ := os.ReadFile(file)
	if !bytes.Equal(before, after) {
		t.Fatal("failed input write changed journal")
	}
	if e = os.Chmod(h.journalDir, 0700); e != nil {
		t.Fatal(e)
	}
	h.store, e = journal.Open(h.journalDir)
	if e != nil {
		t.Fatal(e)
	}
	g = deliveryGateway(t, h, p)
	if r = h.handle(wrap); !r.Delivered {
		t.Fatal("retry refused", r)
	}
	c, close := deliveryConn(t, h, g)
	defer close()
	f := receiveDelivery(t, c)
	if ack, e := c.Reply(f.DeliveryID, "answer"); e != nil || ack.Type != stationlink.TypeAck || len(p.accepted) != 1 {
		t.Fatal("valid repair neighbor", e)
	}
}

// The publisher boundary observes a durable ready event before its effect. A
// filesystem failure cannot escape that ordering; the separate failure test
// proves the neighboring refusal path.
func TestDeliveryWriteBeforePublish(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	p := &deliveryPublisher{}
	g := deliveryGateway(t, h, p)
	if !h.handle(h.renterDM("question", nowMid)).Delivered {
		t.Fatal("input")
	}
	c, close := deliveryConn(t, h, g)
	defer close()
	f := receiveDelivery(t, c)
	ready := false
	p.afterSend = func() {
		reopened, e := journal.Open(h.journalDir)
		if e != nil {
			return
		}
		d, ok := reopened.Delivery("slot-1", f.DeliveryID)
		ready = ok && d.Phase == journal.DeliveryReady && d.Reply == "answer" && bytes.Equal(d.Wire, p.attempts[0])
	}
	ack, e := c.Reply(f.DeliveryID, "answer")
	if !ready {
		t.Fatal("publish preceded durable outbox")
	}
	if e != nil || ack.Type != stationlink.TypeAck {
		t.Fatal("positive publish", e)
	}
}

// A crash-left screening reservation never bypasses the admission decision or
// invokes the screening model again. Its replay explicitly reports uncertainty;
// an unrelated valid turn still admits normally.
func TestDeliveryScreeningUncertain(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	p := &deliveryPublisher{}
	deliveryGateway(t, h, p)
	wrap := h.renterDM("question", nowMid)
	dm, e := nostr.UnwrapDM(wrap, h.agent)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.store.RecordInput("slot-1", dm.Rumor.ID, dm.Rumor.Content); e != nil {
		t.Fatal(e)
	}
	h.store, e = journal.Open(h.journalDir)
	if e != nil {
		t.Fatal(e)
	}
	g := deliveryGateway(t, h, p)
	if r := h.handle(wrap); !r.Refused || r.Reason != "screening_uncertain" || r.Delivered || h.scr.Calls != 0 || len(p.attempts) != 0 {
		t.Fatal("screening uncertainty escaped", r)
	}
	c, close := deliveryConn(t, h, g)
	defer close()
	if f, e := c.Pull(); e != nil || f.Type != stationlink.TypeNone {
		t.Fatal("uncertain input dispatched", e)
	}
	if !h.handle(h.renterDM("another question", nowMid)).Delivered {
		t.Fatal("valid neighbor")
	}
	receiveDelivery(t, c)
	if h.scr.Calls != 1 {
		t.Fatal("screening rerun")
	}
}
