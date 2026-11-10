package gateway_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/stationlink"
)

// Actual NIP-44/59 wrapping (not a size mirror) proves escaped accepted replies
// become an immutable short notice, survive lost ACK/restart, and release the
// next delivery. A fitting plain reply remains intact. The real native relay
// boundary is additionally exercised in the relay module.
func TestDeliveryWrappedSizeTerminal(t *testing.T) {
	for _, mode := range []string{"html", "quotes", "plain", "unicode", "fitting"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, harnessOpts{})
			p := &deliveryPublisher{after: true}
			g := deliveryGateway(t, h, p)
			content := strings.Repeat("a", 32768)
			want := "reply exceeded deliverable size"
			switch mode {
			case "html":
				content = strings.Repeat("<", 32768)
				want = "reply exceeded deliverable size"
			case "quotes":
				content = strings.Repeat(`"`, 32768)
				want = "reply exceeded deliverable size"
			case "unicode":
				content = strings.Repeat("я", 16384)
			case "fitting":
				content = strings.Repeat("a", 24000)
				want = content
			}
			_, _, wrapErr := nostr.WrapDM(h.agent, h.renter.PubKeyHex(), content, [][]string{{"e", strings.Repeat("d", 64)}}, nowMid)
			if (wrapErr != nil) != (mode == "html" || mode == "quotes") {
				t.Fatal("wrapped-size witness/positive control invalid", wrapErr)
			}
			if !h.handle(h.renterDM("first", nowMid)).Delivered || !h.handle(h.renterDM("following", nowMid)).Delivered {
				t.Fatal("input admission")
			}
			c, close := deliveryConn(t, h, g)
			f := receiveDelivery(t, c)
			ack, e := c.Reply(f.DeliveryID, content)
			if e != nil || ack.Type != stationlink.TypeError {
				t.Fatal("lost ACK witness", e)
			}
			close()
			d, ok := h.store.Delivery("slot-1", f.DeliveryID)
			if !ok || d.Phase != journal.DeliveryReady || d.Reply != want || len(p.accepted) != 1 || len(p.attempts) != 1 {
				t.Fatal("oversize reply did not become terminal-ready")
			}
			wire := append([]byte(nil), d.Wire...)
			t.Logf("wrapped event bytes %d", len(wire))
			event, e := nostr.ParseEvent(wire)
			if e != nil {
				t.Fatal(e)
			}
			dm, e := nostr.UnwrapDM(event, h.renter)
			if e != nil || dm.Rumor.Content != want {
				t.Fatal("renter size outcome changed", e)
			}
			h.store, e = journal.Open(h.journalDir)
			if e != nil {
				t.Fatal(e)
			}
			g = deliveryGateway(t, h, p)
			c, close = deliveryConn(t, h, g)
			defer close()
			retry := receiveDelivery(t, c)
			if retry.DeliveryID != f.DeliveryID {
				t.Fatal("lost ACK changed pending identity")
			}
			if ack, e = c.Reply(retry.DeliveryID, content); e != nil || ack.Type != stationlink.TypeAck {
				t.Fatal("terminal size replay refused", e)
			}
			d, _ = h.store.Delivery("slot-1", f.DeliveryID)
			if d.Phase != journal.DeliveryAccepted {
				t.Fatal("size outcome did not become terminal-accepted")
			}
			if !bytes.Equal(wire, d.Wire) || !bytes.Equal(wire, p.attempts[1]) || len(p.accepted) != 1 {
				t.Fatal("terminal size result regenerated")
			}
			if ack, e = c.Reply(retry.DeliveryID, "different answer"); e != nil || ack.Type != stationlink.TypeError || len(p.attempts) != 2 {
				t.Fatal("size outcome overwritten", e)
			}
			next := receiveDelivery(t, c)
			if next.DeliveryID == f.DeliveryID || next.Content != "following" {
				t.Fatal("size outcome wedged following delivery")
			}
			if ack, e = c.Reply(next.DeliveryID, "next answer"); e != nil || ack.Type != stationlink.TypeAck || len(p.accepted) != 2 {
				t.Fatal("following delivery not published", e)
			}
			if _, pending := h.store.PendingDelivery("slot-1", nil); pending {
				t.Fatal("terminal size delivery still pending")
			}
		})
	}
}

// The new terminal notice does not bypass input bounds or durable-outbox
// failure. Both refusals leave bytes and publications unchanged, then repair
// permits the same admitted delivery's valid bounded result.
func TestDeliverySizeRefusal(t *testing.T) {
	for _, mode := range []string{"raw-bound", "write-failure"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, harnessOpts{})
			p := &deliveryPublisher{}
			g := deliveryGateway(t, h, p)
			if !h.handle(h.renterDM("question", nowMid)).Delivered {
				t.Fatal("input")
			}
			c, close := deliveryConn(t, h, g)
			f := receiveDelivery(t, c)
			path := filepath.Join(h.journalDir, "slot-slot-1.json")
			before, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			content := strings.Repeat("a", 32769)
			if mode == "write-failure" {
				content = strings.Repeat("<", 32768)
				if e = os.Chmod(h.journalDir, 0500); e != nil {
					t.Fatal(e)
				}
			}
			ack, e := c.Reply(f.DeliveryID, content)
			if e != nil || ack.Type != stationlink.TypeError || len(p.attempts) != 0 {
				t.Fatal("size refusal published", e)
			}
			after, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("size refusal changed journal", e)
			}
			close()
			if e = os.Chmod(h.journalDir, 0700); e != nil {
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
			if mode == "raw-bound" {
				content = strings.Repeat("a", 32768)
			}
			if ack, e = c.Reply(f.DeliveryID, content); e != nil || ack.Type != stationlink.TypeAck || len(p.accepted) != 1 {
				t.Fatal("size refusal repair neighbor failed", e)
			}
		})
	}
}

// Missing/invalid caps and a lowered cap below an existing immutable wire refuse
// construction with unchanged journal and no publication; restoring the original
// cap permits the identical pending event to finish.
func TestDeliveryEventLimitStartup(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	p := &deliveryPublisher{after: true}
	cfg := gateway.Config{RelayMaxEventBytes: 131072, AgentKey: h.agent, Kernel: h.kern, Screener: h.scr, Journal: h.store, Publisher: p, Driver: h.driver, Now: h.clock.Now}
	for _, cap := range []int{0, -1, 1, 131073} {
		bad := cfg
		bad.RelayMaxEventBytes = cap
		if _, e := gateway.New(bad); e == nil {
			t.Fatal("invalid relay cap admitted")
		}
	}
	g, e := gateway.New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	h.gw = g
	if !h.handle(h.renterDM("question", nowMid)).Delivered {
		t.Fatal("input")
	}
	c, stop := deliveryConn(t, h, g, 131072)
	f := receiveDelivery(t, c)
	ack, e := c.Reply(f.DeliveryID, strings.Repeat("a", 32768))
	if e != nil || ack.Type != stationlink.TypeError {
		t.Fatal("lost ACK", e)
	}
	stop()
	d, _ := h.store.Delivery("slot-1", f.DeliveryID)
	if d.Phase != journal.DeliveryReady || len(d.Wire) <= 65536 {
		t.Fatal("large ready witness missing")
	}
	path := filepath.Join(h.journalDir, "slot-slot-1.json")
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	cfg.RelayMaxEventBytes = 65536
	if _, e = gateway.New(cfg); e == nil || !strings.Contains(e.Error(), "pending delivery exceeds") {
		t.Fatal("lowered relay cap admitted immutable outbox")
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) || len(p.attempts) != 1 {
		t.Fatal("relay cap refusal changed state")
	}
	cfg.RelayMaxEventBytes = 131072
	g, e = gateway.New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	c, stop = deliveryConn(t, h, g, 131072)
	defer stop()
	f = receiveDelivery(t, c)
	ack, e = c.Reply(f.DeliveryID, strings.Repeat("a", 32768))
	if e != nil || ack.Type != stationlink.TypeAck {
		t.Fatal("original cap did not recover", e)
	}
	if !bytes.Equal(d.Wire, p.attempts[1]) || len(p.accepted) != 1 {
		t.Fatal("cap repair regenerated outbox")
	}
}

// A pre-upgrade Ready wire can fit at its real timestamp even where the new
// maximum-metadata reservation rejects the text. Exact saved replies must retain
// that wire through ACK/restart; changed text still refuses without publication.
func TestDeliveryLegacySizeBoundary(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	p := &deliveryPublisher{}
	g := deliveryGateway(t, h, p)
	if !h.handle(h.renterDM("legacy", nowMid)).Delivered {
		t.Fatal("input")
	}
	c, stop := deliveryConn(t, h, g)
	f := receiveDelivery(t, c)
	text := strings.Repeat("a", 28304)
	event, _, e := nostr.WrapDM(h.agent, h.renter.PubKeyHex(), text, [][]string{{"e", f.DeliveryID}}, nowMid)
	if e != nil {
		t.Fatal(e)
	}
	wire, e := json.Marshal(event)
	if e != nil || len(wire) > 65536 || nostr.BoundDeliveryReply(text, 65536) == text {
		t.Fatal("legacy size boundary witness invalid", len(wire), e)
	}
	if e = h.store.ChangeDelivery("slot-1", f.DeliveryID, journal.DeliveryReady, text, wire); e != nil {
		t.Fatal(e)
	}
	stop()
	h.store, e = journal.Open(h.journalDir)
	if e != nil {
		t.Fatal(e)
	}
	g = deliveryGateway(t, h, p)
	c, stop = deliveryConn(t, h, g)
	defer stop()
	f = receiveDelivery(t, c)
	ack, e := c.Reply(f.DeliveryID, "changed answer")
	if e != nil || ack.Type != stationlink.TypeError || len(p.attempts) != 0 {
		t.Fatal("legacy reply overwritten", e)
	}
	ack, e = c.Reply(f.DeliveryID, text)
	if e != nil || ack.Type != stationlink.TypeAck {
		t.Fatal("exact legacy reply refused by conservative bound", e)
	}
	d, _ := h.store.Delivery("slot-1", f.DeliveryID)
	if d.Phase != journal.DeliveryAccepted || !bytes.Equal(d.Wire, wire) || len(p.attempts) != 1 || !bytes.Equal(p.attempts[0], wire) {
		t.Fatal("legacy signed wire changed")
	}
}
