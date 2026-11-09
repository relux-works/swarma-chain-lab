package gateway_test

import (
	"context"
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/stationlink"
)

func rawConn(t *testing.T, h *harness) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", h.sockPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { conn.Close() })
	return conn
}

// manualHello performs hello/challenge/auth frame by frame so tests
// can send missing or malformed credentials the client would refuse
// to construct.
func manualHello(t *testing.T, conn net.Conn, slotID, station string, secret []byte) *stationlink.Frame {
	t.Helper()
	if err := stationlink.WriteFrame(conn, &stationlink.Frame{
		Type: stationlink.TypeHello, SlotID: slotID, StationName: station}); err != nil {
		t.Fatal(err)
	}
	ch, err := stationlink.ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Type != stationlink.TypeChallenge {
		return ch
	}
	resp := ""
	if secret != nil {
		resp, err = stationlink.ComputeResponse(secret, ch.Nonce, slotID, station)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		resp = strings.Repeat("0", 64)
	}
	if err := stationlink.WriteFrame(conn, &stationlink.Frame{
		Type: stationlink.TypeAuth, SlotID: slotID, StationName: station, Response: resp}); err != nil {
		t.Fatal(err)
	}
	f, err := stationlink.ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func randomSecret(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestStationAuthWrongSecret proves an unauthenticated or
// wrong-secret peer cannot bind, pull or reply, while the real
// station secret binds and works beside it (RM2 B1).
func TestStationAuthWrongSecret(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	// Stranger with a random (wrong) secret.
	stranger := rawConn(t, h)
	if f := manualHello(t, stranger, "slot-1", "id/swarma-station-1", randomSecret(t)); f.Type != stationlink.TypeError {
		t.Fatalf("wrong secret hello = %+v, want error", f)
	}
	// Stranger with no credential at all (zero response).
	stranger2 := rawConn(t, h)
	if f := manualHello(t, stranger2, "slot-1", "id/swarma-station-1", nil); f.Type != stationlink.TypeError {
		t.Fatalf("no-secret hello = %+v, want error", f)
	}
	// Unauthenticated pull/reply are refused before any binding.
	if err := stationlink.WriteFrame(stranger, &stationlink.Frame{Type: stationlink.TypePull}); err != nil {
		t.Fatal(err)
	}
	if f, _ := stationlink.ReadFrame(stranger); f == nil || f.Type != stationlink.TypeError {
		t.Fatalf("unbound pull = %+v, want error", f)
	}
	// Valid neighbour: the real secret binds and traffic flows.
	c, conn := h.stationClient()
	defer conn.Close()
	h.deliverValid(c, "authenticated station works")
}

// TestStationAuthCrossSlot proves slot A's secret cannot bind
// slot B, and a bound station sees only its own slot's queue.
func TestStationAuthCrossSlot(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	renter2, _ := nostr.GeneratePrivKey()
	if err := h.gw.RegisterSlot(gateway.SlotSpec{
		ID: "slot-2", StationName: "id/swarma-station-2",
		RenterPubKey: renter2.PubKeyHex(), Certificate: []byte("cert-2"),
		ContractSHA256: strings.Repeat("b", 64),
		NotBefore:      slotNotBefore, NotAfter: slotNotAfter,
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.gw.StartSlot(context.Background(), "slot-2"); err != nil {
		t.Fatal(err)
	}
	secret1 := h.slotSecret("slot-1")
	secret2 := h.slotSecret("slot-2")
	// A's secret presented for B must fail.
	connA := rawConn(t, h)
	if f := manualHello(t, connA, "slot-2", "id/swarma-station-2", secret1); f.Type != stationlink.TypeError {
		t.Fatalf("cross-slot secret accepted: %+v", f)
	}
	// Correct secrets bind each slot.
	c1, cc1 := h.stationClient()
	defer cc1.Close()
	connB := rawConn(t, h)
	if f := manualHello(t, connB, "slot-2", "id/swarma-station-2", secret2); f.Type != stationlink.TypeSystem {
		t.Fatalf("slot-2 hello = %+v, want system", f)
	}
	// Deliver to slot-2's renter; slot-1's station must not see it.
	wrap, _, err := nostr.WrapDM(renter2, h.agent.PubKeyHex(), "for station two only", nil, nowMid)
	if err != nil {
		t.Fatal(err)
	}
	if res := h.handle(wrap); !res.Delivered {
		t.Fatalf("slot-2 delivery refused: %+v", res)
	}
	if f := pull(t, c1); f.Type == stationlink.TypeDeliver {
		t.Fatalf("cross-slot disclosure to slot-1 station: %+v", f)
	}
	h.deliverValid(c1, "slot one own traffic")
}

// TestStationRebindRules proves: a second hello while a binding is
// live is refused, a bound connection cannot re-hello into another
// state, and after disconnect the same secret may rebind.
func TestStationRebindRules(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c1, conn1 := h.stationClient()
	// Second connection with the CORRECT secret is refused while bound.
	conn2 := rawConn(t, h)
	if f := manualHello(t, conn2, "slot-1", "id/swarma-station-1", h.slotSecret("slot-1")); f.Type != stationlink.TypeError {
		t.Fatalf("second binding accepted while bound: %+v", f)
	}
	// The bound connection itself cannot re-hello.
	if f, err := c1.Hello("slot-1", "id/swarma-station-1", h.slotSecret("slot-1")); err != nil || f.Type != stationlink.TypeError {
		t.Fatalf("re-hello on bound conn = %+v err %v", f, err)
	}
	h.deliverValid(c1, "original binding still works")
	// After disconnect, the same secret rebinds.
	conn1.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn3 := rawConn(t, h)
		f := manualHello(t, conn3, "slot-1", "id/swarma-station-1", h.slotSecret("slot-1"))
		if f.Type == stationlink.TypeSystem {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rebind after disconnect never succeeded, last = %+v", f)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestStationStaleSecretAfterEnd proves the channel secret dies at
// slot end: hello after end is refused with the end frame even with
// the previously correct secret.
func TestStationStaleSecretAfterEnd(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c, conn := h.stationClient()
	secret := h.slotSecret("slot-1")
	if _, err := c.EndEarly(); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	conn2 := rawConn(t, h)
	f := manualHello(t, conn2, "slot-1", "id/swarma-station-1", secret)
	if f.Type == stationlink.TypeSystem || f.Type == stationlink.TypeChallenge {
		t.Fatalf("stale secret after end accepted: %+v", f)
	}
	slot, _ := h.store.Get("slot-1")
	if slot.ChannelSecretHex != "" {
		t.Fatal("channel secret not cleared at slot end")
	}
}
