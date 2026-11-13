package lifecycle

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func brokerFixture(t *testing.T, now *int64) (*Broker, BrokerConfig) {
	t.Helper()
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	c := BrokerConfig{StateDir: root, Range: Range{First: 1, Last: 64}, Payload: Payload{ID: "relay", SHA256: strings.Repeat("a", 64)}, Now: func() time.Time { return time.Unix(*now, 0) }, StartTimeout: 10 * time.Millisecond}
	b, e := NewBroker(c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { b.Close() })
	return b, c
}

// Durable allocation keeps one credential/number across restart. A delayed
// running ACK cannot undo Stop, and manager cleanup before any Start is terminal.
func TestBrokerLifecycle(t *testing.T) {
	m, _, h, now, _ := managerFixture(t)
	b, c := brokerFixture(t, now)
	key := hash([]byte("booking"))
	grant := hash([]byte("grant"))
	s, e := b.Allocate(key, grant, 90, 200)
	if e != nil {
		t.Fatal(e)
	}
	if s.ID != "1" {
		t.Fatal("allocation")
	}
	b.Close()
	b, e = NewBroker(c)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	again, e := b.Allocate(key, grant, 90, 200)
	if e != nil || string(privateCanonical(s)) != string(privateCanonical(again)) {
		t.Fatal("allocation replay changed")
	}
	if e = b.SetStart(key); e != nil {
		t.Fatal(e)
	}
	poll, e := b.Poll(PollRequest{Version: 1, Results: []Status{}})
	if e != nil || len(poll.Commands) != 1 {
		t.Fatal("missing start", poll, e)
	}
	started, e := m.Apply(context.Background(), poll.Commands[0])
	if e != nil || started.Phase != "running" {
		t.Fatal(started, e)
	}
	if e = b.SetStop(key); e != nil {
		t.Fatal(e)
	}
	poll, e = b.Poll(PollRequest{Version: 1, Results: []Status{started}})
	if e != nil || len(poll.Commands) != 1 || poll.Commands[0].Op != "stop" {
		t.Fatal("late running ACK erased stop", poll, e)
	}
	stopped, e := m.Apply(context.Background(), poll.Commands[0])
	if e != nil || stopped.Phase != "stopped" || h.active[s.ID] {
		t.Fatal(stopped, e)
	}
	if _, e = b.Poll(PollRequest{Version: 1, Results: []Status{stopped}}); e != nil {
		t.Fatal(e)
	}
	if r, e := b.Wait(context.Background(), key, "stopped"); e != nil || r.Phase != "stopped" {
		t.Fatal(r, e)
	}
	if e = b.SetStart(key); e == nil {
		t.Fatal("terminal broker revived")
	}
	b.Close()
	b, e = NewBroker(c)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	if _, e = b.Allocate(key, grant, 90, 200); e == nil {
		t.Fatal("terminal number reused")
	}
	if s, e = b.Allocate(hash([]byte("new")), grant, 90, 200); e != nil || s.ID != "2" {
		t.Fatal("safe new allocation", s, e)
	}
	if e = b.SetStop(hash([]byte("new"))); e != nil {
		t.Fatal(e)
	}
	poll, e = b.Poll(PollRequest{Version: 1, Results: []Status{stopped}})
	if e != nil || len(poll.Commands) != 1 {
		t.Fatal(poll, e)
	}
	before := h.stops
	stopFirst, e := m.Apply(context.Background(), poll.Commands[0])
	if e != nil || stopFirst.Phase != "stopped" || h.stops != before+1 {
		t.Fatal("unseen stop did not ask helper", stopFirst, e)
	}
	delayed := poll.Commands[0]
	delayed.Op = "start"
	_, e = m.Apply(context.Background(), delayed)
	mustCode(t, e, "SLOT_TERMINAL")
}

// Foreign status/binding, conflicting allocation and short remaining windows
// refuse without changing slot authority. A bounded timeout never claims start.
func TestBrokerRefusals(t *testing.T) {
	_, _, _, now, _ := managerFixture(t)
	b, _ := brokerFixture(t, now)
	key := hash([]byte("booking"))
	grant := hash([]byte("grant"))
	if _, e := b.Allocate(key, grant, 90, 160); e == nil || len(b.state.Records) != 0 {
		t.Fatal("short deadline allocated")
	}
	s, e := b.Allocate(key, grant, 90, 200)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.Allocate(key, hash([]byte("foreign")), 90, 200); e == nil {
		t.Fatal("conflicting grant accepted")
	}
	if e = b.SetStart(key); e != nil {
		t.Fatal(e)
	}
	original := authoritySnapshot(b.state.Records)
	for _, bad := range []Status{{SlotID: "9999", Phase: "running"}, {SlotID: s.ID, Phase: "running", Binding: strings.Repeat("f", 64), NotAfter: 200}, {SlotID: s.ID, Phase: "private backend error"}} {
		if _, e = b.Poll(PollRequest{Version: 1, Results: []Status{bad}}); e == nil || !sameAuthority(original, authoritySnapshot(b.state.Records)) {
			t.Fatal("foreign status changed authority")
		}
	}
	if _, e = b.Wait(context.Background(), key, "running"); e == nil || e.Error() != "NOT_READY" {
		t.Fatal("timeout reported success", e)
	}
	*now = 201
	poll, e := b.Poll(PollRequest{Version: 1, Results: []Status{}})
	if e != nil || len(poll.Commands) != 1 || poll.Commands[0].Op != "stop" {
		t.Fatal("offline start survived expiry", poll, e)
	}
}

// A persisted running result is not a fresh readiness acknowledgement after
// restart or a new start wait. Window expiry cannot reuse even a fresh ACK.
func TestBrokerFreshReadiness(t *testing.T) {
	now := int64(100)
	b, c := brokerFixture(t, &now)
	key := hash([]byte("booking"))
	s, e := b.Allocate(key, hash([]byte("grant")), 90, 200)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.SetStart(key); e != nil {
		t.Fatal(e)
	}
	ack := Status{SlotID: s.ID, Binding: publicBinding(s, hash(s.Bootstrap.Reveal())), Phase: "running", NotAfter: s.NotAfter}
	if _, e = b.Poll(PollRequest{Version: 1, Results: []Status{ack}}); e != nil {
		t.Fatal(e)
	}
	if _, e = b.Wait(context.Background(), key, "running"); e != nil {
		t.Fatal(e)
	}
	b.Close()
	b, e = NewBroker(c)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	if _, e = b.Wait(context.Background(), key, "running"); e == nil {
		t.Fatal("restart reused old running ACK")
	}
	if e = b.SetStart(key); e != nil {
		t.Fatal(e)
	}
	if _, e = b.Wait(context.Background(), key, "running"); e == nil {
		t.Fatal("new wait reused old running ACK")
	}
	if _, e = b.Poll(PollRequest{Version: 1, Results: []Status{ack}}); e != nil {
		t.Fatal(e)
	}
	if _, e = b.Wait(context.Background(), key, "running"); e != nil {
		t.Fatal(e)
	}
	now = 200
	if _, e = b.Wait(context.Background(), key, "running"); e == nil {
		t.Fatal("expired ACK reported ready")
	}
}
