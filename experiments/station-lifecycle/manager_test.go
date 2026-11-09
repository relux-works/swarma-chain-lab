package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeHost struct {
	mu                  sync.Mutex
	active              map[string]bool
	starts, stops       int
	failStart, failStop bool
	beforeStart         func(Slot)
}

func (h *fakeHost) Start(_ context.Context, s Slot, _ func(CreateFence) error) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.beforeStart != nil {
		h.beforeStart(s)
	}
	h.starts++
	h.active[s.ID] = true
	if h.failStart {
		return errors.New("private backend error")
	}
	return nil
}
func (h *fakeHost) Stop(_ context.Context, s Slot, _ bool, _ *CreateFence) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stops++
	if h.failStop {
		return errors.New("private backend error")
	}
	delete(h.active, s.ID)
	return nil
}
func (h *fakeHost) Status(_ context.Context, s Slot) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active[s.ID] {
		return "running", nil
	}
	return "stopped", nil
}
func managerFixture(t *testing.T) (*Manager, Config, *fakeHost, *int64, Slot) {
	t.Helper()
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	now := int64(100)
	h := &fakeHost{active: map[string]bool{}}
	c := Config{StateDir: root, Range: Range{First: 1, Last: 9999}, Payload: Payload{ID: "relay", SHA256: strings.Repeat("a", 64)}, Host: h, Now: func() time.Time { return time.Unix(now, 0) }}
	m, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { m.Close() })
	s := Slot{Version: 1, ID: "1", GrantID: strings.Repeat("b", 64), NotBefore: 90, NotAfter: 200, PayloadID: "relay", PayloadSHA256: strings.Repeat("a", 64), Bootstrap: Secret(strings.Repeat("c", 32))}
	return m, c, h, &now, s
}
func mustCode(t *testing.T, e error, code string) {
	t.Helper()
	if e == nil || e.Error() != code {
		t.Fatalf("want %s got %v", code, e)
	}
}

// The manager persists intent before a host effect, retries identical starts
// without duplicate effects, and makes stop terminal while clearing bootstrap.
// OS behavior here is an explicit fake, not Linux enforcement evidence.
func TestManagerLifecycle(t *testing.T) {
	m, c, h, _, s := managerFixture(t)
	ctx := context.Background()
	h.beforeStart = func(slot Slot) {
		raw, e := os.ReadFile(filepath.Join(c.StateDir, "state.json"))
		if e != nil {
			t.Fatal(e)
		}
		var st state
		if json.Unmarshal(raw, &st) != nil || st.Records[slot.ID].Phase != "starting" {
			t.Fatal("host effect before durable intent")
		}
	}
	r, e := m.Start(ctx, s)
	if e != nil || r.Phase != "running" || h.starts != 1 {
		t.Fatal(r, e)
	}
	r, e = m.Start(ctx, s)
	if e != nil || r.Phase != "running" || h.starts != 1 {
		t.Fatal("start repeated", r, e)
	}
	bad := s
	bad.Bootstrap = Secret(strings.Repeat("d", 32))
	_, e = m.Start(ctx, bad)
	mustCode(t, e, "SLOT_CONFLICT")
	m.Close()
	m, e = New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	r, e = m.Status(ctx, s.ID)
	if e != nil || r.Phase != "running" {
		t.Fatal(r, e)
	}
	r, e = m.Stop(ctx, s.ID)
	if e != nil || r.Phase != "stopped" || h.active[s.ID] {
		t.Fatal("stop incomplete", r, e)
	}
	if len(m.state.Records[s.ID].Slot.Bootstrap) != 0 {
		t.Fatal("bootstrap retained after stop")
	}
	_, e = m.Start(ctx, s)
	mustCode(t, e, "SLOT_TERMINAL")
	before := h.stops
	_, e = m.Stop(ctx, s.ID)
	if e != nil || h.stops != before {
		t.Fatal("terminal stop repeated")
	}
	m.Close()
	m, e = New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	_, e = m.Start(ctx, s)
	mustCode(t, e, "SLOT_TERMINAL")
}

// Invalid received slot authority has no host effect or retained allocation;
// the valid neighbor is admitted. Stops received before starts remain terminal.
func TestManagerRefusals(t *testing.T) {
	for _, field := range []string{"id", "alias", "range", "grant", "payload", "hash", "bootstrap", "window"} {
		t.Run(field, func(t *testing.T) {
			m, _, h, _, s := managerFixture(t)
			bad := s
			switch field {
			case "id":
				bad.ID = "../foreign"
			case "grant":
				bad.GrantID = "bad"
			case "alias":
				bad.ID = "01"
			case "range":
				bad.ID = "10000"
			case "payload":
				bad.PayloadID = "shell"
			case "hash":
				bad.PayloadSHA256 = strings.Repeat("d", 64)
			case "bootstrap":
				bad.Bootstrap = nil
			case "window":
				bad.NotAfter = bad.NotBefore
			}
			_, e := m.Start(context.Background(), bad)
			expected := "SLOT_POLICY"
			if field == "payload" || field == "hash" {
				expected = "HOST_POLICY"
			}
			if e == nil || e.Error() != expected || h.starts != 0 || len(m.state.Records) != 0 {
				t.Fatal("invalid slot allocated authority")
			}
			if r, e := m.Start(context.Background(), s); e != nil || r.Phase != "running" {
				t.Fatal("valid neighbor", r, e)
			}
		})
	}
	t.Run("late-start", func(t *testing.T) {
		m, _, h, _, s := managerFixture(t)
		if _, e := m.Apply(context.Background(), Command{Op: "stop", Slot: s, Binding: publicBinding(s, hash(s.Bootstrap))}); e != nil {
			t.Fatal(e)
		}
		_, e := m.Start(context.Background(), s)
		mustCode(t, e, "SLOT_TERMINAL")
		if h.starts != 0 {
			t.Fatal("late start escaped stop")
		}
	})
}

// An unavailable link is irrelevant to expiry. Restart cleans expired/partial
// starts; cleanup failure stays pending and retries, never claiming destruction.
func TestManagerExpiryRecovery(t *testing.T) {
	for _, mode := range []string{"expiry", "restart-expired", "partial", "rollback", "cleanup-failure"} {
		t.Run(mode, func(t *testing.T) {
			m, c, h, now, s := managerFixture(t)
			ctx := context.Background()
			if _, e := m.Start(ctx, s); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "partial":
				r := m.state.Records[s.ID]
				r.Phase = "starting"
				m.state.Records[s.ID] = r
				if e := m.save(); e != nil {
					t.Fatal(e)
				}
			case "rollback":
				*now = 99
			default:
				*now = s.NotAfter
			}
			if mode == "restart-expired" || mode == "partial" {
				m.Close()
				var e error
				m, e = New(c)
				if e != nil {
					t.Fatal(e)
				}
				defer m.Close()
			}
			if mode == "cleanup-failure" {
				h.failStop = true
				mustCode(t, m.Tick(ctx), "HOST_CLEANUP")
				if m.state.Records[s.ID].Phase != "stopping" || !h.active[s.ID] {
					t.Fatal("failed cleanup reported stopped")
				}
				h.failStop = false
			}
			e := m.Tick(ctx)
			if mode == "rollback" {
				mustCode(t, e, "CLOCK_ROLLBACK")
			} else if e != nil {
				t.Fatal(e)
			}
			if m.state.Records[s.ID].Phase != "stopped" || h.active[s.ID] || h.starts != 1 {
				t.Fatal("expiry/recovery did not clean without restart")
			}
		})
	}
}

// Live and lifetime bounds refuse before host allocation. Terminal records are
// retained; exhausting capacity cannot be repaired by reviving or evicting them.
func TestManagerBounds(t *testing.T) {
	m, _, h, _, s := managerFixture(t)
	ctx := context.Background()
	for i := 0; i < MaxRetained; i++ {
		s.ID = fmt.Sprint(i + 1)
		if i == MaxLive {
			_, e := m.Start(ctx, s)
			mustCode(t, e, "CAPACITY")
			for id := range m.state.Records {
				if _, e := m.Stop(ctx, id); e != nil {
					t.Fatal(e)
				}
			}
		}
		if _, e := m.Start(ctx, s); e != nil {
			t.Fatal(i, e)
		}
		if i >= MaxLive {
			if _, e := m.Stop(ctx, s.ID); e != nil {
				t.Fatal(e)
			}
		}
	}
	before := h.starts
	s.ID = "9999"
	_, e := m.Start(ctx, s)
	mustCode(t, e, "CAPACITY")
	if h.starts != before || len(m.state.Records) != MaxRetained {
		t.Fatal("capacity exceeded")
	}
}

// Public formatting and status do not print bootstrap material; canonical state
// binding refuses a changed local policy instead of silently taking ownership.
func TestManagerPrivacyAndBinding(t *testing.T) {
	m, c, _, _, s := managerFixture(t)
	if strings.Contains(fmt.Sprintf("%+v %#v %+v", s, s, s.Bootstrap), string(s.Bootstrap)) {
		t.Fatal("private bootstrap formatted")
	}
	r, e := m.Start(context.Background(), s)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(canonical(r)), string(s.Bootstrap)) {
		t.Fatal("bootstrap in public status")
	}
	m.Close()
	c.Range.Last--
	_, e = New(c)
	mustCode(t, e, "STATE_BINDING")
}

// Unknown Stop cannot attest absence from an empty journal; an authenticated,
// fully bound Stop still reaches the host, as covered by TestBrokerLifecycle.
func TestManagerUnknownStop(t *testing.T) {
	m, _, h, _, s := managerFixture(t)
	_, e := m.Stop(context.Background(), s.ID)
	mustCode(t, e, "NOT_FOUND")
	if len(m.state.Records) != 0 || h.stops != 0 {
		t.Fatal("unknown stop created an unbound tombstone")
	}
	if _, e = m.Start(context.Background(), s); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Stop(context.Background(), s.ID); e != nil {
		t.Fatal(e)
	}
}

// Persisted running state is reconciled with the helper before being advertised
// by the polling loop; a missing unit becomes terminal rather than stale ready.
func TestManagerLostRunningHost(t *testing.T) {
	m, c, h, _, s := managerFixture(t)
	if _, e := m.Start(context.Background(), s); e != nil {
		t.Fatal(e)
	}
	m.Close()
	h.active[s.ID] = false
	m, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	if e = m.Tick(context.Background()); e != nil {
		t.Fatal(e)
	}
	r, e := m.Status(context.Background(), s.ID)
	if e != nil || r.Phase != "stopped" || h.stops == 0 {
		t.Fatalf("lost host remained running: %v %v", r, e)
	}
}
