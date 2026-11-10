package gatewaybind

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/screen"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
)

type fakeHost struct {
	mu            sync.Mutex
	starts, stops int
	active        bool
	slot          lifecycle.Slot
}

func (h *fakeHost) Start(_ context.Context, s lifecycle.Slot, _ func(lifecycle.CreateFence) error) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.starts++
	h.active = true
	h.slot = s
	return nil
}
func (h *fakeHost) Stop(context.Context, lifecycle.Slot, bool, *lifecycle.CreateFence) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stops++
	h.active = false
	return nil
}
func (h *fakeHost) Status(context.Context, lifecycle.Slot) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active {
		return "running", nil
	}
	return "stopped", nil
}

type publisher struct{}

func (publisher) Publish(context.Context, *nostr.Event) error { return nil }

type fixture struct {
	c        Config
	d        *Driver
	g        *gateway.Gateway
	gcfg     gateway.Config
	host     *fakeHost
	m        *lifecycle.Manager
	id, jdir string
}

func privateDir(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if e := os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}
func setup(t *testing.T, model ...proxy.Caps) *fixture {
	t.Helper()
	f := &fixture{id: strings.Repeat("b", 64), jdir: filepath.Join(privateDir(t), "journal"), host: &fakeHost{}}
	j, e := journal.Open(f.jdir)
	if e != nil {
		t.Fatal(e)
	}
	now := func() time.Time { return time.Unix(100, 0) }
	f.c = Config{StateDir: privateDir(t), Journal: j, PayloadID: "relay", PayloadSHA256: strings.Repeat("a", 64), SlotMin: 1, SlotMax: 64, ManagerCertSHA256: strings.Repeat("c", 64), Now: now, StartTimeout: 250 * time.Millisecond}
	f.d, e = New(f.c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.d.Close() })
	f.m, e = lifecycle.New(lifecycle.Config{StateDir: privateDir(t), Range: lifecycle.Range{First: 1, Last: 64}, Payload: lifecycle.Payload{ID: f.c.PayloadID, SHA256: f.c.PayloadSHA256}, Host: f.host, Now: now})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.m.Close() })
	agent, e := nostr.GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	renter, e := nostr.GeneratePrivKey()
	if e != nil {
		t.Fatal(e)
	}
	f.gcfg = gateway.Config{RelayMaxEventBytes: 65536, AgentKey: agent, Kernel: &kernel.Stub{Verdict: kernel.Live}, Screener: &screen.Stub{}, Publisher: publisher{}, Journal: j, Driver: f.d, Now: now}
	f.g, e = gateway.New(f.gcfg)
	if e != nil {
		t.Fatal(e)
	}
	// Canonical transport framing only. Stub kernel deliberately limits this test
	// to gateway/lifecycle composition; this is not a signed-grant proof.
	raw := []byte(`{"signed_grant":{"grant":{"version":3},"signature":"` + strings.Repeat("0", 128) + `"},"issuance":{"txid":"` + strings.Repeat("0", 64) + `"}}`)
	slot := gateway.SlotSpec{ID: f.id, BookingID: f.id, StationName: "id/fixture", RenterPubKey: renter.PubKeyHex(), Certificate: raw, ContractSHA256: strings.Repeat("d", 64), NotBefore: 90, NotAfter: 200}
	if len(model) == 1 {
		fixtureModelContract(t, &slot, agent.PubKeyHex(), model[0])
	}
	if e = f.g.RegisterSlot(slot); e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *fixture) restart(t *testing.T) {
	t.Helper()
	f.d.Close()
	j, e := journal.Open(f.jdir)
	if e != nil {
		t.Fatal(e)
	}
	f.c.Journal = j
	f.d, e = New(f.c)
	if e != nil {
		t.Fatal(e)
	}
	f.gcfg.Journal = j
	f.gcfg.Driver = f.d
	f.g, e = gateway.New(f.gcfg)
	if e != nil {
		t.Fatal(e)
	}
}

// pump substitutes the authenticated transport only; real TLS has separate
// positive/negative integration controls in the independent core module.
func (f *fixture) pump(t *testing.T) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	d := f.d
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				p, e := d.broker.Poll(lifecycle.PollRequest{Version: 1, Results: f.m.Results()})
				if e != nil {
					t.Errorf("poll: %v", e)
					return
				}
				for _, c := range p.Commands {
					if _, e = f.m.Apply(ctx, c); e != nil {
						t.Errorf("apply: %v", e)
						return
					}
				}
			}
		}
	}()
	return func() { cancel(); <-done }
}

// A real gateway and durable broker/manager compose through restart: the same
// channel credential reaches the fake host, and End/Destroy wait for cleanup.
func TestGatewayLifecycleRecovery(t *testing.T) {
	for _, kind := range []string{"end", "destroy"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			stop := f.pump(t)
			if e := f.g.StartSlot(context.Background(), f.id); e != nil {
				stop()
				t.Fatal(e)
			}
			stop()
			s, _ := f.c.Journal.Get(f.id)
			f.host.mu.Lock()
			active := f.host.active
			f.host.mu.Unlock()
			if !active || !s.Started || s.StationHome != "" || s.StationUser != "" {
				t.Fatal("start did not preserve opaque host authority")
			}
			v, e := f.d.broker.Lookup(f.id)
			if e != nil {
				t.Fatal(e)
			}
			decoded, e := DecodeBootstrap(v.Bootstrap)
			if e != nil || decoded.BookingID != f.id || decoded.StationName != "id/fixture" {
				t.Fatal("payload routing bootstrap", e)
			}
			credential, e := f.d.broker.Credential(f.id)
			if e != nil || !bytes.Equal(decoded.ChannelSecret, credential) {
				t.Fatal("payload channel credential", e)
			}
			f.host.mu.Lock()
			same := bytes.Equal(v.Bootstrap, f.host.slot.Bootstrap)
			f.host.mu.Unlock()
			if !same {
				t.Fatal("channel credential differs from helper bootstrap")
			}
			f.restart(t)
			call := func() (journal.OpRecord, error) {
				if kind == "end" {
					return f.g.EndSlot(context.Background(), f.id, "cleanup", "closer")
				}
				_, r, e := f.g.DestroySlot(context.Background(), f.id, "cleanup")
				return r, e
			}
			r, e := call()
			if !errors.Is(e, gateway.ErrOperationUncertain) || r.State != journal.OpStateStarted {
				t.Fatalf("disconnected cleanup: %s %v", r.State, e)
			}
			s, _ = f.c.Journal.Get(f.id)
			if s.Destroyed {
				t.Fatal("timeout marked destroyed")
			}
			p, e := f.d.broker.Poll(lifecycle.PollRequest{Version: 1, Results: f.m.Results()})
			if e != nil || len(p.Commands) != 1 || p.Commands[0].Op != "stop" {
				t.Fatal("restart did not queue Stop")
			}
			stop = f.pump(t)
			r, e = call()
			stop()
			if e != nil || r.State != journal.OpStateDone {
				t.Fatalf("cleanup retry: %s %v", r.State, e)
			}
			f.host.mu.Lock()
			active = f.host.active
			calls := f.host.stops
			f.host.mu.Unlock()
			if active || calls == 0 {
				t.Fatal("gateway completed without real manager cleanup")
			}
			if _, e = f.d.Create(context.Background(), station.SlotSpec{SlotID: f.id, BookingID: f.id, StationName: "id/fixture"}); e == nil {
				t.Fatal("terminal slot revived")
			}
		})
	}
}

// Unknown durable mappings refuse cleanup; altered identity/session facts refuse
// before Start, while the valid neighboring session still reaches the manager.
func TestGatewayBindingRefusals(t *testing.T) {
	f := setup(t)
	if _, _, e := f.g.DestroySlot(context.Background(), f.id, "unknown"); !errors.Is(e, gateway.ErrOperationUncertain) {
		t.Fatal("unknown mapping reported success", e)
	}
	s, _ := f.c.Journal.Get(f.id)
	if s.Destroyed {
		t.Fatal("unknown slot marked destroyed")
	}
	f = setup(t)
	spec := station.SlotSpec{SlotID: f.id, BookingID: f.id, StationName: "id/fixture"}
	bad := spec
	bad.BookingID = strings.Repeat("e", 64)
	if _, e := f.d.Create(context.Background(), bad); e == nil {
		t.Fatal("foreign booking accepted")
	}
	st, e := f.d.Create(context.Background(), spec)
	if e != nil {
		t.Fatal(e)
	}
	s, _ = f.c.Journal.Get(f.id)
	info := station.SessionInfo{NotAfter: s.NotAfter, RenterPubKey: s.RenterPubKey, ContractSHA256: s.ContractSHA256}
	changed := info
	changed.NotAfter++
	if e = f.d.StartSession(context.Background(), st, changed); e == nil {
		t.Fatal("changed session deadline accepted")
	}
	if e = f.d.StartSession(context.Background(), st, info); e == nil || e.Error() != "LIFECYCLE_NOT_READY" {
		t.Fatal("offline start reported ready", e)
	}
	stop := f.pump(t)
	defer stop()
	if e = f.d.StartSession(context.Background(), st, info); e != nil {
		t.Fatal(e)
	}
}
