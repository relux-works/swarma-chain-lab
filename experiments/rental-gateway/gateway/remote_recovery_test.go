package gateway_test

import (
	"context"
	"errors"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
)

type remoteRecoveryDriver struct {
	known, pending              bool
	recovered, ended, destroyed int
}

func (d *remoteRecoveryDriver) Create(_ context.Context, s station.SlotSpec) (*station.Station, error) {
	d.known = true
	return &station.Station{SlotID: s.SlotID, StationName: s.StationName, ChannelSecret: make([]byte, 32)}, nil
}
func (*remoteRecoveryDriver) StartSession(context.Context, *station.Station, station.SessionInfo) error {
	return nil
}
func (d *remoteRecoveryDriver) Reattach(_ context.Context, s station.SlotSpec) (*station.Station, error) {
	d.recovered++
	if !d.known {
		return nil, station.ErrCleanupPending
	}
	return &station.Station{SlotID: s.SlotID, StationName: s.StationName}, nil
}
func (d *remoteRecoveryDriver) End(context.Context, *station.Station, string) error {
	d.ended++
	if d.pending {
		return station.ErrCleanupPending
	}
	return nil
}
func (d *remoteRecoveryDriver) Destroy(context.Context, *station.Station) (station.DestroyReport, error) {
	d.destroyed++
	if d.pending {
		return station.DestroyReport{}, station.ErrCleanupPending
	}
	return station.DestroyReport{Removed: []string{"remote station"}}, nil
}

// Opaque remote handles recover after a new Gateway instance; uncertain cleanup
// stays retryable and unknown mappings never report successful destruction.
// The fake driver proves gateway dispatch/state only, not remote OS effects.
func TestRemoteRecoveryEndDestroy(t *testing.T) {
	for _, kind := range []string{"end", "destroy"} {
		for _, failure := range []string{"none", "pending", "unknown"} {
			t.Run(kind+"/"+failure, func(t *testing.T) {
				h := newHarness(t, harnessOpts{skipStart: true})
				d := &remoteRecoveryDriver{}
				build := func() *gateway.Gateway {
					g, e := gateway.New(gateway.Config{AgentKey: h.agent, Kernel: h.kern, Screener: h.scr, Journal: h.store, Publisher: h.pub, Driver: d, Now: h.clock.Now})
					if e != nil {
						t.Fatal(e)
					}
					return g
				}
				g := build()
				if e := g.StartSlot(context.Background(), "slot-1"); e != nil {
					t.Fatal(e)
				}
				h.rebuild()
				g = build() // disk journal reload, fresh in-memory handle map
				d.pending = failure == "pending"
				d.known = failure != "unknown"
				call := func() (journal.OpRecord, error) {
					if kind == "end" {
						return g.EndSlot(context.Background(), "slot-1", "remote-op", "closer")
					}
					_, r, e := g.DestroySlot(context.Background(), "slot-1", "remote-op")
					return r, e
				}
				r, e := call()
				if failure != "none" {
					if !errors.Is(e, gateway.ErrOperationUncertain) || r.State != journal.OpStateStarted {
						t.Fatalf("uncertain cleanup must remain started: state=%s error=%v", r.State, e)
					}
					s, _ := h.store.Get("slot-1")
					if s.Destroyed {
						t.Fatal("unconfirmed remote cleanup marked destroyed")
					}
					if failure == "unknown" && (d.ended != 0 || d.destroyed != 0) {
						t.Fatal("unknown mapping invoked cleanup")
					}
					d.known = true
					d.pending = false
					r, e = call()
				}
				if e != nil || r.State != journal.OpStateDone || d.recovered == 0 || d.ended == 0 {
					t.Fatalf("remote recovery not completed: state=%s error=%v recover=%d end=%d", r.State, e, d.recovered, d.ended)
				}
				if kind == "destroy" && d.destroyed == 0 {
					t.Fatal("remote Destroy skipped")
				}
			})
		}
	}
}
