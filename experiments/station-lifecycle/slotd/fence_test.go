package slotd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
)

// Malformed/missing r4 fields never dial; canonical neighbors use exactly the
// fixed r4 order, and stale_request remains a closed typed helper refusal.
func TestR4Wire(t *testing.T) {
	host, h, s := fixture(t)
	ctx := context.Background()
	var sent Request
	original := host.Client
	host.Client = callFunc(func(ctx context.Context, q Request) (Response, error) {
		if q.Op == "create" {
			sent = q
		}
		return original.Call(ctx, q)
	})
	if e := host.Start(ctx, s, func(lifecycle.CreateFence) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if !ValidRequest(sent) || !strings.Contains(string(canonical(sent)), `"slot":"17","boot_id":"`+h.bootID+`","issued_boottime_ns":"10000000000","not_after":`) {
		t.Fatal("r4 wire order/fields")
	}
	for _, kind := range []string{"missing-boot", "missing-time", "alias-time", "overflow", "upper-boot", "other-op"} {
		q := sent
		bad := ""
		switch kind {
		case "missing-boot":
			q.BootID = nil
		case "missing-time":
			q.IssuedBoottimeNS = nil
		case "alias-time":
			bad = "010"
			q.IssuedBoottimeNS = &bad
		case "overflow":
			bad = "18446744073709551616"
			q.IssuedBoottimeNS = &bad
		case "upper-boot":
			bad = strings.ToUpper(h.bootID)
			q.BootID = &bad
		case "other-op":
			q.Op = "status"
		}
		before := len(h.ops)
		if _, e := original.Call(ctx, q); e == nil || e.Error() != "SLOTD_REQUEST" || len(h.ops) != before {
			t.Fatal("invalid r4 request reached helper")
		}
	}
	stored := h.records[s.ID]
	stored.State = "created"
	h.records[s.ID] = stored
	for _, tc := range []struct {
		name  string
		now   uint64
		boot  string
		stale bool
	}{
		{"exact-past-boundary", 15_000_000_000, h.bootID, false},
		{"past-boundary-plus-one", 15_000_000_001, h.bootID, true},
		{"exact-future-boundary", 9_000_000_000, h.bootID, false},
		{"future-boundary-plus-one", 8_999_999_999, h.bootID, true},
		{"reboot", 10_000_000_000, "1f8e1c3a-6b2d-4e7f-9a1b-2c3d4e5f6a7b", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.bootNS = tc.now
			h.bootID = tc.boot
			r, e := original.Call(ctx, sent)
			if e != nil {
				t.Fatal(e)
			}
			if tc.stale {
				if r.OK || r.Error != "stale_request" {
					t.Fatal("stale request not refused")
				}
			} else if !r.OK || r.State != "created" {
				t.Fatal("fresh boundary refused")
			}
		})
	}
}

type pendingFixture struct {
	host    *Host
	helper  *fakeHelper
	slot    lifecycle.Slot
	manager *lifecycle.Manager
	config  lifecycle.Config
	create  *Request
}

func deferredFixture(t *testing.T) *pendingFixture {
	t.Helper()
	host, h, s := fixture(t)
	p := &pendingFixture{host: host, helper: h, slot: s}
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	p.config = lifecycle.Config{StateDir: root, Range: lifecycle.Range{First: 1, Last: 64}, Payload: lifecycle.Payload{ID: s.PayloadID, SHA256: s.PayloadSHA256}, Host: host, Now: host.Now}
	original := host.Client
	host.Client = callFunc(func(ctx context.Context, q Request) (Response, error) {
		if q.Op == "create" {
			raw, e := os.ReadFile(filepath.Join(root, "state.json"))
			if e != nil {
				t.Fatal(e)
			}
			var disk struct {
				Records map[string]struct {
					CreateFence *lifecycle.CreateFence `json:"create_fence"`
				} `json:"records"`
			}
			if json.Unmarshal(raw, &disk) != nil || disk.Records[s.ID].CreateFence == nil {
				t.Fatal("create sent before durable fence")
			}
			f := disk.Records[s.ID].CreateFence
			if f.BootID != *q.BootID || f.IssuedBoottimeNS != *q.IssuedBoottimeNS {
				t.Fatal("sent fence differs from durable fence")
			}
			copied := q
			p.create = &copied
			return Response{}, failure("SLOTD_TRANSPORT")
		}
		return original.Call(ctx, q)
	})
	m, e := lifecycle.New(p.config)
	if e != nil {
		t.Fatal(e)
	}
	p.manager = m
	r, e := m.Start(context.Background(), s)
	if e == nil || e.Error() != "HOST_CLEANUP" || r.Phase != "stopping" || p.create == nil {
		t.Fatal("uncertain create not retained", r, e)
	}
	m.Close()
	m, e = lifecycle.New(p.config)
	if e != nil {
		t.Fatal(e)
	}
	p.manager = m
	t.Cleanup(func() { p.manager.Close() })
	return p
}

// The manager persists its exact pre-send fence and restores it. Before +6s,
// absent cannot finish; after +6s absent is terminal and delayed Create is stale.
// Busy and foreign stored bindings cannot be converted to clean by elapsed time.
func TestR4UncertainRecovery(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"absent", "busy", "reboot", "wall-step", "clock-error", "foreign", "early-late-create"} {
		t.Run(kind, func(t *testing.T) {
			p := deferredFixture(t)
			h := p.helper
			m := p.manager
			h.bootNS = 15_999_999_999
			if e := m.Tick(ctx); e == nil || e.Error() != "HOST_CLEANUP" {
				t.Fatal("early absence finished cleanup", e)
			}
			switch kind {
			case "early-late-create":
				h.bootNS = 14_000_000_000
				if r := h.reply(*p.create); !r.OK || r.State != "created" {
					t.Fatal("fresh delayed fixture did not create")
				}
			case "reboot":
				h.bootID = "1f8e1c3a-6b2d-4e7f-9a1b-2c3d4e5f6a7b"
				h.bootNS = 1
			case "wall-step":
				h.now = 99
				h.bootNS = 16_000_000_000
			default:
				h.bootNS = 16_000_000_000
			}
			if kind == "busy" {
				h.busy = true
				if e := m.Tick(ctx); e == nil || e.Error() != "HOST_CLEANUP" {
					t.Fatal("busy claimed clean", e)
				}
				h.busy = false
			}
			if kind == "clock-error" {
				saved := p.host.BootClock
				p.host.BootClock = func() (lifecycle.CreateFence, error) {
					return lifecycle.CreateFence{}, errors.New("fixture clock failed")
				}
				if e := m.Tick(ctx); e == nil || e.Error() != "HOST_CLEANUP" {
					t.Fatal("unknown clock claimed clean", e)
				}
				p.host.BootClock = saved
			}
			if kind == "foreign" {
				h.records[p.slot.ID] = Response{V: 1, OK: true, Slot: p.slot.ID, State: "destroyed", NotAfter: "1970-01-01T00:05:00Z", PayloadSHA256: h.payload, BootstrapSHA256: strings.Repeat("d", 64)}
				if e := m.Tick(ctx); e == nil || e.Error() != "HOST_CLEANUP" {
					t.Fatal("foreign binding claimed clean", e)
				}
				delete(h.records, p.slot.ID)
			}
			e := m.Tick(ctx)
			if kind == "wall-step" && (e == nil || e.Error() != "CLOCK_ROLLBACK") {
				t.Fatal("wall rollback diagnostic lost", e)
			}
			if e != nil && kind != "wall-step" {
				t.Fatal(e)
			}
			r, e := m.Status(ctx, p.slot.ID)
			if e != nil || r.Phase != "stopped" {
				t.Fatal("fenced cleanup not completed", r, e)
			}
			if kind != "early-late-create" {
				late := h.reply(*p.create)
				if late.OK || late.Error != "stale_request" {
					t.Fatal("late create escaped fence")
				}
			} else if h.records[p.slot.ID].State != "destroyed" {
				t.Fatal("matching delayed resource not destroyed")
			}
		})
	}
}

// The clock must be captured before the absence probe, not after a slow status
// that crossed the deadline. A subsequent properly fenced probe is the neighbor.
func TestR4StatusProbeOrdering(t *testing.T) {
	host, h, s := fixture(t)
	f, e := host.BootClock()
	if e != nil {
		t.Fatal(e)
	}
	h.bootNS = 15_999_999_999
	original := host.Client
	host.Client = callFunc(func(ctx context.Context, q Request) (Response, error) {
		r, e := original.Call(ctx, q)
		h.bootNS = 16_000_000_000
		return r, e
	})
	if e = host.Stop(context.Background(), s, false, &f); e == nil || e.Error() != "SLOTD_ABSENCE_UNCONFIRMED" {
		t.Fatal("pre-fence absence retroactively accepted", e)
	}
	if e = host.Stop(context.Background(), s, false, &f); e != nil {
		t.Fatal("post-fence absence neighbor", e)
	}
}

// Failed persistence prevents any create; no regenerated timestamp is sent on
// retry. Existing r2 attempts without a fence remain conservatively pending.
func TestR4FenceWriteRefusal(t *testing.T) {
	host, h, s := fixture(t)
	if e := host.Start(context.Background(), s, func(lifecycle.CreateFence) error { return errors.New("fixture disk failed") }); e == nil || e.Error() != "SLOTD_FENCE_WRITE" {
		t.Fatal("failed fence write accepted", e)
	}
	for _, op := range h.ops {
		if op != "status" {
			t.Fatal("helper effect after failed fence write")
		}
	}
	h.bootNS = 100_000_000_000
	if e := host.Stop(context.Background(), s, false, nil); e == nil || e.Error() != "SLOTD_ABSENCE_UNCONFIRMED" {
		t.Fatal("legacy attempt invented a fence", e)
	}
	if e := host.Start(context.Background(), s, func(f lifecycle.CreateFence) error {
		if f.IssuedBoottimeNS != strconv.FormatUint(h.bootNS, 10) {
			t.Fatal("wrong boot clock")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
