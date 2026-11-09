package slotd

import (
	"context"
	"encoding/base64"
	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
	"time"
)

// Host translates lifecycle operations to typed helper calls. PayloadID is an
// operator label; only the payload hash is reported/verified by protocol v1 r4.
type Host struct {
	Client    Caller
	Now       func() time.Time
	BootClock func() (lifecycle.CreateFence, error)
}

func (h *Host) call(ctx context.Context, r Request) (Response, error) {
	if h.Client == nil || h.Now == nil {
		return Response{}, failure("SLOTD_CONFIG")
	}
	out, e := h.Client.Call(ctx, r)
	if e != nil {
		return out, e
	}
	if !out.OK {
		return out, failure("SLOTD_" + out.Error)
	}
	return out, nil
}
func bound(r Response, s lifecycle.Slot, checkPayload bool) bool {
	return r.Slot == s.ID && r.NotAfter == time.Unix(s.NotAfter, 0).UTC().Format(time.RFC3339) && r.BootstrapSHA256 == sum(s.Bootstrap) && (!checkPayload || r.PayloadSHA256 == s.PayloadSHA256)
}
func (h *Host) Start(ctx context.Context, s lifecycle.Slot, record func(lifecycle.CreateFence) error) error {
	if h.Now == nil || s.NotAfter-h.Now().Unix() <= 60 {
		return failure("SLOTD_WINDOW")
	}
	r, e := h.call(ctx, Request{V: 1, Op: "status", Slot: s.ID})
	if e != nil {
		return e
	}
	if r.State == "absent" {
		if h.BootClock == nil || record == nil {
			return failure("SLOTD_CLOCK")
		}
		fence, e := h.BootClock()
		if e != nil || !fence.Valid() {
			return failure("SLOTD_CLOCK")
		}
		// Persist before sending; a failed write cannot authorize any Create.
		if e = record(fence); e != nil {
			return failure("SLOTD_FENCE_WRITE")
		}
		until := time.Unix(s.NotAfter, 0).UTC().Format(time.RFC3339)
		bootstrap := base64.StdEncoding.EncodeToString(s.Bootstrap)
		r, e = h.call(ctx, Request{V: 1, Op: "create", Slot: s.ID, BootID: &fence.BootID, IssuedBoottimeNS: &fence.IssuedBoottimeNS, NotAfter: &until, Bootstrap: &bootstrap})
		if e != nil {
			return e
		}
	}
	if !bound(r, s, true) {
		return failure("SLOTD_BINDING")
	}
	switch r.State {
	case "running":
		return nil
	case "created", "stopped":
	default:
		return failure("SLOTD_STATE")
	}
	// The helper checks its bound payload hash against current policy again at
	// start. A mismatch never becomes an executable/argv supplied by this client.
	r, e = h.call(ctx, Request{V: 1, Op: "start", Slot: s.ID})
	if e != nil {
		return e
	}
	if r.State != "running" || !bound(r, s, true) {
		return failure("SLOTD_BINDING")
	}
	return nil
}
func (h *Host) Stop(ctx context.Context, s lifecycle.Slot, allowAbsent bool, fence *lifecycle.CreateFence) error {
	// Snapshot before status. Crossing +6s during an early status probe cannot
	// retroactively prove absence. Early probes may still clean a bound record.
	if !allowAbsent && fence != nil && h.BootClock != nil {
		now, e := h.BootClock()
		if e == nil && fence.Elapsed(now) {
			allowAbsent = true
		}
	}
	r, e := h.call(ctx, Request{V: 1, Op: "status", Slot: s.ID})
	if e != nil {
		return e
	}
	if r.State == "absent" {
		if !allowAbsent {
			return failure("SLOTD_ABSENCE_UNCONFIRMED")
		}
		return nil
	}
	// Bootstrap/deadline prove this account belongs to this intent even if its
	// payload policy was rejected before start; that partial create may be cleaned.
	if !bound(r, s, false) {
		return failure("SLOTD_BINDING")
	}
	if r.State == "destroyed" {
		return nil
	}
	if r.State == "failed" {
		return failure("SLOTD_RECONCILIATION")
	}
	if r.State == "running" {
		_, e = h.call(ctx, Request{V: 1, Op: "stop", Slot: s.ID})
		if e != nil {
			r, check := h.call(ctx, Request{V: 1, Op: "status", Slot: s.ID})
			if check == nil && r.State == "destroyed" && bound(r, s, false) {
				return nil
			}
			return e
		}
		r, e = h.call(ctx, Request{V: 1, Op: "status", Slot: s.ID})
		if e != nil {
			return e
		}
	}
	if r.State == "destroyed" && bound(r, s, false) {
		return nil
	}
	if !bound(r, s, false) || (r.State != "created" && r.State != "stopped") {
		return failure("SLOTD_STATE")
	}
	r, e = h.call(ctx, Request{V: 1, Op: "destroy", Slot: s.ID})
	if e != nil {
		return e
	}
	if r.State != "destroyed" || !bound(r, s, false) {
		return failure("SLOTD_BINDING")
	}
	return nil
}
func (h *Host) Status(ctx context.Context, s lifecycle.Slot) (string, error) {
	r, e := h.call(ctx, Request{V: 1, Op: "status", Slot: s.ID})
	if e != nil {
		return "", e
	}
	if r.State == "absent" {
		return "stopped", nil
	}
	if !bound(r, s, true) {
		return "", failure("SLOTD_BINDING")
	}
	switch r.State {
	case "running":
		return "running", nil
	case "destroyed":
		return "stopped", nil
	default:
		return "", failure("SLOTD_STATE")
	}
}
