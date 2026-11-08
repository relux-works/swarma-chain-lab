package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/journal"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/screen"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/stationlink"
)

// HandleGiftWrap runs the inbound pipeline for one gift-wrapped DM,
// in the request's fixed order. Every refusal is final for that
// event; nothing is delivered on any error path.
func (g *Gateway) HandleGiftWrap(ctx context.Context, wrap *nostr.Event) Result {
	refuse := func(reason string) Result {
		return Result{Refused: true, Reason: reason}
	}
	// (a) Strict unwrap: sender is the seal pubkey.
	unwrapped, err := nostr.UnwrapDM(wrap, g.cfg.AgentKey)
	if err != nil {
		return refuse("unwrap: " + err.Error())
	}
	sender := unwrapped.SenderHex
	rumor := unwrapped.Rumor
	res := Result{SenderHex: sender}

	// (c) Sender must be the grantee of an active slot (looked up
	// first because replay journal and windows are per-slot).
	slot, ok := g.cfg.Journal.ActiveByRenter(sender)
	if !ok {
		res.Refused, res.Reason = true, "no_active_slot"
		return res
	}
	res.SlotID = slot.ID
	now := g.cfg.Now().Unix()
	if now >= slot.NotAfter {
		g.endSlot(ctx, slot.ID, "not_after", "slot ended")
		res.Refused, res.Reason, res.SlotEnded = true, "slot_over", true
		return res
	}

	// (b) Replay journal: rumor time inside the slot window, and the
	// rumor id recorded durably before any delivery.
	if rumor.CreatedAt < slot.NotBefore || rumor.CreatedAt >= slot.NotAfter {
		res.Refused, res.Reason = true, "rumor_outside_slot_window"
		return res
	}
	already, err := g.cfg.Journal.RecordSeen(slot.ID, rumor.ID)
	if err != nil {
		res.Refused, res.Reason = true, "journal_error"
		return res
	}
	if already {
		res.Refused, res.Reason = true, "replayed_rumor"
		return res
	}

	// (d) Grant live check, fresh for this event.
	receipt, err := g.kernelCheckSender(ctx, slot, sender, now)
	if err != nil {
		res.Refused, res.Reason = true, "kernel_error"
		return res
	}
	if !receipt.Admits() {
		res.Refused = true
		res.Reason = fmt.Sprintf("kernel_%s:%s", receipt.Verdict, receipt.Reason)
		return res
	}

	// (e) Screening: only an explicit allow delivers.
	decision, err := g.runScreen(ctx, rumor.Content)
	if err != nil || !decision.Allow {
		reason := decision.Reason
		if err != nil {
			reason = "screening_unavailable"
		}
		if reason == "" {
			reason = "screening_refused"
		}
		return g.screeningRefusal(ctx, slot, res, reason)
	}

	// (f) Deliver to the station pull queue.
	q := g.queueFor(slot.ID)
	frame := &stationlink.Frame{
		Type: stationlink.TypeDeliver, SlotID: slot.ID,
		DeliveryID: rumor.ID, Content: rumor.Content,
	}
	select {
	case q <- frame:
		res.Delivered = true
		return res
	default:
		res.Refused, res.Reason = true, "station_queue_full"
		return res
	}
}

// screeningRefusal implements 5.0: durable counter first (fsync
// before acting), then renter warning + station notice, second
// refusal ends the slot. The message is never delivered.
func (g *Gateway) screeningRefusal(ctx context.Context, slot *journal.Slot, res Result, reason string) Result {
	res.Refused = true
	res.Reason = "screening:" + reason
	count, err := g.cfg.Journal.AddRefusal(slot.ID)
	if err != nil {
		// Without a durable count we must not warn/end on a guess;
		// refusing delivery is still fail-closed.
		res.Reason = "journal_error"
		return res
	}
	warning := fmt.Sprintf("warning: your message was refused by screening (%s). Refusal %d of 2; a second refusal ends the slot.", reason, count)
	if count >= 2 {
		warning = fmt.Sprintf("warning: your message was refused by screening (%s). Second refusal: the slot has ended.", reason)
	}
	if err := g.dmRenter(ctx, slot, warning); err == nil {
		res.WarningSent = true
	}
	q := g.queueFor(slot.ID)
	select {
	case q <- &stationlink.Frame{Type: stationlink.TypeNotice, SlotID: slot.ID, Reason: reason,
		Content: "screening refusal: renter message not delivered"}:
	default:
	}
	if count >= 2 {
		g.endSlot(ctx, slot.ID, "screening_second_refusal", "")
		res.SlotEnded = true
	}
	return res
}

var errScreenTimeout = errors.New("screening timeout")

// runScreen enforces a hard timeout even if the screener ignores ctx.
func (g *Gateway) runScreen(ctx context.Context, content string) (screen.Decision, error) {
	ctx, cancel := context.WithTimeout(ctx, g.cfg.ScreenTimeout)
	defer cancel()
	type out struct {
		d   screen.Decision
		err error
	}
	ch := make(chan out, 1)
	go func() {
		d, err := g.cfg.Screener.Screen(ctx, content)
		ch <- out{d, err}
	}()
	select {
	case o := <-ch:
		return o.d, o.err
	case <-ctx.Done():
		return screen.Decision{Allow: false}, errScreenTimeout
	}
}

// ServeStations accepts station-initiated connections until the
// listener closes. Each connection is served in its own goroutine.
func (g *Gateway) ServeStations(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go g.HandleStationConn(conn)
	}
}

// HandleStationConn serves one station connection. The station must
// hello-bind to a started, not-ended slot with a matching station
// name before any other request is honoured.
func (g *Gateway) HandleStationConn(conn net.Conn) {
	defer conn.Close()
	ctx := context.Background()
	var slotID string
	for {
		frame, err := stationlink.ReadFrame(conn)
		if err != nil {
			return
		}
		resp := g.stationRequest(ctx, &slotID, frame)
		if err := stationlink.WriteFrame(conn, resp); err != nil {
			return
		}
		if resp.Type == stationlink.TypeEnd {
			return
		}
	}
}

func (g *Gateway) stationRequest(ctx context.Context, bound *string, frame *stationlink.Frame) *stationlink.Frame {
	deny := func(reason string) *stationlink.Frame {
		return &stationlink.Frame{Type: stationlink.TypeError, Reason: reason}
	}
	switch frame.Type {
	case stationlink.TypeHello:
		slot, ok := g.cfg.Journal.Get(frame.SlotID)
		if !ok {
			return deny("unknown slot")
		}
		if slot.Destroyed {
			return deny("station destroyed")
		}
		if slot.Ended {
			return &stationlink.Frame{Type: stationlink.TypeEnd, SlotID: slot.ID, Reason: slot.EndReason}
		}
		if !slot.Started {
			return deny("session not started")
		}
		if frame.StationName != slot.StationName {
			return deny("station name mismatch")
		}
		*bound = slot.ID
		return &stationlink.Frame{
			Type: stationlink.TypeSystem, SlotID: slot.ID,
			RenterPubKey: slot.RenterPubKey, ContractSHA256: slot.ContractSHA256,
			NotAfter: slot.NotAfter,
		}
	case stationlink.TypeExtend:
		// The agent may end a slot early; it can never extend one.
		return deny("extension refused")
	}
	if *bound == "" {
		return deny("hello required first")
	}
	slot, ok := g.cfg.Journal.Get(*bound)
	if !ok || slot.Destroyed {
		return deny("station destroyed")
	}
	switch frame.Type {
	case stationlink.TypePull:
		if slot.Ended {
			return &stationlink.Frame{Type: stationlink.TypeEnd, SlotID: slot.ID, Reason: slot.EndReason}
		}
		q := g.queueFor(slot.ID)
		select {
		case f := <-q:
			return f
		case <-time.After(g.cfg.PullTimeout):
			// Re-check end state so a slot that ended while waiting
			// still terminates promptly on the next pull.
			if fresh, ok := g.cfg.Journal.Get(slot.ID); ok && fresh.Ended {
				return &stationlink.Frame{Type: stationlink.TypeEnd, SlotID: slot.ID, Reason: fresh.EndReason}
			}
			return &stationlink.Frame{Type: stationlink.TypeNone, SlotID: slot.ID}
		}
	case stationlink.TypeReply:
		if slot.Ended {
			return deny("slot ended")
		}
		if g.cfg.Now().Unix() >= slot.NotAfter {
			g.endSlot(ctx, slot.ID, "not_after", "slot ended")
			return deny("slot over")
		}
		if err := g.dmRenter(ctx, slot, frame.Content); err != nil {
			return deny("publish failed")
		}
		return &stationlink.Frame{Type: stationlink.TypeAck, SlotID: slot.ID}
	case stationlink.TypeEndEarly:
		g.endSlot(ctx, slot.ID, "agent_end_early", "slot ended early by agent")
		return &stationlink.Frame{Type: stationlink.TypeEnd, SlotID: slot.ID, Reason: "agent_end_early"}
	default:
		return deny("unknown request type")
	}
}
