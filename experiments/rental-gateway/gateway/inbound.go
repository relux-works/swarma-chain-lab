package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/journal"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/screen"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/stationlink"
)

// HandleGiftWrap runs the inbound pipeline for one gift-wrapped DM,
// in fixed order. Every refusal is final for that event; nothing is
// delivered on any error path.
func (g *Gateway) HandleGiftWrap(ctx context.Context, wrap *nostr.Event) Result {
	// (a) Strict unwrap: sender is the seal pubkey.
	unwrapped, err := nostr.UnwrapDM(wrap, g.cfg.AgentKey)
	if err != nil {
		return Result{Refused: true, Reason: "unwrap: " + err.Error()}
	}
	sender := unwrapped.SenderHex
	rumor := unwrapped.Rumor
	res := Result{SenderHex: sender}

	// (c) Sender must be the grantee of an active slot (looked up
	// first because windows and the journal are per-slot).
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

	// (b) Rumor time inside the slot window. The durable seen
	// record moves after the kernel admits (RM2 M4): kernel-refused
	// or pending messages do not burn their rumor id.
	if rumor.CreatedAt < slot.NotBefore || rumor.CreatedAt >= slot.NotAfter {
		res.Refused, res.Reason = true, "rumor_outside_slot_window"
		return res
	}

	// (d0) Inline certificate presentation (detached grants): at
	// most one grant-cert rumor tag. Malformed presentation refuses
	// this message before screening — no strike, rumor id not
	// burned — with a deterministic gateway notice. The tag itself
	// is consumed here and never reaches the station: delivery and
	// screening only ever see the rumor content.
	pres, perr := parseGrantPresentation(rumor)
	if perr != nil {
		res.Refused, res.Reason = true, "presentation_malformed"
		g.presentationNotice(ctx, slot, &res, noticePresentationMalformed)
		return res
	}
	if pres != nil && g.cfg.Presenter == nil {
		res.Refused, res.Reason = true, "presentation_unsupported"
		g.presentationNotice(ctx, slot, &res, noticePresentationUnsupported)
		return res
	}

	// (d) Grant live check, fresh for this event: a presented
	// envelope goes through kernel Presenter (fresh Check inside,
	// live-only cache admission); otherwise the sender's known
	// bytes are Checked fresh. A receipt with durable closure
	// (Closed) ends the slot at once and stops all outbound (RM2 M2).
	var receipt kernel.Receipt
	var kerr error
	if pres != nil {
		receipt, kerr = g.cfg.Presenter.Present(ctx, pres.raw, pres.id,
			g.agentNameFor(slot), sender, now)
	} else {
		receipt, kerr = g.kernelCheckSender(ctx, slot, sender, now)
	}
	if kerr != nil {
		res.Refused, res.Reason = true, "kernel_error"
		return res
	}
	if receipt.Closed {
		g.endSlot(ctx, slot.ID, "kernel_closed", "")
		res.Refused, res.SlotEnded = true, true
		res.Reason = fmt.Sprintf("kernel_closed:%s", receipt.Reason)
		return res
	}
	if !receipt.Admits() {
		res.Refused = true
		res.Reason = fmt.Sprintf("kernel_%s:%s", receipt.Verdict, receipt.Reason)
		// Presentation refusals get a deterministic gateway notice
		// (fixed texts, never the screening model).
		switch {
		case receipt.Reason == "presentation_required":
			g.presentationNotice(ctx, slot, &res, noticePresentationRequired)
		case pres != nil:
			g.presentationNotice(ctx, slot, &res,
				fmt.Sprintf("presentation refused: %s:%s", receipt.Verdict, receipt.Reason))
		}
		return res
	}

	// (d1) Lazy instance start: the first live verdict for an
	// in-window grantee starts that grantee's station instance
	// (one per slot) before anything is recorded or delivered.
	if !slot.Started {
		if err := g.ensureStarted(ctx, slot); err != nil {
			res.Refused, res.Reason = true, "station_start_failed"
			return res
		}
		slot.Started = true
	}

	// (b, durable half) Record the rumor id now — after kernel live,
	// fsynced before screening and delivery — so a replayed,
	// screened message cannot add further strikes (RM2 M4).
	already, err := g.cfg.Journal.RecordSeen(slot.ID, rumor.ID)
	if err != nil {
		res.Refused, res.Reason = true, "journal_error"
		return res
	}
	if already {
		res.Refused, res.Reason = true, "replayed_rumor"
		return res
	}

	// (e) Screening: only an explicit allow delivers, and only an
	// explicit model REFUSE spends a strike (RM2 M1 policy).
	decision, err := g.runScreen(ctx, rumor.Content)
	if err != nil {
		return g.screeningUnavailable(ctx, slot, res)
	}
	if !decision.Allow {
		reason := decision.Reason
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

// screeningUnavailable refuses one message without a strike when
// the model path failed (timeout, transport error, malformed
// answer): the renter is told to retry, the station is noticed.
func (g *Gateway) screeningUnavailable(ctx context.Context, slot *journal.Slot, res Result) Result {
	res.Refused = true
	res.Reason = "screening_unavailable"
	if err := g.dmRenter(ctx, slot,
		"screening unavailable, retry: your message was not delivered and does not count as a refusal."); err == nil {
		res.WarningSent = true
	}
	q := g.queueFor(slot.ID)
	select {
	case q <- &stationlink.Frame{Type: stationlink.TypeNotice, SlotID: slot.ID,
		Reason:  "screening_unavailable",
		Content: "screening unavailable: renter message not delivered (no strike)"}:
	default:
	}
	return res
}

// screeningRefusal implements 5.0 for an explicit model REFUSE:
// durable counter first (fsync before acting), then renter warning
// + station notice, second strike ends the slot. Never delivered.
func (g *Gateway) screeningRefusal(ctx context.Context, slot *journal.Slot, res Result, reason string) Result {
	res.Refused = true
	res.Reason = "screening:" + reason
	count, err := g.cfg.Journal.AddRefusal(slot.ID)
	if err != nil {
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

// connState is one station connection's auth state.
type connState struct {
	pendingSlot    string
	pendingStation string
	nonceHex       string
	boundSlot      string
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

// HandleStationConn serves one station connection. Hello requests a
// challenge; Auth (HMAC over nonce||slot||station with the per-slot
// channel secret) binds the connection. Nothing else is honoured
// before binding, one live binding exists per slot, and a bound
// connection can never rebind (RM2 B1).
func (g *Gateway) HandleStationConn(conn net.Conn) {
	defer conn.Close()
	state := &connState{}
	defer g.unbind(state)
	ctx := context.Background()
	for {
		frame, err := stationlink.ReadFrame(conn)
		if err != nil {
			return
		}
		resp := g.stationRequest(ctx, state, frame)
		if err := stationlink.WriteFrame(conn, resp); err != nil {
			return
		}
		if resp.Type == stationlink.TypeEnd {
			return
		}
	}
}

func (g *Gateway) unbind(state *connState) {
	if state.boundSlot == "" {
		return
	}
	g.mu.Lock()
	if g.bound[state.boundSlot] == state {
		delete(g.bound, state.boundSlot)
	}
	g.mu.Unlock()
	state.boundSlot = ""
}

func (g *Gateway) stationRequest(ctx context.Context, state *connState, frame *stationlink.Frame) *stationlink.Frame {
	deny := func(reason string) *stationlink.Frame {
		return &stationlink.Frame{Type: stationlink.TypeError, Reason: reason}
	}
	switch frame.Type {
	case stationlink.TypeHello:
		return g.stationHello(state, frame, deny)
	case stationlink.TypeAuth:
		return g.stationAuth(state, frame, deny)
	case stationlink.TypeExtend:
		return deny("extension refused")
	}
	if state.boundSlot == "" {
		return deny("authentication required first")
	}
	slot, ok := g.cfg.Journal.Get(state.boundSlot)
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
			if fresh, ok := g.cfg.Journal.Get(slot.ID); ok && fresh.Ended {
				return &stationlink.Frame{Type: stationlink.TypeEnd, SlotID: slot.ID, Reason: fresh.EndReason}
			}
			return &stationlink.Frame{Type: stationlink.TypeNone, SlotID: slot.ID}
		}
	case stationlink.TypeReply:
		if slot.Ended {
			return deny("slot ended")
		}
		now := g.cfg.Now().Unix()
		if now >= slot.NotAfter {
			g.endSlot(ctx, slot.ID, "not_after", "slot ended")
			return deny("slot over")
		}
		// Outbound is signed only to a current grantee: fresh
		// kernel check, no outbound screening (owner decision).
		receipt, err := g.kernelCheckSender(ctx, slot, slot.RenterPubKey, now)
		if err != nil {
			return deny("grant check failed")
		}
		if receipt.Closed {
			g.endSlot(ctx, slot.ID, "kernel_closed", "")
			return deny("grant closed")
		}
		if !receipt.Admits() {
			return deny("grant not live")
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

func (g *Gateway) stationHello(state *connState, frame *stationlink.Frame,
	deny func(string) *stationlink.Frame) *stationlink.Frame {
	if state.boundSlot != "" {
		return deny("already bound; rebind refused")
	}
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
	if slot.ChannelSecretHex == "" {
		return deny("no channel credential registered")
	}
	g.mu.Lock()
	_, alreadyBound := g.bound[slot.ID]
	g.mu.Unlock()
	if alreadyBound {
		return deny("slot already bound")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return deny("challenge unavailable")
	}
	state.pendingSlot = slot.ID
	state.pendingStation = frame.StationName
	state.nonceHex = hex.EncodeToString(nonce)
	return &stationlink.Frame{Type: stationlink.TypeChallenge,
		SlotID: slot.ID, Nonce: state.nonceHex}
}

func (g *Gateway) stationAuth(state *connState, frame *stationlink.Frame,
	deny func(string) *stationlink.Frame) *stationlink.Frame {
	if state.boundSlot != "" {
		return deny("already bound; rebind refused")
	}
	// The nonce is single-use: consume the pending challenge on any
	// auth attempt, success or failure.
	pendingSlot, pendingStation, nonceHex := state.pendingSlot, state.pendingStation, state.nonceHex
	state.pendingSlot, state.pendingStation, state.nonceHex = "", "", ""
	if pendingSlot == "" || frame.SlotID != pendingSlot || frame.StationName != pendingStation {
		return deny("authentication failed")
	}
	slot, ok := g.cfg.Journal.Get(pendingSlot)
	if !ok || slot.Destroyed || slot.Ended || slot.ChannelSecretHex == "" {
		return deny("authentication failed")
	}
	secret, err := hex.DecodeString(slot.ChannelSecretHex)
	if err != nil || !stationlink.VerifyResponse(secret, nonceHex, pendingSlot, pendingStation, frame.Response) {
		return deny("authentication failed")
	}
	g.mu.Lock()
	if _, taken := g.bound[slot.ID]; taken {
		g.mu.Unlock()
		return deny("slot already bound")
	}
	g.bound[slot.ID] = state
	g.mu.Unlock()
	state.boundSlot = slot.ID
	return &stationlink.Frame{
		Type: stationlink.TypeSystem, SlotID: slot.ID,
		RenterPubKey: slot.RenterPubKey, ContractSHA256: slot.ContractSHA256,
		NotAfter: slot.NotAfter,
	}
}
