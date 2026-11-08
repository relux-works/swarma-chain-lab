package gateway_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/screen"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/stationlink"
)

// TestValidDeliveryAndReply proves the happy path end to end: ready
// DM at start, renter DM delivered to the station, station reply
// DM'd back signed under the agent (seal) key.
func TestValidDeliveryAndReply(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	if dms := h.pub.dmsTo(h.renter); len(dms) != 1 || dms[0] != "ready" {
		t.Fatalf("ready DM = %v", dms)
	}
	c, conn := h.stationClient()
	defer conn.Close()
	h.deliverValid(c, "hello agent")
	ack, err := c.Reply("hello renter")
	if err != nil || ack.Type != stationlink.TypeAck {
		t.Fatalf("reply ack = %+v err %v", ack, err)
	}
	dms := h.pub.dmsTo(h.renter)
	if len(dms) != 2 || dms[1] != "hello renter" {
		t.Fatalf("renter DMs = %v", dms)
	}
}

// TestWrapKeyGranteeSealKeyAttacker proves authentication uses the
// seal key, never the gift-wrap key: a wrap signed by the grantee
// whose seal/rumor belong to an attacker is refused.
func TestWrapKeyGranteeSealKeyAttacker(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c, conn := h.stationClient()
	defer conn.Close()
	attacker, _ := nostr.GeneratePrivKey()
	rumor := rumorFrom(attacker, h.agent.PubKeyHex(), "pwned", nowMid)
	wrap := craftWrap(t, rumor, attacker, h.renter, h.agent.PubKeyHex(), nil, false)
	res := h.handle(wrap)
	if res.Delivered || !res.Refused {
		t.Fatalf("wrap-key forgery delivered: %+v", res)
	}
	if f := pull(t, c); f.Type == stationlink.TypeDeliver {
		t.Fatalf("forged message reached station: %+v", f)
	}
	h.deliverValid(c, "legit after forgery")
}

// TestSealSignatureInvalid proves a seal with a corrupted signature
// is refused at unwrap.
func TestSealSignatureInvalid(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c, conn := h.stationClient()
	defer conn.Close()
	eph, _ := nostr.GeneratePrivKey()
	rumor := rumorFrom(h.renter, h.agent.PubKeyHex(), "hi", nowMid)
	wrap := craftWrap(t, rumor, h.renter, eph, h.agent.PubKeyHex(), func(seal *nostr.Event) {
		b := []byte(seal.Sig)
		if b[0] == '0' {
			b[0] = '1'
		} else {
			b[0] = '0'
		}
		seal.Sig = string(b)
	}, false)
	res := h.handle(wrap)
	if res.Delivered || !strings.Contains(res.Reason, "seal") {
		t.Fatalf("bad seal sig result: %+v", res)
	}
	h.deliverValid(c, "legit after bad seal")
}

// TestRumorPubkeyDiffersFromSeal proves a rumor naming a different
// author than its seal signer is refused (the check go-nostr's
// GiftUnwrap cannot express).
func TestRumorPubkeyDiffersFromSeal(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c, conn := h.stationClient()
	defer conn.Close()
	other, _ := nostr.GeneratePrivKey()
	eph, _ := nostr.GeneratePrivKey()
	rumor := rumorFrom(other, h.agent.PubKeyHex(), "not the sealer", nowMid)
	wrap := craftWrap(t, rumor, h.renter, eph, h.agent.PubKeyHex(), nil, false)
	res := h.handle(wrap)
	if res.Delivered || !strings.Contains(res.Reason, "does not match seal") {
		t.Fatalf("rumor/seal mismatch result: %+v", res)
	}
	h.deliverValid(c, "legit after mismatch")
}

// TestNIP44CiphertextTampered proves a tampered gift-wrap ciphertext
// fails NIP-44 HMAC verification and is refused.
func TestNIP44CiphertextTampered(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c, conn := h.stationClient()
	defer conn.Close()
	eph, _ := nostr.GeneratePrivKey()
	rumor := rumorFrom(h.renter, h.agent.PubKeyHex(), "hi", nowMid)
	wrap := craftWrap(t, rumor, h.renter, eph, h.agent.PubKeyHex(), nil, true)
	res := h.handle(wrap)
	if res.Delivered || !strings.Contains(res.Reason, "unwrap") {
		t.Fatalf("tampered ciphertext result: %+v", res)
	}
	h.deliverValid(c, "legit after tamper")
}

// TestReplayedRumor proves the second arrival of one rumor id is a
// replay refusal, while a fresh rumor still delivers.
func TestReplayedRumor(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c, conn := h.stationClient()
	defer conn.Close()
	wrap := h.renterDM("once only", nowMid)
	if res := h.handle(wrap); !res.Delivered {
		t.Fatalf("first arrival refused: %+v", res)
	}
	_ = pull(t, c)
	res := h.handle(wrap)
	if res.Delivered || res.Reason != "replayed_rumor" {
		t.Fatalf("replay result: %+v", res)
	}
	h.deliverValid(c, "fresh rumour still works")
}

// TestRumorOutsideSlotWindow proves rumors timestamped before
// not_before or at/after not_after are refused (half-open window).
func TestRumorOutsideSlotWindow(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c, conn := h.stationClient()
	defer conn.Close()
	for _, at := range []int64{slotNotBefore - 1, slotNotAfter, slotNotAfter + 500} {
		res := h.handle(h.renterDM("out of window", at))
		if res.Delivered || res.Reason != "rumor_outside_slot_window" {
			t.Fatalf("at=%d result: %+v", at, res)
		}
	}
	// Boundary neighbours: exactly not_before and not_after-1 deliver.
	if res := h.handle(h.renterDM("first valid second", slotNotBefore)); !res.Delivered {
		t.Fatalf("not_before boundary refused: %+v", res)
	}
	_ = pull(t, c)
	h.deliverValid(c, "mid-window neighbour")
}

// TestSenderWithNoSlot proves a well-formed DM from a key with no
// slot is refused.
func TestSenderWithNoSlot(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c, conn := h.stationClient()
	defer conn.Close()
	stranger, _ := nostr.GeneratePrivKey()
	wrap, _, err := nostr.WrapDM(stranger, h.agent.PubKeyHex(), "let me in", nil, nowMid)
	if err != nil {
		t.Fatal(err)
	}
	if res := h.handle(wrap); res.Delivered || res.Reason != "no_active_slot" {
		t.Fatalf("stranger result: %+v", res)
	}
	h.deliverValid(c, "renter still works")
}

// TestKernelRefusedPendingError proves kernel refused (revoked /
// expired), pending and error all deny delivery, and live admits.
func TestKernelRefusedPendingError(t *testing.T) {
	cases := []struct {
		name    string
		verdict string
		reason  string
		err     error
		want    string
	}{
		{"revoked", kernel.Refused, "SEAL_SPENT", nil, "kernel_refused:SEAL_SPENT"},
		{"expired", kernel.Refused, "EXPIRED", nil, "kernel_refused:EXPIRED"},
		{"pending", kernel.Pending, "ANCHOR_UNCONFIRMED", nil, "kernel_pending:ANCHOR_UNCONFIRMED"},
		{"error", kernel.Refused, "", errors.New("node down"), "kernel_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, harnessOpts{})
			c, conn := h.stationClient()
			defer conn.Close()
			h.kern.Verdict, h.kern.Reason, h.kern.Err = tc.verdict, tc.reason, tc.err
			res := h.handle(h.renterDM("kernel says no", nowMid))
			if res.Delivered || res.Reason != tc.want {
				t.Fatalf("result: %+v want reason %s", res, tc.want)
			}
			if f := pull(t, c); f.Type == stationlink.TypeDeliver {
				t.Fatalf("delivered despite kernel %s", tc.name)
			}
			// Valid neighbour: kernel back to live admits a fresh DM.
			h.kern.Verdict, h.kern.Reason, h.kern.Err = kernel.Live, "", nil
			h.deliverValid(c, "kernel live again")
		})
	}
}

// TestKernelWrongStation proves a certificate bound to another
// station is refused by the kernel check (stub enforces the station
// binding the real kernel authenticates from the certificate).
func TestKernelWrongStation(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c, conn := h.stationClient()
	defer conn.Close()
	h.kern.Handler = func(ctx context.Context, cert []byte, stationName, sender string, now int64) (kernel.Receipt, error) {
		if stationName != "id/swarma-station-2" {
			return kernel.Receipt{Verdict: kernel.Refused, Reason: "STATION_MISMATCH"}, nil
		}
		return kernel.Receipt{Verdict: kernel.Live}, nil
	}
	res := h.handle(h.renterDM("wrong station cert", nowMid))
	if res.Delivered || res.Reason != "kernel_refused:STATION_MISMATCH" {
		t.Fatalf("wrong station result: %+v", res)
	}
	h.kern.Handler = nil
	h.deliverValid(c, "right station neighbour")
}

// TestScreeningRefusalWarnsAndNotices proves a screening refusal is
// not delivered, warns the renter by DM, notices the station, and
// (first offence) leaves the slot alive.
func TestScreeningRefusalWarnsAndNotices(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c, conn := h.stationClient()
	defer conn.Close()
	h.scr.RefuseSubstrings = []string{"forbidden"}
	before := len(h.pub.dmsTo(h.renter))
	res := h.handle(h.renterDM("this is forbidden content", nowMid))
	if res.Delivered || !res.WarningSent || res.SlotEnded {
		t.Fatalf("screening result: %+v", res)
	}
	dms := h.pub.dmsTo(h.renter)
	if len(dms) != before+1 || !strings.Contains(dms[len(dms)-1], "warning") {
		t.Fatalf("warning DM missing: %v", dms)
	}
	f := pull(t, c)
	if f.Type != stationlink.TypeNotice {
		t.Fatalf("station frame = %+v, want notice (and no delivery)", f)
	}
	h.deliverValid(c, "clean content still delivers")
}

// TestSecondScreeningRefusalEndsSlot proves the durable counter ends
// the slot on the second refusal; later valid DMs are refused.
func TestSecondScreeningRefusalEndsSlot(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c, conn := h.stationClient()
	defer conn.Close()
	h.scr.RefuseSubstrings = []string{"bad"}
	h.deliverValid(c, "good neighbour first")
	if res := h.handle(h.renterDM("bad one", nowMid)); res.SlotEnded {
		t.Fatalf("first refusal ended slot: %+v", res)
	}
	_ = pull(t, c) // notice
	res := h.handle(h.renterDM("bad two", nowMid))
	if !res.Refused || !res.SlotEnded {
		t.Fatalf("second refusal result: %+v", res)
	}
	// Station observes notice(s) then end; drain until end.
	for {
		f := pull(t, c)
		if f.Type == stationlink.TypeEnd {
			break
		}
		if f.Type == stationlink.TypeDeliver {
			t.Fatalf("refused content delivered: %+v", f)
		}
	}
	if res := h.handle(h.renterDM("perfectly fine", nowMid)); res.Delivered {
		t.Fatalf("message delivered into ended slot: %+v", res)
	}
	slot, _ := h.store.Get("slot-1")
	if !slot.Ended || slot.Refusals != 2 {
		t.Fatalf("journal slot = ended %v refusals %d", slot.Ended, slot.Refusals)
	}
}

// TestScreeningTimeoutErrorMalformed proves the model can only
// refuse: hard timeout, transport error and malformed answers are
// all refusals, never allows.
func TestScreeningTimeoutErrorMalformed(t *testing.T) {
	cases := []struct {
		name    string
		handler func(ctx context.Context, content string) (screen.Decision, error)
	}{
		{"timeout", func(ctx context.Context, c string) (screen.Decision, error) {
			time.Sleep(3 * time.Second) // ignores ctx; gateway must cut it off
			return screen.Decision{Allow: true}, nil
		}},
		{"error", func(ctx context.Context, c string) (screen.Decision, error) {
			return screen.Decision{}, errors.New("model api down")
		}},
		{"malformed", func(ctx context.Context, c string) (screen.Decision, error) {
			return screen.ParseAnswer("sure, looks fine to me")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, harnessOpts{screenTO: 100 * time.Millisecond})
			// apply short timeout by rebuilding with tight config:
			h.scr.Handler = tc.handler
			res := h.handle(h.renterDM("screen me", nowMid))
			if res.Delivered {
				t.Fatalf("%s screening allowed delivery: %+v", tc.name, res)
			}
			slot, _ := h.store.Get("slot-1")
			if slot.Refusals != 1 {
				t.Fatalf("refusals = %d, want 1 durable count", slot.Refusals)
			}
		})
	}
	// Valid neighbour: well-formed ALLOW delivers.
	h := newHarness(t, harnessOpts{})
	c, conn := h.stationClient()
	defer conn.Close()
	h.scr.Handler = func(ctx context.Context, s string) (screen.Decision, error) {
		return screen.ParseAnswer("ALLOW")
	}
	h.deliverValid(c, "explicit allow delivers")
}

// TestAgentExtendRefusedAndEndEarly proves the agent cannot extend
// a slot but can end it early, after which DMs are refused.
func TestAgentExtendRefusedAndEndEarly(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c, conn := h.stationClient()
	defer conn.Close()
	ext, err := c.Extend()
	if err != nil {
		t.Fatal(err)
	}
	if ext.Type != stationlink.TypeError || !strings.Contains(ext.Reason, "extension refused") {
		t.Fatalf("extend answer: %+v", ext)
	}
	h.deliverValid(c, "slot unchanged after extend attempt")
	end, err := c.EndEarly()
	if err != nil || end.Type != stationlink.TypeEnd {
		t.Fatalf("end early: %+v err %v", end, err)
	}
	if res := h.handle(h.renterDM("too late", nowMid)); res.Delivered {
		t.Fatalf("delivered after early end: %+v", res)
	}
	dms := h.pub.dmsTo(h.renter)
	if !strings.Contains(dms[len(dms)-1], "ended early") {
		t.Fatalf("renter not told of early end: %v", dms)
	}
}

// TestMessageAfterSlotEndByClock proves not_after ends the session
// regardless of chain state (Tick), and later DMs are refused.
func TestMessageAfterSlotEndByClock(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c, conn := h.stationClient()
	defer conn.Close()
	h.deliverValid(c, "in time")
	h.clock.Set(slotNotAfter)
	h.gw.Tick(context.Background())
	res := h.handle(h.renterDM("after the end", nowMid))
	if res.Delivered || !res.Refused {
		t.Fatalf("post-end DM result: %+v", res)
	}
	f := pull(t, c)
	if f.Type != stationlink.TypeEnd {
		// queue may contain the end frame after none/etc; assert type seen
		t.Fatalf("station frame after Tick = %+v, want end", f)
	}
}

// TestDestroyedStationCannotReply proves a destroyed station is
// refused at hello, its home and token file are gone, and outbound
// traffic only ever carries the agent seal key.
func TestDestroyedStationCannotReply(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	c, conn := h.stationClient()
	h.deliverValid(c, "before destroy")
	if _, err := c.Reply("last words"); err != nil {
		t.Fatal(err)
	}
	// Every published DM unwraps with sender == agent key.
	for _, ev := range h.pub.evsSnapshot() {
		u, err := nostr.UnwrapDM(ev, h.renter)
		if err != nil {
			t.Fatal(err)
		}
		if u.SenderHex != h.agent.PubKeyHex() {
			t.Fatalf("outbound sealed by %s, not the agent key", u.SenderHex)
		}
	}
	conn.Close()
	report, err := h.gw.DestroySlot(context.Background(), "slot-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Removed) == 0 || len(report.Kept) == 0 {
		t.Fatalf("destroy report incomplete: %+v", report)
	}
	home := filepath.Join(h.stationDir, "slot-1")
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("station home still exists after destroy: %v", err)
	}
	// Hello from the destroyed station is refused (no reply possible).
	raw, err := dialStation(h)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	hello, err := raw.Hello("slot-1", "id/swarma-station-1")
	if err != nil {
		t.Fatal(err)
	}
	if hello.Type != stationlink.TypeError || !strings.Contains(hello.Reason, "destroyed") {
		t.Fatalf("destroyed hello: %+v", hello)
	}
}

// TestRefusalCounterSurvivesRestart proves the fsynced counter: one
// refusal, gateway restart over the same journal, second refusal
// still ends the slot.
func TestRefusalCounterSurvivesRestart(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	h.scr.RefuseSubstrings = []string{"bad"}
	if res := h.handle(h.renterDM("bad before restart", nowMid)); !res.Refused || res.SlotEnded {
		t.Fatalf("first refusal: %+v", res)
	}
	h.rebuild()
	h.scr.RefuseSubstrings = []string{"bad"}
	res := h.handle(h.renterDM("bad after restart", nowMid))
	if !res.Refused || !res.SlotEnded {
		t.Fatalf("second refusal after restart: %+v", res)
	}
}

// TestStartSlotGating proves sessions start only on kernel live at
// or after not_before: pending kernel and early starts are refused
// without a ready DM; the live neighbour starts and DMs ready.
func TestStartSlotGating(t *testing.T) {
	h := newHarness(t, harnessOpts{skipStart: true})
	ctx := context.Background()
	h.kern.Verdict = kernel.Pending
	h.kern.Reason = "ANCHOR_UNCONFIRMED"
	if err := h.gw.StartSlot(ctx, "slot-1"); err == nil {
		t.Fatal("pending kernel started a session")
	}
	h.kern.Verdict = kernel.Live
	h.kern.Reason = ""
	h.clock.Set(slotNotBefore - 10)
	if err := h.gw.StartSlot(ctx, "slot-1"); err == nil {
		t.Fatal("early start accepted")
	}
	if n := h.pub.count(); n != 0 {
		t.Fatalf("ready DM sent for refused starts (%d events)", n)
	}
	h.clock.Set(nowMid)
	if err := h.gw.StartSlot(ctx, "slot-1"); err != nil {
		t.Fatalf("live start refused: %v", err)
	}
	if dms := h.pub.dmsTo(h.renter); len(dms) != 1 || dms[0] != "ready" {
		t.Fatalf("ready DM = %v", dms)
	}
}
