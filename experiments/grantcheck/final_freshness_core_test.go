package grantcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// Claim: each public live route refuses a Core observation that crosses A only at its final clock sample, beside exact-A live controls.
func TestCoreFinalSampleFreshness(t *testing.T) {
	agent, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	l := newCoreLab(t, agent.PubKeyHex())
	var keys []string
	var proofs []Presentation
	for i := range 3 {
		peer, err := nostr.GeneratePrivKey()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, peer.PubKeyHex())
		proofs = append(proofs, corePresentation(t, l.grant(peer, fmt.Sprintf("final-%d", i), l.seal(), true)))
	}
	info, tip := coreTip(t, l)
	ctx := context.Background()
	for _, transport := range []Transport{NostrNIP17Seal, SwarmEnvelopeV2} {
		for _, path := range []string{"Inbound", "InboundCached", "InboundFrom", "Outbound", "OutboundFromSingle", "OutboundFromAggregate", "Provision"} {
			if transport == SwarmEnvelopeV2 && (path == "Inbound" || path == "InboundCached" || path == "Outbound") {
				continue
			}
			for _, delta := range []time.Duration{0, time.Nanosecond, time.Second} {
				t.Run(fmt.Sprintf("Transport%d/%s/OverA%dns", transport, path, delta), func(t *testing.T) {
					// Claim: late staleness is retryable, returns no live metadata, and preserves the complete cache and audit; equality admits.
					c := freshCoreChecker(t, l, l.observer, tip+60, testFreshness(time.Minute, 2*time.Minute, info.Blocks), xonly(9), transport)
					for i, p := range proofs {
						if i == 0 && (path == "Inbound" || path == "InboundFrom" || path == "Provision") {
							continue // Supplied-proof cases must not already have the candidate cached.
						}
						assertVerdict(t, c.Provision(ctx, p), Live, CodeLive, false, false)
					}
					before := readCheckerState(t, c)
					final := 3
					if path == "OutboundFromSingle" {
						final = 4
					}
					if path == "OutboundFromAggregate" {
						final = 10
					}
					reads := 0
					c.config.Now = func() time.Time {
						reads++
						at := time.Unix(tip+60, 0)
						if reads >= final {
							at = at.Add(delta)
						}
						return at
					}
					var v Verdict
					switch path {
					case "Inbound":
						v = c.Inbound(ctx, keys[0], &proofs[0])
					case "InboundCached":
						v = c.Inbound(ctx, keys[0], nil)
					case "InboundFrom":
						v = c.InboundFrom(ctx, SenderProof{transport, keys[0]}, &proofs[0])
					case "Outbound":
						v = c.Outbound(ctx, keys[0])
					case "OutboundFromSingle":
						v = c.OutboundFrom(ctx, RecipientProof{transport, keys[:1]})
					case "OutboundFromAggregate":
						v = c.OutboundFrom(ctx, RecipientProof{transport, keys})
					case "Provision":
						v = c.Provision(ctx, proofs[0])
					}
					if reads < final {
						t.Fatalf("final sample not reached: %d < %d", reads, final)
					}
					if delta == 0 {
						assertVerdict(t, v, Live, CodeLive, false, false)
					} else {
						assertVerdict(t, v, Refused, CodeTipStale, false, true)
						if len(v.Scope) != 0 || v.GrantID != "" {
							t.Fatal("late stale refusal returned live metadata")
						}
						if !bytes.Equal(before, readCheckerState(t, c)) {
							t.Fatal("late stale refusal committed cache, audit or high-water")
						}
					}
				})
			}
		}
	}
}

// Claim: an aggregate checks its earlier old Core observation even when its last recipient observes a newer, still-fresh tip.
func TestCoreAggregateEveryObservation(t *testing.T) {
	agent, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	l := newCoreLab(t, agent.PubKeyHex())
	var keys []string
	var proofs []Presentation
	for i := range 2 {
		peer, err := nostr.GeneratePrivKey()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, peer.PubKeyHex())
		proofs = append(proofs, corePresentation(t, l.grant(peer, fmt.Sprintf("observation-%d", i), l.seal(), true)))
	}
	info, tip := coreTip(t, l)
	type fixture struct {
		c         *Checker
		node      *recordedNode
		transport Transport
		delta     time.Duration
	}
	var fixtures []fixture
	for _, transport := range []Transport{NostrNIP17Seal, SwarmEnvelopeV2} {
		for _, delta := range []time.Duration{0, time.Nanosecond} {
			n := &recordedNode{real: l.observer, answers: map[string]json.RawMessage{}}
			c := freshCoreChecker(t, l, n, tip+60, testFreshness(time.Minute, 2*time.Minute, info.Blocks), xonly(9), transport)
			for _, p := range proofs {
				assertVerdict(t, c.Provision(context.Background(), p), Live, CodeLive, false, false)
			}
			fixtures = append(fixtures, fixture{c, n, transport, delta})
		}
	}
	l.rpc("", "setmocktime", tip+1)
	l.mine(1)
	next, nextTime := coreTip(t, l)
	if next.Blocks != info.Blocks+1 || nextTime != tip+1 {
		t.Fatal("newer tip witness missing")
	}
	for _, f := range fixtures {
		t.Run(fmt.Sprintf("Transport%d/OverA%dns", f.transport, f.delta), func(t *testing.T) {
			// Claim: exact-A remains live while A+1ns on only the first observation refuses without changing checker state.
			before := readCheckerState(t, f.c)
			reads := 0
			f.c.config.Now = func() time.Time {
				reads++
				f.node.frozen = reads <= 3
				at := time.Unix(tip+60, 0)
				if reads >= 7 {
					at = at.Add(f.delta)
				}
				return at
			}
			v := f.c.OutboundFrom(context.Background(), RecipientProof{f.transport, keys})
			if reads != 7 {
				t.Fatalf("aggregate final sample: got %d want 7", reads)
			}
			if f.delta == 0 {
				assertVerdict(t, v, Live, CodeLive, false, false)
			} else {
				assertVerdict(t, v, Refused, CodeTipStale, false, true)
				if !bytes.Equal(before, readCheckerState(t, f.c)) {
					t.Fatal("aggregate stale observation changed checker state")
				}
			}
		})
	}
}
