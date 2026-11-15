package grantcheck

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Claim: genuine Core expiry of either current identity closes outbound, inbound and cached re-check by name beside live, same-value renewal and stopped-node controls.
func TestCoreIdentityExpired(t *testing.T) {
	for _, expiredName := range []string{e2eAgentName, e2eLandlordName} {
		t.Run(expiredName, func(t *testing.T) {
			agent, err := nostr.GeneratePrivKey()
			if err != nil {
				t.Fatal(err)
			}
			peer, err := nostr.GeneratePrivKey()
			if err != nil {
				t.Fatal(err)
			}
			l := newCoreLab(t, agent.PubKeyHex())
			p := corePresentation(t, l.grant(peer, "identity-expiry", l.seal(), true))
			info, now := coreTip(t, l)
			c := freshCoreChecker(t, l, l.observer, now, testFreshness(time.Minute, 2*time.Minute, info.Blocks), xonly(9))
			ctx := context.Background()
			sender := SenderProof{SwarmEnvelopeV2, peer.PubKeyHex()}
			recipient := RecipientProof{SwarmEnvelopeV2, []string{peer.PubKeyHex()}}
			routes := func(code Code, closed, retry bool) {
				t.Helper()
				for _, route := range []struct {
					name string
					call func() Verdict
				}{
					{"outbound", func() Verdict { return c.OutboundFrom(ctx, recipient) }},
					{"inbound", func() Verdict { return c.InboundFrom(ctx, sender, &p) }},
					{"re-check", func() Verdict { return c.InboundFrom(ctx, sender, nil) }},
				} {
					v := route.call()
					decision := Refused
					if code == CodeLive {
						decision = Live
					}
					assertVerdict(t, v, decision, code, closed, retry)
					if code == CodeIdentityExpired {
						verdict, reason, again := v.A2ADecision()
						if verdict != "refused" || reason != "identity_expired" || again {
							t.Fatalf("%s unnamed expiry: %s/%s/%v", route.name, verdict, reason, again)
						}
					}
				}
			}
			// Claim: the same genuine issued grant is live before name expiry on every route.
			assertVerdict(t, coreInbound(c, p), Live, CodeLive, false, false)
			routes(CodeLive, false, false)
			read := func(name string) su.NameView {
				var n su.NameView
				if err := json.Unmarshal(l.rpc("", "name_show", name, map[string]any{"allowExpired": true}), &n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			l.mine(int(read(expiredName).ExpiresIn) - 2)
			// Claim: same-value name_update renewals extend lifetime without revoking the same grant.
			for _, name := range []string{e2eAgentName, e2eLandlordName} {
				n := read(name)
				l.rpc("issuer", "name_update", name, n.Value)
			}
			l.mine(1)
			routes(CodeLive, false, false)
			remaining := read(expiredName).ExpiresIn
			l.mine(int(remaining) - 2)
			other := e2eAgentName
			if expiredName == other {
				other = e2eLandlordName
			}
			l.rpc("issuer", "name_update", other, read(other).Value)
			l.mine(1)
			routes(CodeLive, false, false)
			// Claim: crossing the real name expiry boundary refuses the expired role while the other role remains live.
			l.mine(2)
			if !read(expiredName).Expired || read(other).Expired {
				t.Fatal("missing selective expiry witness")
			}
			_, err = l.observer.Call(ctx, "name_show", expiredName)
			var application *su.RPCError
			if !errors.As(err, &application) {
				t.Fatalf("missing Core RPC error: %v", err)
			}
			if !application.NameExpired() {
				t.Fatalf("Core expiry RPC code=%d message=%q", application.Code, application.Message)
			}
			// Claim: the public observation wrapper preserves the genuine application error instead of blanketing it as node-down.
			observation := su.NewReadObservation(ctx, l.observer)
			var raw json.RawMessage
			err = observation.Call("name_show", &raw, expiredName)
			observation.Close()
			if !errors.As(err, &application) || !application.NameExpired() {
				t.Fatalf("missing Core RPC error: %v", err)
			}
			routes(CodeIdentityExpired, true, false)
			// Claim: a stopped genuine node still yields retryable verifier_unavailable on each route.
			l.stop()
			routes(CodeVerifierUnavailable, false, true)
		})
	}
}
