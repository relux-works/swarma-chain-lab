package grantcheck

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// Missing addressees and room IDs refuse before checking; a valid cached key succeeds on the typed envelope path only.
func TestEnvelopeOutboundInputs(t *testing.T) {
	c, b, p := senderChecker(t, SwarmEnvelopeV2)
	ctx := context.Background()
	peer := xonly(2)
	assertVerdict(t, c.InboundFrom(ctx, SenderProof{SwarmEnvelopeV2, peer}, &p), Live, CodeLive, false, false)
	before := b.Calls
	for _, keys := range [][]string{nil, {}, {"!room:example.invalid"}, {""}, {peer, "!room:example.invalid"}, {strings.ToUpper(peer)}} {
		assertVerdict(t, c.OutboundFrom(ctx, RecipientProof{SwarmEnvelopeV2, keys}), Refused, CodeInvalidPeer, false, false)
	}
	assertVerdict(t, c.OutboundFrom(ctx, RecipientProof{SwarmEnvelopeV2, make([]string, MaxRecipients+1)}), Refused, CodeOversize, false, false)
	assertVerdict(t, c.Outbound(ctx, peer), Refused, CodeBindingMismatch, false, false)
	if b.Calls != before {
		t.Fatal("invalid addressee reached backend")
	}
	assertVerdict(t, c.OutboundFrom(ctx, RecipientProof{SwarmEnvelopeV2, []string{peer}}), Live, CodeLive, false, false)
}

// Every addressee needs admitted proof and a fresh live check on every send and retry; one failure denies the entire send.
func TestEnvelopeOutboundAllRecipients(t *testing.T) {
	c, b, p := senderChecker(t, SwarmEnvelopeV2)
	ctx := context.Background()
	peer, other := xonly(2), xonly(3)
	assertVerdict(t, c.InboundFrom(ctx, SenderProof{SwarmEnvelopeV2, peer}, &p), Live, CodeLive, false, false)
	proof := RecipientProof{SwarmEnvelopeV2, []string{peer, other}}
	assertVerdict(t, c.OutboundFrom(ctx, proof), Refused, CodeNoGrant, false, false)
	// This test-only cache fixture supplies a second signed grantee proof via the
	// existing live stub; production uses the real issuer/kernel path.
	raw := unitGrantForPeer(t, other)
	id, err := kernel.PresentationID(raw)
	if err != nil {
		t.Fatal(err)
	}
	p2 := Presentation{GrantID: id, Bytes: raw}
	assertVerdict(t, c.InboundFrom(ctx, SenderProof{SwarmEnvelopeV2, other}, &p2), Live, CodeLive, false, false)
	for range 2 {
		before := b.Calls
		v := c.OutboundFrom(ctx, proof)
		assertVerdict(t, v, Live, CodeLive, false, false)
		if b.Calls != before+2 || v.GrantID != "" || len(v.Scope) != 0 {
			t.Fatal("aggregate reused live or invented grant metadata")
		}
	}
	old := b.Handler
	b.Handler = func(ctx context.Context, raw []byte, a, s string, n int64) (kernel.Receipt, error) {
		r, err := old(ctx, raw, a, s, n)
		if s == other {
			r.Verdict, r.Reason = kernel.Refused, "RPC_UNAVAILABLE"
		}
		return r, err
	}
	assertVerdict(t, c.OutboundFrom(ctx, proof), Refused, CodeVerifierUnavailable, false, true)
}

// An earlier recipient's window is rechecked after all fresh recipient observations, including clock rollback.
func TestEnvelopeOutboundWindow(t *testing.T) {
	for _, now := range []int64{1000, 499} {
		c, _, p := senderChecker(t, SwarmEnvelopeV2)
		ctx := context.Background()
		peer := xonly(2)
		assertVerdict(t, c.InboundFrom(ctx, SenderProof{SwarmEnvelopeV2, peer}, &p), Live, CodeLive, false, false)
		calls := 0
		c.config.Now = func() time.Time {
			calls++
			// check reads at start, end-stamp and final window check.
			if calls <= 3 {
				return time.Unix(500, 0)
			}
			return time.Unix(now, 0)
		}
		code := CodeExpired
		if now == 499 {
			code = CodeClockInvalid
		}
		assertVerdict(t, c.OutboundFrom(ctx, RecipientProof{SwarmEnvelopeV2, []string{peer}}), Refused, code, false, code == CodeClockInvalid)
	}
}

func unitGrantForPeer(t *testing.T, peer string) []byte {
	t.Helper()
	key := make([]byte, 32)
	key[31] = 3
	grantee, err := nostr.PrivKeyFromBytes(key)
	if err != nil || grantee.PubKeyHex() != peer {
		t.Fatal("fixture peer", err)
	}
	key[31] = 1
	issuer, _ := btcec.PrivKeyFromBytes(key)
	g := proofGrant(t, unitGrant(t)).Grant
	g.GranteeKey = peer
	g.Consent.ConsentEvent = signEvent(t, grantee, g.Consent.ConsentEvent)
	hash, err := g.SigningHash()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := rental.PresentIssuedGrant(jsonBytes(t, rental.SignedGrant{Grant: g, Signature: signHash(t, issuer, hash)}), strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
