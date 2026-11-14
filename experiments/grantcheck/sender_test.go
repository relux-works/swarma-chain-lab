package grantcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func senderChecker(t *testing.T, transport Transport) (*Checker, *kernel.Stub, Presentation) {
	t.Helper()
	_, b, p := unitChecker(t)
	c, err := NewForTransport(unitConfig(t), transport)
	if err != nil {
		t.Fatal(err)
	}
	c.backend = b
	return c, b, p
}

// Actual inbound results carry the validated pin into seam mapping for each
// lifecycle reason; stub receipts test wrapper routing, not chain liveness.
func TestInboundLifecycleDecisionProvenance(t *testing.T) {
	for _, transport := range []struct {
		name string
		pin  Transport
	}{{"nostr", NostrNIP17Seal}, {"envelope", SwarmEnvelopeV2}} {
		for _, tc := range []struct {
			code   Code
			reason string
			closed bool
		}{
			{CodeNotYet, "NOT_YET_VALID", false},
			{CodeExpired, "EXPIRED", false},
			{CodeSealSpent, "SEAL_SPENT", true},
			{CodeLandlordRotated, "LANDLORD_KEY_ROTATED", true},
			{CodeLandlordChanged, "AGENT_LANDLORD_CHANGED", true},
		} {
			t.Run(transport.name+"/"+string(tc.code), func(t *testing.T) {
				c, b, p := senderChecker(t, transport.pin)
				old := b.Handler
				b.Handler = func(ctx context.Context, raw []byte, a, s string, n int64) (kernel.Receipt, error) {
					r, err := old(ctx, raw, a, s, n)
					r.Verdict, r.Reason, r.Closed = "refused", tc.reason, tc.closed
					return r, err
				}
				v := c.InboundFrom(context.Background(), SenderProof{transport.pin, xonly(2)}, &p)
				assertVerdict(t, v, Exchange, tc.code, tc.closed, false)
				wantVerdict, wantReason := "exchange", "exchange"
				if transport.pin == SwarmEnvelopeV2 {
					wantVerdict, wantReason = "refused", "denied"
				}
				d, reason, retry := v.A2ADecision()
				if d != wantVerdict || reason != wantReason || retry {
					t.Fatalf("inbound provenance mapping: want %s/%s/false; got %s/%s/%v", wantVerdict, wantReason, d, reason, retry)
				}
			})
		}
	}
}

// Both supported pins construct; unsupported pins fail before publishing state.
func TestTransportConfig(t *testing.T) {
	for _, transport := range []Transport{0, 3, 255} {
		config := unitConfig(t)
		if c, err := NewForTransport(config, transport); c != nil || !errors.Is(err, ErrConfig) {
			t.Fatalf("unsupported transport admitted: %d %v", transport, err)
		}
		entries, err := os.ReadDir(config.StateDir)
		if err != nil || len(entries) != 0 {
			t.Fatal("invalid pin touched state", err)
		}
	}
	for _, transport := range []Transport{NostrNIP17Seal, SwarmEnvelopeV2} {
		if c, err := NewForTransport(unitConfig(t), transport); c == nil || err != nil {
			t.Fatal(err)
		}
	}
}

// Unknown proof provenance refuses before backend/cache work beside a live envelope neighbour.
func TestSenderUnknownTransport(t *testing.T) {
	c, b, p := senderChecker(t, SwarmEnvelopeV2)
	ctx := context.Background()
	peer := xonly(2)
	assertVerdict(t, c.InboundFrom(ctx, SenderProof{SwarmEnvelopeV2, peer}, &p), Live, CodeLive, false, false)
	before := b.Calls
	for _, transport := range []Transport{0, 3, 255} {
		assertVerdict(t, c.InboundFrom(ctx, SenderProof{transport, peer}, &p), Refused, CodeBindingMismatch, false, false)
	}
	if b.Calls != before || !bytes.Equal(b.Cached[peer], p.Bytes) {
		t.Fatal("unknown provenance reached backend or altered cache")
	}
}

// Matrix IDs, display text, malformed hex and invalid curve points cannot become sender keys or mutate cache.
func TestSenderKeyFormat(t *testing.T) {
	c, b, p := senderChecker(t, SwarmEnvelopeV2)
	ctx := context.Background()
	peer := xonly(2)
	assertVerdict(t, c.InboundFrom(ctx, SenderProof{SwarmEnvelopeV2, peer}, &p), Live, CodeLive, false, false)
	for _, tc := range []struct{ name, key string }{
		{"empty", ""}, {"matrix-id", "@sender:example.invalid"}, {"display-name", "Example Sender"},
		{"free-text", "verified sender"}, {"uppercase", strings.ToUpper(peer)},
		{"short", peer[:63]}, {"long", peer + "0"}, {"non-hex", strings.Repeat("z", 64)},
		{"invalid-point", strings.Repeat("f", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := b.Calls
			assertVerdict(t, c.InboundFrom(ctx, SenderProof{SwarmEnvelopeV2, tc.key}, &p), Refused, CodeInvalidPeer, false, false)
			assertVerdict(t, c.InboundFrom(ctx, SenderProof{SwarmEnvelopeV2, tc.key}, nil), Refused, CodeInvalidPeer, false, false)
			if b.Calls != before || !bytes.Equal(b.Cached[peer], p.Bytes) {
				t.Fatal("invalid key reached backend or altered cache")
			}
		})
	}
	assertVerdict(t, c.InboundFrom(ctx, SenderProof{SwarmEnvelopeV2, peer}, nil), Live, CodeLive, false, false)
}

// A valid but foreign key refuses against the signed grantee binding without replacing admitted proof.
func TestSenderGrantKeyMismatch(t *testing.T) {
	c, b, p := senderChecker(t, SwarmEnvelopeV2)
	ctx := context.Background()
	assertVerdict(t, c.InboundFrom(ctx, SenderProof{SwarmEnvelopeV2, xonly(2)}, &p), Live, CodeLive, false, false)
	before := b.Calls
	assertVerdict(t, c.InboundFrom(ctx, SenderProof{SwarmEnvelopeV2, xonly(3)}, &p), Refused, CodeBindingMismatch, false, false)
	if b.Calls != before || len(b.Cached) != 1 {
		t.Fatal("foreign sender reached backend or changed cache")
	}
}

// Each checker rejects the other supported provenance, including the legacy Nostr entry on an envelope pin.
func TestSenderTransportPin(t *testing.T) {
	for _, pin := range []Transport{NostrNIP17Seal, SwarmEnvelopeV2} {
		c, b, p := senderChecker(t, pin)
		peer := xonly(2)
		ctx := context.Background()
		assertVerdict(t, c.InboundFrom(ctx, SenderProof{pin, peer}, &p), Live, CodeLive, false, false)
		other := NostrNIP17Seal
		if pin == other {
			other = SwarmEnvelopeV2
		}
		before := b.Calls
		assertVerdict(t, c.InboundFrom(ctx, SenderProof{other, peer}, &p), Refused, CodeBindingMismatch, false, false)
		assertVerdict(t, c.InboundFrom(ctx, SenderProof{other, peer}, nil), Refused, CodeBindingMismatch, false, false)
		if pin == SwarmEnvelopeV2 {
			assertVerdict(t, c.Inbound(ctx, peer, &p), Refused, CodeBindingMismatch, false, false)
		}
		if b.Calls != before || !bytes.Equal(b.Cached[peer], p.Bytes) {
			t.Fatal("mismatched provenance reached backend or altered cache")
		}
		assertVerdict(t, c.OutboundFrom(ctx, RecipientProof{pin, []string{peer}}), Live, CodeLive, false, false)
	}
}

// Envelope absence refuses; admitted bytes are freshly rechecked, and explicit bad proof cannot fall back.
func TestEnvelopeCacheFresh(t *testing.T) {
	c, b, p := senderChecker(t, SwarmEnvelopeV2)
	ctx := context.Background()
	proof := SenderProof{SwarmEnvelopeV2, xonly(2)}
	assertVerdict(t, c.InboundFrom(ctx, proof, nil), Refused, CodeNoGrant, false, false)
	assertVerdict(t, c.InboundFrom(ctx, proof, &p), Live, CodeLive, false, false)
	before := b.Calls
	assertVerdict(t, c.InboundFrom(ctx, proof, nil), Live, CodeLive, false, false)
	if b.Calls != before+1 || b.PresentCalls != 1 {
		t.Fatal("cache bypassed fresh check")
	}
	assertVerdict(t, c.InboundFrom(ctx, proof, &Presentation{}), Refused, CodeInvalidPresentation, false, false)
	old := b.Handler
	b.Handler = func(ctx context.Context, raw []byte, a, s string, n int64) (kernel.Receipt, error) {
		r, err := old(ctx, raw, a, s, n)
		r.Verdict, r.Reason = kernel.Refused, "RPC_UNAVAILABLE"
		return r, err
	}
	assertVerdict(t, c.InboundFrom(ctx, proof, nil), Refused, CodeVerifierUnavailable, false, true)
	if !bytes.Equal(b.Cached[proof.Key], p.Bytes) {
		t.Fatal("refusal replaced cached proof")
	}
}

// Same-pin restart works; cross-pin and old unpinned identity hashes fail without rewriting durable state.
func TestTransportStateBinding(t *testing.T) {
	for _, pin := range []Transport{NostrNIP17Seal, SwarmEnvelopeV2} {
		config := unitConfig(t)
		if _, err := NewForTransport(config, pin); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(config.StateDir, stateName)
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = NewForTransport(config, pin); err != nil {
			t.Fatal("same pin restart", err)
		}
		other := NostrNIP17Seal
		if pin == other {
			other = SwarmEnvelopeV2
		}
		if _, err = NewForTransport(config, other); !errors.Is(err, ErrState) {
			t.Fatal("transport state relabeled", err)
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(original, after) {
			t.Fatal("cross-pin refusal changed state", err)
		}
	}
	config := unitConfig(t)
	oldPins, _ := json.Marshal(struct{ Identity, Agent, Landlord, Issuer, Network, Genesis, Construction string }{
		config.Identity, config.AgentName, config.LandlordName, config.IssuerPubkey,
		"regtest", su.RegtestGenesis, config.ConstructionProfile,
	})
	oldState := jsonBytes(t, state{Version: 1, Binding: rental.Hash(oldPins), High: 500})
	path := filepath.Join(config.StateDir, stateName)
	if err := os.WriteFile(path, oldState, 0600); err != nil {
		t.Fatal(err)
	}
	for _, pin := range []Transport{NostrNIP17Seal, SwarmEnvelopeV2} {
		if _, err := NewForTransport(config, pin); !errors.Is(err, ErrState) {
			t.Fatal("unpinned state adopted", err)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, oldState) {
		t.Fatal("old state refusal changed state", err)
	}
}

// Nil/zero checkers and cancelled contexts refuse before handling a sender assertion.
func TestSenderInvalidChecker(t *testing.T) {
	proof := SenderProof{SwarmEnvelopeV2, xonly(2)}
	var nilChecker *Checker
	var zero Checker
	assertVerdict(t, nilChecker.InboundFrom(context.Background(), proof, nil), Refused, CodeCheckFailed, false, false)
	assertVerdict(t, zero.InboundFrom(context.Background(), proof, nil), Refused, CodeCheckFailed, false, false)
	c, _, _ := senderChecker(t, SwarmEnvelopeV2)
	assertVerdict(t, c.InboundFrom(nil, proof, nil), Refused, CodeCancelled, false, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assertVerdict(t, c.InboundFrom(ctx, proof, nil), Refused, CodeCancelled, false, true)
}
