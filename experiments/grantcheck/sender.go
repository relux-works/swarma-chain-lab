package grantcheck

import "context"

// Transport is a closed sender-verification provenance, not a routing address.
// SwarmEnvelopeV2 may be carried over Matrix or another transport.
type Transport uint8

const (
	NostrNIP17Seal Transport = iota + 1
	SwarmEnvelopeV2
)

func (t Transport) valid() bool {
	return t == NostrNIP17Seal || t == SwarmEnvelopeV2
}

// SenderProof asserts how the caller verified the lowercase BIP-340 x-only Key.
// For NostrNIP17Seal, the caller verifies the NIP-17 inner seal and passes its
// key, never a rumor field or gift-wrap signer.
// For SwarmEnvelopeV2, Key is the grant-named BIP-340 key that the caller verified
// from a per-message BIP-340 co-signature over the exact swarm-envelope/2 bytes
// (slice 1), or from a BIP-340 author profile once one exists (target); never the
// envelope's Ed25519 author key, a carrier id, display name or message field.
// In slice 1 the caller verifies the envelope first; envelope verification alone
// does not establish Key. This assertion is not an opaque token: grantcheck
// checks its shape and pin but verifies neither the envelope nor the co-signature.
type SenderProof struct {
	Transport Transport
	Key       string
}

// InboundFrom checks a verified sender against this checker's immutable pin and
// freshly checks K1. Nil uses admitted proof bytes, never a cached live verdict.
// Envelope senders without cached proof refuse; Nostr retains exchange routing.
func (c *Checker) InboundFrom(ctx context.Context, proof SenderProof, p *Presentation) Verdict {
	if ctx == nil || ctx.Err() != nil {
		return route(CodeCancelled, true, false)
	}
	if c == nil || c.backend == nil {
		return route(CodeCheckFailed, true, false)
	}
	if !proof.Transport.valid() || proof.Transport != c.transport {
		return route(CodeBindingMismatch, true, false)
	}
	v := c.check(ctx, proof.Key, p, true)
	v.transport = c.transport
	if proof.Transport == SwarmEnvelopeV2 && v.Code == CodeNoGrant {
		v.Decision = Refused
	}
	return v
}

// RecipientProof contains the BIP-340 addressee keys supplied by the adapter.
// For SwarmEnvelopeV2, the adapter resolves the envelope's signed "to" carrier id
// through a pinned binding from authenticated configuration to exactly one
// BIP-340 key per message and passes that key in Keys. Grantcheck never sees a
// carrier id; room membership, room IDs and message fields never supply keys.
// The library permits 1..MaxRecipients (64) supplied keys and freshly checks each;
// exactly one key per envelope message is the adapter's obligation.
// Keys must not be mutated concurrently with the call. Empty lists refuse.
type RecipientProof struct {
	Transport Transport
	Keys      []string
}

// MaxRecipients bounds one send to the kernel's admitted sender-cache capacity.
const MaxRecipients = 64

// OutboundFrom freshly checks every named recipient using admitted public proof
// bytes; any non-live result denies the whole send. It returns no per-grant scope
// or identity metadata on aggregate success. No result is reusable for a retry.
func (c *Checker) OutboundFrom(ctx context.Context, proof RecipientProof) Verdict {
	fail := func(code Code) Verdict { return route(code, false, false) }
	if ctx == nil || ctx.Err() != nil {
		return fail(CodeCancelled)
	}
	if c == nil || c.backend == nil {
		return fail(CodeCheckFailed)
	}
	if !proof.Transport.valid() || proof.Transport != c.transport {
		return fail(CodeBindingMismatch)
	}
	if len(proof.Keys) == 0 {
		return fail(CodeInvalidPeer)
	}
	if len(proof.Keys) > MaxRecipients {
		return fail(CodeOversize)
	}
	for _, key := range proof.Keys {
		if !validKey(key) {
			return fail(CodeInvalidPeer)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.config.CheckTimeout)
	defer cancel()
	end, checked := int64(maxUnix), int64(0)
	for _, key := range proof.Keys {
		v := c.check(ctx, key, nil, false)
		if v.Decision != Live {
			return v
		}
		end = min(end, v.NotAfter)
		checked = max(checked, v.CheckedAt)
	}
	// An earlier addressee's grant may expire while later recipients are checked.
	now := c.config.Now().Unix()
	if now < checked || now > maxUnix {
		return fail(CodeClockInvalid)
	}
	if now >= end {
		return fail(CodeExpired)
	}
	if ctx.Err() != nil {
		return fail(CodeCancelled)
	}
	v := fail(CodeLive)
	v.CheckedAt = now
	return v
}
