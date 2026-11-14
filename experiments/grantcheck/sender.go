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

// SenderProof asserts how the caller verified Key. The caller must verify the
// NIP-17 inner seal or swarm-envelope/2 signature before constructing this value.
// Key is that signature's lowercase BIP-340 x-only key, never a message field,
// Matrix user ID, display name or gift-wrap signer. This is not an opaque token:
// the library checks the assertion's shape and pin, not the envelope signature.
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
	if proof.Transport == SwarmEnvelopeV2 && v.Code == CodeNoGrant {
		v.Decision = Refused
	}
	return v
}

// RecipientProof contains every addressee key extracted by the adapter from its
// authenticated outbound envelope. Room membership and room IDs are not inputs.
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
