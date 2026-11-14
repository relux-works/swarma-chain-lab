# CG1 integration questions

The routing table and per-identity boundary are accepted. Integration corrections
are recorded in DESIGN.md: closed Retryable classification, a2a daemon (a2ad)-owned bounded
held/exchange queues, full grant-cert only in v1, build-time fork registration,
and transport-pinned grant policies. Under the owner's decision T23 of
2026-11-14, transports only carry; authority comes from a signed envelope inside
the message on every transport. Matrix is allowed for the v3 test bench only
with the verified sender key below. The grant ID and canonical v3 proof (at most
16384 bytes) are in the envelope or already cached. Owner DM remains outside
admission. Nostr remains the target transport; the allowance does not replace it.

## Resolved: slice 1 sender and addressee contract; target profile pending

The API adds `NewForTransport`, `SenderProof`/`InboundFrom`,
`RecipientProof`/`OutboundFrom` and the pure `Verdict.A2ADecision` mapping.
`New`/`Inbound`/`Outbound` retain the Nostr API and a fixed Nostr pin.

The `SwarmEnvelopeV2` sender is the grant-named BIP-340 key, verified by the caller
from a per-message BIP-340 co-signature over the exact swarm-envelope/2 bytes
(slice 1), or from a BIP-340 author profile of swarm-envelope/2 once one exists
(target); never the envelope's Ed25519 author key, a carrier id, a display name
or a message field. grantcheck does not verify the envelope or the co-signature
itself; it trusts the caller's verified key and checks the grant.

Track A (slice 1) changes only the downstream fork: it keeps the unchanged
Ed25519 `swarm-envelope/2` and carries a domain-separated, per-message BIP-340
co-signature by the grant-named key beside the envelope in the same message,
under its own content key. The adapter verifies the envelope first, then the
co-signature over those exact envelope bytes, and passes that BIP-340 key as
`SenderProof{Transport: SwarmEnvelopeV2, Key: verifiedCosignerKey}`. A missing,
invalid or mismatched co-signature is denied, not retryable, by the adapter
before calling grantcheck. The downstream adapter defines the byte construction
of the co-signature; this library does not.

Track B (target) proposes a proper BIP-340 author profile inside
`swarm-envelope/2` to its owner. If agreed, the co-signature can fold into that
profile later; slice 1 does not change the envelope format owned elsewhere.
`SwarmEnvelopeV2` names the carriage, not the signature scheme.

Addressees are settled: one signed `to` carrier id per message, resolved by the
adapter through a pinned binding. Envelope outbound requires the resolved
addressee key and a fresh live grant on every send and retry. Missing addressees
refuse; there is no room-pin or membership fallback. These are downstream
adapter responsibilities; this documentation does not claim installed integration
or define the co-signature byte construction. Track B still requires the
envelope owner's agreement.

## Open: explicit state migration

Transport is now included in the durable binding hash. Pre-provenance state and
cross-transport reopening fail unchanged with `ErrState`. No adoption, relabel,
or state deletion is provided; any migration must preserve prior closure history
and be specified and reviewed separately.

## Resolved: inbound envelope lifecycle seam mapping

The keeper's 2026-11-14 11:39:01Z decision maps `not_yet`, `expired`,
`seal_spent`, `landlord_rotated` and `landlord_changed` to
refused/denied/false for SwarmEnvelopeV2 inbound. NostrNIP17Seal keeps
exchange/exchange/false. `A2ADecision` uses the inbound verdict's validated
checker provenance; all other rows are unchanged. The sender and addressee
contract is recorded separately above; this mapping decision does not define
co-signature bytes or change the envelope format.

## Resolved: Go version

The integration owner initially requested a tagged CG1 module usable by Go 1.25.x.
At the landed base, rental, rental-gateway/kernelbind, rental-gateway, single-use
and sealwatch all declare `go 1.26.0`. Running `GOTOOLCHAIN=local go test ./...`
inside kernelbind with Go 1.25.14 exits before compilation with:

```text
go: go.mod requires go >= 1.26.0 (running go 1.25.14; GOTOOLCHAIN=local)
```

The crypto and sys dependency versions themselves declare Go 1.25.0. This does
not establish that the five application modules are source-compatible with it.
Evidence is retained in the task's `.temp/CG1-01/compat/` logs. The initial
repository-root probe was a module-selection error and is not compatibility
evidence; the direct kernelbind probe establishes the version refusal.

The a2a maintainers resolved this by setting the a2a-link fork and CG1 to Go 1.26. Upstream
a2a stays on Go 1.25.x and never imports chain-lab. No dependency migration,
kernel duplication or toolchain workaround is needed. The early standalone
routing test on Go 1.25 is not a compatibility claim for the complete checker.

## Release prerequisite: tagged transitive module graph

Publication must also make the complete transitive module graph resolvable by an
external consumer. In-tree relative replaces are not inherited by consumers;
The GitHub module paths and complete v0.1.0 tag set described in the root README
need a public remote consumer check
before claiming that a2a-link can import CG1. No producer push/tag publication is
authorized by this task. The maintainers own review and release coordination.
