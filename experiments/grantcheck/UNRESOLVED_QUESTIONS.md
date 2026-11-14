# CG1 integration questions

The routing table and per-identity boundary are accepted. Integration corrections
are recorded in DESIGN.md: closed Retryable classification, a2a daemon (a2ad)-owned bounded
held/exchange queues, full grant-cert only in v1, build-time fork registration,
and transport-pinned grant policies. Under the owner's decision T23 of
2026-11-14, Matrix is allowed for the v3 test bench only with the BIP-340 key
that verified the swarm-envelope/2 signature, never a Matrix user ID, display
name or message field. The grant ID and canonical v3 proof (at most 16384 bytes)
are in the envelope or already cached. Owner DM remains outside admission.
Nostr remains the target transport; the allowance does not replace it.

## Open: downstream interface agreement

The proposed API adds `NewForTransport`, `SenderProof`/`InboundFrom`,
`RecipientProof`/`OutboundFrom` and the pure `Verdict.A2ADecision` mapping.
`New`/`Inbound`/`Outbound` retain the Nostr API and a fixed Nostr pin. Envelope
outbound requires every signed-envelope addressee key and fresh live grants for
all of them. Missing addressees refuse; there is no room-pin or membership
fallback. The inspected Matrix carrier passes opaque envelope bytes and supplies
no addressee extraction contract. The downstream adapter must confirm that
contract and agree exact signatures before integration is claimed. If the
signed-envelope format cannot name addressees, that is a downstream blocker,
not permission to invent a message field or derive authority from the room.

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
checker provenance; all other rows are unchanged. This resolves mapping only:
signed-envelope addressee extraction remains open with the a2a-link producer.

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
