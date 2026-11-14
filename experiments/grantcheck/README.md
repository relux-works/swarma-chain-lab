# Grant check boundary for a2a daemon (a2ad) (CG1)

## SW1 witness construction

`Config.ConstructionProfile` is required and must equal `"W"`; it is supplied by the authenticated daemon configuration, never by a peer message. It is included in the durable identity binding. Missing/unknown/L pins refuse before state opens.

See [the W boundary/reason inventory](../WITNESS-PROFILE.md). This first delivery is linkage-only: unconfirmed payment Q is deferred to SW1b with an authenticated GV4 proof contract. Existing signed v3 grant bytes are unchanged.

Go 1.26 library over the landed K1 v3 kernel and M2-05 kernelbind. It returns
`live`, `refused` or inbound-only `exchange`; it never writes a mailbox, wakes
a model, signs a reply, books a rental or broadcasts a transaction. Only a fresh
live result permits a2a daemon's adjacent inbox/sign/send operation.

Construct one `Checker` for an authenticated a2a daemon identity. `New(Config)`
retains the Nostr API and always pins `NostrNIP17Seal`. The explicit constructor
`NewForTransport(Config, Transport)` requires one supported nonzero provenance:
`NostrNIP17Seal` or `SwarmEnvelopeV2`. Each checker has one immutable pin.
Pin `Identity`, `AgentName`, `LandlordName`, `IssuerPubkey`, a canonical absolute
owner-private 0700 `StateDir`, and the verifier's own read-only `Node`. Identity
labels contain 1..128 lowercase ASCII letters, digits, dots, hyphens or underscores.
The directory starts empty; an existing root can reopen only under identical
identity/name/key/transport pins. The transport is included in the durable binding
hash. Old unpinned state and differently pinned state refuse with `ErrState`;
there is no implicit migration or cache adoption. Retain old closure history and
resolve any migration separately before using a new state root. Do not adopt
another kernel's state or delete closure
history to regain capacity. `New` exposes only `ErrConfig` or `ErrState`.

`Now` defaults to `time.Now` and belongs to the verifier. The persistent clock
high-water rejects rollback across restart. `CheckTimeout` defaults to 5 seconds
and cannot exceed it; a custom Node must honor context cancellation. The library
has no background workers or unbounded queue. Concurrent work may return `busy`
or `state_unavailable` instead of waiting for a lock.

```go
// Legacy Nostr API remains unchanged.
// Sender is the transport-verified NIP-17 inner seal key, not a rumor field.
v := checker.Inbound(ctx, verifiedSender, presentation)
// Later, immediately before sending to this exact recipient:
replyVerdict := checker.Outbound(ctx, recipient)

// Envelope API: caller verifies the envelope, then its BIP-340 co-signature (slice 1).
envelopeChecker, err := grantcheck.NewForTransport(config, grantcheck.SwarmEnvelopeV2)
// Handle err before use.
v = envelopeChecker.InboundFrom(ctx, grantcheck.SenderProof{
    Transport: grantcheck.SwarmEnvelopeV2, Key: verifiedCosignerKey,
}, presentation)
// Resolve the signed `to` carrier id through the adapter's pinned binding.
replyVerdict = envelopeChecker.OutboundFrom(ctx, grantcheck.RecipientProof{
    Transport: grantcheck.SwarmEnvelopeV2, Keys: verifiedAddresseeKeys,
})
// Map to the a2a seam's closed strings; the adapter enforces inbound-only exchange.
verdict, reason, retryable := v.A2ADecision()
```

`Presentation` contains `GrantID` and the complete canonical v3 proof `Bytes`.
Inbound `nil` uses this identity's previously live-admitted proof cache.
An envelope sender with no cached proof gets `refused/no_grant`; the Nostr
`exchange/no_grant` behavior is unchanged. A
non-nil invalid proof never falls back. Every cache hit runs the real checker
again. Only lowercase valid BIP-340 peer keys and proofs of at most 16384 bytes
are accepted. Proof cache limits remain K1's 64 senders / 60000 aggregate bytes.

`Retryable` is true only for `verifier_unavailable`, `state_unavailable`, `busy`,
`cancelled`, `clock_invalid`, `grant_pending` and `identity_pending`. a2a daemon
retains those events in its bounded held queue and checks again; cursor progress
must not discard them. An inbound `exchange` goes to the separate bounded
per-identity exchange spool, never the agent inbox or model. Scope is returned
only for live results and remains metadata, not execution authority.

The fork a2a-link registers CG1 at build time and uses Go 1.26. Upstream a2a stays
on Go 1.25 and has no chain-lab dependency. Under the owner's decision T23 of
2026-11-14, transports only carry; authority comes from a signed envelope inside
the message on every transport. For the v3 test bench, Matrix grant policy is
allowed only with the verified sender key defined below. The grant ID and
canonical v3 presentation (at most 16384 bytes) travel inside the envelope or
are already in the admitted proof cache. `SenderProof` is an assertion of caller
verification, not a signature verifier or an unforgeable token. Nostr remains
the target transport; this test-bench allowance does not replace it. Owner DM
stays outside admission, with no owner bypass on Nostr v1.

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

For envelope outbound, `RecipientProof.Keys` contains the key resolved by the
adapter from the one signed `to` carrier id per message through a pinned binding.
The resolved key must pass a fresh K1 check on every send and retry. Empty lists, Matrix room IDs and invalid keys refuse; room membership
and room pins never supply authority. There is no recipient-discovery fallback.
`MaxRecipients` is 64, matching the admitted sender-cache capacity. Success is an
aggregate verdict with no per-grant scope or identity metadata. Legacy string
`Outbound` refuses on an envelope checker. See [the interface prerequisites](UNRESOLVED_QUESTIONS.md).

Unknown/zero provenance or a different supported provenance returns
`refused/binding_mismatch`; malformed sender/addressee keys return
`refused/invalid_peer`. Missing outbound addressees also return `invalid_peer`,
and more than 64 returns `oversize`. These reuse the documented closed code set.
No new reason is introduced. `A2ADecision` provides the pure closed mapping in
[DESIGN.md](DESIGN.md#4-closed-routing-and-refusal-codes).
The keeper's 2026-11-14 11:39:01Z decision resolves the lifecycle mapping:

| Inbound code | SwarmEnvelopeV2 seam verdict / reason / retryable | NostrNIP17Seal seam verdict / reason / retryable |
| --- | --- | --- |
| `not_yet`, `expired`, `seal_spent`, `landlord_rotated`, `landlord_changed` | refused / denied / false | exchange / exchange / false |

The inbound verdict carries the validated checker's transport pin privately;
`A2ADecision` applies this table to that in-memory result. Grantcheck's underlying
lifecycle `Decision`/`Code` observations and all other seam rows are unchanged.
Serialized verdicts do not retain this provenance and must never be reused for
admission; perform a fresh check instead. The addressee contract is settled as
one signed `to` carrier id per message, resolved by the adapter through a pinned
binding; grantcheck defines no new wire field.

a2a daemon v1 supplies a full presentation and does not resolve S1. These
integration responsibilities are specified here, not implemented in a2a by CG1.

Infra provisions the exact `w3-observer` username required by the reused
`single-use.NewRPC`, with read-only rpcauth/rpcwhitelist on its loopback Namecoin
regtest node. There is no username/route fallback. See
[DEPENDENCIES.md](DEPENDENCIES.md) and [DESIGN.md](DESIGN.md).

Results describe a bounded chain observation, not an atomic transaction with a
future mailbox write or relay send. Recheck after delays, retries or reconnects;
never queue a live verdict as a reusable permission token.

## Tools and artifacts

- From this module: `go test -race ./...`, `go vet ./...`, `go build ./...`,
  `go mod tidy -diff` and `go mod verify`. Go 1.26 is required; development
  commands use `GOTOOLCHAIN=local` with the installed Go 1.26 toolchain.
- `go test -run '^TestRecordedVectors$' -v .` validates the 21 offline recorded
  vectors in `testdata/verdicts-v1.json`. They are public historical observations,
  never a production authority source. See [testdata/README.md](testdata/README.md).
- `CG1_REGTEST=1 CG1_RUN_ROOT=<new-absolute-directory>
  CG1_CORE_DAEMON=<namecoind> CG1_CORE_CLI=<namecoin-cli>
  go test -race -count=1 -run '^TestCoreVectors$' -v .` uses isolated hash-pinned
  Core and the real issuer. Set all variables in one shell command. The fresh
  root contains public vectors/issuer receipts plus private node/wallet state.
  The harness stops its own recorded Core PID. No existing datadir is accepted.
- `go run .scripts/guards.go -out .temp/guards -core` runs isolated guard-removal
  controls; set `CG1_CORE_DAEMON` and `CG1_CORE_CLI` as above. Without `-core`,
  only offline plants run. Logs, source hashes and intended-failure verdicts go
  under a fresh run directory in the requested output path. Never publish nested
  Core state directories, including wallet and RPC configuration.
- `go run .scripts/sender-guards.go -out .temp/sender-guards` runs the four
  provenance controls using Go overlays: accept any transport, skip key-format
  validation, ignore the transport pin, and fall back to Nostr exchange for the
  five envelope lifecycle codes. The last is killed by `TestA2ADecisionTable`.
  Each baseline must exit 0 and the
  named assertion must kill its mutant with exit 1. Overlays and logs go under
  a fresh output directory; checked-out source is never mutated.
- `gofmt -l *.go .scripts/*.go` and `git diff --check` check formatting.

This checkout uses GitHub module paths, sibling v0.1.0 requirements and relative
replaces for in-repository builds. External consumers ignore those replaces.
See the [initial tag and consumer procedure](../../README.md#initial-tag-set-and-publication-order).
Tagged external publication is a release prerequisite owned by the maintainers in
[UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md); in-tree success alone does not
prove a remote consumer can resolve the complete transitive module graph.

## Canonical signatures

Inbound grant presentations require canonical BIP-340 signature encodings:
exactly 64 bytes, `r < p`, and `s < n`, per
[BIP-340 Verification](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#verification).
Valid high scalars below `n` are allowed. Invalid encodings are refused before
presentation IDs, checker state writes, backend calls or cache replacement.
A canonical encoding alone does not establish authority: the grant kernel must
still verify signatures, identity bindings and the chain issuance commitment.

Run `go test -run '^TestBIP340InboundBoundary$' .` for the boundary regression
and `go test -race ./...` for the module suite.

`TestCoreBIP340InboundBoundary` also exercises an issuer-produced grant that
reaches a real live kernel verdict, then rejects an out-of-range scalar before
state changes or node calls. Run it with the existing `CG1_REGTEST=1` setup and
a fresh `CG1_RUN_ROOT`. The fixture pins complete executable pairs: the existing
macOS Core 28 pair and the official Linux Core 28 release pair already pinned by
the wallet suite. Mixed or unlisted pairs refuse before node startup. Generated
vector reports record the hashes of the executables actually used.
