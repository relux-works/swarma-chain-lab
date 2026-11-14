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

// Envelope API: caller verifies swarm-envelope/2 first, then passes its BIP-340 key.
envelopeChecker, err := grantcheck.NewForTransport(config, grantcheck.SwarmEnvelopeV2)
// Handle err before use.
v = envelopeChecker.InboundFrom(ctx, grantcheck.SenderProof{
    Transport: grantcheck.SwarmEnvelopeV2, Key: verifiedEnvelopeKey,
}, presentation)
// Extract EVERY addressee key from the authenticated outgoing envelope.
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
allowed only when the sender is the BIP-340 key that verified the
`swarm-envelope/2` signature: never a Matrix user ID, display name or message
field. The grant ID and canonical v3 presentation (at most 16384 bytes) travel
inside the envelope or are already in the admitted proof cache. The adapter
verifies the envelope before calling CG1; `SenderProof` is an assertion of that
verification, not a signature verifier or an unforgeable token. Nostr remains
the target transport; this test-bench allowance does not replace it. Owner DM
stays outside admission, with no owner bypass on Nostr v1.

For envelope outbound, `RecipientProof.Keys` names every addressee from the
authenticated outgoing envelope. All must pass a fresh K1 check on every send
and retry. Empty lists, Matrix room IDs and invalid keys refuse; room membership
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
- `go run .scripts/sender-guards.go -out .temp/sender-guards` runs the three
  provenance controls using Go overlays: accept any transport, skip key-format
  validation, and ignore the transport pin. Each baseline must exit 0 and the
  named assertion must kill its mutant with exit 1. Overlays and logs go under
  a fresh output directory; checked-out source is never mutated.
- `gofmt -l *.go .scripts/*.go` and `git diff --check` check formatting.

This checkout uses GitHub module paths, sibling v0.1.0 requirements and relative
replaces for in-repository builds. External consumers ignore those replaces.
See the [initial tag and consumer procedure](../../README.md#initial-tag-set-and-publication-order).
Tagged external publication is a release prerequisite owned by the maintainers in
[UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md); in-tree success alone does not
prove a remote consumer can resolve the complete transitive module graph.
