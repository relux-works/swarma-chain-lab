# Grant check boundary for a2a daemon (a2ad) (CG1)

## SW1 witness construction

`Config.ConstructionProfile` is required and must equal `"W"`; it is supplied by the authenticated daemon configuration, never by a peer message. It is included in the durable identity binding. Missing/unknown/L pins refuse before state opens.

See [the W boundary/reason inventory](../WITNESS-PROFILE.md). This first delivery is linkage-only: unconfirmed payment Q is deferred to SW1b with an authenticated GV4 proof contract. Existing signed v3 grant bytes are unchanged.

Go 1.26 library over the landed K1 v3 kernel and M2-05 kernelbind. It returns
`live`, `refused` or inbound-only `exchange`; it never writes a mailbox, wakes
a model, signs a reply, books a rental or broadcasts a transaction. Only a fresh
live result permits a2a daemon's adjacent inbox/sign/send operation.

Construct one `Checker` for an authenticated a2a daemon identity with `New(Config)`.
Pin `Identity`, `AgentName`, `LandlordName`, `IssuerPubkey`, a canonical absolute
owner-private 0700 `StateDir`, and the verifier's own read-only `Node`. Identity
labels contain 1..128 lowercase ASCII letters, digits, dots, hyphens or underscores.
The directory starts empty; an existing root can reopen only under identical
identity/name/key pins. Do not adopt another kernel's state or delete closure
history to regain capacity. `New` exposes only `ErrConfig` or `ErrState`.

`Now` defaults to `time.Now` and belongs to the verifier. The persistent clock
high-water rejects rollback across restart. `CheckTimeout` defaults to 5 seconds
and cannot exceed it; a custom Node must honor context cancellation. The library
has no background workers or unbounded queue. Concurrent work may return `busy`
or `state_unavailable` instead of waiting for a lock.

```go
// Sender is the transport-verified NIP-17 inner seal key, not a rumor field.
v := checker.Inbound(ctx, verifiedSender, presentation)
// Later, immediately before sending to this exact recipient:
replyVerdict := checker.Outbound(ctx, recipient)
```

`Presentation` contains `GrantID` and the complete canonical v3 proof `Bytes`.
Inbound `nil` uses this identity's previously live-admitted proof cache. A
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
on Go 1.25 and has no chain-lab dependency. Only Nostr identities with a grant
policy call the checker; a2a daemon rejects grant policy on Matrix at startup.
Owner DM stays on Matrix outside admission, with no owner bypass on Nostr v1.
a2a daemon v1 supplies a full grant-cert only and does not resolve S1. These
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
  evidence uses `GOTOOLCHAIN=go1.26.8` explicitly.
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
