# Grant check boundary for a2a daemon (a2ad) (CG1)


## R1 specification pin and v3 compatibility

The R1 delta is pinned to public spec tag
[`v0.1.49`](https://github.com/relux-works/swarma-link-spec/tree/v0.1.49),
commit `1c3bcafc8bfc1450c3c0cefb69a122f6a97a448e` (tag signature verified).
Its new constructs are implemented only in the
[v4 identity lab](../grant-v4/identity/README.md#r1-decision-map-and-compatibility).

| Decision | Spec section | Module / compatibility |
| --- | --- | --- |
| J12 grouped rows and R2 row fit | LIP-0026 §§2,8; LIP-0014 §9.1 | V4 lab only; no new group/member in v3 |
| J10 landlord class and holder-written value (d) | LIP-0026 §9; LIP-0021 §§2–7; LIP-0008 §3.1 | V4 lab only; v3 `grantee_key` keeps its existing meaning |
| J11 holders in landlord values | LIP-0010 §10, including its compatibility paragraph | **Compatibility item:** accepting holders would widen this verifier's current name parser. Existing rejection is preserved |
| J9 no certifier within one owner | LIP-0014 §8.3; LIP-0026 §10 and conformance impact | V4 only. V3 contract rows still name a notary and v3 children remain certified |

J10/J11/J12 remain pending at the pin, and J9 admits no uncertified child
until J10/J11 are decided. The explicit v4 draft profile is never selected by
this module. Its exported API, existing proof bytes, constructors, name readers
and internal requirement selections are unchanged. No draft rule widens v3
acceptance and no new profile parameter is added to the consumer API. (The
contract profile of the next section is a later, separate and explicit
configuration parameter; it selects no v4 rule.)

`TestR1V3NameCompatibility` pairs valid legacy values with refusals for
holders (empty and populated) and the new agent shape.
`TestR1V3ProofCompatibility` pairs a valid routing control with v4 version,
group, class and no-certifier proof plants. Each refuses before the backend,
with admitted cache and durable state bytes unchanged. These are offline
boundary tests; the unit backend is no evidence of chain qualification.
Run `go test -race -count=1 -run '^TestR1V3' .` from this module, with the
same Go/cache environment as the commands below. Node-backed Core qualification
remains a separate opt-in gate and must not be claimed from a skipped run.

## Contract profiles and configured network (T1.0b)

`Config.ContractProfile` selects how the contract behind a grant's
`contract_sha256` is read. The caller selects it; the checker never detects a
profile from a grant or from contract bytes, and a grant of the other profile
refuses as `terms_invalid`.

| `ContractProfile` | Contract | Network binding |
| --- | --- | --- |
| `""` or `"pay"` | Canonical `rental.PayTermsV2`, as before. Nothing in this path changed | The fixed regtest pin when `Network` and `Genesis` are both empty, as before; an explicit admitted pair otherwise |
| `"trust"` | `swarma-trust-contract/1`, or a root `swarma-trust-contract/2` at depth 0 | `Network` and `Genesis` are required. There is no default |

`Network` and `Genesis` admit exactly two pairs: `regtest` with the regtest
genesis, and `main` with `MainGenesis`. A missing value, an unknown network
name and a pair of one network with the genesis of the other refuse
construction with `ErrConfig` before any state opens. `MainGenesis` is the
hash that Namecoin Core asserts for `CMainParams` in `chainparams.cpp`;
`TestMainGenesisLiteral` checks it against the literal and against the constant
the rental kernel pins. The pair binds the grant, the proof cache, the node
observation (`getblockchaininfo` must report the configured chain) and the
kernel, and it is part of the durable state binding. The profile G1.0 uses is
`trust` on `main`; regtest stays for the junction and qualification fixtures.

The specification is swarma-link-spec v0.1.51, commit
`bd3bc80e5543d8a563343ec05abd1a5f3f67284c`: LIP-0013 section 2 (profile `/1`),
LIP-0014 sections 3.1 and 3.2 (profile `/2` and the reader of both), LIP-0004
and LIP-0005 (Grant v3) and LIP-0010 sections 3 and 10 (landlord values). The
Link book is the primary description of the grant, the consent and the seal
(`link-book/ru/04-doverennost.md`) and of the contract hash
(`link-book/ru/06-dogovor.md`).

After the unchanged presentation, signature and pin checks, the trust profile
applies LIP-0013 section 2.5 with the reader of LIP-0014 section 3.1. The
member set of the document selects the rules; the profile string is then
judged by rule 2. Every refusal maps to a code of the existing closed set. No
code was added.

| Refusal | Code | Why this code |
| --- | --- | --- |
| The contract bytes cannot be resolved, or their SHA-256 is not `contract_sha256` | `terms_invalid` | The same meaning as for pay terms |
| The document breaks a rule that judges it alone: canonical bytes (whitespace, a repeated, unknown, missing, reordered or case-folded member, trailing data, a number or string spelling, more than 8192 bytes), the profile string, a field, the actions (empty, unsorted, repeated or outside the four names), the repositories, the budget, the note, the parent, the delegate | `terms_invalid` | The document is not a valid contract of this profile |
| A valid `/2` document with a right of re-delegation (`delegate.depth` above 0), or a child (a parent id or an ordinal) | `terms_invalid` | A valid contract that this checker does not serve. A child needs the notary's checks of LIP-0014 section 8, which are not made here |
| A valid document whose `network`, `landlord_name`, `agent_name`, `grantee_key`, `not_before` or `not_after` is not the grant's | `binding_mismatch` | The contract is about another grant |
| The grant's scope is not the one LIP-0013 section 2.2 derives, its budget is not `spend_budget`, or its consent tags are not those of section 2.4 | `binding_mismatch` | The grant does not carry what the contract states |
| The grant's network, genesis, names, issuer or grantee is not the configured or verified one | `binding_mismatch` | As before, now with the configured network |
| A grant that pairs one network with the genesis of the other | `invalid_presentation` | It is no valid v3 grant; the kernel's parser refuses it |
| The landlord's name value carries `holders`, empty or populated | `binding_mismatch` | The chain binding of the landlord is not the legacy one that this profile pins |

**Legacy landlord values.** The trust profile is the G1.0 profile: it admits a
landlord value without `holders` only (LIP-0010 section 10, the compatibility
paragraph). The checker inspects the `name_show` answer for the configured
landlord name on its way to the kernel and refuses a `holders` member under
its own code. Every other departure from the legacy value is refused by the
kernel's strict reader, as before. The pay profile's node wrapper is unchanged.

**Reuse.** Both parsers live in `internal/trustcontract`.

- Profile `/1` is a port of `tools/trustcheck/contract.go` of the specification
  at the commit above (the tool is `package main`). It is tested against every
  contract vector of `vectors/LIP-0013/trust-vectors.json`: 4 valid contracts
  accepted with their exact bytes, 32 invalid contracts refused with their
  published codes, 15 bindings and the 3 grants of the envelope section. See
  `internal/trustcontract/testdata/README.md` for the committed file, its
  SHA-256. The file is copied verbatim, including the 26 kind-8185
  envelope vectors, whose admission verdicts are not judged by this module.
- Profile `/2` is a copy of `experiments/notary-checker` `contract.go` and the
  helpers it calls. It is a copy and not an import because a new requirement
  edge between two modules of this repository changes the published module
  graph, and not a shared module because that would change the notary's
  sources and its release hash. The notary is unchanged.
  `TestNotaryCopyMatchesSource` fails when the notary's two source files
  change, and `TestNotaryCorpusAgrees` runs the notary's own committed vectors
  through the copy. The grantcheck workflow also watches notary-checker
  paths so notary-only changes run the drift check. The pinned LIP-0014
  corpus supplies all 151 contract vectors. `TestTrustLIP0014PairScope` checks
  all 39 pairs: each parent against its own §3.1 contract verdict, and every
  child-slot document against the trust profile’s `terms_invalid` refusal.
  §8 pair verdicts are not judged by CG1; it refuses all children (D2); the notary judges pairs.
  Pair-21’s child slot is a root at depth 1 and refuses by D2’s depth rule;
  the six hypothetical spend parents retain `CONTRACT_DELEGATE` under D12.
  The `trust_pair_child_refusal` plant removes D2’s parent-id/ordinal refusal
  and must fail this test. These checks do not certify delegation pairs.

**Limits.** The tests of this section are offline boundary tests with a
routing stub in the kernel's place. They are no evidence of chain
qualification on regtest or on mainnet, which stays a separate gate. The
checker admits a grant; it admits no instruction: the kind-8185 envelope and
the admission steps of LIP-0013 section 3.4 are not implemented here. Under
the trust profile `Config.ExecutorKey` must be empty; any non-empty value
refuses at construction with `ErrConfig` before state opens. Pay still requires
its valid executor key. A `/2` root with a non-empty `scope_text_sha256` refuses
as `terms_invalid` until a gate resolves and checks the text. The G1.0 holders
refusal stays `binding_mismatch`, non-retryable; no vocabulary change is made.

Run `go test -race -count=1 ./...` from this module for both packages.
`go run .scripts/guards.go -out .temp/guards` now also removes each gate of
this section in an isolated copy and requires its named test to fail.

## Required executor and interim node policy

`New` and `NewForTransport` require `Config.Terms` and an explicit
`Config.Freshness` policy. The pay profile additionally requires
`Config.ExecutorKey`; the trust profile requires it to be empty. Missing/invalid inputs refuse
construction with `ErrConfig`, including an unset pay executor pin. Both inbound
and cached/outbound checks enforce the canonical terms' executor, headers equal
to blocks, minimum height, maximum tip age and maximum future skew.
`node_not_synced`, `tip_below_floor` and `tip_stale` are retryable;
`executor_mismatch`, `terms_invalid`, `tip_future` and `issuance_mismatch` are not.

The HIDDEN age of an admitted view is at most A + F (not A).
`trusted_now` is the consumer's trusted `Config.Now` clock input (the consumer's
`time.Now` system clock if omitted), never the node's own time. A must be positive;
F is explicitly supplied in `[0, 600 seconds]`; this is a BENCH ceiling, not a
production value. Consensus permits headers up to two hours ahead, so any
non-bench use revisits both F and A through LIP-0022 after the real-node probe. FLOOR is explicitly supplied in
`[0, 2147483647]`. No A/F/FLOOR value defaults; subsecond policy values are supported.
This is an INTERIM rule for the v3 TEST BENCH, superseded by LIP-0022 once
accepted. Production values are NOT set here and need a runtime probe on a real
Namecoin node before any non-bench use.

`Checker.Provision(ctx, Presentation)` verifies a counterpart's canonical proof
through the full admission path before caching it, with a durable bounded audit.
It enables first-message bootstrap without any prior inbound message. The cache
and successful provision audit are persisted together after all final checks.
The bench delegates executor and freshness checks to grantcheck.
See [POLICY.md](POLICY.md) for the required config/API change, exact rule,
provisioning hash semantics, explicit bench values, tests and eight overlay controls.

## Expired current identities

`identity_expired` is a named refusal with `closed=true` and `retryable=false`
on outbound, supplied inbound and cached re-checks. It maps to A2A
`refused/identity_expired/false`, never `dependency_unavailable` or exchange.
The rental kernel requests Core `name_show` with `allowExpired=true` for both
current identity roles and returns `IDENTITY_EXPIRED` when `expired=true`.
Expiry is a terminal observation of that current generation, not a cached
permission or an irreversible journal tombstone: a chain reorg is checked afresh.
A same-value renewal confirmed before expiry remains live.

The read-only RPC client preserves a valid JSON-RPC error as typed
`singleuse.RPCError` (code/message), including HTTP 500 responses. `NameExpired`
recognizes Core code -4 with its expired-name message. Raw messages are not
copied to public receipts. Transport failures and 5xx responses without a valid
RPC error remain `verifier_unavailable`, retryable.

An application error requires a complete JSON-RPC 1.0 envelope: exactly `id`,
`result` and `error`, the matching request ID, a null result and an error object
with an integer code and string message. Missing members, a non-null result
alongside an error, duplicate keys and trailing data remain retryable node
failures at every HTTP status. `TestCoreMalformedRPCEnvelopeRetryable` checks
the public inbound, cached and outbound routes beside genuine live and valid
application-error controls, including unchanged durable bytes on malformed replies.

`TestCoreIdentityExpired` uses the existing pinned Core harness, real name
registration, same-value renewal, block-height expiry of each identity role,
and stopped-node controls. Run with the same `CG1_*` environment below:
`go test -race -count=1 -run '^TestCoreIdentityExpired$' .`.

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
history to regain capacity. `New` exposes only bounded construction/configuration/state errors.

`Now` defaults to `time.Now` and belongs to the verifier. The persistent clock
high-water rejects rollback across restart. `CheckTimeout` defaults to 5 seconds
and cannot exceed it; a custom Node must honor context cancellation. The library
has no background workers or unbounded queue. Concurrent work may return `busy`
or `state_unavailable` instead of waiting for a lock.

```go
// Nostr call signatures remain; the required construction policy applies.
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
are accepted. Grantcheck persists proof only after all checks; limits remain 64 senders /
60000 aggregate encoded bytes. The 64-record audit and full cache share a
calculated 73192-byte maximum state; `capacity_exceeded` refuses predictable
capacity overflow without changing state or poisoning the checker. Cancelled
calls return `cancelled` and record no checker audit. See [POLICY.md](POLICY.md)
for the commit boundary and preservation guarantees.

`Retryable` is true only for `verifier_unavailable`, `state_unavailable`, `busy`,
`cancelled`, `clock_invalid`, `grant_pending`, `identity_pending`, `node_not_synced`, `tip_stale` and
`tip_below_floor`. a2a daemon
retains those events in its bounded held queue and checks again; cursor progress
must not discard them. An inbound `exchange` goes to the separate bounded
per-identity exchange spool, never the agent inbox or model. Scope is returned
only for live results and remains metadata, not execution authority.

A downstream transport adapter registers CG1 at build time and uses Go 1.26. Upstream a2a stays
on Go 1.25 and has no chain-lab dependency. For the test bench, transports only carry; authority comes from a signed envelope inside
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
The inbound lifecycle mapping is:

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

- Final-sample freshness for every live route, including every aggregate recipient,
  is audited in [POLICY.md](POLICY.md#final-sample-authority-audit).
- The policy witnesses and overlay controls are documented in
  [POLICY.md](POLICY.md#validation-and-controls); outputs go to the explicitly
  chosen `.temp/` evidence directory and fresh isolated regtest root.


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
- `go run .scripts/guards.go -out .temp/guards -core -private-root <fresh-absolute-directory>` runs isolated guard-removal
  controls; set `CG1_CORE_DAEMON` and `CG1_CORE_CLI` as above. Without `-core`,
  only offline plants run. Logs, source hashes and intended-failure verdicts go
  under a fresh run directory in the requested output path. Core datadirs go
  under `-private-root` (default: a fresh directory under `TMPDIR`), separately
  from public evidence. Never publish nested
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

## Swarma Identity G1.0 junction and ceremony checker

The [issuance corpus](testdata/identity-interop/README.md) preserves the exact
public bytes produced by swarma-identity `48a32fb0`: Grant v3, trust-contract
`/1`, instruct/review, depth zero and legacy landlord values. The offline
interop tests use the actual kernel with synthetic read-only chain observations;
they do not qualify a live node. Run `go test -run '^TestIdentityInterop' -v .`.

`go run ./cmd/no-holders < landlord-value.json` is the read-only offline
ceremony gate: `LEGACY-OK`/exit 0 or `REFUSE <reason>`/exit 1. Input is the
VALUE, raw JSON or the JSON string from `name_show.value`. It opens no node
and checks no chain authority. Regenerate bytes from the repository root with
`bash .scripts/regenerate-identity-interop.sh "$PWD/.temp/identity-interop-new"`;
the output directory must be new. See the corpus for exact pins, dispatcher
commands, refusal pairs and limits.
