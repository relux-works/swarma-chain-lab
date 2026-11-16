# Offline v4 documents (not admission)

The specification pin is public `swarma-link-spec`
`3bef542fc8c0a5dedeeaaa990bd7f93abe194813` (0.1.53).
`Config{ContractProfile: "v4", Network: ..., Genesis: ...}` selects this
experimental document reader explicitly. Both network and genesis are required;
only the existing main/regtest pairs are supported. No content sniffing or
legacy fallback is performed. The pay/trust proof and contract paths retain
their existing bytes and tests.

`Checker.VerifyV4Document` returns a **document**, never an admission `Verdict`.
It applies the LIP-0020 W9/W11 pipeline in the wire module and then the configured
genesis binding. `GrantFailure` exposes the exact first refusal's code and
pipeline step, and the W11.9/W11.10 rule where applicable. Returned bytes are
copies. A parent must itself be a previously verified immutable document;
transport locators do not establish a parent or trust root.

The document result does not establish name or seal liveness, independently
trusted issuance, an issuance anchor, current height, a closed ancestor,
child-authority attenuation or an available budget. In particular LIP-0008
section 12.2 requires more parent/child checks than W11.8 assigns refusal codes
to. This experiment does not invent those codes. Every v4 effect/admission
entry point is unavailable, so a document result cannot bypass those checks.

## Proposals and heights

The four undetermined vectors are not assigned a policy. `Required` checks
all binding document rules; `ProposalOutcome` separately reports the result
of enabling all the pending W11.10 proposals. This is evidence of both
interpretations, not an admission policy selector.

The grant schema has no clock member. `V4HeightWindowContains` is only the
half-open height predicate from LIP-0008 section 7.1; it adds no grace and no
refusal code absent from the pin. It does not supply a validated chain tip or
freshness observation. The invocation's distinct clock-time rules are not
implemented here.

## Holders read seam

`identity.ReadHolderPin` checks H8/H9 spelling, sequence and hash grammar.
`identity.VerifyHoldersList` checks H53 in order: byte bound, exact-octet hash,
whole-list form, then owner/network/sequence binding. Names, owner pins,
outpoints, list order and uniqueness are checked before membership is usable.
`ReadInlineHolders` retains the strict transition form without deciding journal
migration or rollback policy.

`HolderSealView.ReadHolderSeal` describes the H44/H48 recheck at one named
validated observation. Its request binds the hash-pinned entry's outpoint,
observation tip, and independently derived H46 pin-run anchor. The necessary
answer includes exact confirmed funding transaction octets (including amount
and script), its block, mempool-inclusive spend state, every available
spender's exact octets and block/mempool sighting tip, and H28/H47 watcher
funding/spender evidence. State-only or observe-grade evidence is not sufficient
(H50). A txid or a caller's `validated` boolean cannot replace these reads.

There is **no production implementation** and no public enforcement-grade
observation constructor. A missing view, a zero observation, a non-enforcement
grade result, inconsistent tips, malformed funding or unprocessed watcher/spend
evidence refuses `CLASS_HISTORY_UNAVAILABLE`. Tests alone can construct an
internal fixture observation: confirmed funding must match the pinned txid,
output, native witness script and pin-run height; spent output refuses
`HOLDER_SEAL_NOT_LIVE`. Even fixture success is not admission or proof of the
H23/H38-H44 durable journals. No holder closure is written. A later production
adapter must validate provenance, chain consistency and H47 spends before
creating an observation; it must not expose a public grade setter.

## Published API boundary and tools

The wire/identity API slice is already on main. This consumer copies none of
its implementation and pins both modules to
`v0.0.0-20261116222636-e56bc61de826`, published commit
`e56bc61de826a99848e7c6946f331997fb424dbe`. Both are above their recorded
per-module floors; wire's own identity requirement retains its ParsePin floor
`v0.0.0-20261116164432-80bcaa527f51`. No local replacement is used.

`go test -count=1 -run '^TestV4' -v .` exercises the configured consumer,
112 grant vectors, height boundaries, holder seam and the B4a differential.
`GRANT_VERDICT_TABLE=/absolute/task-scratch/verdicts.tsv go test -count=1 -run '^TestV4DocumentVectors$' .`
exports all 112 verdict rows; partial filtered runs cannot emit a complete table.
`go run .scripts/guards.go -out /absolute/task-scratch/guards` runs consumer
and existing pay/trust controls. Upstream wire/identity guards stay in their
own modules. Logs, diffs and mutant results go to the requested evidence path.
Run `go vet ./...`, `go test -count=1 ./...`, `go test -race -count=1 ./...`
and `go build ./...` with Go 1.26.10 and `GOTOOLCHAIN=local`.

The child-attenuation evaluator remains the next unit against spec 0.1.55.
This profile stays pinned to 0.1.53 document rules; it does not implement that
evaluator. `Inbound`, `InboundFrom`, `Outbound`, `OutboundFrom` and `Provision`
refuse v4 admission with `verifier_unavailable` for an active context. No v4
cache, state or kernel is created. Pay/trust formats and fixtures are unchanged.

## B4a differential provenance

B4a's encoder is `internal/grantv4` in `swarma-identity` at
`e7c68ce46be00fb0a03f6c1edf2e02d04ca92fc9`. Go's internal-package boundary
prevents this module from importing it. The exported fixture is therefore
vendored as `testdata/b4a-grant-v4.json`; its exact command, SHA-256, source
commit and fixture license are recorded in [fixture provenance](testdata/V4-PROVENANCE.md).

`TestV4B4aDifferential` compares the literal bytes for all 112 vectors with the
reader's pinned specification fixture, calls the landed `wire.VerifyGrant` on
all issuer-exported inputs with verified parents, checks each required verdict,
and compares successful reader bytes byte for byte. For the 11 valid vectors
it also checks payload, signature, digest, grant ID, content address and seal
script. The issuer export independently re-drafts those 11 valid encodings;
the 97 rejected and four proposal vectors remain supplied corpus inputs.
Those 101 rows are rejection/proposal interoperability checks, not a claim
that the issuer emits invalid grants. Any difference fails as a `FINDING`;
neither side is normalized or reconciled.
