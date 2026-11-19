# Published module graph audit

The default floor is signed error-envelope source `f1936aa1117aaa97df2802182af966edbacd0d50`, with commit time
`20261115082735`. Existing internal requirements retain this ancestry-verified default floor.
It contains complete JSON-RPC error-envelope fix
`1b02659161608036dfa9820167a2dbbbbd983b10`. A typed application error requires all three response members,
a matching request ID and a null result. Malformed envelopes remain node failures.
Its own 101 internal requirements select fixed source `1b02659161608036dfa9820167a2dbbbbd983b10`.
Both source and manifest selections contain the fix by verified ancestry.
The detached-v2 consumer byte inventory was regenerated and audited unchanged.
The wire → identity API edge selects the main-published snapshot
`v0.0.0-20261117003532-d68447f630c8`, without a local replacement.
The identity floor remains `v0.0.0-20261116164432-80bcaa527f51`; its explicit
`module_provenance` records main commit
`80bcaa527f51b1f4910fc84d9f78d51abad4139c` and UTC time `20261116164432`.
The checker verifies main ancestry, module presence and exact pseudo-version
provenance. The service module has its own recorded floor below; every other
module keeps the global default above.
Existing internal selections are unchanged outside the new wire/identity
and service requirements. Grantcheck and its wallet consumer were tidied against that
graph; grantcheck has no local replacements.

These selections were regenerated locally from the selected ancestors' Git
commit times and ancestry-verified module-specific version bases. Public-proxy
resolution and checksum verification await publication.

**Landing hold: pure fast-forward only.** The selected source and manifest
commits are this branch's own ancestors. Preserve their signed commit objects;
squash, rebase and rewriting platform merges would invalidate those selections.

The identity-expiry snapshot also descends from the PR #111 combined-budget
writer `43a49e4c07acfc4e966c7ca2fdd8aa0331eeef51`, retaining final-sample
freshness and atomic aggregate acceptance. Ancestry, not version order,
establishes containment of those earlier fixes.

Semantic-version order establishes an API floor, **not fix containment**. The
numerically higher rental snapshot `3baa201bafb6` lacks the strict certificate
parser. `.scripts/check-strict-module-snapshots.py` separately resolves every
protected internal requirement (and versioned replacement) to its Git commit,
runs `git merge-base --is-ancestor` against the strict change, and reads the
selected commit's parser call sites and shared bounds. Unknown/missing commits
fail closed; CI fetches full history. The source-marker check is bounded and
is not a semantic proof against arbitrary future source rewrites. A later
snapshot must pass both ancestry and source checks; version order never waives
them. The earlier audit below records why coherent snapshot floors matter.

The current inventory covers all 27 `go.mod` files and all 109 internal require edges.
The initial audit covered 20 manifests across 19 consumer modules at base
`288d63e191fefac885d6a39aa65f0a5fbb6ed7ee`.
Every edge previously named `v0.1.0`; directory replacements supplied current
source during repository tests. That does not establish published compatibility.
A concrete external consumer of `single-use/configguard` fails because
`single-use/policy.go` calls `sealwatch.ValidateJSON`, absent from `sealwatch v0.1.0`.
The new bootstrap/model packages are also absent from `single-use v0.1.0`.

All 109 internal requirements, in standalone `require` lines,
`require (...)` blocks and `// indirect` entries alike, retain versions at or
above their recorded source snapshot floors, including the service edge whose
landed ancestry floor and same-PR API checkpoint are distinguished below.
The first revision of this audit counted 96: it missed the two
standalone `single-use` requires in `deploy/go.mod` and
`experiments/station-lifecycle/go.mod`, which left `deploy` and
`station-lifecycle/cmd/station-manager` unbuildable for external consumers
(`configguard` is absent from `single-use v0.1.0`). Both are now refreshed.
This avoids mixing current consumer source with stale sibling APIs. It is a
coherent snapshot refresh, not a claim that every old edge individually fails.
No third-party requirement, product source, or local replacement changes.
The earlier snapshot audit compared its dependency module ZIPs with signed
source and used normal checksum verification. Current external consumer checks
resolve the selected versions through the public proxy and verify checksums
before test-only parser instrumentation.

| Dependency under experiments/ | Selected requirement |
| --- | --- |
| `grant-store` | `v0.1.1-0.20261115082735-f1936aa1117a` |
| `m5-host-smoke` | `v0.3.1-0.20261115082735-f1936aa1117a` |
| `model-proxy` | `v0.4.1-0.20261115082735-f1936aa1117a` |
| `model-proxy/service` | `v0.0.0-20261119004354-f239a7e42695` |
| `payment-chain` | `v0.2.1-0.20261115082735-f1936aa1117a` |
| `rental` | `v0.5.1-0.20261115082735-f1936aa1117a` |
| `rental-booking` | `v0.4.1-0.20261115082735-f1936aa1117a` |
| `rental-gateway` | `v0.4.1-0.20261115082735-f1936aa1117a` |
| `rental-gateway/kernelbind` | `v0.1.1-0.20261115082735-f1936aa1117a` |
| `sealwatch` | `v0.2.1-0.20261115082735-f1936aa1117a` |
| `signer-service` | `v0.3.1-0.20261115082735-f1936aa1117a` |
| `single-use` | `v0.3.1-0.20261115082735-f1936aa1117a` |
| `station-lifecycle` | `v0.2.1-0.20261115082735-f1936aa1117a` |
| `station-lifecycle/gatewaybind` | `v0.1.1-0.20261115082735-f1936aa1117a` |
| `station-payload` | `v0.3.1-0.20261115082735-f1936aa1117a` |
| `grantcheck` | `v0.1.2-0.20261115082735-f1936aa1117a` |

The inventory below is generated and checked by
`python3 .scripts/check-module-graph.py`, which parses every `go.mod` with
`go mod edit -json` (never a line filter) and fails when any internal require
edge is older than its floor in
[`module-graph-snapshot.json`](module-graph-snapshot.json). Regenerate both with
`python3 .scripts/check-module-graph.py --snapshot-commit FULL_PUBLISHED_SHA --write-doc`.
The generator queries canonical versions through the public proxy and verifies
all origin SHAs before writing the snapshot; a failed resolution leaves it intact.

The `grant-v4/wire` module has one internal edge: identity at
`v0.0.0-20261117003532-d68447f630c8` (published on main at
`d68447f630c8f1bf7617532d8f74ab18efa49502`).
The identity and chainview modules have no internal require edges; none of
these three modules uses local replacements or imports an earlier grant module.
The wire/identity API slice landed at `e56bc61d` before this consumer.
Grantcheck requires wire at `v0.0.0-20261117003733-ff7688e88b9f` and
identity at `v0.0.0-20261117003532-d68447f630c8`, both publicly resolved.
These selections exceed the unchanged per-module floors above. Grantcheck has no local replacements;
its tests use module-local pinned fixtures. Its eight internal requirements
include the two new API edges. The wallet's two corresponding indirect API
requirements and checksums make its existing sibling replacement buildable.

<!-- module-graph-inventory: generated by `python3 .scripts/check-module-graph.py --write-doc`; do not edit -->
| Consumer manifest | Internal require edges |
| --- | ---: |
| `deploy/go.mod` | 2 |
| `experiments/agent-wallet/go.mod` | 9 |
| `experiments/chain-gateway/go.mod` | 0 |
| `experiments/grant-store/go.mod` | 5 |
| `experiments/grant-v4/chainview/go.mod` | 0 |
| `experiments/grant-v4/identity/go.mod` | 0 |
| `experiments/grant-v4/vectors/go.mod` | 2 |
| `experiments/grant-v4/wire/go.mod` | 1 |
| `experiments/grantcheck/go.mod` | 8 |
| `experiments/m5-host-smoke/go.mod` | 6 |
| `experiments/m5-rehearsal/go.mod` | 13 |
| `experiments/model-proxy/go.mod` | 3 |
| `experiments/model-proxy/service/go.mod` | 0 |
| `experiments/notary-checker/go.mod` | 0 |
| `experiments/payment-chain/go.mod` | 2 |
| `experiments/relay/go.mod` | 5 |
| `experiments/rental-booking/go.mod` | 3 |
| `experiments/rental-executor/go.mod` | 4 |
| `experiments/rental-gateway/go.mod` | 11 |
| `experiments/rental-gateway/kernelbind/go.mod` | 6 |
| `experiments/rental/go.mod` | 4 |
| `experiments/sealwatch/go.mod` | 0 |
| `experiments/signer-service/go.mod` | 7 |
| `experiments/single-use/go.mod` | 1 |
| `experiments/station-lifecycle/gatewaybind/go.mod` | 7 |
| `experiments/station-lifecycle/go.mod` | 2 |
| `experiments/station-payload/go.mod` | 8 |
| **Total: 27 manifests / 21 consumers** | **109** |
<!-- /module-graph-inventory -->

## Qualification boundary

The published-consumer CI harness creates one fresh module per entry point
outside the checkout, with no replacements or workspace: the actual
configguard, payloadbootstrap and modelprofile APIs of `single-use`, the
`deploy` package, the `agent-wallet/g1bench` API, and the
`station-lifecycle/cmd/station-manager` command (as a
`tool` directive). Separate modules matter: one shared consumer would let
minimal version selection take the highest `single-use` and hide a stale edge.
It resolves each requested full commit through the public Go proxy and checks the
returned origin SHA. It warms the explicit transitive requirement metadata
closure, with unchanged consumer manifests, then downloads exactly the declared
graph online with checksum verification. It resolves imports, vets and builds with GOPROXY=off and
readonly module metadata, so an online `@latest` lookup cannot mask a missing
package. The historical base `288d63e` must fail specifically at the missing
ValidateJSON API; the historical head `b516cc2` must fail for both `deploy` and
`station-manager` with `cannot find module providing package
.../single-use/configguard`. Setup errors are not accepted as negative witnesses.
The candidate must pass every case. CI preserves exact versions, selected graphs,
source, commands, PIDs, exits and logs.

The inventory check covers every internal require edge; the external compile
fixtures qualify these four public entry points and the bounded rental
pre-parse regression. They do not claim that every
other exported module/package or downstream slotd runtime was independently
executed. Existing repository checks remain required. Future cross-module API
changes must refresh affected requirements to an API-containing source, advance
the main-provenance floors in `module-graph-snapshot.json` once that source is
on main, and extend consumer fixtures where public contracts change. A same-PR
source checkpoint must be distinguished from the already-landed floor, as below.

The envelope admission bench adds the first wallet consumer edge to `grantcheck`
and its two gateway dependencies. The previously unconsumed `grantcheck` module
now follows the shared strict-parser snapshot floor above.

The bench calls the transport-neutral grantcheck API and terms-v2 rental
API. Its wallet manifest pins both to `e70a35a41dec`, which contains those APIs
and the strict-parser change. The external `grant-bench` consumer at `1b3c321`
is the known stale-API negative: resolve succeeds, but vet/build must fail with
missing terms-v2 or transport API symbols. The candidate must resolve, vet and
build offline without replacements.

`TestPublishedRentalRejectsBeforeLibraryParse` adds a runtime regression in a
fresh external wallet consumer. It resolves the real bench and rental APIs
through `https://proxy.golang.org`, with no replace directives or workspace,
then vendors the verified graph. Only the vendored library's parser entry is
instrumented to signal `s >= n`; all application bytes are unchanged. The test
requires `s = n` to be refused before reaching that entry through public
`rental.VerifySignature`, the certificate verifier. Official high-s vector 1
must still verify, and a direct library call calibrates the sentinel. All three
checks run with `-race`. The historical wallet at `27d39435` must select rental
`3baa201b` and fail the named regression with
`PUBLISHED_RENTAL_STRICT_GATE_MISSING: NONCANONICAL_REACHED_LIB_PARSER`;
both controls must pass. The candidate must pass the same regression and
controls. This detects loss of pre-parse refusal, not a demonstrated forgery:
the old uninstrumented verifier also rejects this signature mathematically.

## Shared BIP-340 parser placement

`single-use/bip340` holds the strict signature encoding parser. Every current
BIP-340 verification module already depends on `single-use`, so this placement
adds no internal require edge and no new dependency cycle. The subpackage
depends only on the existing `btcec/v2 v2.3.5` library; it imports no parent
`single-use` package or higher-level grant, gateway or wallet package. The
module graph inventory remains unchanged.

## Gateway service edge: same-PR API checkpoint and landed ancestry floor

The only new edge is `model-proxy` to its separable `service` module. The
command is its sole importing package; service imports no other experiment.
The requirement now selects signed source checkpoint
`v0.0.0-20261119121123-b44b4ce81f49` from this PR. That commit contains
`Gateway`, `Placeholder` and the generation-metering source contract used by the
command, including the literal-marker adapter change. The service tree is not
byte-identical to PR #159. This follows the branch-local signed-checkpoint
pattern recorded by `d760513`, rather than claiming unreleased APIs exist in an
older landed module. Publication of the checkpoint remains part of PR delivery.

The recorded semantic-version ancestry floor remains the genuinely landed
`v0.0.0-20261119004354-f239a7e42695` from PR #159. Its explicit
`module_provenance` records main commit
`f239a7e426950b2f4965ea2b8c326a4d35cc8333` and UTC time `20261119004354`.
This is a lower ancestry bound, not an assertion that its APIs build the new
command. The current require is above that floor. The unchanged checker requires
floor provenance on `origin/main`, so an unlanded checkpoint must not be labeled
landed or substituted into that provenance. Advance the floor after the source
checkpoint lands. No checker is changed or bypassed.

CI drops all three parent replacements and builds the command against its exact
required service version. A separate negative substitutes the former landed
floor with no service replacement and must fail specifically at the missing
intake APIs. Before publication, the same positive can be checked by resolving
the signed commit from the local Git source; that is source-snapshot evidence,
not a claim that the public proxy or remote PR checks have passed.
The `replace .../service => ./service` is retained consistently with the
parent module's existing local internal replacements. The inventory remains
27 manifests, 21 consumers and 109 internal require edges. All pre-existing
floors and provenance are unchanged.
