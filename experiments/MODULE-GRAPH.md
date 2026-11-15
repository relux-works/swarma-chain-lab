# Published module graph audit

The current floor is signed manifest-selection source `2332f74636d435e5086bbc4f23cc2d5f7b2ad0d8`, published at
`20261115072539`. All 101 internal requirements select this ancestry-verified snapshot.
It contains signed identity-expiry source
`8f2786b2c6ac773b2bfa67bac7680c52e72fa885` and selects that source in its own
manifests. This two-layer refresh preserves typed RPC application errors and
named expired-identity refusals through published transitive dependencies.
No third-party requirement or local replacement changes.

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

The current inventory covers all 21 `go.mod` files and all 101 internal require edges.
The initial audit covered 20 manifests across 19 consumer modules at base
`288d63e191fefac885d6a39aa65f0a5fbb6ed7ee`.
Every edge previously named `v0.1.0`; directory replacements supplied current
source during repository tests. That does not establish published compatibility.
A concrete external consumer of `single-use/configguard` fails because
`single-use/policy.go` calls `sealwatch.ValidateJSON`, absent from `sealwatch v0.1.0`.
The new bootstrap/model packages are also absent from `single-use v0.1.0`.

All 101 internal require edges, in standalone `require` lines, `require (...)`
blocks and `// indirect` entries alike, now select versions at or above the
published source snapshot. The first revision of this audit counted 96: it missed the two
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

| Dependency under experiments/ | Published requirement |
| --- | --- |
| `grant-store` | `v0.1.1-0.20261115072539-2332f74636d4` |
| `m5-host-smoke` | `v0.3.1-0.20261115072539-2332f74636d4` |
| `model-proxy` | `v0.4.1-0.20261115072539-2332f74636d4` |
| `payment-chain` | `v0.2.1-0.20261115072539-2332f74636d4` |
| `rental` | `v0.5.1-0.20261115072539-2332f74636d4` |
| `rental-booking` | `v0.4.1-0.20261115072539-2332f74636d4` |
| `rental-gateway` | `v0.4.1-0.20261115072539-2332f74636d4` |
| `rental-gateway/kernelbind` | `v0.1.1-0.20261115072539-2332f74636d4` |
| `sealwatch` | `v0.2.1-0.20261115072539-2332f74636d4` |
| `signer-service` | `v0.3.1-0.20261115072539-2332f74636d4` |
| `single-use` | `v0.3.1-0.20261115072539-2332f74636d4` |
| `station-lifecycle` | `v0.2.1-0.20261115072539-2332f74636d4` |
| `station-lifecycle/gatewaybind` | `v0.1.1-0.20261115072539-2332f74636d4` |
| `station-payload` | `v0.3.1-0.20261115072539-2332f74636d4` |
| `grantcheck` | `v0.1.2-0.20261115072539-2332f74636d4` |

The inventory below is generated and checked by
`python3 .scripts/check-module-graph.py`, which parses every `go.mod` with
`go mod edit -json` (never a line filter) and fails when any internal require
edge is older than its floor in
[`module-graph-snapshot.json`](module-graph-snapshot.json). Regenerate both with
`python3 .scripts/check-module-graph.py --snapshot-commit FULL_PUBLISHED_SHA --write-doc`.
The generator queries canonical versions through the public proxy and verifies
all origin SHAs before writing the snapshot; a failed resolution leaves it intact.

The separate `grant-v4/wire` module has no internal require edges or local
replacements. It does not import any earlier grant module.

<!-- module-graph-inventory: generated by `python3 .scripts/check-module-graph.py --write-doc`; do not edit -->
| Consumer manifest | Internal require edges |
| --- | ---: |
| `deploy/go.mod` | 2 |
| `experiments/agent-wallet/go.mod` | 7 |
| `experiments/grant-store/go.mod` | 5 |
| `experiments/grant-v4/wire/go.mod` | 0 |
| `experiments/grantcheck/go.mod` | 6 |
| `experiments/m5-host-smoke/go.mod` | 6 |
| `experiments/m5-rehearsal/go.mod` | 13 |
| `experiments/model-proxy/go.mod` | 2 |
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
| **Total: 21 manifests / 19 consumers** | **101** |
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
changes must refresh the affected published requirements, raise the floors in
`module-graph-snapshot.json`, and extend consumer fixtures where their public
contracts change.

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
