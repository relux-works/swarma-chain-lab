# Published module graph audit

The audit covers all 20 `go.mod` files and all 96 internal require edges across
19 consumer modules at base `288d63e191fefac885d6a39aa65f0a5fbb6ed7ee`.
Every edge previously named `v0.1.0`; directory replacements supplied current
source during repository tests. That does not establish published compatibility.
A concrete external consumer of `single-use/configguard` fails because
`single-use/policy.go` calls `sealwatch.ValidateJSON`, absent from `sealwatch v0.1.0`.
The new bootstrap/model packages are also absent from `single-use v0.1.0`.

All declared internal edges now select the same already-published base snapshot.
This avoids mixing current consumer source with stale sibling APIs. It is a
coherent snapshot refresh, not a claim that all 96 old edges individually fail.
No third-party requirement, product source, or local replacement changes.
All 14 dependency module ZIPs (624 files including inherited licenses) were
compared byte-for-byte with that signed source; Go 1.26.10 downloaded them with
normal checksum verification. The earlier default Go 1.25.14 metadata command
refused the Go 1.26 requirement; its failure was retained, not treated as a pass.

| Dependency under experiments/ | Published requirement |
| --- | --- |
| `grant-store` | `v0.1.1-0.20261111181054-288d63e191fe` |
| `m5-host-smoke` | `v0.3.1-0.20261111181054-288d63e191fe` |
| `model-proxy` | `v0.4.1-0.20261111181054-288d63e191fe` |
| `payment-chain` | `v0.2.1-0.20261111181054-288d63e191fe` |
| `rental` | `v0.5.1-0.20261111181054-288d63e191fe` |
| `rental-booking` | `v0.4.1-0.20261111181054-288d63e191fe` |
| `rental-gateway` | `v0.4.1-0.20261111181054-288d63e191fe` |
| `rental-gateway/kernelbind` | `v0.1.1-0.20261111181054-288d63e191fe` |
| `sealwatch` | `v0.2.1-0.20261111181054-288d63e191fe` |
| `signer-service` | `v0.3.1-0.20261111181054-288d63e191fe` |
| `single-use` | `v0.3.1-0.20261111181054-288d63e191fe` |
| `station-lifecycle` | `v0.2.1-0.20261111181054-288d63e191fe` |
| `station-lifecycle/gatewaybind` | `v0.1.1-0.20261111181054-288d63e191fe` |
| `station-payload` | `v0.3.1-0.20261111181054-288d63e191fe` |

| Consumer manifest | Internal edges audited/refreshed |
| --- | ---: |
| `deploy/go.mod` | 1 |
| `experiments/agent-wallet/go.mod` | 4 |
| `experiments/grant-store/go.mod` | 5 |
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
| `experiments/station-lifecycle/go.mod` | 1 |
| `experiments/station-payload/go.mod` | 8 |

## Qualification boundary

The published-consumer CI harness uses a fresh module outside the checkout,
with no replacements or workspace, importing the actual configguard,
payloadbootstrap and modelprofile APIs. It resolves each requested full commit
through the public Go proxy and checks the returned origin SHA. After populating
the checksummed cache, both vet and build run with GOPROXY=off and readonly module
metadata. The historical base must fail specifically at the missing ValidateJSON
API; setup errors are not accepted as the negative witness. The candidate must
pass both commands. CI preserves exact versions, selected graphs, source,
commands, PIDs, exits and logs.

The source audit covers every internal require edge; the external compile
fixture qualifies these three public single-use package surfaces. It does not
claim that every other exported module/package or downstream slotd runtime was
independently executed. Existing repository checks remain required. Future
cross-module API changes must refresh the affected published requirements and
extend consumer fixtures where their public contracts change.
