# DK1-01 deployment survey

Survey base: `5f148fb965e6ed58995e862c34e3bc6ab0577866`, the landed E1 main.
Scope is release preparation only: no product changes, host installation,
deployment, mainnet transaction, or credential creation. The root `deploy/`
directory groups cross-module release tooling, configuration/unit templates and
the Infra handoff; these artifacts are not another experimental service.

The operator-approved layout is `/opt/swarma/<service>/<version>/bin`, config
under `/etc/swarma/<service>/`, state under `/var/lib/swarma-<service>/`.
All target VMs are linux/amd64. NMC regtest on the public and signer hosts uses user `nmc`, unit
`namecoind-regtest`, datadir `/var/lib/namecoind-regtest`, loopback RPC18443,
and no P2P listener. This kit does not create or alter that node.

## Landed binaries and actual readiness

| Artifact | Module/package | CLI and runtime | Deployment status |
| --- | --- | --- | --- |
| `gateway` | `experiments/rental-gateway`, `./cmd/gateway` | `serve -key FILE -journal DIR -relay URL -station-unix PATH -stations-root DIR`; optional `-slot-file`, `-stub-agent`, `-stub-verdict`; also `keygen` and `station-stub` | Buildable local demo only. `serve` constructs kernel.Stub, screen.Stub and LocalTestDriver; E1/real K1 are library wiring, not this executable. |
| `rental-booking` | `experiments/rental-booking`, `./cmd/rental-booking` | `-config FILE -profile FILE -provider-key FILE -route FILE -listen 127.0.0.1:18819 -relay ws://127.0.0.1:18818 -poll 2s` | Real regtest NMC v1 contract/payment HTTP service. P1 v2 is not in this base. |
| `grant-store` | `experiments/grant-store`, `./cmd/grant-store` | `serve -config FILE -listen 127.0.0.1:8091`; separate client verbs put/get/delete/list | Real loopback S1 server; no server signing key or node access. |
| `rental-relay` | `experiments/rental-booking`, `./cmd/rental-relay` | `-listen 127.0.0.1:18818 -state DIR` | Existing bounded local test relay. Surveyed as a booking dependency; not one of the three requested release artifacts. Infra may provide its existing relay. |

All three requested binaries were built locally with Go1.26.8 and their help
output was captured under the task's `.temp/DK1-01/` evidence. Help requests
are read-only; gateway/store report flag-help as an error after listing flags.
No service, messaging key, listener or host-side process was started.

## Runtime inputs

Booking requires a private0700 ledger, provider signing key in a0600 hex file,
public branch plus hash, agent/provider public keys, profile/template hashes and
scope, current rate/age limits, calendar slots, and bounded watcher limits. Its
CLI currently consumes the v1 `booking.Config` and uses a loopback relay.
`GET /` can establish HTTP availability without creating a booking; it does not
prove the watcher or node is healthy. There is no `/health` endpoint.

Booking's `-route` is `singleuse.OperatorRoute`: explicit regtest network/genesis,
absolute pinned `NodeCLI` plus `NodeCLISHA256`, `NodeConfig` and `NodeDataDir`.
The adapter executes that CLI with `-conf`, `-datadir`, `-chain=regtest` and an
exact read-method allowlist. It never opens the private config itself or accepts
credentials in argv. Infra's0400 service-owned RPC config can therefore remain
under `/var/lib/swarma-booking/rpc/`; the pinned CLI reads it. The route must point
at a service-owned client datadir, not grant booking access to the node wallet.
The native CLI path/hash and the RPC config file provisioned by Infra are required
inputs, not guessed release values. NodeConfig pins the loopback18443 endpoint.

S1 config has root, public_url, writer public keys and storage/replay limits.
Its server root must already be private0700. It does not need RPC or a private
writer key; clients retain their own signing keys. A bounded unsigned GET for a
well-formed absent hash must refuse401, which probes the running authorization
path without disclosing existence or consuming authorized replay capacity.
An OPTIONS204 alone is insufficient as an operational-readiness assertion.

Gateway requires an agent messaging key and a relay, journal and station socket
for its local demo, but has no flags to supply a verifier node, real kernel,
booking/exchange engine or production station driver. A template cannot add
those absent code paths. Its default stub verdict is live, making a normal
service template particularly misleading. No runnable M5 gateway unit should
be presented as ready on this base.

## Proposed implementation after survey handoff

Use a separate Go module in `deploy/`, with a stdlib release command that accepts
an exact clean repository commit. Extract that commit twice into separate work
directories, build each requested package with linux/amd64, CGO0, trimpath and
buildvcs=false, compare bytes and fail before publishing a release if different.
Record commit, exact Go version, module/package, artifact and SHA256 in the
manifest. Keep signing outside the program; document operator
`ssh-keygen -Y sign -n swarma-release` over SHA256SUMS. No host builds.

Use native service JSON templates, with comments/explanations in adjacent docs
(the native parsers reject JSON comments and unknown fields). A separate deploy
descriptor records network and public installation policy. Validate bounded
inputs and unresolved placeholders before accepting a regtest preparation;
mainnet must never gain acceptance merely because a placeholder was replaced.
Do not read, print or copy RPC/key contents in the validator. Final native
service startup still validates its own complete runtime configuration.

Booking and store units can use their actual flags, own OS users, strict system
protection, NoNewPrivileges, PrivateTmp, MemoryMax and only their service state
as writable storage. SG1, a2a daemon (a2ad)/CG1 and Nostr transport get pending manifest
rows only, with no guessed executables or templates.

## Decision required: gateway runtime gap

The request calls for gateway with E1 and a service unit, while forbidding product
code changes. Those cannot both be operational on the landed CLI. Recommended
resolution: include the reproducible gateway binary as `demo_only`, mark its M5
runtime/unit blocked pending a separately tracked real serve entrypoint, and
deliver runnable templates only for booking/store. An explicitly non-startable
gateway reference template is possible if desired, but is not a service smoke
pass. Adding real serve wiring belongs to a separately authorized product task.

This decision does not block the reproducible builder or booking/store preparation.

## Verification availability

The host is macOS. Docker, Podman, Colima and systemd-analyze are unavailable.
Lima2.2.0 is installed but reports no VM instances. `systemd-analyze verify`
therefore cannot currently run locally; report it as not run unless an available
authorized Linux environment is supplied. Do not claim static text checks prove
systemd compatibility or create a host/VM deployment as a side effect.

Required controls include byte-identical independent builds plus a bounded
nondeterminism plant, dirty-checkout refusal, mainnet/placeholder refusal beside
a complete regtest positive fixture, and no secret/home paths in templates.
The eventual smoke plan must distinguish process/HTTP availability from real
payment/grant/exchange end-to-end acceptance; gateway M5 remains blocked until
real runtime wiring exists.

## Source anchors

- `experiments/rental-gateway/cmd/gateway/{main,serve}.go` and README: stub CLI,
  actual flags and separately landed E1 library wiring.
- `experiments/rental-booking/cmd/rental-booking/main.go`, `service.go`,
  `contract.go`, `watcher.go`, `http.go`: flags, native config and HTTP semantics.
- `experiments/single-use/operator_route.go`: pinned CLI/file-reference boundary.
- `experiments/grant-store/cmd/grant-store/main.go`, `store.go`, `http.go`: S1
  configuration, loopback listen, shutdown and signed access requirements.
- The deployment preparation note and request fix the host/users/layout;
  this survey does not read actual deployment credentials or private configs.
