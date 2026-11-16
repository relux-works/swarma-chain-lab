# Swarma Chain Lab

**LAB — experimental research, not production software.**

This repository contains bounded blockchain experiments. A passing experiment
supports only its stated assumptions and checks; it does not qualify a production
service, grant format, wallet, consensus implementation or deployment.

Experiments live in `experiments/<name>/`:

- [Grant v4 identity checks](experiments/grant-v4/identity/README.md): experimental
  owner pins, script/writer checks, expiry, issuer/notary history verdicts,
  consent evidence and recipient union from LIP-0021 Draft sections 2–7 and
  LIP-0008 Draft section 3.1; all checks use stated octets, heights and facts.
- [Grant v4 wire primitives](experiments/grant-v4/wire/README.md): the proposed
  LIP-0020 canonical bytes, typed hashes, strict signatures and defined objects;
  all 205 pinned vectors, with no chain reads or whole-grant admission.

- [Grant v4 observation decisions](experiments/grant-v4/chainview/README.md):
  LIP-0022 Draft sections 1–6 comparisons, durable first sightings and clock
  marks, all 97 pinned vectors and an independent second reader; stated inputs
  only, with no production thresholds or node-read qualification.

- [Rental Nostr relay](experiments/relay/README.md): bounded durable gift-wrap,
  consent and package transport, NIP-42, relay-side IP limits and deployment
  templates; AUTH client integration remains a separate follow-up.

- [Mutual full-node grants](experiments/fullnode-trusts/README.md): closed-regtest
  mutual grants and ownership-lineage controls, plus finite T1/T1b collector
  source pending independent review and separate runtime admission.
- [Notary comparison](experiments/notary/README.md): synthetic notary authority,
  named-output lineage, seal liveness and observation consistency checks.
- [UTXO creation-age analysis](experiments/utxo-age/README.md): a bounded
  Namecoin snapshot-v2 decoder, synthetic fixtures and an optional offline
  native serialization reference. Real-chain measurements remain unavailable
  pending the validated-chain evidence adapter and separate authorization.
  Pinned native reference materials retain the upstream license reproduced
  in the experiment's `COPYING.namecoin`.
- [Namecoin Electrum laboratory](experiments/namecoin-electrum-local/README.md):
  pinned server preparation and a closed regtest research harness. The retained
  Part A evidence applies to its original runtime source; the checkpoint-height
  correction has offline replay evidence only. This composition requires fresh
  independent review and does not qualify a new runtime or Part B.

The notary experiment includes Python standard-library-only offline controls.
Run these only in an offline namespace with read-only source and tools, an empty
home view, and private writable HOME, TMPDIR and cache directories. No node,
wallet, live chain data, signing key or network download is required for those
controls. See the experiment README for commands and limitations.

Historical runtime helpers retain their expired admission cutoff. This source
publication supplies no operational receipts, node binaries, wallets or runtime
state. A new runtime experiment requires its own admitted isolation and bounds.

Licensed under [Apache-2.0](LICENSE); see [NOTICE](NOTICE) and experiment notices.

See the [signature-bearing identifier audit](docs/signature-identities.md) for
exact-byte identities, independent replay bindings and signature-variant tests.

The automatic rental checks enforce the detached-v2 observer-local ID audit
with `python3 -B .scripts/check-detached-v2-consumers.py` and detector controls
via `python3 -B -m unittest discover -s .scripts -p 'test_check_detached_v2_consumers.py' -v`.
The reviewed file hashes and locality reasons live in
`.scripts/detached-v2-consumers.json`; changed consumers require a fresh audit.
Only Go's `*_test.go` files are excluded by name (`go help test`); Git's
root `.git` entry is repository metadata. No other suffix, directory (including
`testdata`, `vendor`, hidden or scratch directories), build tag or detector-tool
path is excluded. The guard scans bytes conservatively, including documentation
and its own tools, so it also covers extensionless consumers. Run it on a clean
source tree and keep generated code/caches outside that checked tree.
Python collection uses `unittest discover -p 'test_*.py'` in the directories
selected by `.github/scripts/offline-checks.sh`, and explicit test files in other
workflow steps; `.github/CI.md` documents the offline selection. Collection does
not prevent production imports or execution, so no Python file is excluded.
Output goes to stdout; retain validation logs outside the checked source tree.

The wallet Core-test inventory is `.scripts/w2-core-gate.json`. Run
`python3 -B -m unittest discover -s .scripts -p 'test_check_px1_core_gate.py' -v`
to check that every Core-fixture test is registered and that missing, skipped
or failing evidence is refused. The controls write to stdout; local logs and
Go JSON evidence belong under `.temp/`.

## Public repository hygiene tools

Run `python3 -B .github/scripts/check-public-hygiene.py` from the repository root
to reject Matrix IDs outside the exact example-domain allowlist. The guard
scans Git-tracked filenames and contents, including common URL/JSON/HTML escapes
and dot obfuscations; stage new files before checking. Diagnostics go to the
terminal without printing the identifier. It does not scan history or detect
all secrets, arbitrary encodings or private names on example domains.
Run `python3 -B -m unittest discover -s .github/scripts -p 'test_public_hygiene.py' -v`
for paired examples, rejection controls and an isolated tracked-file plant.
The `public-hygiene` CI job runs both on every pull request and main push.
Any saved local logs belong in `.temp/`. Historical Git objects are unchanged;
replacing a current-tree identifier does not erase its publication history.

## Single-use grant tools

[Single-use grants](experiments/single-use/README.md) provides a Go
executor with explicit network pins, genuine Core controls and an offline mainnet JSON planner. From
`experiments/single-use`, run `go test -race ./...`,
`go build -trimpath -o .temp/single-use ./cmd/single-use` and
`go build -trimpath -o .temp/single-use-plan ./cmd/single-use-plan`.
The experiment README lists opt-in Core harness inputs and exact CLI commands.
Build scratch belongs in `.temp/`; admitted harness runs separate `public/`
evidence from private node/wallet state. Mainnet use requires separate review and runtime admission.
Spend discovery tolerates unrelated witness/large-input traffic while retaining
strict legacy checks for seal-spend candidates and explicit observation budgets.

## Rental booking tools

[Rental booking](experiments/rental-booking/README.md) is the bounded M3 regtest
booking/payment/contract experiment. From that module, run `go test -race ./...`,
`go build -trimpath -o ../../.temp/rental-booking ./cmd/rental-booking` and
`go build -trimpath -o ../../.temp/rental-relay ./cmd/rental-relay`.
Its README defines canonical contract/consent/issuance formats, loopback CLI
commands, pinned Core integration inputs and private/public evidence separation.
No mainnet or public deployment is authorized by the experiment.


Rental-booking M3-02 requires confirmed payments for both advance and start-now
slots. See its [operator observation-window notes](experiments/rental-booking/README.md#payments-outside-the-observation-window)
and opt-in genuine witness-payment controls. No automatic refund/sweep is added.

## Rental grant tools

[Rental certificates](experiments/rental/README.md) adds a regtest-only BIP-340
kernel, offline seal-pool planner and read-only payment/package admission gate.
From `experiments/rental`, run `go test -race ./...`,
`go build -trimpath -o .temp/rental-kernel ./cmd/rental-kernel` and
`go build -trimpath -o .temp/rental-plan ./cmd/rental-plan`. Its README documents
separate opt-in Core runs, private state, public evidence and remaining M4/M5
integration. Shared storage and fee primitives remain used by single-use too.

The rehearsal-only standing grant helper is built from the same pinned head
with `go build -trimpath -o .temp/rt-grant-fixture ./cmd/rt-grant-fixture`
from `experiments/rental`. It is excluded from signed releases; Infra records
its SHA-256 separately. Its strict regtest/loopback refusals, private output
files, required flags and Core test command are documented in the
[rental fixture tool contract](experiments/rental/README.md#rehearsal-only-standing-grant-fixture).

## Rental executor and contest endpoints

[Rental executor](experiments/rental-executor/README.md) adds strict renter-signed
requests, fresh M1 checks, durable nonce/budget reservations, explicit regtest
budget payments and separate Track B admin/claim sockets. It requires pinned M1
63087f31 or its integrated sibling modules. From its module run
`go test -race ./...`, `go vet ./...` and
`go build -trimpath -o ../../.temp/rental-executor ./cmd/rental-executor`.
See its README for exact Core/control environment and private/public artifacts.

## Agent wallet and Curator skill draft

[Agent wallet](experiments/agent-wallet/README.md) now provides the W2 signing
socket client and `agent-walletd` with a separate service user. See its
[LIP-0006 profile](experiments/agent-wallet/SERVICE.md) for spend/reads/budget,
signed receipts, peer checks and durable recovery. The old W1 same-user CLI and
two-stage name registration remain only in `agent-wallet-legacy`.
From `experiments/agent-wallet`, run `go test -race ./...`, `go vet ./...` and
`go build -trimpath -o ../../.temp/agent-wallet ./cmd/agent-wallet`; build the
daemon with `go build -trimpath -o ../../.temp/agent-walletd ./cmd/agent-walletd`.
Its README lists exact Core/guard controls, bounded RPC routes and private/public
artifact separation. The [skill draft](skills/namecoin-wallet/SKILL.md) requires
Curator deployment to pin paths; it makes no sandbox or custody guarantee.

## Rental gateway tools

[Rental gateway](experiments/rental-gateway/README.md) routes authenticated NIP-17
messages to separate renter stations after fresh K1 v3 grant checks. Its nested
`kernelbind` module uses the in-tree rental kernel, landlord/agent policy pins
and stable signed-grant IDs. From each module run `GOWORK=off go vet ./...` and
`GOWORK=off go test -race ./...`; build the configured CLI from the gateway module with
`go build -trimpath -o .temp/gateway ./cmd/gateway`. The module README documents
the opt-in issuer-driven Core regtest test, private/public output boundaries
and required tool paths. Scratch builds and logs belong in `.temp/`.

## Grant store tools

[Grant store](experiments/grant-store/README.md) provides a bounded Blossom HTTP
store with mandatory signed uploads/downloads and per-blob readers. From
`experiments/grant-store`, run `go test -race -count=1 ./...`,
`go build -trimpath -o ../../.temp/grant-store ./cmd/grant-store`, and
`go run .scripts/guard-controls.go -out .temp/guards`.
The module README documents loopback CLI configuration, limits, grant helpers,
replay/ACL persistence, and the scope of the local checks. Build and guard
artifacts stay in `.temp/`; private state/key files are never delivery artifacts.

## Multi-coin booking payments (P1 laboratory)

`experiments/payment-chain` defines closed BTC/LTC/NMC regtest profiles,
watch-only derivation, frozen USD quotes and bounded independent payment reads.
`rental-booking.ServiceV2` owns one durable calendar with per-coin indices;
`rental.IssueGrantWithNodes` authenticates v2 signed bytes and checks payment on
separate issuer routes before the existing grant burns/signatures. NMC execution
budget and Namecoin grant authority remain separate from the fee currency.

Run `GOWORK=off go test -race ./...` and `go vet ./...` in payment-chain,
rental-booking and rental. The genuine-node TestCorePaymentLifecycle entrypoint,
pinned binary inputs, private/public output separation and supported replacement
limits are documented in the rental and payment-chain READMEs. Existing v1 CLI
entrypoints and frozen wire regressions remain available. The booking CLI also
serves ServiceV2 through an explicit versioned config; see its
[HTTP configuration](experiments/rental-booking/README.md#config-selected-servicev2-http).
The gateway exchange uses typed V2 HTTP with an explicit offered coin and frozen
payment terms; legacy V1 is confined to test mode. See the
[gateway V2 binding](experiments/rental-gateway/README.md#v2-booking-exchange-g6).

### SG1 landlord signer service

[`experiments/signer-service`](experiments/signer-service/README.md) adds the
explicitly network-pinned landlord custody loop: immutable outbox pull, genuine K1/P1 grant
issuance and L5 commitment broadcast, sticky/operator seal revocation and
funding-only pool refill. It persists reservations, caps, signed transaction
bytes and S1 upload receipts; uncertain signing refuses recovery by re-signing.
Booking ServiceV2 emits its exact indexed intake. An optional signer publisher
writes canonical booking-ID presentations after active-chain confirmation; the
gateway's shared directory reader consumes those bytes. The V2 exchange-to-SG1
path is exercised on isolated genuine Core; cross-host transport remains
separate provisioning work.
The module README documents private configuration, Go CLI/build/test commands,
three-chain Core fixtures and guard controls. Local evidence belongs under
`.temp/` or an explicitly configured isolated run root; no mainnet/deployment
or executor authority is included. CI runs Go vet/race/build and non-Core guards.

## Release preparation

[DK1 deploy kit](deploy/README.md) builds the existing service binaries and the
deploy-kit tool twice from a clean exact commit into an unsigned linux/amd64
bundle, with manifest and SHA256SUMS. Its required per-binary `linkage` evidence
checks embedded internal module selections against the pinned strict signature
parse commit by Git ancestry before any release layout is written. From `deploy/`, run `go test -race ./...`, `go vet ./...` and
`go run ./cmd/deploy-kit build -repo "$SOURCE_ROOT" -commit "$REVIEWED_COMMIT" -out "$RELEASE_DIR"`.
Its public validator, gateway/booking/store unit templates and Infra smoke plan
are documented there. Gateway uses real grant/exchange/manager wiring with
screening off; operator payload and Linux host acceptance remain required.
The [M5 test config](deploy/templates/m5-test/README.md) explicitly selects
NMC main for v3 grants, v2 payments and W2 spend/reads, with configured movement,
exposure and model caps. BTC/LTC main and legacy/name executors refuse.
No host deployment or mainnet action is part of this tooling. Release outputs
use a new directory outside the source checkout; task logs stay in `.temp/`.
The [G2 attempt ledger](deploy/G2-LEDGER.md) requires explicit declarations for
every pre-existing entry parent, including unit-link directories. Station
retained children receive a named parent allowance only for their exact ledger
identities; rehearsal restores the baseline entry set. From `deploy/`, validate
this contract with `go test -race ./g2ledger ./cmd/deploy-kit`.

## Demo station lifecycle tools

[Station lifecycle](experiments/station-lifecycle/README.md) is a relay-independent
manager/broker and typed client of the Infra-owned slotd helper, with a separate
rental-gateway adapter module. From `experiments/station-lifecycle`, run
`go test -race ./...`, `go build -o .temp/station-manager ./cmd/station-manager`,
`go run .scripts/guards.go -out .temp/guards` and
`(cd gatewaybind && go test -race ./...)`. The README documents private input
configuration and external Linux/payload validation; local test/build evidence
belongs in `.temp/`. No host deployment is performed by these commands.


## Per-slot model proxy tools

[Model proxy](experiments/model-proxy/README.md) adds an independent, bounded
text Messages and optional function-tool Responses profiles with private per-slot bearers, conservative durable caps,
SSE usage accounting and Linux peer-checked local administration. The optional
station-lifecycle/gatewaybind registrar prepares bootstrap v2, activates before
Start and revokes independently of Stop. Runtime and deployment remain external
decisions. From `experiments/model-proxy`, run `go test -race ./...`,
`go build -o .temp/model-proxy ./cmd/model-proxy`, and
`go run .scripts/guards.go -out .temp/guards`; logs/binaries stay in `.temp/`.
Tests use only a local fake upstream and synthetic keys.

### Scripted station payload

[station-payload](experiments/station-payload/README.md) consumes canonical v1/v2
private bootstrap, retains scripted station controls and exercises the per-slot
model proxy using operator-pinned Messages or text-only Responses over verified,
leaf-pinned TLS. Run its Go tests, guard controls and
CLI using the commands in that module; artifacts belong under `.temp/`. It is a
rehearsal fixture, not a selected rented-agent runtime or host deployment.

### Relay liveness and reconnect controls

The gateway keeps expiry running during relay transport outages, re-authenticates
on reconnect, and pages NIP01 history with a NIP59-aware overlap. Equal-timestamp
or bounded replay exhaustion reports `REPLAY_OVERFLOW` while live traffic
continues. Capacity/retention and explicit closer limits are documented in
`experiments/relay/README.md` and `experiments/rental-gateway/README.md`.
Run `go -C experiments/relay test -race ./...` and
`go -C experiments/rental-gateway test -race ./...`; the Go control runner
`go -C experiments/relay run .scripts/rk1-guards.go` writes evidence under
`experiments/relay/.temp/rk1-guards/` and mutates copied sources only.

### Full composition rehearsal

[m5-host-smoke](experiments/m5-host-smoke/README.md) drives installed services as an external client with explicit operator receipt handoffs. Its fixed host profile and [runbook delta](experiments/m5-host-smoke/HOST_SMOKE.md) preserve M5C gates; Darwin runner self-tests do not qualify Linux hosts. Build/test commands and sealed packet locations are documented in the module README.

[m5-rehearsal](experiments/m5-rehearsal/README.md) passed both full genuine-Core
NMC expiry and native-SG1 seal-revocation scenarios on product `14e35bbc`, through
V2 exchange, real relay, manager and scripted model payload. The approved macOS
helper/admin substitutions remain rehearsal-only; these results do not qualify
Linux isolation, physical wipe or a paid external model.
Use the module's opt-in Go commands for release-isolation controls and fresh
Core runs; public receipts stay separate from private fixture trees. A build or
preparation result is not evidence that the full runtime scenario passed.

The [startup ordering gap](experiments/m5-rehearsal/GAP-IT2-STARTUP.md) records
historical failures. SR1 fixed startup admission; RK1 fixed relay liveness and
expiry across transport loss. The current witness checks admission during an
active Starting attempt, including rejection of an incorrect credential.

## Grantcheck admission policy

[Grantcheck](experiments/grantcheck/POLICY.md) requires the consumer's own
executor key, a canonical terms resolver, and explicit A/F/FLOOR configuration.
It checks headers equal to blocks, minimum height, maximum tip age and future
skew for every admission and cached send. `Checker.Provision` protects manual
first-message proof bootstrap with the same full checks and durable auditing.
The envelope bench delegates these shared checks to grantcheck.
Aggregate sends stage all checker state under one transaction and persist once
after the final sample; refusals preserve the durable checker file. The
`TestCoreAggregateFinalDecisionAtomic` Core witness and policy overlays cover
the no-write-on-final-refusal guarantee.

The HIDDEN age of an admitted view is at most A + F (not A).
`trusted_now` is the consumer's `Config.Now` trusted clock input, using the
consumer's system clock if omitted, never the node's own time. A/F/FLOOR have
no defaults; missing or invalid policy and missing executor pins refuse
construction. This is an INTERIM rule for the v3 TEST BENCH, superseded by
LIP-0022 once accepted. Production values are NOT set here and need a runtime
probe on a real Namecoin node before any non-bench use. Exact test values and
named Core witnesses are listed in the policy document.

Policy tools from the repository root: `python3 -B .scripts/grantcheck-policy-guards.py
--out .temp/policy-guards --private-root <fresh-absolute-regtest-parent>` runs sixteen
Go-overlay controls and writes hashes/exits/logs there. The existing
`python3 -B .scripts/check-px1-core-gate.py check --manifest
.scripts/grantcheck-policy-core-gate.json <go-test-json>` checks the Core witness
stream. Both use the commands and pinned Core setup documented in
[grantcheck's tools section](experiments/grantcheck/POLICY.md#validation-and-controls).

## Go modules and releases

The 19 modules use `github.com/relux-works/swarma-chain-lab/<directory>` paths.
Each sibling requirement is `v0.1.0`. Relative directory `replace` directives
are for builds inside this repository: Go ignores a dependency module's replaces
when another module imports it. External consumers require the published module
versions, without their own replaces or a workspace. There is no root Go module
or committed workspace; use Go 1.26.8 and `GOWORK=off` from each module directory.
The pinned `experiments/namecoin-mail-source/pins/ncdns.go.mod` is third-party
input and is not a module maintained by this repository.

For example, from the repository root:

```sh
GOWORK=off go -C experiments/grantcheck mod download
GOWORK=off go -C experiments/grantcheck mod verify
GOWORK=off go -C experiments/grantcheck vet ./...
GOWORK=off go -C experiments/grantcheck test -race -count=1 ./...
GOWORK=off go -C experiments/rental-gateway/kernelbind test -race -count=1 ./...
```

Existing module guard scripts use copied modules and the same relative sibling
layout, so mutations exercise those copies. Deployment uses two independent
source archives with separate build caches. Import-path changes alter binary
hashes through Go package names and build metadata; build a new release manifest
and use its payload pins. Matching two builds of the new source and rejecting the
rehearsal overlay remain required; old binary hashes are not expected to survive
a module-path migration. See [deploy](deploy/README.md) and the
[rehearsal release-isolation check](experiments/m5-rehearsal/README.md).

### Initial tag set and publication order

The release maintainer creates author-signed `<directory>/v0.1.0` tags for every
module below, all pointing to the same independently reviewed, tested and landed
commit. The module graph contains cycles, so make the complete tag set available
together; use an atomic push of the explicit tag refs where supported. Never
publish a partial set, move a published tag, or advertise external importability
before the public consumer check passes. This first v0 release is experimental
and makes no stable API promise.

- `deploy/v0.1.0`
- `experiments/agent-wallet/v0.1.0`
- `experiments/grant-store/v0.1.0`
- `experiments/grantcheck/v0.1.0`
- `experiments/m5-rehearsal/v0.1.0`
- `experiments/model-proxy/v0.1.0`
- `experiments/payment-chain/v0.1.0`
- `experiments/relay/v0.1.0`
- `experiments/rental/v0.1.0`
- `experiments/rental-booking/v0.1.0`
- `experiments/rental-executor/v0.1.0`
- `experiments/rental-gateway/v0.1.0`
- `experiments/rental-gateway/kernelbind/v0.1.0`
- `experiments/sealwatch/v0.1.0`
- `experiments/signer-service/v0.1.0`
- `experiments/single-use/v0.1.0`
- `experiments/station-lifecycle/gatewaybind/v0.1.0`
- `experiments/station-lifecycle/v0.1.0`
- `experiments/station-payload/v0.1.0`

Before publication, validate an exact candidate through a disposable local bare
mirror with signed tags, a process-local Git URL rewrite to its `file://` URL,
and a separate module cache. Do not push that mirror. The scratch consumer must
use `GOWORK=off`, have no `replace`, import both grantcheck and kernelbind, and
build from the tag graph. This proves local VCS resolution only. Delete the
mirror after retaining its candidate, tag list, signatures and check results.

Do not commit sibling ZIP or go.mod checksums produced by that scratch consumer
back into repository modules. Repository builds use directory replacements;
consumers maintain their own sums. In particular, initial same-commit cyclic
sibling ZIP sums would refer to a tree that changes when those sums are added.
Keep existing third-party checksums and versions pinned.

After landing, the maintainer publishes the complete signed tag set and repeats
the no-replace/no-workspace consumer check against the actual remote before
announcing availability. For an external scratch module after publication:

```sh
go mod init example.com/chain-consumer
GOWORK=off GOFLAGS=-mod=mod go get github.com/relux-works/swarma-chain-lab/experiments/grantcheck@v0.1.0 github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernelbind@v0.1.0
# Add a program importing both packages, then:
GOWORK=off GOFLAGS=-mod=mod go build ./...
```

For later releases, choose new versions for changed modules and update their
consumers explicitly; validate the complete selected graph before tagging.
The current cross-module requirements pin the published `e70a35a41dec` snapshot;
local directory replacements remain development conveniences. In particular,
`single-use` needs `sealwatch.ValidateJSON`, which is absent from `sealwatch v0.1.0`.
Published, immutable dependency checksums may be recorded in module sums; this
does not permit recording speculative same-commit mirror checksums described above.
See [the module graph audit](experiments/MODULE-GRAPH.md) for scope and limits.

The `Published consumer graph` workflow has two jobs. `module-graph-inventory`
runs `python3 .scripts/check-module-graph.py`: it parses every `go.mod` with
`go mod edit -json`, so standalone, block and indirect requires count alike, and
exits 1 when any internal require edge is older than its floor in
`experiments/module-graph-snapshot.json`, or when the generated inventory in
`experiments/MODULE-GRAPH.md` drifts (refresh it with `--write-doc`). Regenerate
snapshot floors and inventory together with
`python3 .scripts/check-module-graph.py --snapshot-commit FULL_PUBLISHED_SHA --write-doc`;
this resolves canonical versions through the public proxy, verifies every origin
SHA before writing, and stores the floors in the snapshot JSON. Its tests,
`python3 -m unittest discover -s .scripts -p 'test_check_module_graph.py' -v`,
hold the standalone-require regression and the narrowing mutant controls; both
need only `go` on `PATH` and write nothing outside a temporary directory.

The same inventory job runs `python3 .scripts/check-strict-module-snapshots.py`
and `python3 -m unittest discover -s .scripts -p 'test_check_strict_module_snapshots.py' -v`.
These require full Git history, check that selected protected snapshots descend
from the strict-parser commit, and inspect the selected source call sites.
Semantic-version order alone does not preserve a fix. Controls reject the bad
rental selection, an unrelated higher pseudo-version, unavailable commits and
missing source sites; outputs go to stdout and fixture scratch.

`published-consumer` runs
`python3 .scripts/check-published-consumer.py --candidate FULL_COMMIT_SHA --scratch-parent ABSOLUTE_EXTERNAL_SCRATCH`
against actual proxy-published module versions. The parent must exist outside this
checkout. It creates private HOME/cache/temp and, for each entry point (the
`single-use` configguard/payloadbootstrap/modelprofile APIs, the `deploy`
package, the `station-lifecycle/cmd/station-manager` command, and the
`agent-wallet/g1bench` API), a separate
external consumer module without replacements. It warms the transitive metadata
closure of explicit published requirements and downloads the declared graph
online with checksum verification, checking that the manifest stays unchanged.
It then resolves imports, vets and builds offline,
so a missing package cannot be papered over by an online `@latest` lookup. The
fixed historical consumers must fail with their specific witness: `288d63e` with
the missing `sealwatch.ValidateJSON`, and `b516cc2` (standalone `single-use v0.1.0`
requires) with `cannot find module providing package .../single-use/configguard`
for both `deploy` and `station-manager`. The bench consumer at `1b3c321`
must fail at its declared pre-terms-v2/pre-transport API dependencies; its
candidate pins compatible strict-parser snapshots and must compile without
replacements. `TestPublishedRentalRejectsBeforeLibraryParse` runs in another
fresh external wallet consumer: it vendors the checksum-verified graph and
instruments only the library parser entry, then requires `s = n` to be refused
before that entry through the public rental certificate verifier. A valid
high-s vector and a direct sentinel calibration must pass beside it. The bad
wallet snapshot `27d39435` selecting rental `3baa201b` must fail with the exact
parser-entry witness. This checks pre-parse refusal rather than a forgery. The candidate must pass every case. Logs,
commands/PIDs/exits, manifests and consumer inputs stay in the printed scratch
directory; CI uploads those small files without caches. This proves public graph
compilation, not slotd runtime behavior or production installation.
Logs, consumer fixtures, mirrors and release artifacts belong under task-scoped
`.temp/` directories and must not contain credentials or private runtime state.

The grantcheck capacity regression runs outside the checkout, with no workspace
or replacements, and exercises `TestCoreProvisioning/CombinedCapacity` from the
selected module on genuine pinned Core. Run
`python3 .scripts/check-published-grantcheck-capacity.py --grantcheck GRANTCHECK_VERSION --single-use BUDGET_VERSION --old-single-use PRE_BUDGET_VERSION --scratch-parent ABSOLUTE_EXTERNAL_SCRATCH`.
Set `CG1_CORE_DAEMON` and `CG1_CORE_CLI` to the pinned release executables.
The scratch directory contains separate consumer manifests, module graphs,
command logs, PIDs and `results.json`. The old dependency must fail specifically
for the missing bounded-writer API; an unrelated error is rejected. `--proxy`
can select an exact-commit file proxy for unpublished local delivery; this is
local artifact evidence and does not attest public proxy availability. Run gate
controls with `python3 .scripts/test_check_published_grantcheck_capacity.py`.

The published wallet checker regression runs outside the checkout without module
replacements. Run `python3 .scripts/check-published-wallet-grantcheck.py --help`
for the selected wallet, checker, writer and historical checker versions. It
uses the same external public-API tests against both downloaded checker snapshots:
r4 must reject final-sample staleness and r5 must stage aggregate state until
acceptance. Logs, exact module graphs and command exits go under the external
`--scratch-parent`; `--proxy` may identify a local artifact proxy for unpublished
source, which does not establish public availability. Gate controls run with
`python3 -B -m unittest discover -s .scripts -p 'test_check_published_wallet_grantcheck.py' -v`.

## N1 identity and discovery tools

The rental module supports [typed optional N1 identity values](experiments/rental/N1-VALUES.md)
and an isolated local d/ mirror builder/checker. From `experiments/rental`, run
`go run ./cmd/name-discovery -inventory testdata/n1-values/inventory.json -record testdata/n1-values/record.json` to check the public fixture. Validation
commands and `.temp/` evidence locations are documented in that profile.
Authority stays in id/; every verifier must be upgraded before changing names.

## Signed model limits

Model-enabled rentals bind six model limits in the renter-signed ContractV2. See [signed model limits](experiments/rental-booking/MODEL-CAPS.md) for the wire, upgrade boundary, public preflight and control commands. The repository tool `.scripts/cc1-guards.go` runs bounded Go-overlay controls; use `go run .scripts/cc1-guards.go -out /absolute/new-cc1-evidence` from the root. Logs and hash/exit/PID records go to that new scratch directory. CC1 validation includes `go -C experiments/m5-host-smoke test -race -count=1 ./...` and overlay controls for the host runner's independently supplied expected caps and exact signed-contract binding.

Authority JSON inputs reject recursive duplicate keys and escaped object-key spellings. See the [SJ1 decoder inventory and evidence contract](experiments/STRICT-JSON.md) for canonical boundaries, opaque payload handling, compatibility changes and test limits. The repository tool `.scripts/sj1-guards.go` calibrates those regressions with bounded Go overlays: from an isolated task checkout, run `go run .scripts/sj1-guards.go -out /absolute/new-task-scratch/sj1-controls`. Baseline/mutant logs, hashes, PIDs and exit records go to that new scratch directory; source and live state are not modified.

## Witness construction validation tools

V3 T/A construction requires the explicit authenticated W pin and native P2WPKH/ALL inputs. The first delivery permits only exact T:L as an unconfirmed dependency; the payment exception is deferred to SW1b. See [the boundary and reason inventory](experiments/WITNESS-PROFILE.md). From an isolated physical scratch checkout, run `go run .scripts/sw1-guards.go -out /absolute/new-dir`; baseline/plant logs and hashes go to that directory. The inventory lists the separate real-Core commands and module checks.

### Installed configuration admission (DK5)

The [signed installation contract](deploy/INSTALL-CONFIG.md) describes root-owned
static inputs, private service groups, same-binary systemd preflight and Infra's
external installation/qualification duties. Use the exact `deploy-kit render-install-anchor` command in
[deploy tools](deploy/README.md#dk5-tools) for public-anchor rendering;
from the repository root run `go run .scripts/dk5-guards.go -out "$NEW_ABSOLUTE_SCRATCH_DIR"`
for21 isolated guard controls. Keep validation HOME/cache/temp under task scratch.
Dynamic payload bootstrap/slotd enforcement remains the separate DK5b gate.

The public configguard.ValidateStagedSet API admits custody-checked staged
static bytes before installation, using independent expected final paths,
release/service/GID. It performs no filesystem access. The
[staged contract and verification commands](experiments/single-use/configguard/STAGED.md)
describe its boundary; the existing .scripts/dk5-guards.go runner includes
staged signature, content and final-path bypass controls with task-local output.

## Payload consumer API controls

The single-use [public bootstrap decoder](experiments/single-use/payloadbootstrap/README.md)
and [public model validator](experiments/single-use/modelprofile/README.md) share
schemas with gatewaybind, model-proxy and station-payload. In owned scratch run
`go -C experiments/single-use test -race ./payloadbootstrap/... ./modelprofile/...`
and `go run .scripts/dk5b-api-guards.go -out /absolute/task-scratch/new-controls`.
The latter writes paired baseline/mutant logs, source hashes and results to the
specified new directory. These checks prove byte/selection contracts, not daemon
custody, provisioning, proxy startup or runtime admission.

Bootstrap credentials and downstream station channel handles use opaque scalar
pointer storage, including for fmt's method-bypassing bad-verb diagnostics.
Run `go -C experiments/single-use test -count=1 ./payloadbootstrap/...` and
`go -C experiments/station-lifecycle/gatewaybind test -count=1 -run 'TestBootstrap|TestStationHandleCredentialFormatting' .`
for the synthetic formatting matrix, unchanged wire vectors, usable credentials,
public pins and refusal clearing. Run
`go -C experiments/station-payload test -count=1 -run TestClientCredentialFormattingAllVerbs .`
for the containing client. Redirect validation output to a task-owned `.temp/`
directory. [The bootstrap API notes](experiments/single-use/payloadbootstrap/README.md)
describe the constructor/accessor migration and explicit private wire boundary.

Generic JSON/text encodings now redact protected credentials, including nested
`slog.Any`/`slog.Group` values. Private bootstrap encoding uses `codec.Encode`;
journal persistence uses `journal.EncodePrivateSlot`, and the proxy/lifecycle
private codecs preserve their existing registrar, registry, poll and disk bytes.
Run `go -C experiments/single-use test -count=1 -run TestReview ./payloadbootstrap/codec`
and `go -C experiments/station-lifecycle/gatewaybind test -count=1 -run TestReview .`
for the independent fmt/slog/carrier and wire-differential regressions. Run
`go -C experiments/model-proxy test -count=1 -run 'TestCredentialValueEquality|TestModelPrivateWireCompatibility' .`,
`go -C experiments/station-lifecycle test -count=1 -run 'TestReviewBrokerCredentialOutput|TestLifecyclePrivateWireCompatibility' .`,
and `go -C experiments/rental-gateway test -count=1 -run TestJournalPrivateWireCompatibility ./journal`
for private persistence compatibility and value comparison. Capture output in
task-owned `.temp/`. The N1b checks below extend this storage and output defense
to Track B tokens and upstream proxy API keys.

### Credential output boundary checks

Track B tokens and upstream model keys use opaque credential holders. Their
[carrier and explicit-reveal inventory](docs/security/credential-output-n1b.md)
records private wire/authentication boundaries and output regression coverage.
Run `go run .scripts/check-credential-output-boundaries.go` from the repository
root to check 14 storage fields and the nested exact `Reveal*` inventory:
`Reveal` has 53 sites / 67 calls; `RevealForOpen` has an empty set. The guard
includes package-level initializers, method values and declarations on any type.
The linked document lists reflection, casts and test-file exclusions. Capture
its JSON under `.temp/`. Run
`python3 -I experiments/model-proxy/session/tools/guard_controls.py .temp/credential-controls .tmp/credential-controls`
with task-owned absolute HOME/caches/TMPDIR and a new fixture directory for the
exact positive inventory and old/new refusal controls. Logs go under `.temp/`;
copied source and binaries go under `.tmp/`. Optional trailing legacy guard
source paths enable comparison of the preserved old rules. These controls are
local evidence, separate from hosted CI. Run `go -C experiments/model-proxy test
./...`, `go -C experiments/rental-executor test ./...` and `go -C
experiments/rental-gateway test ./...` for the fmt, slog, generic JSON and private
wire regressions; use the same module paths with `vet ./...` for static checks.

The [regtest envelope grant-admission bench](experiments/agent-wallet/g1bench/README.md)
reuses the wallet Core harness, verifies native-shaped Ed25519 envelopes plus
Track A BIP-340 co-signatures, and checks live v3 grants through the
transport-neutral API. It retains exact refusal assertions, warm-gate revocation
and 22 overlay controls. Keys and envelope attestation remain synthetic;
Track B is a separate future change.

## Grant v4 wire tools

The isolated wire module uses Go 1.26.10 for `go test -race`, `go vet`,
`go build` and `gofmt`, and Python 3 for its bounded mutation controls. Exact
commands, the public fixture pin and `.temp/` evidence locations are documented
in the [module README](experiments/grant-v4/wire/README.md#tools-and-commands).
The existing module-graph and public-hygiene scripts cover its registration.

Grant identity expiry is reported by name as non-retryable
`identity_expired` (`closed=true`), including cached re-checks. See
[grantcheck identity expiry](experiments/grantcheck/README.md#expired-current-identities)
for Core regtest controls and the RPC application/transport distinction.
The client validates the complete JSON-RPC 1.0 error envelope before assigning
an application code; malformed envelopes remain retryable node failures.

## Grant v4 identity tools

The [identity module commands](experiments/grant-v4/identity/README.md#tools-and-commands)
cover Go formatting, dependency verification, vet, race tests and build, an
independent Python reader for all 140 identity vectors (including all 56 walks),
agreement controls and Go overlay mutants. The same module contains the
explicitly gated [R1 draft lab](experiments/grant-v4/identity/README.md#r1-decision-map-and-compatibility),
pinned to spec `v0.1.49`, with a separate independent reader for **440** cases:
151 vectors (38 groups/ordinals, 65 class, 28 holder values, 5 capacity and
15 row-fit), 276 earlier revision controls and 13 absence/leading-whitespace
controls. Its commands are listed with the identity tools and write evidence
under `.temp/`; the v3 grantcheck API and
acceptance boundary are unchanged.
Run them from the repository root; test and mutation evidence goes under
`.temp/`. The module-graph and public-hygiene tools above cover its registration.

## Grant v4 observation tools

The [chainview module](experiments/grant-v4/chainview/README.md#tools-and-commands)
uses Go 1.26.10 for `gofmt`, `go vet`, `go test -race` and `go build`, and Python
3.14.4 for the independent vector reader and three narrowing overlay controls.
From the repository root, run `go -C experiments/grant-v4/chainview test -race ./...`;
the module README gives the exact vector-export, second-reader and mutation
commands. Evidence belongs in `.temp/chainview/`. The dependency-free module
reads no node and assigns no action/evidence classes or production thresholds.

The [notary checker service](experiments/notary-checker/README.md#notary-service-regtest-laboratory)
adds a bounded regtest signing endpoint and exclusive host key generation around
the pinned checker. Its build, node harness and validation entry points are in
that module’s tools section; funding, broadcast, network ACLs and deployment
remain operator responsibilities.
