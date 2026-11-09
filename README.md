# Swarma Chain Lab

**LAB — experimental research, not production software.**

This repository contains bounded blockchain experiments. A passing experiment
supports only its stated assumptions and checks; it does not qualify a production
service, grant format, wallet, consensus implementation or deployment.

Experiments live in `experiments/<name>/`:

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

## Rental executor and contest endpoints

[Rental executor](experiments/rental-executor/README.md) adds strict renter-signed
requests, fresh M1 checks, durable nonce/budget reservations, explicit regtest
budget payments and separate Track B admin/claim sockets. It requires pinned M1
63087f31 or its integrated sibling modules. From its module run
`go test -race ./...`, `go vet ./...` and
`go build -trimpath -o ../../.temp/rental-executor ./cmd/rental-executor`.
See its README for exact Core/control environment and private/public artifacts.

## Agent wallet and Curator skill draft

[Agent wallet](experiments/agent-wallet/README.md) is the W1 regtest CLI for
balance/receive/history, K1-authorized payments, fee-inclusive separate rental
budgets, two-stage name registration and independent W3 single-use authority.
From `experiments/agent-wallet`, run `go test -race ./...`, `go vet ./...` and
`go build -trimpath -o ../../.temp/agent-wallet ./cmd/agent-wallet`.
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
regtest-only landlord custody loop: immutable outbox pull, genuine K1/P1 grant
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

## Regtest release preparation

[DK1 deploy kit](deploy/README.md) builds the existing service binaries twice
from a clean exact commit into an unsigned linux/amd64 bundle, with manifest and
SHA256SUMS. From `deploy/`, run `go test -race ./...`, `go vet ./...` and
`go run ./cmd/deploy-kit build -repo "$SOURCE_ROOT" -commit "$REVIEWED_COMMIT" -out "$RELEASE_DIR"`.
Its public validator, gateway/booking/store unit templates and Infra smoke plan
are documented there. Gateway uses real grant/exchange/manager wiring with
screening off; operator payload and Linux host acceptance remain required.
No host deployment or mainnet action is part of this tooling. Release outputs
use a new directory outside the source checkout; task logs stay in `.temp/`.

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
text Messages proxy with private per-slot bearers, conservative durable caps,
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
model proxy over verified, leaf-pinned TLS. Run its Go tests, guard controls and
CLI using the commands in that module; artifacts belong under `.temp/`. It is a
rehearsal fixture, not a selected rented-agent runtime or host deployment.
