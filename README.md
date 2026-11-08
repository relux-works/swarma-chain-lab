# Swarma Chain Lab

**LAB — experimental research, not production software.**

This repository contains bounded blockchain experiments. A passing experiment
supports only its stated assumptions and checks; it does not qualify a production
service, grant format, wallet, consensus implementation or deployment.

Experiments live in `experiments/<name>/`:

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
