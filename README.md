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
