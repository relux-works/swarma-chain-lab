# Swarma Chain Lab

**LAB — experimental research, not production software.**

This repository contains bounded blockchain experiments. A passing experiment
supports only its stated assumptions and checks; it does not qualify a production
service, grant format, wallet, consensus implementation or deployment.

Experiments live in `experiments/<name>/`:

- [Notary comparison](experiments/notary/README.md): synthetic notary authority,
  named-output lineage, seal liveness and observation consistency checks.

The notary experiment includes Python standard-library-only offline controls.
Run these only in an offline namespace with read-only source and tools, an empty
home view, and private writable HOME, TMPDIR and cache directories. No node,
wallet, live chain data, signing key or network download is required for those
controls. See the experiment README for commands and limitations.

Historical runtime helpers retain their expired admission cutoff. This source
publication supplies no operational receipts, node binaries, wallets or runtime
state. A new runtime experiment requires its own admitted isolation and bounds.

Licensed under [Apache-2.0](LICENSE); see [NOTICE](NOTICE) and experiment notices.
