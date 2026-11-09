# Thin closed-regtest assembly admission

This harness prepares composition of the unchanged KeyVault verifier with a
Namecoin wrapper, ephemeral test signer, T1 seal/anchor adapter and seal watcher.
It does not implement those components. It runs no repository operation.

The fixed owner is `@operator:example.invalid`; the target is
`relux-works/matrix-grants-poc-261031`, and the test action is verification of
`repository.create`. Names are `id/swarma-poc-operator` and
`id/swarma-poc-requester`. Existing certificate, enrollment and request formats
remain unchanged. The mirror direction and BIP47 are outside this slice.

## Runnable admission

Run `assembly.py --plan /absolute/path/plan.json --acceptance /absolute/path/acceptance.json` inside the supplied offline
sandbox. It returns 3 and a structured missing list until all four exact signed
candidates and their manifests are present. No retry loop or polling exists.
The example in the evidence packet intentionally contains null hashes for absent
artifacts. Populate them only from completed, sealed component packets.

Each component entry supplies a read-only root, exact head/tree, manifest path,
manifest SHA-256, signed bundle path, and required sealed files. The public
Relux Zion selector is supplied at `/inputs/public-signing.pub`; its fingerprint
is checked before candidate signature verification. Optional module ZIP entries
are checked with canonical Go h1 hashing, never a hash of the ZIP container.
The exact public dependency closure must be verified before executing a Go
component. No dependency upgrade or network download is performed here.

The harness deliberately has no arbitrary command execution CLI. A separately
completed composition driver can call `run_stages(plan, executor, acceptance)` after exact
artifact admission. The driver must bind the concrete incoming APIs and collect
public chain evidence; those bindings are pending while artifacts are absent.
`run_child` supplies finite task-owned process execution and PID-birth cleanup.
Stage exit codes alone never constitute closed-regtest evidence.

## Required driver and custody contract

Use a disposable node inside its own offline network namespace, verified
against the canonical pinned release closure. The node, issuer, requester and
verifier require distinct isolated custody. Only the node may access its own
wallet data. Issuer and requester retain separate throwaway P256 keys in private
mode-0700 storage; neither key enters verifier state, receipts or exports.
The read-only verifier receives only public name/config/certificate/request,
anchor and seal observations through a restricted pipe. Do not give a signer
cookie, wallet directory, host home or agent socket to any offline verifier.
Source and tools must be mounted read-only; HOME, TMP and caches are absolute,
private mode-0700 paths. All node children are finite owned PID-birth processes;
no native service, systemd or host node is part of this harness.

The causal stage sequence is publish names, issue the existing certificate,
anchor exact certificate bytes and seal, sign the existing request, admit the
fixed action, spend that exact seal, refuse while the spend is in mempool, mine
one block, and refuse at that block. Reuse incoming component implementations;
do not substitute a fixture or T1's historical secp256k1 grant protocol for the
P256 certificate/request slice. One block is reversible lab policy.

Record exact certificate bytes/hash, name txids and public fields, anchor txid,
seal outpoint/script/value, request hash, signature outcomes, before/after tip,
mempool spend txid, block inclusion, verifier decisions and reasons. Establish
an admitted baseline before changing one causal input for each necessary
malformed-name, pin/hash/signature, expiry, wrong-request, revoked or stale
control. Preserve original failures, start/end times and exits. Stop at the
first failed prerequisite and retain the export/cleanup reserve from the
immutable acceptance deadline.

## Verification boundary

`test_assembly.py` contains explicit synthetic orchestration fixtures for artifact
mutation, missing components, scope/deadline guards, canonical archive hashing,
causal stage order and finite child cleanup. Its candidate-verifier stub is
confined to fixtures. Default admission verifies actual SSH-signed Git bundles.
No fixture is presented as a node, signer, certificate or closed-regtest result.

A real whole-composition run, fresh independent review, and exact Meta marker
remain required. Unit checks do not establish mainnet readiness.

The portable `reproduce.sh` launches namespaces from the host as shell plumbing;
all Python execution remains offline. This host refuses nested unprivileged
namespace creation. Do not run the launcher from inside another bwrap, weaken
isolation, or infer that the not-yet-assembled multi-actor driver was tested.
Use separately launched flat actor namespaces and the established restricted
public pipe design when the complete component artifacts become available.
