# Notary comparison laboratory

**LAB — experimental research, not production software.** This experiment checks
notary authority, observation consistency and seal depth. It does not qualify a
production policy, full grant contract or general name lifecycle.

A separate attestation still permits N to withdraw continuing endorsement by
spending its own seal. A 2-of-2 issuance still requires N before issuance, and a
later endorsement withdrawal does not reverse the issuance or revoke A's seal.
The conceptual default remains separate attestation, subject to corrected verifier
review and an explicitly selected trusted-notary policy.

Every required name transition has exactly one name operation, exact A or N name,
exact pinned destination owner and expected commitment. Its actual consumed named
predecessor must have that same name/owner. Each predecessor is followed back to
the pinned identity firstupdate, checking every intermediate name/owner and its
confirmation depth. At most 128 transitions are admitted. This deliberately strict
fixture excludes transfers, rotation and new registration generations; it does
not choose a general name lifecycle policy. The co-signed route also requires its
A name transition, exact issuance/anchor identity and the existing bound 2-of-2
input with SIGHASH_ALL signatures.

The first tip snapshot precedes every chain identity/authority/liveness read.
All decisions, including early rejection, are provisional until the closing tip
matches. Change returns UNAVAILABLE. Accepted evidence reports that same snapshot,
without an extra unbracketed tip read. A dishonest/stalled node, an A-to-B-to-A
(ABA) tip sequence or mempool mutation after the final live read is not detected
by simple before/after equality. This is a trusted single-node observation, not
an atomic snapshot, SPV liveness proof or independent synchronization guarantee.

Experimental seal policy requires at least max(1,minconf) confirmations for both
A grant and N endorsement funding outputs. Presence is checked including mempool
spends; an unconfirmed funding output is rejected. This states the confirmed-seal
intent of this fixture, not a production confirmation-depth decision.

`offline-counterexamples.py` executes only selected pure verifier functions with
explicitly synthetic symbolic responses. Signature/consensus validity is assumed.
It compares old acceptance with new refusal, covers wrong name/owner/input,
lineage, zero-depth funding and tip transitions through the whole decision, plus
freshness/expiry/withdrawal regressions. `baseline-lab.py` preserves the old
verifier functions and is used only as a pure-function baseline, never as a runtime
driver. Its boundary telemetry uses the same generic empty-home check as the
current driver; the original sealed source remains private and immutable.

`lab.py` regenerates isolated regtest A/B/N keys and reruns the existing controls.
Dedicated seal outpoints are locked against ordinary wallet coin selection;
explicit raw withdrawal/revocation remains permitted. Actual B-signed name updates relay unchanged signed N statements and A grants:
the old verifier accepts them while the corrected verifier rejects them. No old
wallets, cookies, keys or private runtime state are read. Exported addresses,
public keys, scripts and signatures are hash labels rather than reusable vectors.

The historical runtime uses UID 1002, an explicitly configured disposable root, RPC 18640,
env-cleared bwrap with unshare-all,
private PID/network/mount namespaces, loopback only and no agent home or sockets.
The controller limits private/public disk to 1,900 MiB plus <148 MiB tools/source,
32 namespace processes, 256 MiB per file, 2 GiB virtual memory per process and
1,800 CPU seconds. Wall time is <=35 minutes with immutable absolute cutoff
2026-11-07T03:16:00Z. That admission is expired and is preserved unchanged.
No other lab paths or processes may be inspected, cleaned or signaled.
The supervisor refuses admission at or after that cutoff before creating a
child, writing a failure receipt with no child exit. Every budget stop reports
supervisor failure even when the terminated child exits zero; the receipt keeps
that child exit separately. Offline supervisor controls use fake process APIs
and simulated pre-cutoff clocks, so they cannot reactivate the old admission.

Set `NOTARY_LAB_ROOT` to an absolute, canonical path ending in `notary-lab`.
For example, `NOTARY_LAB_ROOT=/srv/experiments/notary-lab` selects the host
directory; its parent must already exist and be writable by the laboratory user.
Paths containing spaces are supported. Relative paths, traversal, symlinks and
other leaf names are refused. Preparation refuses an existing root; reset and
cleanup require that exact configured directory and the existing export checks.
All lifecycle helpers and the sandbox use this same interface. The environment
value is passed explicitly across the cleared laboratory-user boundary, and is
not passed into the node namespace. Namespace paths remain `/source`, `/runtime`,
`/private` and `/public`; no host home or credential socket is mounted.

This directory is the source-only experiment layout. After mounting this
directory read-only at `/source` inside an offline namespace, run:

```sh
python3 -B /source/test_lab_paths.py
python3 -B /source/offline-counterexamples.py /source/lab.py
python3 -B /source/offline-counterexamples.py /source/baseline-lab.py
```

The path test module also checks supervisor admission and zero-exit budget stops
without starting any child. The corrected symbolic checker has 95 expectations;
the baseline has 35.
These commands exercise pure functions with synthetic responses. They do not
run the runtime drivers, start a node or validate real cryptographic signatures.
Use private mode-0700 absolute HOME, TMPDIR and cache directories, read-only
tools, and no host home, credential files, sockets or external network.

`reproduce.sh`, `prepare-lab.py`, `sandbox.sh`, `supervise.py`, `export.py`,
`reset-own-generated.py` and `cleanup.py` preserve the historical private-packet
layout: a packet parent containing `source/`, admission receipts, pinned upstream
verification inputs and separately acquired binaries. This public tree is not
that runnable packet and includes none of its private inputs. Do not invoke
these lifecycle entrypoints from this checkout. Their receipt checks, archive
checksum and expired cutoff have not been changed. Later runtime experiments
need a separately authorized isolated path, port and window; never rewrite the
original admission or infer permission from publication of these files.

`source-binding.json` is generated only by the historical runtime and records
self-observed staged file hashes. Hashes and signatures are source provenance,
not independent execution attestation. Publication does not extend the lab's
qualification or supply a production approval.

Python uses only the standard library. The historical optional runtime archive
is Namecoin Core 28.0, SHA-256
`6f12031926f0999b8507e073648cc2b4488d452531301a2244a562a92f2f7860`.
Publication does not download or upgrade it. No Go modules are used, so canonical
Go module h1 verification does not apply.
