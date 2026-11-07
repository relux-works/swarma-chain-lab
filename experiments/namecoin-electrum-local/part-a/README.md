# Closed regtest research harness

This harness composes the unchanged, pinned Namecoin Core release with the
accepted ElectrumX local header correction. It adds no server patch, dependency
upgrade, consensus override or persistent-node configuration change.

The controller starts one fresh Core regtest node and one Namecoin ElectrumX
index in a private bubblewrap network namespace. Only private loopback is used.
A cookie-authenticated read-only RPC proxy separates the indexer from the local
fixture's transaction producer. Client protocol adapters allow only read-only
methods. One adapter can replay actual prior responses or a canonical foreign
chain header. These are views of one index, not independent server operators.

`thin.py` uses the unchanged pinned ElectrumX Merkle and Namecoin transaction and
script parsers. It checks transaction identifiers, transaction Merkle inclusion,
header membership in an explicitly trusted laboratory checkpoint and exact name
output bytes. The full validating Core process supplies that out-of-band
checkpoint and the laboratory state oracle. The network driver and supervisor
share a Python process; their data/capability separation is an implementation
convention, not a separate OS credential boundary. The protocol object retains
no complete blockchain or header chain. The independent offline replay mounts
only public protocol evidence, the pinned parsing/Merkle modules and tools, with
no node binary, RPC cookie, wallet, blocks or chain directory.

This is not a standalone Namecoin consensus SPV implementation. It does not
verify AuxPoW work, the full header chain/difficulty, script signatures, name
commitment/update signature ancestry, latest-state completeness or absence.
Proofs of supplied older transactions can remain valid after a newer update or
seal spend. A single consistent server omission can remain undetected.

The private execution layout stages these exact files as read-only `/tools`,
the accepted source as `/src`, and verified release/runtime inputs as `/runtime`.
The shell wrappers derive their task-owned staging root; they do not discover
foreign homes, keys, sockets or caches. `prepare.py` verifies release/dependency
hashes and release signatures offline before extracting executables. Artifact
acquisition is a separate, bounded canonical transport step. No binaries,
private fixture material or credentials belong in this source directory.

The immutable UTC stop bound in the exact executed controller is intentionally
retained in the evidence version. This harness is not a general deployment
launcher. A later independently admitted run must supply its own immutable
scope and bounds rather than treating this expired acceptance as authority.
The tested whole-lab limits are 3 GiB memory, no swap, two CPU equivalents, 64
tasks, 1500 s wall per runtime with a 1600 s systemd backstop, a 1536 MiB private
tmpfs, 256 total client requests and 64 MiB total received protocol bytes. The
controller stops new work at the private tmpfs 80% threshold. Read-only staged
inputs and retained public receipts also count toward the separate 2 GiB
retained-task budget; the run packet records their measured size.

Core's default relay policy is preserved. The seal fixture pays 0.0004 regtest
NMC from a 0.01 NMC input; an earlier 0.0001 NMC fee was refused and its exact
failed run remains in the packet. No server cost limit is relaxed to complete
any scenario. All runtime state is disposable and is destroyed after service
shutdown by terminating the private namespace.

The packet supplies actual positive controls, four adversarial outcomes, raw
public protocol receipts, notification timestamps and real-proof replay. A
notification timestamp is not an instrumented consensus acceptance timestamp.
Notification-to-verification time includes checkpoint-oracle construction and
sequential protocol requests; it is not cryptography-only latency. Restart,
reorg, representative mainnet AuxPoW, mainnet indexing and production operation
are outside the resulting qualification claim. Fresh independent review of this
new harness and exact evidence remains required.
