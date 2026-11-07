This closed regtest composition executes the existing KeyVault local certificate
and request formats. It never invokes a repository provider or operation.

The separate lab signer generates fresh throwaway keys in each actor's private
custody. Only public DER crosses to the other actor. The owner signs the exact
unchanged local-prepare payload, and the requester signs a distinct request.
The node owns fresh test wallets. A public read pipe connects the actual wrapper
and finite watcher to that own Core node; no supplied snapshot replaces RPC.

The anchor adapter retains its ordinary one-input transaction contract and its
original reservation, input-allocation and fee/size ceilings. A companion name
update, constructed by the existing T1 transaction builder, carries the same
exact certificate SHA256 and the actual seal tuple in the issuer's current name
record, plus exactly one 32-byte OP_RETURN commitment. Both transactions are
retained in evidence. No certificate field points to its own transaction hash.

The companion name_firstupdate/name_update route has named MAINNET constants:
1024 vB, 200 sat/vB, and 204800 sat. The same helper requires explicit separate
regtest parameters and never broadcasts. Name_new retains 252 vB, funding
retains 230 vB, and the ordinary anchor retains 534 vB. Other T1 operation caps
are unchanged. This local candidate still requires independent whole review;
constants alone do not grant mainnet execution or raw-transaction approval.
The final monetary helper source is a separate pending gate and is not included
in this graph. The existing allocation helper is retained at its exact pin.
The ordinary adapter anchor remains within its original 534-vB/106800-sat cap.
The 0.875-NMC reservation is represented by a real locked test UTXO; ordinary
adapter inputs fit the remaining allocation. The supplied conservative ledger
reserves 1000000 sat for prior/setup fees and two disjoint name locks, including
the independently funded requester name; it is deliberately conservative.

Core defaults to ASCII name output. The public read broker forwards the wrapper's exact ASCII/allowExpired=false
name_show options and validates the returned encodings; it never rewrites or relabels RPC results. Both
components compare the actual exact 6a20+SHA256(certificate bytes) output. The
watcher's documentation word "short" means the 32-byte hash commitment, not a
truncated digest. The wrapper's explicit lab observation time is whole seconds
because its unchanged CLI comparison uses RFC3339 whole-second serialization.

The outer bwrap has no external network, host home, credential environment,
signing socket or foreign cache. Each actor runs as a separate direct child,
with an individual mounted private subtree and a Landlock filesystem allowlist;
no capability remains. Harmless sentinel controls prove cross-actor file refusal.
The host LSM refuses chroot; that original failed attempt is retained. Actors
share a host UID. This does not establish different OS users, resistance to a
hostile same-UID host process, or production custody qualification.

The finite read bridge checks the unspent seal and verifies the real signed request,
then observes the real exact seal input in the mempool and first active block.
The wrapper's successfully persisted refusal file survives fresh bridge processes. A new valid
request is independently accepted by the unchanged CLI, and still refused by
the chain-aware wrapper after revocation. One block is lab finality policy. A separate policy root observes a confirmed
owner-generation replacement, then the original branch is restored. A new
verifier process retaining that root must refuse after only the two network-health reads, before name or CLI checks. This tests
successful local persistence only, without crash or cross-process durability
qualification. Repeated positive verification is an observation, not admission,
anti-replay or execution. No provider or repository command is invoked.

The unchanged watcher is also checked with a controlled LastBlockAt timestamp
older than 30 minutes against the same actual tip. STOP must occur with zero
RPC calls. This is a bounded clock-input control, not a real 30-minute wait or
qualification of a protected host clock or a durable idle service.

Run actual.py only through the supplied offline sandbox with pinned source,
Core/tools, isolated state and original acceptance receipt. Every mutation is
preceded by an own-node regtest/genesis check. Actor commands, total RPC calls,
runtime, file sizes, child PID births and kill/reap are bounded. The supervisor
never opens a PKCS8 file. Only public certificate/request/DER and signed-chain
evidence are exported. All keys, RPC configuration and wallets are deleted by
the scoped cleanup after children have been reaped.

This is producer evidence for an unreviewed prototype. Fresh independent review
of the whole exact composition and its exact Meta marker remain mandatory.
No live/mainnet readiness, owner key, BIP47 or mirror direction is included.
