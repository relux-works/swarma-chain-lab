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

The current record requires approximately 801 vB for the name-update transaction,
above T1's original 534-vB anchor ceiling. This separate bridge passes a strict
1024-vB/204800-sat cap to the existing parameterized builder for regtest name
operations only. It changes no T1/mainnet constant. Mainnet budgeting for these
larger records is unresolved and requires explicit review before live use.
The ordinary adapter anchor remains within its original 534-vB/106800-sat cap.
The 0.875-NMC reservation is represented by a real locked test UTXO; ordinary
adapter inputs fit the remaining allocation. The supplied conservative ledger
reserves 1000000 sat for prior/setup fees and two disjoint name locks, including
the independently funded requester name; it is deliberately conservative.

Core defaults to ASCII name output. The public read broker requests UTF-8 using
the actual name_show options; it never rewrites or relabels RPC results. Both
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

The finite read bridge checks the unspent seal, verifies the real signed request,
then observes the real exact seal input in the mempool and first active block.
The wrapper's durable refusal file survives fresh bridge processes. A new valid
request is independently accepted by the unchanged CLI, and still refused by
the chain-aware wrapper after revocation. One block is lab finality policy.

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
