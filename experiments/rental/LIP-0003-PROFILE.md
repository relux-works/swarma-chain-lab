# Implemented detached grant profile

This regtest profile records implementation choices for independent review.
It is not a production authorization or a publication of the public LIP.

## Exact wire and identity

Agent name value, compact and in this order:
`{"swarma":{"agent":{"nostr":"<x-only>","grant":"<x-only>"}}}`.
The cold name-owner output is independent of both hot keys. The parser accepts
only exact canonical shape and valid secp256k1 x-only keys, with no aliases,
unknown or duplicate fields, nulls, whitespace or alternate order.

Certificate fixed field order: `version` (2), `network`, `genesis`, `agent_name`,
`issuer_key`, `grantee_key`, optional `grantee_name`, `contract_sha256`, `scope`,
`not_before`, `not_after`, `seal` (`txid`, `vout`), optional `budget` (integer
satoshis). An absent budget means zero. Present zero and absence have different
signed bytes. Optional null is forbidden. `grantee_name` is informative only.
`scope` is a sorted unique list of the closed action vocabulary; empty means no
allowed actions. Public fixtures under `testdata/detached-v2` pin concrete bytes.

The envelope is `{"certificate":<payload>,"signature":"<128 lower hex>"}`.
BIP-340 signs SHA256 of canonical unsigned payload. Certificate id is SHA256
of the exact complete envelope, including signature. `ParseDetachedEnvelope`
authenticates the signature; it alone does not establish liveness.

Every seal must be legacy P2PKH `76a914 HASH160(02 || issuer_key) 88ac`, matching
`Policy.SealScript`. This is the even-y compressed point. A separate ECDSA
spender must normalize the scalar to that point. Reuse of the grant key across
BIP-340 and ECDSA is deliberate; callers must use correct implementations with
separate signature algorithms and nonce rules. This module signs BIP-340
certificates only. The key file is exactly 32 binary scalar bytes, owner-only
0600 regular single-link file without symlink path components. Runtime copies
and OS custody are not eliminated by best-effort clearing.

## Check and monotonic closure

`Check(ctx,node,policy,raw,agentName,sender,nowUnix) Receipt` keeps its call shape.
`Receipt.Version` is 2; compatibility field `StationName` carries the agent
identity name; `Anchor` is nil. Only `live` admits. Name expiry uses chain
height. Certificate time uses the caller's trusted UTC clock. There is **no
block timestamp/MTP comparison and no proof of issuance time**; `not_before`
may precede the seal's block timestamp. The seal must be actively confirmed,
raw/projection bound, positive and owned by the grant key. Mempool-inclusive
`gettxout` checks its unspentness. Node reads, active block membership, name
observations, mempool set and final tip must agree within observation bounds.

A matching confirmed name generation is remembered only after admission (or
an observed seal-spend closure). A later confirmed different grant key closes
that certificate only if the saved generation is still active. First mismatch
or an older generation following rollback refuses without closure. Pending
different grant key refuses without closure; if dropped, the original grant
can become live again. Malformed current/pending values and read failures
refuse without closure. Nostr-only updates preserve grants.

Observed seal spend closes permanently, including a mempool spend later
dropped. Confirmed observed key rotation closes permanently, including reorg
and rotate-back. There is no reopen API. A first observer cannot reconstruct
unseen rotations. Closure is per certificate on observation, not an eager scan
of all certificates. Expiry refuses but does not write a closure transaction.

Persistent state uses the shared owner-only locked/fsynced store. A never-
evicted seal index binds each network/genesis/outpoint to one envelope id.
Different envelope reuse refuses. This cannot detect equivocation across two
independent verifiers that have never seen the competing envelope. Backup or
restore must preserve this memory, closure records and issuer burns.
`SealScript` is a policy pin: key rotation requires a new pin for new grants;
retain old policy/state to observe and enforce old-grant closure.

## Presentation and issuance

`Present` accepts inline bytes only and requires the exact claimed id. It
performs fresh `Check` before inserting/replacing the sender's cached envelope.
Cache limit is 64 sender entries and 60000 encoded bytes. At capacity a live
replacement can succeed; a new sender refuses. A failed presentation leaves
the cache unchanged; preceding `Check` may still persist its seal index or
closure. Cache entries are public bytes, never authority. `CachedCertificate`
returns bytes/id only; every message must freshly Check them with the current
authenticated sender and node. State/cache locking does not freeze the chain;
executor admission still needs its own immediate recheck and effect policy.

`IssueDetached` validates the existing signed M3 package and freshly admits its
confirmed payment at or above signed price, current agent keys and confirmed
unspent key-owned pool output. Signed hold/time bounds remain mandatory.
Under one durable lock it writes permanent booking and pool burns using the
same index scheme as legacy issuance, then a reserved record, **before**
signing. Complete exact envelope bytes are fsynced before returning. An
uncertain reservation is never signed again. Completed identical retry returns
exact bytes even after expiry or without node/key; this is replay, not a new
liveness verdict. Changed request/publication/seal refuses. Partial journal
failure can strand a burn, deliberately preferring no duplicate signature.
No per-certificate name update or transaction occurs.

## Optional batch audit anchor

Disabled by default. A batch contains 1..256 unique sorted envelope ids.
Leaf = SHA256(00 || id bytes); internal = SHA256(01 || left || right); duplicate
the last node at an odd width. Proof carries version 1, index, count and an
exact sibling path. The anchored commitment is
`SHA256("swarma-batch-v1" || uint64_big_endian(count) || merkle_root_bytes)`.
`VerifyBatchProof` recomputes this commitment from the proof's count and path;
no separately trusted count is required. A duplicated odd tail can preserve
the internal root, but changes the commitment. The plan has one zero-valued
`6a20<commitment>` output plus pinned change. It is
unsigned, offline, and conveys no pool reservation or spending authority.
Membership proves only this envelope's inclusion in the chosen commitment. It does
not replace Check or prove certificate issuance time.
