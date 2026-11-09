# Implemented landlord grant v3 profile

This regtest implementation profile is review input, not a production grant,
public LIP publication, wallet-spending approval or deployment instruction.

## Identities and custody

Exact compact name values, in the displayed order:

```json
{"swarma":{"landlord":{"grant":"<x-only grant key>"}}}
{"swarma":{"agent":{"nostr":"<x-only Nostr key>","landlord":"id/landlord"}}}
```

Parsers reject missing, aliased, extra, duplicate, reordered and malformed fields.
Cold name-owner scripts are independent of these public keys. The seal script
is P2PKH to the even-y compressed landlord grant key; the name-owner key need
not match it. BIP-340 normalization and ECDSA seal custody must agree on the
even-y secret. The kernel does not import or require private keys.

## Exact bytes and consent

Canonical compact UTF-8 JSON follows Go struct field order, with no whitespace
or unknown fields. Signed payload order:

`version` (=3), `network`, `genesis`, `agent_name`, `landlord_name`, `issuer_key`,
`grantee_key`, optional `grantee_name`, `contract_sha256`, `scope`, `not_before`,
`not_after`, `seal` (`txid`,`vout`), optional `budget`, `consent`.

`consent` order: `contract_sha256`, `consent_event`, `landlord_sig`.
`consent_event` is the existing M3 event (`id`, `pubkey`, `created_at`, `kind`,
`tags`, `content`, `sig` in the Event struct order). The actual fixture bytes
in `testdata/grant-v3/` are authoritative examples of serialization.

The consent event has kind 8181, empty content, pubkey equal to `grantee_key`,
and exactly these ordered tags:

```text
["t","swarma-rental-consent-v1"]
["contract",contract_sha256]
["booking",booking_sha256]
["privacy",privacy_sha256]
```

Its ID is recomputed from the NIP-01 `[0,pubkey,created_at,kind,tags,content]`
serialization, and its BIP-340 signature verifies that ID. It is **not** a raw
contract signature. The landlord's BIP-340 signature signs the raw 32-byte
contract hash. Both embedded contract hashes must match. Consent cannot come
from the future at checking time or fall at/after the grant's expiry. Admission
also binds the original package, hold, payment, booking and privacy context.
The kernel does not reconstruct a full contract from its digest.

The outer BIP-340 signature signs the 32-byte digest
`SHA256(ASCII("swarma-grant-v3") || canonical payload bytes)`. The prefix is
exactly 15 ASCII bytes, without a terminator, length field or separator.
This fixed-prefix construction is not BIP-340's tagged-hash construction.
`Grant.SigningHash()` exposes this digest. Untagged signatures and alternate
prefixes refuse; there is no untagged v3 compatibility path. This pre-landing
revision supersedes the earlier development fixture signatures and grant IDs.

```text
SignedGrant = {"grant":<payload>,"signature":"<signature>"}
grant_id = SHA256(exact canonical SignedGrant bytes)
GrantPresentation = {"signed_grant":<SignedGrant>,"issuance":{"txid":"..."}}
```

The transport locator is unsigned and excluded from `grant_id`. Changing it
never changes the signed authority but always requires a fresh own-node check.
This avoids a cycle between the issuance transaction and its commitment.

## Mandatory issuance commitment

Concatenate the following **decoded raw bytes**, without lengths or separators:

```text
ASCII("swarma-issue-v1")              15 bytes
contract_sha256                      32 bytes
consent_event.id                     32 bytes
consent_event.sig                    64 bytes
landlord_sig                         64 bytes
grant_id                             32 bytes
```

The domain is exactly the literal above (15 ASCII bytes). SHA256 of that
concatenation is the 32-byte commitment. The transaction must have exactly one
OP_RETURN output, zero value, with exact script `6a20<commitment>`; any additional
OP_RETURN, alternate hash/push encoding or nonzero value refuses. The seal must
not appear among its inputs. Other outputs are allowed by the checking profile;
the planner emits only the commitment and pinned change.

The locator transaction must be actively confirmed. Raw serialization, txid,
RPC projections and active block membership are bound through the own-node
observation. Missing, wrong or reorged proof cannot become live. No issuer
journal, external indexer, block-time/MTP rule or optional batch proof can
substitute. First checking sees pending while issuance is unconfirmed.

The final commitment cannot be shown before renter signing: it depends on the
renter signature, landlord countersignature and signed-grant ID. A renter can
see the formula and own inputs first, then verify the final grant and commitment
after issuance. UI design for that sequence remains outside this module.

## Fresh checking and durable closure

`Check(ctx,node,policy,presentation,agentName,sender,now)` retains its Go argument
shape but accepts only v3. Policy pins both names, chain and seal script. It
checks both confirmed name generations, pending identity transitions, issuance,
seal ownership/unspent state, stable names/tip/mempool and elapsed expiry.

A valid pending landlord-key or agent-pointer change refuses without closure.
Malformed current/pending values and read failures also refuse without closure.
Nostr-only updates do not revoke grants. A confirmed key/pointer change closes
an old grant only after this verifier observed its matching generation, that
old generation's block is still active, and the new generation is not older.
A first mismatch or rollback to an older generation refuses without inventing
a forward rotation. A valid new pointer may close an observed old binding even
if its new target is absent. Returning to the old key/pointer never reopens a
recorded closure. Closures are observed per grant, not eagerly broadcast to all
verifiers. Old policy pins and old state must be retained to observe old grants.

An observed seal spend closes permanently, including a subsequently dropped
mempool spend. The verifier records one signed grant per seal ever, sharing the
v2 seal-index key and honoring existing v2 records. Independent first observers
cannot detect all equivocations or rotations they never saw. State must survive
restarts; deleting it is not an allowed recovery strategy.

V3 receipts use `grant_id`, `agent_name`, `landlord_name`; v1/v2 compatibility
fields are omitted. `scope` and `budget_sat` remain output constraints for the
separate enforcement point. This is a wire migration for downstream callers.
`Present` expects the stable signed-grant ID and only caches after fresh live
checking. `CachedGrant` returns public proof bytes/ID, never live authority.
Cache bounds are 64 entries **and** 60000 bytes; larger v3 proofs hit the byte
limit earlier. Refusals preserve old cached proof. Every later use must recheck.

The read-only `ResolveLandlordGrantKey(ctx,node,policy,landlordName)` API returns
`(key string, generation Anchor, refusal error)`. It validates only pinned
`network`, `genesis`, `landlord_name`, binds the raw confirmed name generation,
parses the same exact landlord value and checks pending key changes plus stable
name/mempool/tip. It opens no state directory and does not require an agent or
seal. Errors return an empty key/generation. A successful result is a current
identity observation, not a grant or external-effect approval.

A separate one-off authority consumer must compare the signing key and retain
its own observed generation and permanent closure journal. A proven forward
mismatch needs the prior generation block still active; `ReadObservation.Active`
is available to the consumer. Pending refusals and older rollback observations
must not invent a permanent rotation. A stateless lookup does not detect
unobserved rotation-and-return histories; no consumer may treat it as such.

## Issuer, plans and action compatibility

`IssueGrant` validates the original M3 admission package, confirmed payment,
current identities, pool and funding, and locally supplied private 0600 key.
It durably burns booking and pool before either landlord signature. A crash
before completion yields uncertain refusal; completed identical retries return
the exact stored grant/plan without re-signing, even after expiry, provided
none of its funding inputs is now a known or reserved pool seal. Replay is
not a renewed live approval. Conflicting request/package/spec/seal bindings
refuse. Existing booking/pool indices prevent reuse across v2/v3 issuers.

The result is `prepared/GRANT_PREPARED`, never live. `MakeGrantIssuancePlan`
validates declared offline funding, excludes the seal, bounds fees at 200
sat/vB using 140-byte input-script reserves, and returns an unsigned plan. It
does not reserve funding inputs or give chain-signing/broadcast authority.
A separate signer must recheck current inputs, custody, transaction and policy.
Only a later confirmed commitment allows live checking.

Funding may never use any output at the seal script. Issuer and v3 pool-planner
policy requires a P2PKH funding_script distinct from seal_script. Every declared
funding input and change output must use that pin; a missing/equal pin refuses.
Fresh issuer admission independently checks actual raw-bound funding prevouts,
not merely the input spec: seal-script UTXOs refuse with FUNDING_SEAL_SCRIPT,
even when unreserved, unlisted or falsely described as funding-script outputs.

V3 refill consumes only funding-script inputs and creates only explicitly counted
pool-seal outputs at the seal script. Its change returns to funding_script.
An explicit revoke alone may consume its selected seal, with change likewise
returning to funding_script. Frozen v1/v2 regression planning is unchanged.
These plans remain unsigned; the kernel needs no FundingScript to check grants.

Pool reservations remain defence in depth. The issuer checks every funding
outpoint against the durable pool-* index before replay and in both fresh
output-observation passes. Any bytes, including interrupted/corrupt state,
refuse with FUNDING_RESERVED_POOL; unreadable state fails closed. Optional
known_pool_seals inventory adds an offline/online exclusion for allocated
points. It is bounded to 4096 unique well-formed points; malformed lists refuse.
Safety does not depend on its completeness: all seal-script inputs are excluded.

Replay first revalidates the input/change script contract and current reservation
exclusions. Old completed development records with seal-script funding/change
therefore refuse; they never return their old plan. The funding pin is included
in the issuer binding. A prepared unsigned plan does not freeze chain state or
reserve ordinary funds. A separate signer must independently recheck actual
prevouts, the funding/change pin, reservations, custody and exact outputs
immediately before signing. One authoritative issuer reservation store remains
necessary for booking/pool uniqueness; script separation protects unknown seals.

Actions are sorted, unique members of `deliver`, `names.register`, `pay`,
`publish`, `repository.push`, `secret.release`; no wildcard or prefix matching.
This six-action set applies to v3 grants and authenticated M3 admission only.
Frozen v1/v2 decoders retain the original five-action set and refuse any
`names.register` scope, including correctly signed envelopes.
Existing M3 five-action contracts remain valid with `names.register` absent
and therefore ungranted. Explicit presence in either allowed or forbidden
requires all six actions to be partitioned without overlap. M3 generation must
adopt the new action separately; this module never rewrites signed contracts.
Optional budget absence is effective zero, distinct in signed bytes from an
explicit zero. Grant scope/budget never bypass a wallet's separate enforcement.

Optional batch anchoring remains explicitly enabled and supplemental. Legacy
v1/v2 check and issue paths are named explicitly; default v3 never falls back.
