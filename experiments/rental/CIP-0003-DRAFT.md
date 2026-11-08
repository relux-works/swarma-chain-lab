# CIP-0003 draft: rental certificates and kernel observations

Status: M1 handoff draft; separate format, no KeyVault schema change.

## Signed bytes

Canonical unsigned certificate is compact ASCII JSON in this exact order:
`version,network,genesis,station_name,agent_pubkey,issuer_pubkey,grantee_pubkey,contract_sha256,scope,not_before,not_after,seal,budget_sat`.
No whitespace/newline, unknown/missing/duplicate fields, aliases, null arrays,
floating numbers or alternative hex spellings are accepted. Parse into the
typed schema, validate and require byte equality with canonical encoding.
This is schema-specific canonical JSON, not general JCS.

Version is 1. Network and genesis are explicitly signed. Public keys are
32-byte lowercase-hex BIP-340 x-only keys; hashes/txids are 32-byte lowercase
hex. `station_name` is `id/` followed by 1..252 lowercase ASCII letters,
digits, dot, underscore or hyphen. Always compare it to the exact trusted
station pin. `id/swarma-station-*` is a deployment naming convention, not
an authorization rule. `agent_pubkey` identifies the stable gateway-held key;
stations have no long-term identity key. Issuer and provider countersigning
keys are separately pinned roles; they need not be the same key.

Scope is sorted and unique, drawn from `deliver`, `pay`, `publish`,
`repository.push`, `secret.release`. Empty `[]` means chat-only with no effects.
Budget is an integer number of Namecoin atoms, between 0 and 21 million NMC.
`not_before` and `not_after` are nonnegative UTC Unix seconds with increasing
bounds; admission uses `[not_before,not_after)`. Seal is exactly
`{"txid":"<hex>","vout":<uint32>}` in that field order.

Issuer signature is BIP-340 over SHA256 of the canonical unsigned bytes.
Envelope is exactly `{"certificate":<object>,"signature":"<128 lower hex>"}`.
Certificate ID is SHA256 of the entire canonical envelope, without newline.
Do not hash only the unsigned certificate or reformat the signed file.

## Station value and anchor

Active value, exact compact ASCII JSON and field order:

```json
{"swarma":{"rental_issuer_pubkey":"<issuer>","rental_certificate_sha256":"<envelope hash>","rental_seal":{"txid":"<txid>","vout":0}}}
```

Idle value is exactly `{"swarma":{"rental_issuer_pubkey":"<issuer>"}}`.
No null or partially present certificate/seal pair is valid.
The current name output must be an active confirmed raw `name_update` back
to the pinned station script. Its transaction has exactly one OP_RETURN,
zero valued, with exact script `6a20<envelope sha256>`. Raw serialization,
RPC projection, active header and block membership must agree. Seal is a
positive-value confirmed P2PKH output at the station script, strictly older
in height than the anchor, and unspent in mempool-inclusive gettxout.

## API and lifecycle

`Check(ctx,node,policy,envelopeBytes,stationName,senderPubkey,nowUnix) Receipt`
returns `live`, `pending` or `refused`; only live admits. The sender must be
the NIP-17 authenticated inner-seal key supplied by the gateway, equal to the
grantee. The kernel does not implement NIP-17 or judge action scope.

Primary pending reasons: NOT_YET_VALID, ANCHOR_UNCONFIRMED, ANCHOR_INACTIVE,
SEAL_UNCONFIRMED. On actual Core a new mempool anchor normally leaves the
previous confirmed name value visible, so the result can be refused/NAME_VALUE
rather than pending; both deny. Refusal codes identify invalid signatures,
canonical input, policy/name/transaction binding, expiry, node/projection
failure, resource bounds or unsafe/corrupt/busy state. These are not retries
or permits. Scope/budget are authenticated data only.

After proving the seal's confirmed existence, null from successful
mempool-inclusive gettxout proves a spend. Persist closure before returning
refused/SEAL_SPENT. When a previously accepted station generation remains
active and a later current confirmed generation changes its value, persist
refused/NAME_REPLACED, including a transfer to another payment script.
Closures never reopen after dropped spends, reorgs, restored values or restart.
Store accepted generation and closure under network/policy/certificate pins,
with private files, exclusive lock, file fsync, atomic rename and directory
fsync. Missing/corrupt/unavailable storage cannot yield live.

An anchor rollback alone is not proof of replacement and can recover.
Unobserved history cannot be inferred from the certificate alone; a fresh
kernel with no generation history refuses a mismatched current value but
cannot claim to have observed a historical replacement. Preserve state.

**Rental-specific change from decisions/0002 F4:** a failed or ambiguous node
read refuses without permanent closure. Only proven spend/replacement closes.
A paid slot must not die on a node hiccup; safety holds because that failed
observation does not admit. Existing verifier/watcher profiles are unchanged.

## Issuer admission and M3

Consume M3's exact issuance request and signed kind-8182 package event.
Verify event ID/signature and pinned provider, canonical package, provider
countersignature over contract hash, renter kind-8181 consent and exact tags,
privacy acknowledgement, and request/contract field equality. The package
appends `hold_created_at,hold_expires_at` after `privacy_sha256`, protected by
the publication signature. Consent must lie inside those signed bounds.

First online admission for **both** advance and start_now requires trusted
`now < hold_expires_at`; equality refuses `hold_expired_at_admission` for
refund/operator review. Never use miner block time as observation time. M3's
default hold is 1800 seconds, configurable within its 1200..1800 policy.
Both advance and start_now require payment confirmed in the active chain now.
A mempool-only or rolled-back payment refuses `payment_unconfirmed`; a wallet
sequence number cannot disable full RBF. Start_now means the slot starts after
the subsequent anchor confirmation (two blocks total), not mempool issuance.
Match the exact
outpoint amount/address to the signed contract; a replacement transaction is
not a substitute even if it pays the same amount/address. Recheck before
return. Missing transaction/read failure refuses; it need not be distinguished
from a temporarily unavailable node to avoid admission.

AdmitIssuance is read-only and not a durable spending capability. M4 must
invoke it immediately before signing and independently verify pool/funding
prevouts, templates and caps. Payment replacement/disappearance after issue
triggers revocation. Start_now never relaxes the confirmed anchor/seal rules.

Payment serialization may be legacy or witness. The shared decoder validates
the exact marker/flag (00/01), minimal CompactSize values, witness stack for
each input, non-superfluous witness and complete consumption through locktime.
Bounds: 1 MiB raw, 64 inputs/outputs, 1000 witness items per input and 10000
bytes per script/item. Use stripped txid, not wtxid; bind raw outputs and
projected outpoints. Core establishes witness script/signature validity and
active confirmation. This read path returns a stripped transaction view; it
is not a witness-preserving signing/rebroadcast API. Anchor/seal decoding and
W3 signer attribution retain their existing legacy-only profile.
