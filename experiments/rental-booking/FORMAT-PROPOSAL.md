# M3 / M1 interface proposal v1

Status: accepted baseline by the orchestrator; M1 action agreement received.
Amendment: signed package hold bounds added on 2026-11-08 at M1 request.
2026-11-08, M3-01. Shared approval is required before the issuer depends on it.

## Common encoding and vocabulary

Canonical form: UTF-8 JSON, compact, no final newline, exactly the documented
field order, integers in decimal without leading zeroes, ASCII string values,
no unknown/missing/duplicate keys. Hex is lowercase, keys/hashes/txids are
64 hex characters, signatures 128. Arrays cannot be null. Actions are unique
and sorted lexicographically. Canonicalize by validation + typed encoding;
compare supplied canonical bytes exactly when verifying a contract package.
No floating-point numbers, implicit network, or implicit action grants.

Proposed closed action set: `deliver`, `pay`, `publish`, `repository.push`,
`secret.release`. Allow/forbid arrays must partition this set; overlap and
unknown actions are invalid. A template chooses explicit actions/targets;
M4 must enforce exact destinations in structured requests, including repo
push targets. `secret.release` is forbidden in the contest template. M1
exports scope/budget; it does not interpret conversation or enforce actions.
Budget is integer `budget_sat` (Namecoin atoms, 10^-8 NMC); it is independent
of the booking fee. M3 never grants a default spending budget.

## Contract

Field order:

```
version, booking_id, renter_pubkey, renter_name, agent_pubkey, station_name,
not_before, not_after, allowed, forbidden, budget_sat,
template_id, template_sha256, profile_id, profile_version, profile_sha256,
price_usd_cents, usd_micros_per_nmc, rate_as_of, price_nmc_sat,
payment_policy, payment_address, privacy_sha256
```

`version` = 1. `booking_id` is 32 random bytes as lowercase hex. `renter_name`
is empty when no name is claimed; otherwise booking verifies unexpired
`name_show` value `swarma.nostr_pubkey` equals the renter key under a coherent
tip. `agent_pubkey` is the stable public agent key; no station Nostr key.
Times are UTC Unix seconds; `not_after > not_before`, duration <= 3600.
`payment_policy` is `advance` or `start_now`. `privacy_sha256` commits to the
exact displayed notice. Template bytes carry id, profile pins, allowed/forbidden
classes and budget; startup verifies their hash and the actual profile bytes.
`contract_sha256` is SHA-256 of canonical contract bytes.

Quote formula: ceil(price_usd_cents * 10^12 / usd_micros_per_nmc).
Freeze all quote fields at hold creation; checked integer arithmetic only.

## Renter consent and provider package

Experimental regular event kind 8181 (local scope, not a registered NIP):
`created_at` in [hold_created_at, hold_expires_at), not in the server's future;
`pubkey` = renter_pubkey; `content` = empty string. Exact ordered tags:

```
[["t","swarma-rental-consent-v1"],
 ["contract",contract_sha256],
 ["booking",booking_id],
 ["privacy",privacy_sha256]]
```

NIP-01 id is SHA-256 of `[0,pubkey,created_at,8181,tags,""]`; verify BIP-340
signature and id before accepting. Replay to any other booking fails. The
browser gets pubkey with NIP-07 `getPublicKey` and signs this event with
`signEvent`. Receipt must arrive before hold expiry. The privacy checkbox must
be explicitly true before address allocation; store acknowledgement time/hash,
and include both in the completed package. The signed privacy tag binds it.

Provider countersignature = BIP-340 signature over the same 32-byte
contract_sha256, with a pinned provider public key. Package field order:
`version, contract, consent, provider_pubkey, provider_signature,
privacy_ack_at, privacy_sha256, hold_created_at, hold_expires_at`. Contract is embedded JSON, not base64. The signed hold bounds allow downstream consent-time checks. They are not proof of when a payment was observed; initial advance admission after hold expiry requires an additional trusted receipt or must refuse.
A provider-signed Nostr event kind 8182 publishes canonical package JSON in
content, with `t=swarma-rental-package-v1`, `contract`, `booking`, and `e`
(consent id) tags. Persist the event before publishing; retry the exact id
until the loopback relay acknowledges that id with OK/true. No new event on
retry. A package alone is not a payment receipt.

## Issuance request

One durable outbox entry per booking, only after complete verified package,
relay acknowledgement, and eligible current payment observation. Canonical
field order:

```
version, booking_id, station_name, agent_pubkey, renter_pubkey,
contract_sha256, scope, budget_sat, not_before, not_after, payment_policy,
payment_txid, payment_vout, payment_height, payment_block_hash,
observed_tip_hash, package_event_id
```

For both `advance` and `start_now`: height > 0 and nonempty block hash, active
chain confirmation observed before hold expiry. M3-02 removes mempool-only
issuance. start_now concerns scheduling after anchor confirmation; it does not
relax the payment gate or mutate already signed contract times.
`scope` is the contract's allowed list. M1 must independently re-check payment
status and the package before actual issuance; this file is a request, not an
authority to spend or an eternal assertion of payment liveness. Outbox file
name is the booking id. Repeated scans cannot create a second request.

Revoke outbox: `version, booking_id, contract_sha256, payment_txid,
payment_vout, reason, observed_tip_hash`; reason is `payment_reorged` or
`payment_disappeared`. Durable once per issued booking, status `revoked`. An
issued payment disappearing/reorganizing never automatically reissues. A
mempool-only payment is pending for either policy and cannot create issuance
or revocation; replacement/drop cannot make the old outpoint paid. Another
current confirmed payment may qualify during the hold. Extra/late outputs
remain refund-review data.

Open integration questions: M1 acknowledgement/dequeue and revoke consumer
contract; exact shared action spellings; whether an emission is considered
handed off even before M1 ack (proposal: conservative yes). No production
issuer automation is implied by this regtest file interface.
