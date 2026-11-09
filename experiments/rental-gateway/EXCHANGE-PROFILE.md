# E1 deterministic rental exchange (implementation contract)

This regtest exchange is a gateway path for authenticated NIP-17 senders who do
not have a live rental grant. It never invokes screening, creates an instance,
or signs a contract/grant/transaction. The agent messaging key signs only the
fixed response formats below. Booking and issuance remain separate services.

## Commands and replies

Commands are exact, case-sensitive ASCII rumor content. No leading/trailing
whitespace, aliases, prompt interpretation or extra arguments. A first-contact
rumor carries one NIP-13 `nonce` tag with canonical decimal nonce and target
at least the configured difficulty. Work is measured on the recomputed rumor
ID, bound to the authenticated inner seal sender; the ephemeral wrap key is
never a renter identity. Duplicate/malformed nonce tags refuse.

| Command | Required state | Response |
| --- | --- | --- |
| `terms` | Non-grantee; no pending reply or issued pre-window hold | `terms\n` followed by the terms JSON below |
| `book <template> <slot> [coin]` | Terms delivered; no unexpired hold | `contract\n` followed by contract JSON |
| `consent <canonical kind-8181 event JSON>` | Active hold belonging to this sender | `pay\n` followed by payment JSON |
| Automatic issuance notification | Booking consent/payment accepted; issuer supplied a grant | `issued\n` followed by grant JSON and its window |
| Slot-start timer | Normal current-time kernel Check says live | `ready` |

Omitted coin means `nmc`. The adapter's closed coin set is `nmc`, `btc`, `ltc`;
unsupported configured routes refuse without booking. Contract bytes are
opaque to the exchange; one booking adapter owns v1/v2 interpretation.

Every admitted malformed/out-of-order/unsupported command gets exactly (subject
to the pending-reply and issued pre-window rules below):

```text
Rental exchange: send terms, then book <template> <slot> [coin], then consent <signed kind-8181 event JSON>. Booking acknowledges the privacy notice shown in terms. Wait for ready before sending a message with your grant.
```

Overload, bad work and replay are silent drops, not amplification responses.
Backend unavailability gets exactly `Rental exchange unavailable; retry later.`
No untrusted error strings or model output are signed as exchange responses.

Response JSON is compact, fixed field order, no HTML escaping, with these fields:

- Terms: `agent_name`, `landlord_name`, `privacy_notice`, `privacy_sha256`,
  `templates` (id, template pin, profile id/version/pin, USD cents, slot lengths),
  `slots` (id, template id, start/end, available coins), `pow_bits`.
- Contract: `booking_id`, `contract_sha256`, `contract_base64`, `hold_expires_at`.
  Base64 preserves the exact canonical signed-wire input, including escaping.
- Payment: `booking_id`, `coin`, `address`, `amount_atomic`, `hold_expires_at`.
- Issued: `booking_id`, `grant_id`, `presentation_base64`, `not_before`, `not_after`, `notice`.
  This notice says the slot starts at `not_before` and does not vouch for live
  authority. The presentation is
  inline and its signed-grant ID is the S1 object key. Issuer publication to S1
  remains outside the exchange; delivery does not claim store availability.

Terms disclose the exact existing booking privacy notice. Only a subsequent
explicit `book` command acknowledges it. Consent must be signed by the inner
seal sender and bind this active booking/contract/privacy hash; the booking
service performs its existing canonical validation. No consent is synthesized.
Late/expired consent cannot advance to payment. The separate booking watcher and
issuer enforce timely payment and issuance; the exchange never manufactures their
records. An already-issued presentation may be delivered after hold expiry, with
current liveness still determined only by the kernel.

## Boundaries and recovery

The gateway classifies the sender through the existing slot/fresh kernel path.
Live grantees bypass all exchange PoW, buckets and queues. Every non-live path
stays outside screening and station delivery. Exchange requests enter a bounded
nonblocking queue; a single worker performs bounded booking calls and fixed
replies independently from the relay read/ACK pump. Full queues drop immediately.

Per-sender token buckets use the authenticated seal key. A bounded first-contact
PoW cache expires; replay IDs have a bounded validity window. Limits, state
capacity and message sizes are explicit configuration with hard upper bounds.
At capacity, a fresh sender must pass PoW before the oldest unprogressed entry
can be evicted: empty phase, no hold/consent or pending response. Age is the
retained knowledge horizon, with sender-key order breaking ties. The old file is
removed and fsynced before replacement; failures poison/refuse the engine. All
protected entries means new admission still refuses. Evicted introductions lose
cached terms, bucket and replay state and require first-contact PoW again. A
still-valid old proof may qualify: there is no global replay tombstone. An old book command
cannot reuse their lost terms. This does not guarantee fairness under continuous
Sybil churn. Memory and private client-file counts remain bounded. Retained bucket state,
clock high-water, accepted command IDs, hold mappings and pending notification
facts survive restart; queue contents are volatile and unacknowledged requests
may be retried. Ambiguous booking effects fail closed rather than issuing a
second booking. The booking service retains authoritative holds and consent.

The exchange receives issued grants through a separate read-only issuance source;
it has no landlord signing key or transaction broadcast capability. Issuance
notification may register a dormant slot, but never starts it. The renter's later
first message must carry the inline presentation and pass the normal fresh
kernel gate before lazy instance creation or screening.

NIP-01 subscription events do not contain the original client IP. E1 therefore
implements no gateway per-IP limiter and trusts no IP tags/headers. Per-IP and
connection limits belong to the operator's relay deployment policy. This is an
explicit maintainer scope decision; application work limits do not claim to
prevent transport/cryptographic CPU exhaustion before authentication.

## Booking adapter and evidence plan

The exchange sees a narrow catalogue/book/consent/status interface plus a
separate issued-presentation source. The adapter alone translates service types and
checks returned sender, agent, slot, contract hash and expiry. The booking
service gains one read-only catalogue method in a separate file: no signed
contract, consent, package or issuance wire changes. Availability excludes
unexpired holds and issued overlaps, applies start-now margin, and uses a
bounded time window and result limit.

Required controls include every transition and refusal beside a valid neighbor;
wrong signer/hash/expired consent; malformed/insufficient work; same-key and
many-key saturation; memory bounds, replay, clock and restart; queue saturation
and slow backend while a live grantee proceeds and relay ACKs still complete;
no screening/instance side effects; genuine Core terms-to-book-to-consent-to-pay
through real issuance, ready delivery and the first admitted station message.
Guard plants must reach their intended assertions, not skips or setup failures.

The slot-start timer uses the normal current-time kernel Check. It emits `ready`
only on a live verdict, otherwise exactly `Rental grant is not live; try again
later.` once. Pre-window messages receive exactly `Rental slot has not started
yet.` No fabricated future clock or new issuance-source authority is used.

Protocol references: [LIP-0003 section 7 at v0.1.3](https://github.com/relux-works/swarma-link-spec/blob/v0.1.3/lips/LIP-0003-detached-grants.md)
and [NIP-13](https://github.com/nostr-protocol/nips/blob/master/13.md).

## Resource and restart contract

| Resource | Default | Hard maximum |
| --- | ---: | ---: |
| Retained sender records | 32 | 64 |
| Inbound queue | 32 rumors | 128 rumors |
| Bucket burst | 8 | 64 |
| Replay IDs per sender | 32 | 64 |
| Rumor content / serialized rumor | 8192 / 12288 bytes | fixed |
| Client file | 65536 bytes | fixed |
| Catalogue JSON / fixed response | 16000 / 24000 bytes | fixed |
| Inline issued presentation | 16384 bytes | fixed |
| Backend/publish call deadline | 2s | 5s |

The default bucket refills one token per 10s; first-contact knowledge lasts 600s;
rumors are valid for 300s with at most 30s future skew. These are configurable
within the bounds enforced by Config. Replay capacity can also stop a sender
whose tokens have refilled. The default PoW target is 16 bits (configurable 1–32).
The sender must commit a target at least as large and supply at least the required
actual leading-zero work. Dependency implementations must honor context deadlines;
the engine never spawns unbounded goroutines to abandon a stuck dependency.

Each retained client has one private file, limiting client data to 4 MiB at the
hard cap, plus bounded metadata. A lock prevents concurrent engines on one root.
Corrupt, missing binding, unsafe-permission or incompatible-config state fails
closed. State is bound to agent/landlord, limits and the actual messaging public
key. A monotonic persisted clock high-water refuses rollback. Loss or rollback
of the whole state directory is outside these restart guarantees; do not discard
it to recover service.

Accepted rumor IDs and token debits are persisted before external effects. Each
response is persisted as an exact encrypted, signed gift wrap before publication;
retry after an unknown ACK outcome republishes that same event ID. Delivery is
at-least-once at transport level and recipients/relays can deduplicate by ID.
While such a reply is pending, a newly admitted command is consumed solely to
retry it; send a new command after receiving the reply. Issued pre-window senders
receive the fixed not-yet response instead of commands. Polling retries pending
responses without allocating a new event or spending another command token.

A durable `book_pending` intent precedes the backend Book. An unknown outcome
retains this intent and never repeats Book, including after restart; it requires
operator reconciliation against authoritative booking state. The fixed reply is
"Booking pending reconciliation. Wait or retry terms; do not repeat the booking."
Further commands return that same text without echoing input; `terms` can still
refresh the catalogue and never resets the booking intent. Explicit no-effect
rejections can retry. Without capacity pressure, ordinary idle records are reclaimed after knowledge,
replay and full bucket refill horizons have elapsed, with no pending response or
unexpired slot; ambiguous booking intents are never automatically evicted.

At start, the ready/not-live decision is made once and its exact reply persists.
A transient kernel failure therefore yields the fixed non-live notice once;
a later renter message can independently pass the normal fresh gate. Gateway
journal and exchange state must both be retained. Every new message is subject
to fresh kernel authorization even after a previous ready notice.

## Implementation limits

This is opt-in library wiring on the existing regtest gateway experiment, not a
production serve binary or relay deployment. The v1 adapter does not implement
BTC/LTC; P1's contract-v2 service will require a separate adapter change. The
existing gateway presentation/screening/closer notices are outside this exchange
worker; E1's ACK control proves that exchange work itself leaves the read pump
available, not that every legacy gateway operation is asynchronous. First-contact
work does not eliminate NIP-17 decryption cost or transport-level DDoS.
