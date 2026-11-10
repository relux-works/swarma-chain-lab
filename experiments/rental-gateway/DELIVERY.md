# DA1 delivery boundary

One ordinary station reply is bound to `(slot_id, delivery_id)`, where the
delivery ID is the admitted NIP17 rumor ID. The gateway publishes one immutable
signed event for that reply. A retry after uncertain relay acknowledgement uses
the same signed event bytes and event ID. A durably recorded relay acceptance
suppresses further publication, including after gateway restart. This establishes
**relay acceptance**, not renter display: a third-party renter's durable inbox and
display deduplication remain outside this implementation.

## Wire sequence

TLS and the existing per-slot HMAC handshake are unchanged. The authenticated
connection binds the slot; a caller cannot select another slot in a request.
Its System frame supplies the required validated `relay_max_event_bytes` before
the station pulls work. Missing or invalid caps refuse without a model call.

1. `pull` returns `deliver` with `slot_id`, `delivery_id` and complete `content`.
2. The station persists the exact input, then sends `received` with `delivery_id`.
3. The gateway persists receipt and returns `ack` with `slot_id` and `delivery_id`.
4. The station persists `in-flight` before a model call and `ready` with its result
   before sending `reply` with the same `delivery_id` and `content`.
5. The gateway persists the signed outbox event, publishes it, persists
   `relay-accepted`, then returns the ID-bound `ack`.

The Go stationlink API is `Received(deliveryID)` and `Reply(deliveryID, content)`.
Legacy Reply without an ID, unknown IDs, reply before receipt, and a different
reply for an existing outbox ID refuse. A Received request requires that this
connection was offered the delivery. Repeated matching receipts are idempotent.
The reply rumor includes an `e` tag naming its input rumor. All call sites must
move together; there is no unsafe fallback for older station clients. The local
gateway stub acknowledges for test purposes and has no durable station journal.

## Persistence and restart

The existing per-slot gateway journal retains complete input and its hash before
screening, commits `queued` only after screening allows, then records `received`,
`ready` and `relay-accepted`. The RAM queue is a wakeup only. A new connection can
pull retained queued/received/ready work, even if the old queue was full or lost.
An input is offered once per connection; a new connection retries pending input.

Screening is itself an external call. A crash-left `screening` reservation cannot
be assumed allowed or safely regenerated. Replaying it returns
`screening_uncertain`, performs no screening call, and never dispatches the input.
An explicit screening error/refusal is recorded as `refused`; existing warning
and strike behavior then applies. Legacy seen-ID-only records remain deduplicated
and cannot recover content that was never stored by the old version.

The station's explicit private journal stores the input and terminal reply,
bound to the exact bootstrap hash. Reopening an `in-flight` turn records the fixed
reply `uncertain` without invoking the model again. Ready/accepted turns reuse
their recorded reply. A model error with a known return code is also recorded;
same-ID replay does not retry that generation. Recoverable remote model-result
lookup is a separate DA1b contract.

`Client.Run` serves one connection. On a channel failure it exits with
`PAYLOAD_CHANNEL`; the supervisor/operator must restart it with the **same**
bootstrap and journal directory after the gateway is available. This change
does not add supervisor relaunch policy or automatic connection retry. No new
directory may replace pending state. Ready gateway publication resumes when the
station reconnects and replies; there is no background publisher bypassing
station recovery. If the gateway already marked acceptance but its final ACK was
lost, it does not offer the completed input again or publish another event.

Both journals use file sync, atomic rename and directory sync. An ambiguous
delivery write poisons further writes until reopen, preventing stale memory from
overwriting a possibly committed outbox. Checksums, schema/phase checks, exact
input binding and signed-event validation reject corrupt records without repair
or deletion. Checksums detect corruption, not an attacker who can rewrite private
state and recompute them. Existing one-process gateway ownership is unchanged;
the station journal additionally holds an exclusive lifetime lock.

Records remain with the slot and are not garbage-collected or reset here. Each
slot/journal permits at most 1024 delivery records, then refuses new inputs.
Input storage is bounded to 65535 UTF-8 bytes and reply storage to 32768 bytes;
existing channel/model bounds also apply. Every receipt and reply, including a
retry, rechecks current grant authority and slot expiry. Expired/revoked pending
work cannot publish. Ordinary replies use this outbox; existing ready, screening,
extension and slot-end control notices retain their separate lifecycle contract.

## Operator wiring and qualification

The payload requires `-journal-dir /absolute/private/slot-turns` (Go:
`Options.JournalDir`). The directory must already exist, be owner-only0700,
canonical and symlink-free, with no group/world-writable ancestor. No default is
inferred. Missing/unsafe paths, foreign binding, lock conflicts and corruption
refuse before a usable session. Files contain private input/replies and must not
be exported as public evidence. DK5b/Infra owns provisioning, retention and launch
wiring. DA1 r1 adds only the required public gateway size field to the shipped
gateway templates; no hosts or relay defaults are changed.

Run from rental-gateway with an isolated absolute HOME/cwd/cache/temp:

```sh
go test -race -count=1 ./...
go run .scripts/da1-guards.go -out /absolute/task-scratch/da1-guards
```

The DA1 runner mutates copied source, requires a passing baseline, and accepts
only each named assertion failure. Existing module guard scripts remain required.
Station payload tests use real TLS/HMAC and the real model proxy with a local
fake upstream, including lost receipt/reply ACKs and failed result persistence.
Gateway restart tests use real file journals and a controlled publisher boundary;
real relay event-ID deduplication is a separate relay integration test. Controlled
I/O failures/reopen exercise the persistence boundaries, not physical power loss.

## Reply-size terminal outcome (DA1 r1)

Gateway configuration requires `relay_max_event_bytes`, with **no default**.
Set it at or below the deployed relay's `max_event_bytes`; the shipped gateway
and relay templates use65536. Native startup refuses missing, zero, a cap too
small for the fixed notice, or a value above the relay's supported131072 maximum.
This is an explicit deployment assertion: the gateway does not discover or attest
a remote relay's configuration. Operators must align the two public configs.
A lower cap also refuses startup if an existing Ready wire exceeds it; restore
compatible configuration without rewriting the immutable signed outbox.

A raw UTF-8 reply up to32768 bytes can still exceed either NIP-44 plaintext
limit or the relay event limit after JSON escaping and nested encryption.
Before Ready, both station and gateway apply shared `nostr.BoundDeliveryReply`.
It serializes the actual rumor shape (one e-tag and one p-tag), computes NIP-44
padding/base64, serializes the seal, checks both65535-byte plaintext limits,
and computes the complete signed gift-wrap JSON size for the explicit relay cap.
Full key/ID/signature widths and maximum nonnegative int64 timestamp reserve
metadata independently of local clocks and encryption randomness. The actual
wrap at that timestamp is the executable size oracle, not a character heuristic.

An oversized answer becomes the fixed renter-visible reply
`reply exceeded deliverable size`. The gateway fsyncs that notice and its signed
wire as Ready before publication, then records relay-accepted normally. A lost
ACK retries only the same wire. Once accepted, PendingDelivery skips it and the
next input proceeds. The authenticated System frame supplies the same cap to the
station, which saves the same notice before its ready phase. No bootstrap or
journal-binding codec change is involved. A legacy ready oversized text reply
is normalized by the gateway without another model call. Replies mapping to
that fixed notice are the same normalized logical reply; a different deliverable
reply still refuses after Ready/acceptance. Exact saved legacy text remains
replayable when its actual signed wire fits the cap, even if maximum metadata
reservation would now classify that text as oversized. No wire is regenerated.
Keep the configured cap stable while
pending turns exist; raising it must not reinterpret a previously normalized reply.

At the default65536 cap the reserved-metadata plain ASCII maximum is28303 bytes
(about27.6KiB), while a32768-byte plain reply becomes the notice. Escaped text has
a lower effective maximum. Actual default-relay tests exercise a fitting24000-byte
reply, the32768-byte notice, and the following reply through the real gateway
publisher, then check both relay memory and its persisted snapshot. Separate
restart/lost-ACK tests verify byte-identical outbox reuse.

Gateway raw input above32768 bytes still refuses. Durability failures and authority
refusal remain unchanged: a notice cannot bypass a failed write, revoke, expiry
or receipt requirement. Relay acceptance is not renter display. Chunking is outside
this change; relay defaults and demo1 stay65536.
