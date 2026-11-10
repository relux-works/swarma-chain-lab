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
wiring; no deployment templates or hosts are changed by DA1.

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
