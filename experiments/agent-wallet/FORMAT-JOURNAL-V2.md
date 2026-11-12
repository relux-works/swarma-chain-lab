# Journal v2 and UTC day buckets (PX1 stream S2)

This file documents the G2 journal engine in `px1_journal.go` and the G2
service layer in `service.go` / `px1_service_seams.go`. The frozen contract is
`px1_journal_api.go`; this text adds the rules that the contract leaves to the
implementation. Under W2 (no `g2` operator block) nothing here is used.

## Files and locks

| Layer | Directory | Lock | Writer |
| --- | --- | --- | --- |
| wallet | wallet config `state_dir` (next to the W2 `wallet.json`) | `journal-v2.lock` | wallet layer (S1) |
| service | service config `state_dir` (next to the W2 `service.json`) | `service-v2.lock` | service layer (S2) |

Each layer is a chain of segment files `journal-v2-000001.json`,
`journal-v2-000002.json`, ... Every write goes through `durable.Store.Write`
(temporary file, fsync, rename, directory fsync). A new journal writes an
empty segment 1 at open, so the header binding is pinned before the first
record.

## Segment format

A segment is the compact canonical JSON of `JournalSegmentV2`:
`{header, index, prev_sha256, first_seq, records}`.

- `header` must equal the opener's header in every member (`version` 2,
  `layer`, `binding`, `receipt_key`), so the reconcile signer is pinned on
  disk. The opener's `receipt_key` must be `""` or a valid x-only key (64
  lowercase hex digits that parse as a BIP-340 public key); anything else
  refuses `JOURNAL_SEGMENT` before the directory is touched. The wallet
  layer names the executor receipt key; the service layer names `""`.
- `index` is 1-based and contiguous.
- `prev_sha256` is the SHA-256 of the exact bytes of the previous (sealed)
  segment, or 64 zeros for index 1.
- `first_seq` is the previous segment's last `seq` + 1. `records` is never
  `null`, and only the last (active) segment may be empty.
- The active segment seals when the next record would exceed
  `SegmentMaxRecords` (default 128) or `SegmentMaxBytes` (default 61440,
  at most 65536) of canonical JSON. The record then starts the next segment.
  A record that cannot fit an empty segment refuses `JOURNAL_RECORD_SIZE`
  and nothing is written.

Open re-verifies the whole chain and replays every record through the same
checks as `Append`, including `VerifyReconcileV2` for every stored
`reconcile`. Any failure (strict JSON, non-canonical bytes, header, index,
chain, `first_seq`, `seq` contiguity, a reconcile signature, the record table,
a missing or stray `journal-v2-*` file) refuses `JOURNAL_SEGMENT`.

## Records

`Append` assigns `seq` (previous + 1, from 1; the caller's `seq` is ignored)
and rejects, in this order:

1. a closed journal (`STATE_UNAVAILABLE`) or a poisoned one (`JOURNAL_WRITE_UNCERTAIN`);
2. for a `reconcile`: `VerifyReconcileV2(header, record)` with the assigned
   `seq` (`RECONCILE_AUTHORIZATION`); see "Release authorization";
3. `last_time` below the previous record's `last_time` (`CLOCK_ROLLBACK`);
4. any violation of the table below (`JOURNAL_RECORD`), and for a
   `reconcile`: its evidence rules (`RECONCILE_EVIDENCE`), then the interval
   (`RECONCILE_RATE_LIMITED`);
5. an `admit` when `admitted == SpendCapacity` (`SERVICE_JOURNAL_LIMIT`);
6. a record too large for an empty segment (`JOURNAL_RECORD_SIZE`).

A failed durable write poisons the journal. That append and every later one
refuse `JOURNAL_WRITE_UNCERTAIN`, and `FoldLedgerV2` refuses a poisoned
journal.

### Kind, layer and phase

The record's `phase` field follows the frozen kind table. The column "May
follow" is keyed by the request's **accounting phase**: execution records
(`reserve`, `complete`, `uncertain`, `refuse-retained`, and the service
kinds) set it; a `track` record never changes it (Q12); a `reconcile` sets
it to `released` only when nothing stays retained. A partially released
request therefore keeps its accounting phase, and nothing may follow a fully
released one.

| Kind | Layer | Phase field | May follow accounting phase |
| --- | --- | --- | --- |
| `admit` | service | `pending` | (no record for this nonce) |
| `service-reserve` | service | `reserved` | `pending` |
| `terminal` | service | `terminal` | `pending`, `reserved` |
| `reserve` | wallet | `reserved` | (no record for this grant and nonce) |
| `complete` | wallet | `complete` | `reserved` |
| `uncertain` | wallet | `uncertain` | `reserved` |
| `refuse-retained` | wallet | `refused` | `reserved` |
| `track` | wallet | `confirmed` or `conflicted` (= `track.state`) | `reserved`, `uncertain`, `complete` |
| `reconcile` | wallet | `released` | `reserved`, `uncertain`, `refused`, `complete` |

The request key is the action nonce (32 hex) in the service layer, and
`grant_id` + derived wallet nonce (64 hex) in the wallet layer.

### Field rules

- `inputs` is never `null`; `request_hash` is 64 hex; `created` and
  `last_time` are non-negative.
- Exactly one optional member: `service` for `admit`, `service-reserve` and
  `terminal`; `track` for `track`; `reconcile` for `reconcile`.
- **Service layer:** `action` is `spend` (with a 64-hex `grant_id`) or `receive`
  (with an empty `grant_id`). `service.request` must hash to `request_hash`
  and carry the same `nonce`, `action`, grant ID and `created_at`.
  `service.receipt` is present only on `terminal`. An `admit` has no plan
  fields. A spend's `service-reserve` and `terminal` may mirror the wallet plan
  (`reserved_sat`, `fee_sat`, `inputs`, `txid`), with `day` left empty: the day
  bucket authority is the wallet layer.
- **Wallet layer:** `action` is `spend`. Every record carries the plan:
  `reserved_sat > fee_sat >= 1`, `reserved_sat` at most 21,000,000 NMC,
  a 64-hex `txid`, and 1..16 distinct `inputs`. `day` is `UTCDay` of the
  **reserve record's** `last_time`.
- **Follow-ups copy the first record.** Every record after `admit` or
  `reserve` repeats its `request_hash`, `action` and `created`. In the wallet
  layer it also repeats the plan (`reserved_sat`, `fee_sat`, `day`, `inputs`,
  `txid`). In the service layer it repeats `service.request` and `service.peer`.
  The record then adds its own `kind`, `phase`, `last_time` and payload.
- **`track`** (S3 writes it, S2 stores it): the binding fields are copied from
  the request's `reserve` record (`grant_id`, wallet `nonce`, `request_hash`,
  `action`, `reserved_sat`, `fee_sat`, `day`, `inputs`, `txid`, `created`);
  `last_time` is the executor clock; `state` equals the phase; `height >= 0`;
  `block_hash` is 64 hex; `confirmations >= 1` for `confirmed`;
  `conflict_txid` is empty or 64 hex, empty for `confirmed`, and never the
  payment's own `txid`. A track record never changes a debit, a day count,
  an input reservation or the accounting phase.
- **`reconcile`:**
  - `target_seq` is the `seq` of the request's `reserve` record.
  - `released_sat` is between 1 and the debit still retained; several
    partial releases may follow each other.
  - `note_sha256` is 64 hex (`JOURNAL_RECORD`). The `signature` is checked
    by `VerifyReconcileV2` before this table (`RECONCILE_AUTHORIZATION`).
  - Evidence (`RECONCILE_EVIDENCE`): `evidence` is `absent` (empty
    `conflict_txid`) or `conflict` (a 64-hex `conflict_txid` that is not the
    payment's own `txid`).
  - Authorization (`RECONCILE_AUTHORIZATION`): see below.
  - No replay: the signed preimage contains the record's `seq`, so the bytes
    of an applied authorization verify at no other position, and appending
    them again refuses `RECONCILE_AUTHORIZATION`.
  - `last_time` is at least `ReconcileMinIntervalSeconds` after the previous
    reconcile record (`RECONCILE_RATE_LIMITED`).

### Release authorization (Q8, freeze amendment 1)

The signer is the receipt key named in the journal header
(`JournalHeaderV2.ReceiptKey`, A5). A `reconcile` record is accepted only when
the frozen `VerifyReconcileV2(header, record)` passes: a BIP-340 signature by
that key over `ReconcileDigestV2`, which is
`SHA256("swarma-wallet-reconcile-v2" || canonical({binding, grant_id, nonce, seq, reconcile with signature ""}))`
(A6). The signature therefore binds the journal binding, the request
(`grant_id`, `nonce`), the position (`seq`) and the whole payload. A
signature over the superseded v1 preimage, by another key, for another
journal, grant, nonce or `seq`, or under a header whose `receipt_key` is `""`
refuses.

Verification runs at three sites, each with its own call:

- `Append`, after `seq` is assigned and before the record is written. The
  operator CLI signs for `Usage().LastSeq+1` while it holds the journal lock;
  if another record took that `seq` first, the release refuses and must be
  re-signed.
- Open (replay): every stored `reconcile` is verified under the opener's
  header while loading. A replaced or lifted signature refuses
  `JOURNAL_SEGMENT`.
- `FoldLedgerV2`, under `j.Header().ReceiptKey`, for any `JournalV2`
  implementation. A release that does not verify refuses
  `RECONCILE_AUTHORIZATION` and nothing is folded; after it, the journal's
  own table still applies (`JOURNAL_RECORD`).

A shape-valid signature is not authentication, and a verified signature is
not sufficient: the amount, target and evidence rules above still apply.

One check stays outside the journal: whether the cited chain evidence is
true (the tip `height`/`block_hash`, absence, the conflicting spender) needs
a node. That is the operator tool's job.

## Capacity

- `SpendCapacity` counts `admit` records only. Reads are never journaled.
  Follow-up records of an admitted request are never refused for capacity.
- `RequiredSpendCapacity(day_count, not_before, not_after)` is
  `day_count * UTCDaysSpanned(not_before, not_after) + 64`. It returns -1,
  which never fits, for a day count outside 1..1000 or an overflowing window.
- The service layer checks every spend's grant at step 8. It uses the
  operator's `max_day_count`, which is an upper bound of the effective day
  count. If `journal_spend_capacity` is below the requirement, the spend
  refuses `JOURNAL_CAPACITY_CONFIG` before any effect. Integration step 3 may
  narrow this to the effective terms value.
- The service refuses an admission whose record could not leave room for its
  terminal receipt in an empty segment (`SERVICE_JOURNAL_LIMIT`).
- `px1jHighWater` reports usage at or above 80 % for the S3 alert.

## Ledger fold and day buckets (Q4, signer-service rule)

`FoldLedgerV2` verifies every release under `j.Header().ReceiptKey` and
re-checks the table while folding, so a foreign `JournalV2` cannot inject an
unbacked release. For every `reserve` record of a grant:

- **Retained debit** = `reserved_sat` minus the sum of reconcile
  `released_sat`. `SpendUsed` sums it over all records, released or not.
- **Open records** are those whose accounting phase is `reserved` (no outcome
  recorded, for example after a crash) or `uncertain`. An open record counts
  its retained debit toward **every** day until an outcome or a release of
  the whole debit closes it. `UncertainSat` sums the open records. A `track`
  record or a partial release leaves the record open.
- **Other records** (accounting phase `complete`, `refused` or `released`)
  count only toward their reservation `day`, with their retained debit. A
  release lowers the sats but keeps the count, because a day count is never
  given back.
- `InputReserved` covers the inputs of every record that still retains a
  debit (accounting phase other than `released`).
- The day key is `UTCDay(executor clock)`, so a new day starts at
  00:00:00 UTC exactly. The request's `created_at` never selects a day.

## Clock guard

`NewClockGuard(clock, journal last_time)` refuses `CLOCK_ROLLBACK` when the
clock reads below `last_time` at startup. `Now` refuses when the clock reads
below the highest value seen so far, and a refusal never lowers that value.
The service uses one guard for admission, reads and its own follow-up
records. The journal enforces non-decreasing `last_time` on its own as a
second layer.

## Read limiter (T17)

- `balance`, `history` and `budget` are never journaled.
- Each grantee may make `read_rate_per_hour` reads in the trailing hour.
  Further reads refuse `READ_RATE_LIMITED` before any node call.
- A timestamp later than the current clock still counts, so a clock step back
  frees no read budget.
- A rate of 0 or less refuses every read.
- The limiter tracks at most 1024 grantees and drops the idle ones.
- The audit tail keeps the last 1024 decisions, newest last. Each entry holds
  `{at, grantee, action, verdict, reason}` and never a request body.
- Read receipts are signed with `journal_seq` 0 and are not stored, so a read
  replay runs the read again.

## G2 service flow (steps 5-23 at the service layer)

1. Refuse `SERVICE_STATE_UNAVAILABLE` if the service or its journal is
   poisoned.
2. Send reads to the limiter path. For a spend, ask S3's admission halt
   seam (`px1oHalted` on `*ActionService`, probed as an optional method so
   that any landing order compiles). A non-empty answer refuses before
   admission, with nothing journaled. `FLOAT_CANARY_SPENT` (T14),
   `STATE_RECONCILE_REQUIRED`, `SERVICE_STATE_UNAVAILABLE` and
   `PX1_NOT_IMPLEMENTED` pass through; any other answer refuses
   `SERVICE_STATE_UNAVAILABLE`. Without S3 nothing halts here.
3. Look up the nonce in the service journal:
   - other bytes: `NONCE_CONFLICT`;
   - `terminal`: return the stored receipt bytes;
   - `reserved`: store and return `uncertain` `DURABLE_RESERVATION_NO_RETRY`;
   - `pending`: run the request again. The wallet layer answers its own
     retained reservation.
4. First admission: clock guard (`CLOCK_ROLLBACK`), skew (`ACTION_SKEW`),
   capacity (`SERVICE_JOURNAL_LIMIT`), then the `admit` record. The receipt's
   `journal_seq` is the `admit` record's `seq`.
5. Step 8: a non-standing request kind, a proof, or a non-standing grant
   object refuses `SINGLE_USE_DISABLED`. The grant is resolved from the
   objects directory, then step 9 (`GRANT_GRANTEE_MISMATCH`), then the
   capacity check for the grant's window, then the terms bytes by
   `contract_sha256`.
6. Step 11 is the own-node observation.
7. A spend refuses `PX1_NOT_IMPLEMENTED` until the wallet layer's journal v2
   is attached. Then the wallet layer (S1) runs steps 12-19 and 21-23. The
   `before` callback appends `service-reserve` with the wallet plan (step 20).
8. After an `executed` spend, the service builds a `TrackedPayment` from the
   wallet `reserve` record and passes it to `PX1Enqueue`. An enqueue error
   never changes the verdict: the tracker is for alerting only and reloads
   complete records at startup.
9. A `terminal` record stores the signed receipt. If that append fails, the
   reply is `uncertain` with `SERVICE_JOURNAL_UNCERTAIN` (or `CLOCK_ROLLBACK`).

## Startup

The G2 service open refuses:

- `SERVICE_PROFILE` if the W2 `service.json` still holds entries;
- `JOURNAL_SEGMENT` for a broken chain or a foreign binding;
- `SERVICE_JOURNAL_ENTRY` for a request with the wrong network, grantee or
  peer, or a duplicate admit;
- `SERVICE_JOURNAL_RECEIPT` for a stored receipt that fails verification
  under this receipt key, has the wrong `journal_seq` or peer, or has the
  verdict `pending`;
- `CLOCK_ROLLBACK` if the clock is below the journal's `last_time`.

It also re-checks the PX1 decisions it depends on: terms v2 only,
`allow_single_use` false, a positive read rate and capacity
(`SERVICE_CONFIG`).

The profile is not selected from `ServiceConfig` yet. The `g2` member belongs
to S1, so `px1jProfileOf` returns nil until integration step 3.
