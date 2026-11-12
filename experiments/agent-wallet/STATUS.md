# PX1 S3: tracker, canary, float, reconciliation and the status projection

This is the observation side of the G2 pay-limits profile of `agent-walletd`
(G2-PAYMENT-EXECUTOR-v1 §3.4, §3.6, §3.7). Contracts are frozen in
`px1_observe_api.go`; the implementation is `px1_observe.go`,
`px1_runtime.go` and `px1_status_socket.go`.

**Nothing here grants, restores or releases authority.** Tracker, canary and
float states are alerts and status only (Q12). A retained debit is released
only by an operator reconcile record (Q8). A spent canary or a failed startup
reconciliation poisons the service, and that is the only effect on spending.

## The observation pass (`PX1Tick`)

`agent-walletd` runs one pass at startup, before it serves the first request,
and then one pass every `-tick-seconds` (default 30). A pass takes
`ActionService.mu`, then `Wallet.mu`, and reads the own node through the
`w3-observer` route and the hot wallet through the `w1-wallet` route
(`getbalances`, `listtransactions`). It never uses the broadcast route.

1. **Startup, first pass only.** Builds the tracker from the wallet-layer
   journal and runs startup reconciliation. A refusal of
   `STATE_RECONCILE_REQUIRED` poisons the service. The refusal is sticky until
   a restart, and `agent-walletd` exits with status 2.
2. **Clock.** A wall clock below either journal's `last_time` raises
   `ALERT_CLOCK_ROLLBACK`, once per episode.
3. **Tip.** It caches the own-node height and hash for the status.
4. **Canary.** It reads `gettxout` with the mempool included. A JSON null is
   `spent`: the service is poisoned on this pass and on every later pass, and
   `ALERT_CANARY_SPENT` is raised once. A node failure, or an outpoint with
   another value, is `unknown`, which is never read as unspent.
5. **Tracker.** Each state change becomes a wallet-layer `track` record. A
   change to `conflicted` also raises `ALERT_PAYMENT_CONFLICTED`, once, when
   it is observed. The tracker has moved on when it reports a change, so the
   runtime keeps each change in a queue until its `track` record is durable,
   and never discards one. Each pass first writes the queued changes, in
   order, each exactly once; only when all of them are durable does it poll
   the tracker and write the new changes. An `Append` refusal (for example
   `CLOCK_ROLLBACK`) fails the pass and keeps that change and every later one
   queued, and the tracker is not polled again until the queue drains
   (backpressure). The queue therefore never holds more than one poll's
   changes, at most one per tracked payment (65536). While it cannot drain,
   one alert per episode names the cause, with detail `TRACK_BACKLOG`:
   `ALERT_CLOCK_ROLLBACK` for a clock refusal, `ALERT_JOURNAL_HIGH_WATER` for
   any other refusal (the wallet journal takes no records). During the
   episode no payment is observed, so no conflict alert can be raised; the
   tracker compares with its last returned state when polling resumes. After
   a restart the tracker reloads from the durable journal, so an unwritten
   change is observed again and written then. A change whose `reserve` record
   is missing can never be written: it is dropped and the pass fails
   `JOURNAL_SEGMENT`. A change of a request whose whole debit was released is
   dropped without a record: the request is closed, and the journal table
   accepts no `track` after a full release. Its conflict alert is still
   raised.
6. **Uncertain records.** Each new wallet-layer `uncertain` record (detail: its
   txid) and each new service-layer `terminal` record whose receipt verdict is
   `uncertain` (detail: the receipt's reason code) raises
   `ALERT_UNCERTAIN_VERDICT` once. One request can raise one alert per layer.
7. **Journal high-water.** When the service journal reaches 80% of its spend
   capacity, the pass raises `ALERT_JOURNAL_HIGH_WATER`, once per upward
   crossing.
8. **Float.** It reads `mine.trusted + mine.untrusted_pending`. The state is
   `low` below `low_float_sat`, `excess` above `max_float_sat`, and `ok` from
   `low_float_sat` through `max_float_sat`. Entering `low` or `excess` raises
   an alert. The monitor never moves funds.
9. **Grants.** It covers every grant that a journal record names. It caches
   the effective limits once (grants and terms are immutable) and records the
   kernel verdict: `live`, `closed` (`GRANT_SEAL_SPENT`, `GRANT_EXPIRED`,
   `GRANT_LANDLORD_KEY_ROTATED`, `GRANT_AGENT_LANDLORD_CHANGED`), `pending`
   (`GRANT_NOT_YET_VALID`, `GRANT_ISSUANCE_UNCONFIRMED`,
   `GRANT_SEAL_UNCONFIRMED`), or `unknown` for anything else. The first
   `closed` verdict raises `ALERT_SEAL_CLOSED`.

Every step runs even when an earlier one fails. The pass returns the first
failure of a safety step: the tip, the canary, the tracker or a journal. A
failed float read, or limits that cannot be computed for a grant, shows only
in the projection: the float is `unknown`, and the grant is left out until a
later pass computes its limits. Neither fails the pass, so a fault that only
affects the status cannot block startup.

Each pass is bounded: the startup pass by 120 s, later passes by the tick
interval. While a pass runs, it holds the service lock.

## Tracker rules

The tracker sees each payment at one tip. If the tip moves during a pass, it
discards the pass with `TRACKER_TIP_MOVED`, and no state changes.

| Observation | State |
| --- | --- |
| depth ≥ `confirmations_k` (2) | `confirmed` |
| an input is no longer available while the payment is absent | `conflicted`, citing the spender if it is mined in the newest 64 blocks |
| absent from the mempool and the chain for `conflict_blocks_n` (6) blocks | `conflicted` |
| a confirmed payment lost depth (reorg) | `pending` (no record; there is no `pending` track state) |
| a conflicted payment back in the mempool | stays `conflicted` until it is confirmed |

A node that answers "no such transaction" counts as absence. An unreachable
node never does: the pass fails instead. When a node has no transaction index,
a mined payment looks absent with its inputs spent. The tracker therefore
searches the newest blocks, and when the spender is the payment itself, the
payment is confirmed.

A conflicted payment is not searched again. On a node without a transaction
index, a conflicted payment that is later mined therefore stays
`conflicted`. The executor node runs with `txindex=1`.

On startup the tracker reloads these requests from the wallet-layer journal:
- completed requests;
- uncertain requests;
- requests still left `reserve`d (their broadcast may have happened before a
  crash, T10).

It skips requests that ended `refuse-retained`, because they were never
broadcast. The latest `track` record restores the state. `broadcast_tip` and
`missing_since` are not journaled, so they restart at 0, and a conflict alert
can come up to `conflict_blocks_n` blocks later after a restart.

A `track` record repeats the binding fields of the request's `reserve` record:
`grant_id`, `nonce`, `request_hash`, `action`, `reserved_sat`, `fee_sat`,
`day`, `inputs`, `txid` and `created`. Its `phase` is the track state, its
`last_time` is the executor clock, and it carries the `track` member.

## Startup reconciliation (T13)

The pass pages through every hot-wallet `listtransactions` row, 1000 rows per
page and at most 100 pages. Any `send` whose txid is carried by no
wallet-layer record refuses `STATE_RECONCILE_REQUIRED`. Such a send is either
an out-of-band spend or a restored older journal. A longer history also
refuses, because the check could not finish.

**Operational rule:** the hot wallet must start with no sends at all. Fund the
float and the canary from outside the wallet.

## Status projection (`PX1Status`, `ProjectStatus`)

The status document is `StatusProjectionV1`
(`testdata/px1/status-projection-v1.schema.json`). A status request makes no
node call and no journal write. It combines the two journals with the
observations cached by the last pass.

- **Grants.** One entry per grant with cached limits, sorted by `grant_id`.
  The numbers are the ledger's (`FoldLedgerV2`, S2), which is the authority:
  the status repeats them and never decides anything with them.
  Per request, `retained = reserve.reserved_sat - Σ reconcile.released_sat`.
  The accounting phase of a request is set by `reserve`, `complete`,
  `uncertain` and `refuse-retained` records. A `track` record is observation
  only: it never changes the phase, the day carry or `uncertain_sat`. A
  reconcile that releases the whole retained debit closes the request; a
  partial release keeps its phase. A request is *open* while it is reserved
  without an outcome, or uncertain, and not fully released.
  - `reserved_sat` is the sum of retained debits (`SpendUsed`).
  - `spent_sat` is the retained debit of completed requests.
  - `uncertain_sat` is the retained debit of open requests (`UncertainSat`),
    so a reservation still in flight shows here too.
  - `released_sat` is the sum of releases.
  - Day usage (`DayUsage`): a request counts toward day D if it is open or if
    its reservation day is D. `day_used_sat` adds its retained debit, and
    `day_count` adds one request. A release lowers `day_used_sat` but never
    gives back a request counted today: a request completed and fully released
    today still counts once, with 0 atoms.
  - `day` is the UTC calendar day of `generated_at`.
- **Payments.** Tracker snapshot, sorted by `reserve_seq`.
- **Refusals.** Terminal service-layer refusals, counted by reason. Refusals
  before admission are not journaled, so they are not counted.
- **Alerts.** The last 64 alerts, oldest first.
- **Poisoned.** `true` when the service, either journal, the canary or
  startup reconciliation poisoned the service.

Before the first pass, the canary and the float are `unknown`.

## Status socket

The status socket is the frozen `StatusSocketPath`,
`/run/swarma-wallet-status/status.sock` (freeze amendment 1, A8). It is owned
by the service UID with group `-status-gid` (the operator group) and mode
0660, in its own runtime directory `/run/swarma-wallet-status` (0750, owner
the service UID, group the operator group). That directory is never bound
into an agent slot. The agent-facing `/run/swarma-wallet` holds only
`wallet.sock`, and operators are never members of `socket_gid`
(`swarma-wallet-peer`). The daemon needs the operator group as a
supplementary group to set the socket's group (see `SERVICE.md`).

The agent (`peer_uid`) must never reach this socket (T19). The directory's
group shuts it out; startup and the listener add these checks:

- The path must be `StatusSocketPath` (`STATUS_SOCKET_CONFIG`), and the
  operator group must differ from the agent socket group.
- Startup refuses `STATUS_SOCKET_DIR` unless the directory is a real
  directory reached without a symlink, mode 0750, owned by the service UID,
  with the operator group, and is neither the directory of `wallet.sock` nor
  above or below it. The daemon never creates or repairs it.
- Startup refuses `STATUS_SOCKET_AGENT` if the agent account is a member of
  the operator group, or if its groups cannot be read (defence in depth).
- A connection whose `SO_PEERCRED` UID is `peer_uid` is closed without a
  reply (defence in depth).

An existing path refuses startup and is never unlinked by the daemon at
startup. A clean stop closes and unlinks the socket before the daemon exits,
because the status directory is not removed when the service stops.

The framing is the action-socket framing: a 4-byte big-endian length, then
one request per connection. The request must be exactly
`{"v":1,"action":"status"}`. Any other request, and any projection failure,
closes the connection without a reply. A reply is at most 4 MiB.

To read the status, call `ReadPX1Status(ctx, path)`, or `ExchangeStatus` over
a connection you already have.

## Alerts and logs

The PX1 sink writes one line per alert to stderr, which journald captures:

```
PX1_ALERT code=<ALERT_*> at=<unix> detail=<detail>
```

The code set is closed (`px1_api.go`), and any other code is dropped. A detail
must have one of the typed public shapes that the callers emit: empty, a
bounded code, a 64-hex txid or grant id, an outpoint `<txid>:<vout>`, a
decimal amount or count, or the journal ratio `<admitted>.<capacity>`.
Anything else is replaced by `REDACTED`. This is a shape check, not a secret
detector: a 64-hex secret has the txid shape. The callers therefore pass only
journal and configuration identifiers, never a key, password, request body or
terms body.
Tick failures are logged as `PX1_TICK <bounded code>`.

## Tests

- **Unit layer** (`px1_observe_test.go`, `px1_observe_r2_test.go`,
  `px1_observe_rev154_test.go`): runs against a simulated own node and an
  in-memory `JournalV2`. `TestPX1oStatusMatchesLedgerPhases` compares the
  status with S2's `FoldLedgerV2` in every accounting phase and across the
  UTC rollover; it skips while the S2 stub is in place.
- **Core layer** (`px1_observe_core_test.go`, `TestPX1CoreObserve`): runs a
  genuine Namecoin Core 28 regtest node and covers T11 (confirmation at k=2,
  `invalidateblock`, a conflicting spend mined from the admin route), T13 and
  T14 at the observer level. The journals are fakes there.
- **Pending S1/S2:**
  - the service-level spend refusal `FLOAT_CANARY_SPENT`: S3 provides the
    admission seam `px1oHalted` (tested in `TestPX1oHalted`), which S2 calls;
  - `agent-walletd` startup refusing `STATE_RECONCILE_REQUIRED` with real
    journals.

Run the Core layer:

```sh
W1_REGTEST=1 W1_RUN_ROOT=<fresh absolute dir> \
W1_CORE_CLI=<namecoin-cli> W1_CORE_DAEMON=<namecoind> \
go test -count=1 -run '^TestPX1CoreObserve$' .
```

Mutants: `testdata/px1-mutations-s3.json` (run with `W1_MUTATIONS=1`, see
`mutation_test.go`).
