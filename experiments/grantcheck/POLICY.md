# Executor, interim freshness and protected provisioning

This is an INTERIM rule for the v3 TEST BENCH, superseded by LIP-0022 once
accepted. Production values are NOT set here and need a runtime probe on a real
Namecoin node before any non-bench use. All executable witnesses use regtest.

## Required construction inputs

Both `New` and `NewForTransport` require the following authenticated consumer
configuration. Neither constructor provides a compatibility path around it.

- `ExecutorKey`: the consumer's own lowercase, 64-hex, x-only BIP-340 key.
  Missing or malformed pins return `ErrConfig` before opening state.
- `Terms`: a bounded, nonblocking `func(contractHash string) ([]byte, error)`
  lookup. Resolve objects before admission; this callback must not perform I/O.
  It returns canonical `rental.PayTermsV2` bytes, at most 16384 bytes. Every
  supplied or cached grant checks the terms hash against `ContractSHA256`, the
  canonical encoding, network/genesis, and `ExecutorKey` against the consumer
  pin. Missing/malformed/hash-mismatched terms refuse as `terms_invalid`;
  a different executor refuses as `executor_mismatch`. Inbound pin mismatches
  occur before state changes. Provisioning records refusals in its audit only.
- `Freshness`: a required `*FreshnessPolicy`. `MaxTipAge` is A and must be a
  positive duration. `MaxFutureSkew` is a required pointer to F,
  a duration with `0 <= F <= MaxFutureSkew` (600 seconds). This cap is a
  BENCH ceiling, not a production value. Consensus allows headers up to two
  hours ahead; any non-bench use must revisit both F and A through LIP-0022
  after the real-node probe.
  `MinimumHeight` is a required pointer to FLOOR, in `[0, 2147483647]`.
  The pointer fields distinguish explicit zero from missing configuration.
  Missing or invalid values return `ErrConfig`; there are no defaults.

The checker copies policy values and includes the executor, A, F and FLOOR in
its durable identity binding. Changing them cannot reopen an existing state root.
There is no automatic migration or adoption of an old proof cache. Preserve
closure history; migration requires a separately specified procedure.

## Own-node observation rule

`trusted_now` is the consumer's trusted clock input, supplied through
`Config.Now func() time.Time`. If omitted, it uses the consumer process's
`time.Now` system clock. It is never the node's own time, an RPC `mediantime`,
a peer timestamp or a transport receive timestamp. Clock rollback remains a
retryable `clock_invalid` refusal, including across restart.

Every actual `getblockchaininfo` observation used by the real kernel, including
stability reads, is checked in this order:

| Required condition | Named refusal | Retryable |
| --- | --- | --- |
| Not IBD, and `headers == blocks` | `node_not_synced` | true |
| `tip_height >= FLOOR` | `tip_below_floor` | true |
| `trusted_now - tip_header_time <= A` | `tip_stale` | true |
| `tip_header_time <= trusted_now + F` | `tip_future` | false |

The tip time comes from the active `getblockheader(bestblockhash)` response,
with matching hash, height and one confirmation. Missing, malformed or
inconsistent projections refuse as `verifier_unavailable`. The kernel still
checks genesis, active-chain membership, transactions, names and stability.
The final trusted clock sample rechecks the complete rule above at full time precision before
any proof-cache write; neither configured durations nor clock samples are rounded
to Unix seconds for freshness. Public grant/audit timestamps remain Unix seconds.
Cache hits and every outbound attempt use the same rules.

The HIDDEN age of an admitted view is at most A + F (not A).
This interim bound does not establish that the node has the globally newest
block. A consistent old view within A can admit; beyond A it refuses even if
all its RPC answers agree. A higher independently configured FLOOR can also
refuse that view. Recheck after delays, retries and reconnects.

The dedicated Core policy witnesses use A = 60 seconds, F = 120 seconds and a
FLOOR explicitly set to the observed fixture height (or height + 1 for its
negative). The existing lifecycle Core vectors use A = 600 seconds, F = 120
seconds and FLOOR = 0. The envelope bench uses A = 24 hours, F = 120 seconds and
the independently captured post-issuance height as FLOOR, so its separate
whole-grant-lifetime tests remain in scope. These are test values only. The
frozen-view witness records a complete real Core observation, mines a newer
block, then replays the old responses: age A is live, age A+1 refuses. The
headers-ahead witness refuses; equal headers/blocks admits. Actual mined Core
headers at F admit, while F+1 and two hours ahead refuse non-retryably.

## Final-sample authority audit

| Live-return path | Checks at its final trusted sample |
| --- | --- |
| `Inbound` and `InboundFrom`, supplied or cached | Full observation rule, grant start/end, nondecreasing clock, cancellation; deferred cache commit checks cancellation again. |
| `Outbound` | Same shared operation checks, with no proof-cache replacement or provisioning audit. |
| `OutboundFrom`, one or multiple recipients | Shared checks for every recipient, then full observation rule on **each retained recipient observation** at the aggregate final sample; earliest grant end, clock order against every recipient, and cancellation. |
| `Provision` | Same shared operation checks before cache/audit commit; cancellation is checked again immediately before persistence. Late freshness refusal commits neither cache nor audit nor clock high-water. |

Grant timestamps are integral Unix seconds; the shared operation checks the
window at the stamp and requires its final sample to remain in that same second.
Clock ordering and tip age/skew retain nanosecond precision. Aggregate clock
ordering preserves every already-checked grant start; its minimum end bounds
all recipients. The retained observations are private, immutable copies, so a
later recipient or concurrent call cannot overwrite an earlier decision's tip.

Executor and terms are hash-bound immutable configuration/proof checks, not
clock-dependent conditions. Seal, issuance, names and chain stability are checked
by the real kernel on each call's node observation; advancing the trusted clock
does not reinterpret those facts. No final-sample check claims another RPC read,
a globally latest tip, or atomicity with a future chain spend or message send.
A live verdict remains one bounded observation and must be rechecked after delay.

`TestCoreFinalSampleFreshness` crosses A only at the final sample for every
public live route and both transports where supported, with exact-A positive
controls and A+1 ns/A+1 s retryable refusals that preserve checker state.
`TestCoreAggregateEveryObservation` gives only the first recipient a recorded
old Core view while the last sees a genuine newer tip. Exact A admits and A+1 ns
refuses. The policy overlay controls remove aggregate final freshness, retain
only the last observation, and remove shared final freshness; each must fail its
named regression. They supplement all earlier policy and provenance controls.

## Protected first-message bootstrap

`checker.Provision(ctx, Presentation{GrantID: id, Bytes: canonicalProof})`
implements protected manual retrieval-by-hash for a counterpart grant. It is a
transport-neutral configuration operation, not an inbound transport assertion
and not an automatic fetch. It needs no prior inbound message. The caller must
handle a non-live result before proceeding; every later inbound/send still
performs a fresh check.

The full canonical presentation includes a signed grant and an unsigned
issuance locator. The signed-grant hash is `GrantID`; the on-chain issuance
commitment binds that hash, the terms hash and consent proofs. The locator is
checked against the verifier's own chain. The hash of the entire presentation
is different because it includes the locator; it is recorded for auditing, not
misrepresented as the on-chain commitment. No wire format changes here.

Provisioning calls the same grantcheck admission implementation as inbound:
canonical bytes/signatures/ID, terms hash and executor, issuer/name/network
bindings, grant window, fresh node, on-chain issuance commitment, unspent seal,
name generations, receipt consistency and the final clock/freshness checks.
Only then does a private cache builder insert/replace bytes. The checker uses
`kernelbind.Adapter.Check`, then atomically persists its own proof cache after
all wrapper checks, instead of calling the kernel's earlier-writing `Present`.
The bench now delegates executor and node-policy checks to grantcheck; its
transport signature, carriage, signed terms binding and replay checks remain.

Cache limits remain 64 senders and 60000 aggregate encoded bytes. A refusal
cannot insert or replace proof bytes. Existing cached proof is not a fallback
for an explicitly invalid presentation. Closure journals remain separate and
must not be deleted. A positively persisted closure can refuse without another
node read because it can never grant authority.

Provision attempts record `{grant_id, hash, at, result}` in `grantcheck.json`.
`hash` is SHA-256 of the supplied presentation bytes; `at` records the
operation's validated trusted clock sample. Early refusals use the available
consumer clock sample; an invalid sample falls back to its durable high-water. The newest 64 records survive restart. Export audit observations
if longer retention is required. Successful cache insertion and its audit
record share one durable state write. Malformed or mismatched proofs record the
refusal and leave the cache unchanged. Busy/unavailable private state cannot
promise an audit; it refuses rather than returning live. An uncertain write
poisons that instance and reports `state_unavailable`.

Cancellation records no audit (including no refusal audit), changes no checker
cache or clock high-water, and returns retryable `cancelled`. Checks run after
trusted-clock callbacks and again immediately before each checker commit. The
clock high-water is staged with the operation and persisted before returning
live. Cancellation cannot roll back kernel observations or recipient checks
already committed before it became observable. A context cancelled during the
filesystem write is outside the pre-write observation boundary; callers must
still treat every verdict as an observation, never an atomic future effect.

The cache and audit stay in one atomically replaced file. The exact maximum is
73192 bytes: 60000 cache bytes, 64 records of at most 203 bytes plus array
punctuation (13057 bytes), and 135 envelope bytes (including a 64-character
binding and maximum timestamp). Tests fill both independent capacities and the
combined maximum. The shared durable store retains its original 65536-byte
`Write` limit; grantcheck uses `WriteBounded` with the calculated 73192-byte
budget, below that API's 131072-byte ceiling. No other journal's allowance changes.
`encodeState` checks the full serialized candidate before calling the writer.
An entry beyond the cache count/byte limit or the combined bound returns
non-retryable `capacity_exceeded` (seam reason `denied`) without a write, audit,
state change or poisoned checker. A subsequent valid cached check or replacement
still works. The 64-record audit remains a ring: a new retained observation
replaces its oldest record rather than expanding the ring.

## Validation and controls

From this module, with Go 1.26 and `GOTOOLCHAIN=local`:

```sh
go vet ./...
go test -race -count=1 ./...
go build ./...
go mod tidy -diff
go mod verify
```

Enable genuine Core with `CG1_REGTEST=1`, `CG1_CORE_DAEMON=<pinned-namecoind>`,
`CG1_CORE_CLI=<pinned-namecoin-cli>` and a fresh absolute `CG1_RUN_ROOT`.
`TestCoreVectors`, `TestCoreFreshness`, `TestCoreProvisioning`,
`TestCoreFinalSampleFreshness` and `TestCoreAggregateEveryObservation` each
create an isolated subdirectory and stop only their recorded node PID. Release pairs are
hash-pinned; no mixed or unlisted pair starts. Generated vectors record the
actual executable hashes. Never publish their private datadirs or RPC config.

From the repository root:

```sh
python3 -B .scripts/grantcheck-policy-guards.py --out .temp/policy-guards --private-root <fresh-absolute-regtest-parent>
python3 -B .scripts/check-px1-core-gate.py check --manifest .scripts/grantcheck-policy-core-gate.json <go-test-json>
python3 -B .scripts/check-module-graph.py
```

The overlay script records source/mutant hashes, commands, PIDs, real exits and
named assertions in its output directory. Each baseline must exit 0; each
mutant must exit 1 at its intended verdict assertion. Skips, setup failures,
compile errors and unrelated failures are invalid controls.

| Mutant | Named failing test | What the kill establishes |
| --- | --- | --- |
| Aggregate final freshness removed | `TestCoreFinalSampleFreshness/Transport2/OutboundFromAggregate/OverA1ns` | Earlier recipient checks cannot authorize a stale final sample |
| Only last aggregate observation retained | `TestCoreAggregateEveryObservation/Transport2/OverA1ns` | A fresh last observation cannot cover an earlier stale one |
| Shared final freshness removed | `TestCoreFinalSampleFreshness/Transport2/Provision/OverA1ns` | Late staleness refuses before proof-cache or audit commit |
| Executor pin removed | `TestCoreFreshness/ExecutorPin` | Canonical terms must name this consumer's executor |
| Headers equality removed | `TestCoreFreshness/HeadersEqualBlocks` | Both directions of inequality are retryably not-synced |
| Max age removed | `TestCoreFreshness/FrozenOldView` | A consistent view with a real newer block elsewhere refuses at A+1 |
| Future skew removed | `TestCoreFreshness/FutureSkew` | Actual Core headers beyond F refuse non-retryably |
| Height floor removed | `TestCoreFreshness/HeightFloor` | A view below the independently configured floor refuses |
| Combined serialized-state bound removed | `TestCombinedStateBudget` | Overflow must refuse before writer failure or poisoning |
| Wrapper cancellation checks removed together | `TestCoreProvisioning/FinalSampleCancellation/Sample3` | Final-clock cancellation cannot commit live cache/audit |
| Issuance hash check removed | `TestCoreProvisioning/UncommittedHash` | An issuer-signed but uncommitted hash cannot replace admitted proof |

The hosted Agent wallet workflow runs these witnesses and overlays with its
verified Core release, a real-skip gate control, and the existing envelope bench
and its controls. This supplements the existing grantcheck offline/race controls.

Round-two commit witnesses:

- `TestFinalSampleCancellation` covers provision, inbound, cached outbound,
  aggregate outbound and early refusal auditing, beside live/early-cancel controls.
- `TestCoreProvisioning/FinalSampleCancellation` retains the final-sample
  replacement regression against genuine committed Core grants.
- `TestCombinedStateBudget` fills both encoding budgets, rejects a combined
  overflow by name and checks unchanged bytes plus subsequent valid writes.
- `TestCoreProvisioning/CombinedCapacity` fills the cache through public
  provisioning against Core beside a full audit; byte overflow is non-poisoning,
  preserves prior state, and permits valid operations and reopening.
- `durable.TestExplicitWriteBudget` retains the legacy writer limit and checks
  exact explicit limits, overflow, preservation and recovery.
