# C0e: gateway per-attempt accounting, version 1

Status: CONTRACT CANDIDATE FOR REVIEW. Lab-only construction, not a live budget,
owner approval, executable release or production acceptance. This refines C0b's
executor allocation: **G1b in the gateway is the sole billable-attempt gate**.
M1 verifies approved start admission and serves C0c native observations; M1 does
not count model attempts. Monetary reservations/settlements do not modify native
receipts/debits and do NOT consume C0c pairs. Actual final native commit/debit/
stop/invalidation publication still needs its C0d pair; use closes immediately
before waiting for such a conclusive result. Recurring current/revocation and
periodic-single rules are unchanged. A CLI start, native start debit and Messages attempt
are three different events. The measured error control made three POSTs from
one CLI invocation (`probe/REPORT.md`, section 4, Required negative model control).
The profile's book/spec dispositions and declared lab conflict remain unchanged.
No implementation of a gateway gate, observation server or client is supplied.

## Closed records, ownership and approval chain

`surfaces.json` defines every required member, exact nesting and scalar grammar:

| Surface | Writer / readers | Maximum canonical bytes |
| --- | --- | ---: |
| `swarma-broker-lab-model-price/1` | B5, approved release / G1b and B4 | 65536 |
| `swarma-broker-lab-attempt-group/1` | G1b / M1, B1 and B4 | 65536 |
| `swarma-broker-lab-attempt-ledger/1` | G1b / B1, B4 and B5 | 262144 |

All three are CCJ-1 file records, not new worker RPCs. Unknown/missing/null, wrong
JSON kind, duplicate or aliasing member, noncanonical number and foreign format
refuse before joins. Existing Context, digest, operation, native-id, UUID, uint,
positive, invocation-count, output-tokens, USD and array grammars apply unchanged;
arrays have at most 256 members. No optional/default approval or missing-as-zero.
Ledger statuses are exactly open/stopped/unknown/terminal; attempt states exactly
reserved/settled/unknown. Reserved has no authoritative usage: all usage counters,
settled amount and settled time are zero, usage_complete=false, upstream_request_id
is `not-observed`, and usage_sha256 is the digest of the canonical object
`{"domain":"swarma-broker-lab-usage-unavailable/1"}`. These are absence sentinels,
not evidence of zero charge. A settled attempt requires complete authoritative
usage, a non-sentinel upstream request ID and digest of the canonical GatewayUsage
projection. An unknown attempt retains the absence sentinels and settles at its
full reservation; its completion time is the observed failure/closure time.

The five GatewayPrices fields are positive USD strings per million tokens;
GatewayUsage holds input_tokens, output_tokens, cache_creation_input_tokens,
cache_creation_5m_input_tokens, cache_creation_1h_input_tokens and
cache_read_input_tokens as safe unsigned integers. GatewayAttempt binds ordinal,
state, reservation_output_tokens, reservation_cost_usd, settled_micro_usd,
usage_complete, usage, upstream_request_id, usage_sha256, started_monotonic_ms
and settled_monotonic_ms. No response text, prompt, credential or auth header is
stored. Zero cost is represented only as integer settled_micro_usd=0, never an
invalid zero USD price/reservation string. Safe-integer overflow is UNKNOWN.

The existing C0b chain is unchanged: target T -> sealed section 6 release R ->
sealed off-VM approval A -> full plan P digest D -> manager launch L. R includes
exactly one `product=gateway` member at `contracts/lab-v0/model-price.json`, mode
0644, with the exact file digest; duplicate matching members, even in different
assets, refuse. This is an approved RG archive member, not an unapproved download.
The enclosing asset/second-build/source/checksum/provenance gates still apply.
Changing the price file changes R, A, P and L; no digest cycle or independent
budget approval is added. The owner selects every C0b bound and approves the
price source/model/tier/scope at the existing section 6 gate. Nothing in a sample
price, numeric ceiling or synthetic fixture grants approval.

Before M1 preauthorization, G1b creates an immutable, fsynced group record G in
its protected accounting store: Context, operation_id, full P/A/R/L/price digests,
known native start_operation_id/start_id, boot_id and group_started_monotonic_ms.
The trusted gateway CLOCK_BOOTTIME latch occurs before first group authorization
and includes subsequent process startup; M1 reads the protected G digest and
checks the same plan/approval/start IDs and unexpired group deadline before
native admission. A missing G refuses start. No worker timestamp, receipt tick
conversion or timestamp reset is allowed. G cannot enable a forward: native
start evidence does not yet exist. G depends on L; no pin of G is inserted back
into L. Failed/uncertain group creation closes that operation, never recreates G.

The ledger binds group_sha256=digest(ALL G), its exact boot/start clock and
all immutable G joins, plus the full P, A, R, L and price digests, complete Context and
P.operation_id. start_observation_sha256 is the complete final response of the
accepted C0d admission pair, not an arbitrary later single. B1 supplies its
protected accepted digest/baseline to G1b before enabling the generation listener.
Exact native start_operation_id/start_id, installed store_generation,
manager_instance_id, boot_id, start_receipt and start_debit join that response;
its start.plan_sha256 equals digest(L), generation equals P.target_generation,
and its committed-use predicate, floor/currentness and all C0b launch joins hold.
G1b cannot substitute a process-start count for this join or infer authority from
a shape-valid response. Further final start-affecting publication still requires
C0d's fresh pair; this admission reference never replaces it. Periodic singles
and current checks retain C0d timing and never publish or advance its floor.

## Published price pin and enforceable reservation

`model-price.json` transcribes only the standard/global Claude API row for
`claude-opus-5-5` from the published **2026-11-09** price card, page 1. It carries
the public source URL and SHA-256 of the downloaded PDF. The second public
source/digest pins the model overview's stable Markdown endpoint and its 1000000-token context ceiling and
128000-token output ceiling. The five USD/MTok rates are input 4, output 20,
5-minute cache write 5, 1-hour cache write 8, cache read 0.20. These facts are a
reviewable candidate price artifact, not owner-selected budget values. Retrieval
uses ordinary unauthenticated HTTPS; a changed/missing source, model/tier/scope,
price entitlement or ceiling requires a reviewed re-pin and new release approval,
never an automatic refresh. B4/RG verify the published source and the actual
vendor workspace's standard/global billing applicability before execution.

G1b admits only the measured text-only Messages route and exact model/max_tokens,
with no tools, batch, fast/priority tier, regional surcharge, server tools, new
billing dimensions or automatic fallback. A provider change, different response
billing tier/model, unverifiable input/context ceiling or extra charge closes
UNKNOWN without another forward. Contract fixtures do not establish vendor
billing guarantees; qualifying these hard ceilings and the gateway's actual
transport/retry coverage is an RG/G1b/B4 release gate.

Before **every** potentially billable upstream forward, including each retry,
G1b durably allocates the next never-reused ordinal and reserves output capacity
P.max_output_tokens_per_invocation and worst-case USD:

`ceil((1000000 * max(input, cache5m, cache1h, cache_read) + max_tokens * output)
/ 1000000)` in **integer micro-USD**, rates first parsed to micro-USD/MTok.

Use checked exact integers (or wider exact intermediates), never floats or
round-down. Input categories partition at most the pinned model context ceiling;
reserve all of it at the most expensive input/cache rate, regardless of cache
expectations. This conservative cap needs no new token-count endpoint, worker
quote or guessed prompt/token ratio. The measured max_tokens=128000 gives a
10.560000 USD reservation under this candidate table; this is NOT a suggested
budget or approval. A smaller owner cap simply refuses this profile. No request
is sent unless the independently verified bound fits the remaining approved
budget, including other committed charges/reservations. A response exceeding a
qualified hard ceiling is an invariant failure, not permission to charge more
and continue. Vendor workspace cap/readback remains separately required.

## Durable transitions, authoritative settlement and closure

G1b serializes the whole group with at most one active forward and no queue.
Every billable route/SDK/transport retry must pass this gate; no alternative
listener, direct upstream path or retry below it is permitted. A root-protected,
gateway-owned append-only ledger and protected compare-and-swap head anchor are
the authority, never worker state or a copied evidence pack. The head digest is
SHA-256 of ALL canonical snapshot bytes; sequence starts at 1 and increments
exactly once per transition. previous_sha256 is the prior full snapshot digest;
the first predecessor is the digest of the canonical domain object
`{"domain":"swarma-broker-lab-attempt-ledger-genesis/1","operation_id":ID}`.
Snapshots retain the full ordered attempt prefix, ordinals 1..N without gaps,
and immutable admission joins, group start time and boot. CAS, append/fsync and
head publication must commit before any upstream header/body byte. Failure,
uncertain persistence, lost head, regression, boot change or a repeated ordinal
closes UNKNOWN; no request is emitted. A crash after reservation consumes the
ordinal even if no send can be proven. Reboot/restart never recreates an empty
ledger for that group or refunds unresolved allocations.

Before reservation and continuously in flight, enforce C0b's fresh approvals,
revocation/access/currentness, qualification, model, count, output and both wall
deadlines. Total elapsed starts before first preauthorization/process admission,
not the first POST, and includes all gaps/cleanup. C0d removal budgets are outer
ceilings only; an earlier C0b wall/approval/qualification bound wins. A final
reserved ordinal may finish inside its allocation when the count bound is
reached, but no later forward starts. At output, actual cost or either wall bound
equality close active use; uncertainty is not a clean stop. Stop cleanup inside
the approved time bounds, with no extra grace or automatic group reopening.

For a conclusive complete upstream response, combine message_start input/cache
usage and the final cumulative message_delta output usage (never add successive
cumulative deltas). Require terminal message_stop, consistent request/model/tier,
all six counters present and canonical, cache_creation_input_tokens equal to
5m+1h, input+cache_creation+cache_read <=1000000 and output <= reserved output.
Price the **disjoint** input, output, 5m-write, 1h-write and cache-read counters at
the pinned five rates, sum exactly and round upward ONCE to integer micro-USD.
Persist settlement atomically before another attempt; free only the proven
unused reservation. Retain count and complete usage projection/digest. The
native start debit records execution admission, NOT this monetary settlement.

Timeout, disconnect, missing/partial/inconsistent usage, cancellation without
complete authoritative usage, lost settlement persistence or any uncertain
outcome charges the FULL reservation and durably marks that attempt and group
UNKNOWN. No local zero estimate, retrospective worker report, error status,
retry or later approval clears it. Read-only reconciliation is by the exact
(P.operation_id, D, ordinal), returns the protected current ledger/head and joins,
and never sends upstream. Owner-approved authoritative recovery is separate;
no automatic refund or reopening of an unknown/stopped group. The first bound
reached prevents every subsequent forward. A permitted retry is a NEW ordinal
and full reservation after conclusive settlement and all renewed admission checks.

B4's `swarma-broker-lab-q-evidence/1` uses the accounting control row
`QRow.effect_sha256` to pin the ALL-bytes ledger digest; its release_set_sha256
equals R. The ledger transitively pins full P/A/R/L, admission and price bytes;
Q evidence binds the same Context/operation and native start. B4 compares the
pack against G1b's protected authoritative head and B1's current native baseline. If a final
start-affecting result is asserted, B1 validates its C0d publication pair; a mere
ledger/status/evidence copy neither enables a native publication nor requires a
pair. A stale prefix, changed/missing join or partial record is
UNKNOWN, not absence of spend. Neither B4 nor M1 writes/repairs the ledger.
Exit 0 is fully observed bounded settlement/exhaustion, 1 definitive admission
refusal or an observed invariant violation, 2 sticky UNKNOWN. No pack grants
credential, native launch, production acceptance or permission for a live call.

## Reproducing the public source pins

Use an empty task-owned scratch directory, unauthenticated HTTPS, the exact
source_url and limits_url in model-price.json, and SHA-256 of the returned bytes.
The source is the dated PDF; limits_url is the official `.md` endpoint, not the
dynamic HTML page (two HTML responses differed while two Markdown responses
matched). Never hash a rendered page, silently normalize it, refresh a pin or
interpret retrieval success as approval. For example, with SCRATCH set to an
absolute task-owned directory and URL read from the corresponding record member:

```sh
curl --fail --silent --show-error --location "$URL" -o "$SCRATCH/source"
sha256sum "$SCRATCH/source"
```

Compare with the corresponding source_sha256 or limits_sha256, including the
record's sha256 label convention. Preserve both downloaded-source digests in
release provenance and require the owner-approved aggregate's exact price bytes.
These source tools do not contact a model API and never take credentials.
