# C0b: bounded invocation, version 1

Status: CONTRACT CANDIDATE FOR REVIEW. Lab-only inert construction; no production
acceptance, live budget, owner act, executable release or vendor request is
approved here. B5 writes the owner-approved plan; M1 (start admission), G1b (the gateway per-attempt gate) and B4 read it.
[C0e](attempt-accounting.md) owns all billable forwards, not CLI process counts. This refines the lab-only execution obligations of
[profile sections 5.2 and 6](../../docs/lab-profile-v0.md), not broker section 14
or the production operator contract. The profile's book dispositions remain:
**OS user and network**, **Credentials**, and the declared **Operator's phone**
conflict. No production schema or approval mechanism changes.

## Closed bytes and limits

`swarma-broker-lab-bounded-invocation/1` is a CCJ-1 file record, maximum 65536
bytes, not a new socket frame. `surfaces.json` is its exact required member set;
unknown, missing, null, duplicate, wrong-kind or noncanonical members refuse
before approval. Context and all existing scalar grammars retain their meanings.
All bound values are explicitly selected by the owner at the section 6 approval
step. Representation ceilings below are not defaults, recommended budgets or
permission to choose them. Published fixture values are synthetic only.

| Member | Grammar / meaning |
| --- | --- |
| format | Exact version above; no production alias. |
| context | Existing closed Context; exact approved installation/account/qualification. |
| operation_id | Existing 32-lowercase-hex operation; the whole bounded group, never reused for changed bytes. |
| target_generation | Existing id; exact M1 launch generation. |
| client_profile_sha256 | Digest of the exact `probe/client.json` bytes. |
| wire_profile_sha256 | Digest of the exact reviewed `wire-fixtures.json` bytes. |
| executor_sha256 | Exact executable digest from the independently approved manager release. |
| model | Existing id grammar, but semantically the exact reviewed API model identifier; no alias, fallback or inference from a default. |
| max_invocations | `invocation-count`: integer 1..256, including every potentially billable attempt/retry. |
| max_output_tokens_per_invocation | `output-tokens`: integer 1..128000; all generated tokens, including thinking, not just displayed text. |
| max_total_cost_usd | `usd`: exact positive USD decimal string, six fractional digits; 0.000001..9007199254.740991 inclusive. |
| max_wall_time_per_invocation_ms | `wall-ms`: integer 1..900000, monotonic elapsed milliseconds per attempt. |
| max_wall_time_total_ms | `wall-ms`: integer 1..900000 for the whole group, including gaps, startup, shutdown and waiting. Per-attempt bound must not exceed this bound. |
| approval_record_sha256 | Digest of the complete canonical off-VM approval record below. Nonzero-looking syntax alone is not approval. |
| live_budget_approved | Required Boolean. False is an unapproved record and never executable; true is admissible only with the authenticated, fresh, exact approval join. |

USD has one decimal point, a zero or nonzero-leading integer part (at most ten
digits), and exactly six fractional digits. No sign, grouping, exponent, Unicode
digit, whitespace, extra leading zero, variable scale or numeric JSON value is
accepted. Parse/compare integer micro-USD, never binary floating point. The
upper bound is the existing safe-integer ceiling in micro-USD, not an approved
spend. Conservative cost reservations round upward, never down, to micro-USD.
An input, quote or authoritative charge that cannot be safely bounded is UNKNOWN.

## Acyclic approval and full-plan joins

1. B5 constructs candidate P with every member, explicitly selected values and
   live_budget_approved=true for the requested approval. Define target bytes as
   CCJ-1 `{"domain":"swarma-broker-lab-bounded-invocation-target/1","record":R}`,
   where R is P with **only** approval_record_sha256 omitted. The omission is a
   hash preimage, never an executable record or permission to omit a field.
2. The owner authenticates and approves that exact target digest through the
   existing off-VM approval procedure. A is a complete
   `swarma-broker-lab-off-vm-approval/1` record: invocation_sha256 equals that
   target digest; Context, heads, release set, access attestation and start
   generation match protected current observations. Its existing embedded
   Approval binds every A field using the existing approval-target domain.
   The section 6 release approval R is the complete swarma-lab-release-set/1:
   R.invocation_sha256 MUST equal this SAME target digest, and its owner_approval
   seals R using the existing approval-target domain. R.context equals P.context.
   A.release_set_sha256 equals digest(ALL canonical R bytes), not an unrelated
   release label; authenticate both owner records and their unexpired windows.
   Thus section 6 selects the bounds via target -> sealed R -> sealed A -> P -> D
   -> launch L. No second invocation/budget approval or digest cycle is implied.
   R's contract-index pin is the frozen approved index, not a digest of P or A.
   Authentication/provenance is an external owner gate, not a channel string or
   a hash. Require approved_at <= off_vm_now <= now < expires_at and unexpired qualification;
   unknown freshness/provenance is UNKNOWN, explicit revocation refuses.
3. B5 sets P.approval_record_sha256 to the digest of **all** canonical A bytes.
   Plan digest D is the digest of **all** canonical P bytes, including that field
   and live_budget_approved. No approval or launch-plan digest is hashed back
   into its own target; timestamps/owner receipts remain in A.
4. B5 supplies D through its protected approved-plan path. M1 at start admission and G1b before forwarding
   independently recompute D, require that exact protected expected digest, and
   compare the complete Context, operation_id and target_generation to the
   existing M1 launch plan L. L has exactly one InputPin for each required name:
   bounded-invocation=D, client-profile=P.client_profile_sha256,
   wire-profile=P.wire_profile_sha256 and bounded-executor=P.executor_sha256.
   Any duplicate InputPin name refuses, including duplicates of other names.
   L.pins.invocation_sha256 is the target digest, off_vm_approval_sha256 is the
   digest of A, and its release/access pins and predecessor_heads equal A.
   Existing launch-plan/helper authorization gates remain mandatory; these joins
   add constraints, never replace them. No full L digest is inserted into P:
   L depends on P, not vice versa. B4 binds
   its evidence to complete D and L digests and the same attempt ledger.
5. Client/profile bytes must match the frozen contract index and approved
   release. The observed client binary digest must equal client.json's exact
   executable pin; the executor must equal the approved manager asset digest.
   `client.json.live_budget_approved:false` and its inert invocation are
   **unchanged**: neither can approve a budget or supply missing bound values.
   Approval of P is separate; flipping that client flag does not authorize it.
   P.model and its output-token limit must equal the reviewed wire profile's
   admitted Messages model and max_tokens. A different owner-selected pair or
   invocation that changes measured body/header bytes requires a newly reviewed
   exact-client probe/profile and re-pinning before execution, not silent fixture
   edits. No unsupported CLI flag, model option or enforcement capability is
   inferred from this addendum. Exact argument/environment realization and its
   native refusal evidence belong to the pinned M1 executor release.

## Gateway executor, first-bound stop and UNKNOWN

Here executor means G1b for per-attempt accounting; M1 only checks the approved
start and serves C0c. C0e defines the sole gateway ledger, approved price pin,
reservation and authoritative settlement boundary for every Messages forward.
A native start debit is not a monetary debit. No worker-side retry escapes G1b.

Before effects, the executor verifies **every** shape/approval/client/profile/
launch/release/access/context join above. It also verifies demonstrable controls
for the selected model, aggregate output, cost and both monotonic deadlines.
Before EVERY ordinal, including later attempts in the same group, revalidate
owner authentication, the release R and A approval windows, explicit revocation,
qualification expiry, and ALL current release/access/context joins. Require
approved_at <= now < expires_at for BOTH approvals and now < qualification expiry;
no initial-check cache or extension is valid. Expiry/revocation is a reached
bound: stop the group before the next ordinal, with no forwarding or refund.
During an active attempt schedule expiry/qualification stops at the earliest
known expiry (converted with qualified monotonic continuity); monitor revocation
and access/currentness with the C0d 3000-ms lab end-to-end removal ceiling
(profile section 3.2), AND inside every remaining per-attempt/total deadline.
Whichever arrives first closes use and stops/reaps in those bounds; unknown
freshness/monitoring is sticky UNKNOWN, not grace or another attempt. Retain
all consumed ordinals/debits/reservations. A later renewed approval cannot reopen
this stopped group; reconciliation/new owner admission remains required.
Missing controls, incomplete accounting/clock evidence or a changed approved
input prohibit launch. An advisory CLI spend flag, best-effort kill, post-hoc
usage estimate or vendor alert alone is not proof of a hard bound. B5's vendor
workspace cap/readback remains required; P's limit cannot exceed that approved
available cap. No fixture proves that native enforcement capability.

Each potentially billable Messages attempt, including SDK/transport retries,
consumes one durable ordinal **before** forwarding that request; M1 publishes only the distinct native start.
Autonomous internal retries must be disabled or intercepted by that same gate;
one CLI process is not proof of one invocation. Credential-free policy GETs
are not billable invocations. Persist the full-plan digest, operation, ordinals,
reserved/settled cost and terminal/UNKNOWN state before further admission.
An authenticated read-only status uses (operation_id, D, attempt ordinal).
A repeated/uncertain start is status-only, never an automatic resend. A new plan
or reboot does not erase old unresolved debits or extend qualification.

Reserve an independently enforceable worst-case charge for the entire attempt
before admission, covering input, output/thinking, cache and every billable
component under the approved price/control policy. If this cannot be established,
return UNKNOWN without forwarding. Reservations consume available budget but
are not actual spend: an attempt whose reservation exactly fits the remaining
budget may run inside that allocation; no additional attempt may start
while that reservation is outstanding.
Settle/release a reservation only against complete authoritative evidence.
An uncertain response/charge settles at the FULL reservation, marks sticky UNKNOWN and keeps the consumed ordinal; never
refund it as zero, retry to discover its outcome, or rely on a soft USD estimate.
The G1b gateway release and B4 native checks must prove the mechanism; this C0b
reference transition table is not such a mechanism.

Start at count < max_invocations, elapsed_total < total bound and a positive
reservation <= remaining budget, with no active or UNKNOWN prior attempt. At
count equality no further attempt starts; the last already-admitted attempt may
finish within its other limits. At output, actual total cost, per-attempt wall
or total-wall equality, stop the active request/process tree and admit nothing
further; an overshoot is a failed invariant, not success. Begin total elapsed
before the first preauthorization and retain waiting/gaps; do not add unbudgeted
cleanup grace. Cleanup, output/SSE drain and reaping must finish inside the
approved deadline; uncertainty is not a successful bounded exit. A clock or
counter regression is UNKNOWN. Stop at the **first** reached bound, irrespective
of remaining capacity in the others; never retry past it or reset counters.

For M1/B4 evidence: 0 means a fully observed bounded outcome or clean exhausted
stop; 1 means malformed/denied/mismatched input or an observed bound violation;
2 means UNKNOWN/incomplete provenance, control, accounting, response, monotonic
continuity or cleanup. UNKNOWN is sticky, stops/tears down further work and
retains debit/reservation. Missing evidence is not zero usage, no effect or a
license to resubmit. Recovery requires authoritative read-only reconciliation
and the owner-approved recovery path; local successful fixtures never grant it.
