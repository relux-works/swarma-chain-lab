# Unresolved questions

## Claude Unix intake qualification and settlement

PR #161's Unix intake now enforces configured models and durable daily exposure;
zero or omitted ceilings refuse startup. It conservatively charges full model
context plus requested maximum output before forwarding, without refunds. It is
not a per-slot API and does not settle verified usage from arbitrary real-client
JSON/SSE. Actual-usage settlement, per-launch/slot caps, measured conversation
sizes, broker renewal-rate capacity, durable UNKNOWN/account-hold reconciliation
and live outbound revocation qualification remain explicit owner/integration
gates. None is authorization to activate the service or spend without a ceiling.

## Grant v4 member encodings

The primitive/stated-fact fixture is available with independent Python checks and
explicitly unjudged lab-choice verdicts. It does not admit grant bytes. The
qualified specification lacks the grant and group member encodings. See the
[specification requirements](experiments/grant-v4/vectors/VECTORS.md#specification-decisions-and-integration-requirements)
for the remaining forms, refusal questions and registry contingencies, and the
already settled limits and key semantics.

## Resolved: detached-v2 observer-local identity

Detached v2 retains its first-admitted seal/ID binding as an explicit v2
exception. Only the grant-key holder can produce valid signature twins; both
bind the same grant key, funded seal and name generation. Each observer admits
the seal at most once; a twin is refused as `SEAL_ALREADY_SEEN` without changing
cache or state. Two fresh observers may record different envelope IDs, so that
ID must never key payment, deduplication, journals or audits across observers.
A new detached profile with a per-certificate commitment is the fix, outside
this change; grants v4's content-only stable object IDs remove the issue.
See the [identifier audit](docs/signature-identities.md) and the genuine-Core
same-observer and two-fresh-observer signature tests.

## Grant v4 observation decisions (Draft)

LIP-0022's comparisons are implemented only on stated inputs in
[chainview](experiments/grant-v4/chainview/README.md). Owners' acceptance and
co-author agreement remain pending. Node reads (including pending-state
coherence and hidden tip return), action/evidence classes, object pin members,
production skew/lag/recent-block/age parameters, first-sight observation cadence,
lost/rolled-back store recovery and real-node/storage qualification remain open.
No adapter or passing placeholder supplies those gaps.

## Chain gateway contract candidate

[OPEN.md](experiments/chain-gateway/OPEN.md) records Source's accepted answers,
Infra's install proposals and remaining Q3 feasibility, Q8 book/spec/policy and
Q10 continuous watcher/journal gates. Part (B)'s format is accepted for helper
build; tip-time delta acceptance and D29 parser adoption remain separate exact-
head obligations. Enforcement over the snapshot remains prohibited without a
separate owner decision. No ordinary RPC bracket satisfies §4's hidden-transition
witness; The accepted HELPER-B r3 §5 amendment permits bracketed observe-only snapshots; the witness gate remains for (a) and enforcement.

## Hardening follow-up (B3a-CHILD-H)

These non-blocking code notes are deferred, not represented as closed product
work in the evidence-only fix. The review IDs identify the public record.

| Review | Note | Follow-up / disposition |
| --- | --- | --- |
| 5977140834 | N-1 | Add a found-guard to TestChildV4ReaderErrorIsNotB; it can pass vacuously if its named source vector disappears. The vector is preserved here. |
| 5977141492 | N-2 | Same reader found-guard request; carry into B3a-CHILD-H. |
| 5977140834 | N-2 | Add a public-wrapper/constant wiring assertion at adoption. public-ignores-constant is equivalent at this head; not counted as a killed survivor. |
| 5977141492 | N-4 | Remove or use the uncalled ParentNameObservation.validate wrapper. No product-code edit is authorized in this round without a wrong verdict. |
| 5977141492 | N-1 | Addressed by generated Q1/Q2 compound probes, including depth > no-delegate on a declared breached boundary; retain those controls in hardening. |
| 5977141492 | N-3 | Documentation corrected: one-line adoption applies to product code only; nine public-path A expectations must flip too. |
| 5977140834 | N-3 | Out of contract: local input-error ordering is not pinned or claimed; do not invent a semantic gate for it. |

No supported F17(c) profile exists at the fixed pin. A nonempty all-supported
limit list cannot be manufactured as a clean numeric control. F14 executor,
F15 recipient/mode and F18 bounds are scalar checks in this slice; class-list
membership belongs to F19. These bounds do not waive the generated F9, CS3,
F11, F16 and F17(a) list-position controls.

## Gateway release adoption

The [gateway release template](docs/releasing.md) lists the pending unit and
service documentation from service PR #159 explicitly. Main builds refuse until
those inputs land; fixture tests do not satisfy service adoption or runtime
qualification. The existing daemon remains a packaging input, not proof of
managed broker integration. Repository `gateway/v*` tag ruleset administration,
release publication, dedicated signing-key custody, aggregate set approval and
runtime qualification remain separate owner/operator gates.
