# Unresolved questions

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
