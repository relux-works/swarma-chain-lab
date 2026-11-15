# Unresolved questions

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
