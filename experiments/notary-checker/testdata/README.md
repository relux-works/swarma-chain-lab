# Public synthetic fixtures

`keys.json` contains deliberately unsafe fixed **public test secrets** (small
integers), never generated or loaded from a real wallet. Never fund them.
Every transaction ID, block, seal, registration, policy affiliation and
agreement in these fixtures is fabricated. No node was contacted.

`vectors.json` contains complete signed presentations, exact contract/request
strings, explicit policy, name value, statement claims and time. Each vector
states its expected first refusal or the full unsigned candidate, digest,
fixed-key signature, signed-envelope ID and anchor script. Positive neighbors
cover same-owner, cross-owner, narrowed authority, inherited text, a second
row, any designated notary under D9, and top-level name-value extensions.

Negatives cover action/repository/budget/window widening, ordinal and row
identity, depth 2, owner relation, missing bilateral cross-owner agreement,
missing or mismatched local evidence, canonical encoding and unknown members,
invalid keys and signatures (including BIP-340 r/s bounds), consent and request
binding, expired/not-yet-valid windows, notary designation and independence,
and malformed statement claims. `row_vectors` separately exercises the
zero-cap inequality that D12 prevents a valid spend child from reaching.

Run `python3 scripts/make-fixtures.py` from the module to reproduce these
files, then `python3 scripts/reference.py` and `go test -race ./...`.
A fixture's expected code is written explicitly in the generator. Regeneration
never asks the Go implementation what verdict to expect.
