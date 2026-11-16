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
and malformed statement claims. Attestation boundary fixtures compose to exactly
8191, 8192 and 8193 bytes from statements below their own 8192-byte cap. Both
valid neighbors round-trip through the signed decoder; the oversized candidate
refuses without returning any candidate or digest. `row_vectors` separately
exercises the zero-cap inequality that D12 prevents a valid spend child from reaching.

MVP deployment vectors cover either pair-owned notary, a third-party notary,
missing/either unilateral/duplicate/unrelated/invalid approval, signature replay
across grant pairs, owner identities/roles, notary names and owner pins, absent,
empty or unknown mode, opposite-parity aliases of one signing key, and the
retained strict third-party agreement gate.
The two owner approvals use only the same deliberately public fixed test keys;
the absent-mode fixtures and their strict outcomes remain unchanged.

Run `python3 scripts/make-fixtures.py` from the module to reproduce these
files, then `python3 scripts/reference.py` and `go test -race ./...`.
A fixture's expected code is written explicitly in the generator. Regeneration
never asks the Go implementation what verdict to expect.

MVP round-4 fixtures pin the current `swarma.landlord.grant` value, registration,
height and block hash for each synthetic `id/fixture-*` owner name. **Precondition:**
these offline observations are assumed accurate for their stated view; no file
or operator assertion is chain evidence in running mode. The positive pinned
`mvp-names.json` has SHA-256
`bd429b0f3f159ebc2ba90c971e03a86f8c9450bdcce05e04aa3cfb8f3ad85a3c`.
Negative vectors deliberately alter that synthetic view, reuse an identity,
or sign with a noncurrent key. The checker and independent reader must reject
them by their named codes. Only `-offline-name-fixture FILE` may load a file;
its CLI result is marked `offline-fixture`. Running MVP refuses pending N3.

`positive-main-network-bundle` is a synthetic, correctly signed non-regtest
bundle for the pure checker and the regtest-only service network refusal.
It uses the same public fixture keys and fabricated locators; it never contacts
a main-network node or represents live authority.
