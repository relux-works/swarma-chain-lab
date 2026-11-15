# Grant v4 identity checks and history

Experimental functions for [LIP-0021 draft sections 2–7](https://github.com/relux-works/swarma-link-spec/blob/45054797ee9ad3e38213e067051dfbd3eb2a21a1/lips/LIP-0021-name-ownership-and-history.md).
All profile rules remain **Draft**, with co-author agreement pending. This
module decides only on stated octets, heights and history facts. It grants no authority,
reads no node and verifies no transaction signature.

- `ParsePin`: lowercase compressed secp256k1 key, form and point checked
  separately. `SameKeyAsSigning` compares the x coordinate with a validated
  signing key (O2.1–O2.3).
- `ReadOutput`: exact update, registration or reservation prefix, shortest
  pushes, and exactly a key-hash or witness-key-hash address script. Witness
  support requires a stated confirmation height and activation height.
  Other scripts return `Unsupported`, which proves no ownership change
  (O3.2–O3.5). Returned pushed octets are copies.
- `CheckWriter`: exactly one matching name input, its spent output controlled
  by the pin, and the exact unlocking/witness layout with the pin and hash-type
  octet `01`. A spent output of another key gives `WrittenByAnother`;
  malformed or ambiguous evidence gives `WriterUnsupported` (O4.1–O4.4).
  This reads the hash type; a validating node must establish signature validity.
- `CheckLive(h, H, D)`: live iff `H < h + D`, expired at equality. The difference
  comparison avoids signed addition overflow. Negative heights, `H < h`, and
  `D < 1` return `ErrLiveInput`. The caller supplies consensus depth for `H`;
  there is no production default (O5.1).
- `CheckHistory`: walk stated name-input links back to a registration, including
  the output current at `R` and every later output in the constrained stretch.
  Issuer refusals follow O7.1's first-applicable-row order. Notary history ignores
  `swarma` and checks the current writer after the walk (O7.3); simultaneous
  notary walk findings are returned as a set, with no priority invented.
- `CheckRecipientOwner`, `ResolveRecipient`, `CheckRecipientKey`: exactly one
  recipient mode, a signed request key or name plus owner. Name mode proves the
  current output's owner before selecting its current Nostr key. The `nostr`
  member is supplied as a key string or a `names` map; only `names._` is selected.
  No namespace prefix, registration pin or exact output pin is required.
- `CheckConsentEvidence`, `CheckConsentKey`: the evidence output must be current,
  live and controlled at `R`; the walk stops there. Consent uses its historical
  Nostr key, while later requests use the current key. These check stated facts,
  not event signatures, consent binding, age or consumption (O7.4; W7.6).
- `ReadOwnerSignedChange`: O7.5's pure owner-signed change predicate, including
  unsupported ownership as unproven and a supported prefix's changed member as
  an independent ground of change. No journal or pending-operation feed exists.

`StatedName` explicitly asserts that its facts belong to one coherent observation,
that each adjacent pair follows a name input, and that readings are relative to
its owner pin. It is not a node adapter or presenter-proof interface. Output IDs
are opaque stated identifiers, not a new object-member encoding.
`ReadStatedOutput` composes the existing script and writer checks on raw octets;
value-member extraction and transaction/link validation remain caller duties.
An absent live output is distinct from an unavailable read, and a zero decision
never passes. Missing facts, unsupported prefixes, duplicate output IDs,
ascending heights and a cut-short walk never report an unchanged history.

An optional operator step bound counts each examined output, including the
registration/evidence output at exactly the bound. There is no built-in maximum.
`HistoryPredicate.CacheKey` copies the rule (issuer or notary), name,
registration, pin, member octets, `R`/checkpoint, active-chain identity through
the cached output, and that output's identity. It is only a key constructor:
no cache storage or reorg detector is implemented. A caller must discard saved
walk computations on a reorganisation touching their stretch and recheck
liveness at every admission.

This draft uses `R` as the constrained history start and a cache-key input;
that choice remains Draft. Consent checks the channel key at the coherent
issuance snapshot, and request admission resolves the current channel key.
`created_at` is not an input to any height comparison here.

Zero pins, unknown heights and an unstated chain cannot establish witness
ownership. The package's zero reading/writer/liveness values never pass.
`ParseNameScript` parses the prefix alone: success does not imply that its
address script is supported or that any key controls it.

## Vectors and independent second reader

`testdata/name-vectors.json` is the unchanged public specification fixture at
commit `45054797ee9ad3e38213e067051dfbd3eb2a21a1`, path
`vectors/LIP-0021/name-vectors.json`, length **176121** octets, SHA-256
`67e45caabfa4599160e53bd95541db2b02ad8afdc21872776756881a85c97b4c`.

The pin field contains three **groups**, not three cases: 3 valid, 9 invalid,
and 3 comparisons. This module therefore checks **140 vectors**, with no skips:

| Test | Cases | Claim and limit |
| --- | ---: | --- |
| `TestV4OwnerPin` | 15 | Pin encoding, curve point and x-only comparison; no object schema |
| `TestV4NameScript` | 39 | Exact scripts and pushed fields; no node parser or consensus execution |
| `TestV4Writer` | 24 | Input selection, key, layout and hash type; no signature verification |
| `TestV4LiveName` | 6 | Exclusive expiry on supplied depths; no consensus-depth lookup |
| `TestV4IssuerHistory` | 29 | Renewal, transfer/return, re-registration, ordered refusals and incomplete walks; no node reads |
| `TestV4RecipientHistory` | 5 | Current-owner verdicts; no recipient-history closure |
| `TestV4ConsentHistory` | 12 | Evidence current at `R`, owner, expiry and bound; no event pipeline |
| `TestV4NotaryHistoryPredicate` | 10 | Checkpoint, ownership and current writer; distinct issuer/notary cache predicates |

Each case with a declared valid neighbour evaluates that neighbour in the
same subtest before evaluating the case. Claim comments state the limit of
each test group; individual vector claims are printed in the Go test stream.
Additional tests cover malformed/truncated octets, missing facts, ambiguous
inputs, wrong witness keys, push boundaries and overflow-safe height arithmetic.
All 56 walk cases run, with no skips. `TestV4RecipientUnion` adds both/neither
mode refusal, a non-`id/` positive control, current-channel rotation, old-key
refusal, owner-before-key resolution, missing/ambiguous member and unknown-channel
refusals. `TestV4ConsentSnapshotKey` distinguishes historical consent from current
request keys. Boundary tests cover missing/malformed facts, zero/exact step
bounds, cache predicate inputs, notary compound findings and owner-signed changes.
No LIP-0022 observation vectors are claimed here.

`scripts/second-reader.py` independently implements the draft grammar and
arithmetic in Python, without importing Go or using its parser. Its own
`scripts/ripemd160.py` follows the [published RIPEMD-160 pseudocode](https://homes.esat.kuleuven.be/~bosselae/ripemd/rmd160.txt)
with two parallel lanes of 32-bit words. It uses no external command, optional hash provider, external Python
dependency or fallback.
Its curve check uses modular
square-root verification; its script
reader consumes the literal grammar with a cursor. It computes each decision
before consulting the expected answer, then compares all 84 decisions with
both the fixture and the actual Go results. Differences, missing/duplicate
results, skips, test failures or incomplete output refuse the agreement gate.
Python is the repository's existing tooling language. The reader uses its
standard library only; the Go digest remains the pure implementation pinned
at `golang.org/x/crypto v0.55.0` in `go.mod` and verified by `go.sum`.

Both implementations are checked against all nine [original published
RIPEMD-160 vectors](https://homes.esat.kuleuven.be/~bosselae/ripemd160.html),
including the empty string, two-block padding, multiple blocks and one million
`a` bytes. The shared fixture is `testdata/ripemd160-vectors.json`; its expected
digests are published answers, not generated by either reader.

`TestBIP340IdentityKnownAnswer` and `Ripemd160Vectors.test_bip340_known_answer`
use only the public key from [BIP-340 test vector index 0,
`bip-0340/test-vectors.csv`](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv),
compressed with prefix `02`. Both assert HASH160
`7dd65592d0ab2fe0d0257d571abf032cd9db93dc` and P2PKH script
`76a9147dd65592d0ab2fe0d0257d571abf032cd9db93dc88ac`. This is a published
test key, with no live identity binding.

`scripts/test_second_reader.py` calibrates the agreement gate with a wrong vector
answer, altered Go answer, missing/duplicate output, a skip and truncated output,
beside valid controls. `test_hash_backend` empties `PATH` and forbids
subprocess calls and `hashlib.new` while computing the known answer and all
84 decisions. There is no alternate backend to exercise. These are bounded
instrument controls, not proof against a shared misunderstanding of the draft.

## Tools and commands

Use Go 1.26.10 and Python 3.14.4 from the repository root.
Set `GOTOOLCHAIN=local`,
`GOWORK=off`, a short private `TMPDIR`, and private `GOCACHE`/`GOMODCACHE`.
Supply the pinned `golang.org/x/crypto v0.55.0` dependency from a verified cache;
validation runs with `GOPROXY=off` and `GOFLAGS=-mod=readonly`.
No local replacement or dependency on an earlier grant module is used.

```sh
go -C experiments/grant-v4/identity mod verify
gofmt -l experiments/grant-v4/identity/*.go
go -C experiments/grant-v4/identity vet ./...
go -C experiments/grant-v4/identity test -race -count=1 -json ./... > .temp/identity-tests.json
go -C experiments/grant-v4/identity build ./...
python3 -B experiments/grant-v4/identity/scripts/second-reader.py --go-results .temp/identity-tests.json --output .temp/identity-independent.json
python3 -B -m unittest discover -s experiments/grant-v4/identity/scripts -p 'test_second_reader.py' -v
python3 -B experiments/grant-v4/identity/scripts/check-mutants.py --scratch .temp/identity-mutants
python3 -B .scripts/check-module-graph.py
python3 -B .scripts/check-strict-module-snapshots.py
python3 -B .github/scripts/check-public-hygiene.py
```

Create `.temp/` before using these output paths. Go formatting reports source
paths; vet/build/mod verification report on stdout. Test streams and the
independent verdict map go to the named `.temp/` files. The mutant runner
requires a fresh scratch directory, records source hashes, commands, real
exits, complete streams, Go overlay replacements and isolated Python copies there;
it never edits the checked source.
The dedicated workflow runs these module checks and uploads its evidence.
The repository hygiene scanner checks tracked Matrix identifiers; review must
also check the public diff for private information outside that bounded scan.

| Mutant | Property narrowed | Required failing test |
| --- | --- | --- |
| Check current owner only | An issuer transfer-and-return on the stretch refuses | `TestV4IssuerHistory/walk-issuer-04` |
| Require an `id/` recipient | A supported non-`id/` name still resolves after owner proof | `TestV4RecipientUnion/any-namespace` |
| Share issuer/notary cache key | Identical other inputs cannot reuse a different predicate | `TestV4NotaryHistoryPredicate/cache-rule-separation` |
| Accept any script containing the pin | A multisig containing the key stays outside the closed list | `TestV4NameScript/script-21` |
| Inclusive expiry | Equality at `h + D` is expired | `TestV4LiveName/live-03` |
| Skip witness checking, accept controlled witness spends | Hash type must be `01` in the witness too | `TestV4Writer/writer-21` |
| Omit witness branch, refuse all witness spends | A supported owner witness spend passes | `TestV4Writer/writer-04` |
| Flip one bit in the Python XOR round | The Python digest must match published answers independently of Go | `Ripemd160Vectors.test_published_vectors` |

Every plant must exit 1 with the named failing test and its assertion
diagnostic. Build/setup failures do not kill a mutant. Unplanted Go and Python
controls must pass first; no survivor is accepted. These are eight narrow bounds,
not exhaustive mutation coverage.

## Gaps and remaining scope

The implementation plan's closed single-key script list is followed exactly.
No arbitrary walk limit or production observation threshold is introduced.

- **GAP: node reads.** LIP-0021 section 1 and LIP-0022's buildability table
  require a run on the pinned node build before reads can be qualified. No
  RPC adapter, observation consistency or presenter-supplied authority is added.
- **GAP: action classes and evidence classes.** These await action profiles
  and LIP-0008 sections 2 and 12.1. Nothing stubs them as passing.
- **GAP: pins inside grant, notary and pointer objects.** Their members await
  LIP-0020 and LIP-0014 section 7.1. This module defines no such schema.
- **GAP: the `swarma` member.** Its comparison can only be equality of given
  octets until its extraction rule exists; this slice performs no extraction.
- Full grant admission, consent event parsing/signatures/binding/time/single-use
  integration, durable closures, a cache implementation, and node-side chain/link
  or snapshot validation remain separate work. LIP-0022 observation/freshness
  comparisons also remain separate. No unimplemented stage is returned as passing.
- The measured numbers `S`, `K`, `LAG` and age thresholds have no production
  values here. This module implements no clock, age, recency or depth policy.

See [unresolved questions](UNRESOLVED_QUESTIONS.md). No claim of owner
acceptance, co-author agreement, real-chain qualification or production
admission follows from these tests.
