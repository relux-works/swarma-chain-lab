# Grant v4 identity checks and history

Experimental functions for [LIP-0021 draft sections 2–7](https://github.com/relux-works/swarma-link-spec/blob/45054797ee9ad3e38213e067051dfbd3eb2a21a1/lips/LIP-0021-name-ownership-and-history.md).
The older identity profile remains **Draft**. J9–J12 have the separate
explicit in-force profile described below. This
module decides only on stated octets, heights and history facts. It grants no authority,
reads no node and verifies no transaction signature.

## R1 decision map and compatibility

The R1 experiment is pinned to public specification tag
[`v0.1.51`](https://github.com/relux-works/swarma-link-spec/tree/v0.1.51),
commit `bd3bc80e5543d8a563343ec05abd1a5f3f67284c` (verified signed tag).
J9 is agreed by both owners. J10, J11 and J12 are in force on the owner's
2026-11-16 decision. The sections also contain explicitly undecided additions.
The [complete decided/draft rule and vector-family map](R1-DECISIONS-051.md)
cites the exact sections and lines and records conservative open questions.

| Rules | Status | `R1InForce051` behavior |
| --- | --- | --- |
| J12 group/range facts, weighted exact pools, distinct coins | IN FORCE | Checks decided predicates; scripts are opaque; no proposed count bounds |
| J10 class modes, ordered (a) pointer, (b) pinned history/pending, (c) holder, (d) recipient writer | IN FORCE | Requires an explicit per-landlord checkpoint; computes channel from the checked value |
| J11 holder shape, compressed pins, absent/empty list; 520-byte envelope | IN FORCE | Reads lists without enforcing draft order or uniqueness |
| J9 issuer-only no-certifier rows, certifier policy and no stop coin | IN FORCE | Returns whether attestation is required; exact names run full decided class checks |
| R2 ordinal/executor/recipient/typed ceiling checks | IN FORCE dependency | `CheckR1Fit` checks independently established selected facts |
| Bounds, range witness script, ordinal traversal, holder order | DRAFT | Rule availability returns `R1_DRAFT_RULE_UNAVAILABLE` |
| Recent-block checkpoint derivation, landlord-value writer, proposed class code/inner order | DRAFT | No derivation or writer enforcement; existing strings are local diagnostics |
| R10.3 shortcut; R10.4 no-read guarantee | DRAFT | No shortcut; API has no attestation input and asserts only not-required |
| Whole-parent atomic refusal | DRAFT, conservative open question | `CheckR1Parent`/`CheckR1Child` unavailable in this profile |

`R1DraftLab` retains all decided and draft checks. `R1InForce051` selects
exactly the decided subset at `R1SpecTag`/`R1SpecCommit`. Zero/default,
unknown profiles and the legacy refusal-only `R1InForce` remain closed with
`R1_PROFILE_UNAVAILABLE`. No behavior becomes the default. `RequireR1Rule`
reports availability, not success of facts; unknown rules refuse.

`SelectRow` is unavailable under `R1InForce051`: the detailed traversal order
is explicitly draft. `CheckR1Fit` takes a separately established selected
template and row count, and cannot prove their signed binding. The composed
parent/child methods remain draft-only pending the atomic-refusal question.
The in-force functions establish individual predicates and never whole-grant
admission. Node/coin/anchor reads, signatures, parent admission, channel
request authentication and required attestations remain external duties.
Nothing enables these rules in `grantcheck` or changes its bytes or modules.

The row types are Go stated facts. `CheckRowGroups` checks group/range counts,
32-bit output bounds, overlap/seal exclusion and exact, unbounded integer pool
sums without expanding the coins. `CheckR1Parent` additionally checks **every**
template before any child fits. `CheckR1Child` follows R2: ordinal, exact service
name/key, recipient identity/mode, typed limit ceilings, then current recipient
proof and class predicates. A valid attestation cannot override row widening.
The opaque period identity must already be established by its type profile;
this module does not invent period arithmetic or a rule for floors.

The class pipeline proves recipient ownership before reading its pointer, then
checks (a) the selected landlord, (b) its ordered history/checkpoint/writer/pending
facts, (c) the current holder, and (d) the current operation's name input and
hash type. Both holder checks use **only** the current list of the landlord
named by that value, never the union of a class. The writer may be a different
listed holder from the current owner. A gift written by another key refuses;
a holder's later update of that gift passes, the explicit limit of R9.11.
Signer adoption policy cannot be inferred by this verifier.

The channel key is parsed from the same recipient output value whose owner and
writer were checked. A certified exact-name row makes no class read and needs
no `swarma` binding; its owned name still supplies the channel key. In `R1DraftLab`, for an exact
name without a certifier, R10.3 requires independently established parent
admission and checks the issuer's current writer and pending spend. The parent
issuer pipeline must establish unchanged issuer `swarma`, including `holders`.
Changing that list therefore cannot be treated as keeping an earlier parent
live. Existing issuer-history predicates remain unchanged.

`ClassObservation` is a coherent observation asserted by the calling adapter,
not presenter proof. It includes explicit heights, consensus depth, witness
activation, transaction availability and a known/unknown pending read.
`ClassLandlordEvidence.Binding` ties the exact signed pin to the opaque
registration ID and the stated walk; its value is the current output's value.
The adapter must establish those connections and validate transactions.
Missing, bounded, unsupported or incoherent facts refuse with no key or
certifier policy and no writes. Returned byte spans/scripts are copies.
`RowRecipientResult` is only a resolved key and a statement of whether the
attestation pipeline **remains required**. It is never whole-child admission.
There is no attestation argument or callback, so a no-certifier row cannot
read a supplied attestation. Grant signatures, issuer admission, coin/anchor
reads, notary identity/attestation verification and request authentication
remain mandatory outside this slice. The module performs none of those effects.

### R1 vectors, independent reader and limits

`testdata/profile-vectors.json` pins the decision profile, lists all profile and
rule-family rows, and records only the deliberate changes to the original
vector verdicts with normative reasons. The three upstream fixtures are copied byte-for-byte from v0.1.51.
Only their top-level notes changed since v0.1.49; all vector data and verdicts
are unchanged. The fixture adapter
explicitly supplies checkpoint 500 for each class pin. Separate Go/Python
controls change Recent, remove the checkpoint and place it after the tip.
This convention establishes no production checkpoint derivation.

Three unmodified files are copied from the verified specification commit:
`groups-vectors.json` (38), `class-vectors.json` (65), and
`holders-vectors.json` (28 values plus 5 capacity rows). Their SHA-256 identities
are enforced in the Go vector harness and independent Python reader. Their
[licence and upstream attribution](testdata/R1-NOTICE.md) are retained separately.
`row-fit-vectors.json` adds 15 local R2 controls: fit, both ordinal bounds,
executor name/key, recipient mode, typed limits and compound refusal order.
The independent reader additionally compares **855** profile cases (five
profiles × 151 vectors and 20 rule families), plus **14** executor-shape
results under both open profiles, plus **537** capacity-range and invalid-input results and **24** refusal-order
results, for **1,870** total R1 results.
Its earlier **440** R1 cases remain: **151** vectors (38 groups/ordinals, 65 class, 28 holder values,
5 capacity and 15 row-fit), **276** earlier revision controls and **13**
additional absence/leading-whitespace controls. It reuses the independent Python O3/O4 primitives, never Go parsing or
Go-derived intermediate results. Both implementations are by one producer;
this is implementation independence, not independent authorship.

The pinned class fixture abstracts recipient confirmation and input heights.
Its adapter supplies recipient confirmation at the stated tip and spent-input
height 1 with witness activation 0; these are fixture conventions, not chain
parameters. Production predicates require explicit facts. History readings and
writers are stated in the fixture; recipient script and writer are computed
from its raw octets. Placeholders do not establish signature/chain validity.

`TestR1Groups`, `TestR1Holders`, `TestR1Class` and
`TestR1RowFitVectors` emit all results with no skips. Additional tests cover
zero/legacy/unknown profile rejection and the v0.1.51 profile matrix, duplicate/aliased read members, exact-name
and key modes, R2 compound order, whole-parent refusal, absent observations,
changed channel keys, input preservation and returned-byte ownership.
`test_r1_reader.py` checks known wrong expectations, both Go disagreement
directions, incomplete/duplicate results and value-reader boundaries.

**Open boundaries:** groups/templates/rows and attestation composition have no
grant octets; R8.4's 65536-byte parent bound awaits them. Request keys in the
class fixture are compressed, whereas Nostr authentication uses x-only keys:
R2.3 compares an independently validated opaque identity exactly and never
normalizes it or claims authentication. Name-mode channel keys are validated
as x-only keys. R8.9–R8.10, R9.11–R9.12 and all signer/ledger/node duties stay
outside this pure slice. Stop-coin placement in certified groups is open.
See [open questions](UNRESOLVED_QUESTIONS.md).

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

The three additional narrowing overlays cover the history/recipient contracts:

| Mutant | Property narrowed | Required failing test |
| --- | --- | --- |
| Check current owner only | An issuer transfer-and-return on the stretch refuses | `TestV4IssuerHistory/walk-issuer-04` |
| Require an `id/` recipient | A supported non-`id/` name still resolves after owner proof | `TestV4RecipientUnion/any-namespace` |
| Share issuer/notary cache key | Identical other inputs cannot reuse a different predicate | `TestV4NotaryHistoryPredicate/cache-rule-separation` |

Each requires exit 1 and the named assertion failure; setup failures do not
count. The original octet/height overlays are documented separately below.

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

`scripts/walk_reader.py` independently evaluates all 56 stated histories from
sections 6–7, without Go helpers. The agreement entry point combines those with
the original reader's 84 octet/height cases and compares **all 140** results
against the fixture and Go. Its calibration includes changed walk expectations,
changed Go walk verdicts and omitted walk results. The original-reader and hash
backend description below concerns the original 84-case subset.

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

### R1 mutation controls

The existing runner adds 24 R1 Go overlays to its seven identity overlays and
one Python digest plant: **32 intended kills**, no accepted survivors. Each Go
plant requires exit 1 and its exact named failing assertion; a compilation,
setup failure or skip is not a kill. The complete unplanted suite must pass
first. Reader agreement controls also plant a false acceptance, a false refusal
and an incorrect gift expectation beside valid results.

| Mutant | Property narrowed | Named failing test |
| --- | --- | --- |
| `r1-enable-in-force` | The in-force/zero profile never enables the draft reader | `TestR1ProfileGate/0` |
| `r1-unweighted-pool` | Each template amount is multiplied by its row count | `TestR1Groups/group-19` |
| `r1-wrapped-pool` | A 2^64 sum cannot wrap into a small pool | `TestR1Groups/group-22` |
| `r1-overlapping-ranges` | Ranges in different groups cannot share a coin | `TestR1Groups/group-24` |
| `r1-zero-based-ordinal` | Ordinal 1 selects the first output | `TestR1Groups/ordinal-01` |
| `r1-unordered-holders` | Holder pins have strict ascending order | `TestR1Holders/value-24` |
| `r1-cross-owner-no-certifier` | A foreign singleton requires a certifier | `TestR1Class/template-12` |
| `r1-same-name-issuer-pin` | The registration and owner are part of issuer identity | `TestR1Class/template-13` |
| `r1-drop-certifier-requirement` | A certified row retains its attestation requirement | `TestR1Class/class-01` |
| `r1-no-certifier-stop-coin` | An uncertified row states no stop coin | `TestR1CertifierBoundary` |
| `r1-current-owner-only` | A transfer-and-return on the constrained stretch refuses | `TestR1Class/class-14` |
| `r1-check-writer-before-history` | History change precedes current-writer refusal | `TestR1Class/class-14` |
| `r1-ignore-landlord-writer` | Exact-name rows also check the issuer value writer | `TestR1Class/certifier-10` |
| `r1-ignore-pending` | Pending landlord spend precedes holder comparison | `TestR1Class/class-31` |
| `r1-ignore-holder` | A co-listed landlord holder cannot hold this landlord agent | `TestR1Class/class-37` |
| `r1-ignore-value-writer` | A gifted value written by another key refuses | `TestR1Class/class-25` |
| `r1-only-current-holder-writes` | A different listed holder may write the value | `TestR1Class/class-02` |
| `r1-ignore-unsupported-writer` | Unsupported hash type reports unavailable evidence | `TestR1Class/class-28` |
| `r1-ignore-recipient-owner` | The child owner proof is checked before class facts | `TestR1Class/class-34` |
| `r1-executor-after-recipient` | Executor refusal precedes recipient refusal | `TestR1ChildOrder/executor-before-recipient` |
| `r1-budget-before-recipient` | Recipient refusal precedes the limit ceiling | `TestR1ChildOrder/recipient-before-budget` |
| `r1-union-class-holders` | A co-listed landlord cannot supply a value writer | `TestR1Class/class-36` |
| `r1-prefix-class-holders` | Earlier class entries cannot supply holders for a later landlord | `TestR1Class/class-38` |
| `r1-partial-parent` | An invalid later template refuses the whole parent | `TestR1ParentAtomic/later-template` |

These controls bound the named properties; they do not establish complete
mutation coverage, observation provenance or transaction-signature validity.

## Exact value and status boundaries

The lab takes the stricter reading of LIP-0010 §2.1: the value's first
byte must be `{`, and the top-level object must end at the last input byte.
Leading space, TAB, LF and CRLF refuse in Go and Python. No value in any pinned
upstream fixture starts with JSON whitespace: this includes the three R1
fixtures above and `name-vectors.json`, with values decoded from name scripts.
No upstream acceptance fixture therefore requires preserving leading whitespace.
`objectMembers` also checks the raw decoder offset, so a space, TAB, LF, CRLF or
second object after the closing brace refuses. The shared check covers binding
values and the certified exact-name channel path. The independent Python reader
requires an object at offset zero and its consumed-object end at the input end.

For the selected
landlord, proved absence returns `CLASS_LANDLORD_CHANGED` under R9.5;
unknown/undefined states return `CLASS_HISTORY_UNAVAILABLE`. Class switches also
close over `Reading`, `Writer` and `Liveness`: unsupported states never count
as affirmative evidence.

Recipient proof proceeds only for `CurrentOutput`. Under LIP-0021 O7.2 row 1
and LIP-0026 R9.9, `NoLiveOutput` proves absence and returns
`RECIPIENT_NAME_NOT_HELD`; `CurrentUnknown` and every undefined value return
`RECIPIENT_NAME_UNAVAILABLE`. Expiry and another owner also return NOT_HELD.
`TestR1RecipientAbsenceAgreesWithOwner` checks that `CheckR1Child` and
`CheckRecipientOwner` give that same mandatory code for the same stated absence,
with valid current-owner controls in both APIs.

Every negative holder, group, template and admission vector executes its
positive neighbour inside the same named subtest. Every positive executes the
negative vectors declaring it, plus an explicit negative neighbour if provided.
Neighbours must exist and have opposite outcomes; their exact expected results
are asserted without emitting duplicate reader records. Unlinked admission,
ordinal and row-fit negatives execute an explicit valid setup. The upstream vector facts and expectations are unchanged; hashes now bind
the released v0.1.51 copies, including their amended top-level notes.

The retained review probes include paired suffix refusals through both name
paths, all 256 recipient statuses, landlord absence/unknown/undefined controls,
all 256 profile values, maximum topology and named-neighbour execution.
The R1 reader compares all 151 pinned/local vectors plus 276 earlier revision
cases (5 suffix, 10 child suffix, 5 landlord status and 256 recipient status)
and 13 new cases (4 prefix, 8 child prefix and 1 cross-path absence), plus
855 cross-profile cases, 14 executor-shape cases, 537 capacity cases and
24 template/composition order cases with Go (1,870 total). Additional caller-status tests cover all byte values and the
negative/out-of-byte values of int-backed `Reading` and `Writer`.

Eight additional narrowing plants restore leading/trailing whitespace acceptance,
unsupported recipient acceptance, the wrong recipient/landlord absence verdicts,
or always refuse
holders, groups and templates. The latter must fail `TestR1Holders/value-10`,
`TestR1Groups/group-11` and `TestR1Class/template-07` respectively on their
executed positive neighbours. Run them using the existing mutation command
below; evidence includes each named failing test and command exit.

| New mutant | Property narrowed | Required failing test |
| --- | --- | --- |
| Map recipient absence to UNAVAILABLE | Both ownership paths retain O7.2 row 1's NOT_HELD meaning | `TestR1RecipientAbsenceAgreesWithOwner` |
| Accept leading JSON whitespace | The value starts at byte zero with `{` | `TestR1TopLevelPrefix/prefix_20` |

The complete runner now requires **49/49** killed mutants (47 Go overlays and
two isolated Python plants), including all 42 earlier plants.
The two v0.1.51 plants enable the draft landlord writer in the in-force
profile (`TestR1Profiles/in-force-051/class-16`) and disable its decided holder
check (`TestR1Profiles/in-force-051/class-37`). Both must fail their named
assertions.

The A3 executor check lives in `CheckRowTemplate`, reachable in both profiles
without whole-parent composition. Upstream class fixtures omit executor facts;
both fixture adapters supply a stated synthetic valid executor. Their pinned
bytes and recipient expectations are unchanged. `TestR1ExecutorShape` compares
the valid template with empty-name and malformed-key variants in each profile;
all 14 results are independently calculated by Python.
For a no-certifier template, standalone `CheckRowRecipient` rechecks
`CheckRowTemplate`, including R8.1: an invalid executor now refuses before node
facts. This is fail-closed tightening of that existing standalone path.
`TestR1NoCertifierExecutorRecheck` pairs this refusal with a valid admission in
both profiles.

`TestR1ExecutorRecipientOrder` combines an empty executor name with two
recipient modes. The executor-only control refuses R8.1, the recipient-only
control R9.1, and the compound prefers R8.1 on standalone templates in both
profiles and full parent/child composition in draft. In-force parent/child
composition remains unavailable (`R1_DRAFT_RULE_UNAVAILABLE`) before template
evaluation, even for the valid control; its tests preserve that contract rather
than enabling draft rules. Python independently compares all 24 outcomes.

`HoldersCapacity(valueWithout)` is a product predicate for a valid landlord
value with `holders` absent. It returns the maximum count, its byte size and
the size with one more holder, or `ErrR1Value` and zero results. It uses rule 8's
`12 + 69 n` for nonempty lists; zero capacity retains the original absent member
(an explicit empty list would add 13 bytes). It validates the input shape and
520-byte envelope and rejects an existing `holders` member. Both profile tests
and the original five capacity vectors call this product function. Boundary
tests cover exact 520 bytes, no room for one holder, UTF-8 byte counts and invalid
inputs; the function establishes no universal count limit or authority.
`TestR1HoldersCapacityRange` and Python compare every size from 0 through 520:
0–99 bytes are below the canonical landlord minimum and refuse, while 100–520
have valid values padded outside the binding. Independent enumeration checks
that the maximum fits and one more exceeds 520. Fifteen additional invalid
inputs (including existing holders, oversize, duplicate/aliased/noncompact
bindings and invalid UTF-8) return no partial capacity, beside a multibyte
positive control. These 537 results are all included in Go/Python agreement.
The Python helper is shared by both fixture-reading paths; it clamps `most`
to zero and retains the original size when no holder fits.

| A4 mutant | Property narrowed | Required failing test / comparison |
| --- | --- | --- |
| `r1-a4-old-python-capacity` | Zero capacity retains the absent member; 509–520 bytes never produce a negative count | `R1ReaderControls.test_capacity_full_range` and `r1_reader.agree` against `TestR1HoldersCapacityRange`, explicitly including sizes 440 and 520 |

| A3 mutant | Property narrowed | Required failing test |
| --- | --- | --- |
| `r1-a3-remove-executor-shape` | In-force templates reject an empty executor name | `TestR1ExecutorShape/in-force-051/empty-name` |
| `r1-a3-remove-executor-key` | In-force templates reject an off-curve key even with a name | `TestR1ExecutorShape/in-force-051/off-curve-key` |
| `r1-a3-capacity-off-by-one` | Computed maximum fits exactly within 520 bytes | `TestR1HoldersCapacity/439` |
| `r1-a3-enable-draft-rule` | In-force never exposes draft parent composition | `TestR1Profiles/in-force-051/rule/parent-atomic` |
| `r1-a3-disable-explicit-checkpoint` | The explicit checkpoint overrides Recent | `TestR1ExplicitCheckpoint` |
| `r1-a3-accept-missing-checkpoint` | A missing checkpoint refuses without a result | `TestR1ExplicitCheckpoint` |

The checkpoint-disable plant removes both the initial guard and the checkpoint
assignment: removing the guard alone leaves the later unknown-Recent guard
enforcing the same refusal. The second plant independently changes the missing
checkpoint branch to return success. These are calibration overlays only;
`LandlordPin` and checkpoint product behavior are unchanged pending the spec
decision recorded in Q3 of the decision map.

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
python3 -B experiments/grant-v4/identity/scripts/r1_reader.py --go-results .temp/identity-tests.json --output .temp/r1-independent.json
python3 -B -m unittest discover -s experiments/grant-v4/identity/scripts -p test_r1_reader.py -v
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
| Accept any script containing the pin | A multisig containing the key stays outside the closed list | `TestV4NameScript/script-21` |
| Inclusive expiry | Equality at `h + D` is expired | `TestV4LiveName/live-03` |
| Skip witness checking, accept controlled witness spends | Hash type must be `01` in the witness too | `TestV4Writer/writer-21` |
| Omit witness branch, refuse all witness spends | A supported owner witness spend passes | `TestV4Writer/writer-04` |
| Flip one bit in the Python XOR round | The Python digest must match published answers independently of Go | `Ripemd160Vectors.test_published_vectors` |

Every plant must exit 1 with the named failing test and its assertion
diagnostic. Build/setup failures do not kill a mutant. Unplanted Go and Python
controls must pass first; no survivor is accepted. These five original plants establish narrow bounds,
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

## Holders-list document API

`holders_document.go` reads a pinned holders-list document, checks its
SHA-256/sequence binding, closed schema and holder entries, and returns
immutable document bytes and holder observations. `ReadHolderPin` reads
the corresponding name-value pin. These are pure document checks, not
node observations, live authority or admission. Tests retain the r1 valid
controls and exact negative refusals. The API slice lands before #154;
the grantcheck consumer must separately pin the landed main snapshot.

Grant document semantics use heights only, with no clock member; the
wire grant-vector tests report all four undetermined vectors under both
mandatory and proposed interpretations. `tools/grantv4` independently
checks `grant-v4.json` only. Holders-list and wire-vector assertions are
repository tests, not claims of independent checker coverage.
