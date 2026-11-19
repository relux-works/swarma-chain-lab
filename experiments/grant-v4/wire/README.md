# Grant v4 wire primitives

## Child attenuation at spec 0.1.61 (B3a-CHILD, draft)

`CheckChildAttenuationV4(parent, child, observation)` is a pure comparison of
already verified documents and caller-supplied F7.3 facts. The verified parent is the ancestry context of W11.8:
v4 has no numeric `depth` member, a root is the first link and a child is
the second. The function rechecks the parent identifier before comparisons.
The API belongs beside `VerifyGrant` because it reads those immutable signed
trees without reparsing, exposing mutable grant structures or introducing a
consumer dependency. Grantcheck wiring is a later unit.

The exact spec pin is
[464c445f](https://github.com/relux-works/swarma-link-spec/tree/464c445fd52ce0ec8bdc52c0ead8a866a7b77f56).
F13's order is in force: Ivan Oparin explicitly accepted it on 2026-11-17
(CHANGELOG 0.1.57; LIP-0026 section 8). Groups and ranges follow their signed
order; coins follow ascending output index, counted from 1. The full ordinal
bound is checked before any template read. F14–F18 use that selected row.

The API returns `(ChildAttenuationEvaluation, error)`. Success records the
zero-based group/range indices and signed row outpoint, **not admission**.
It evaluates F5, F8 to F12, F13(a), F14 to F18 with F11 caller facts and F1/F2
verified-document preconditions. An error returns a zero result; missing/root
child input uses a typed `ChildDocumentInputError`, not a protocol verdict.

F13(b) is not evaluated at its place. The composed path reports a
selected-group rule 4/5 finding in F1 (parent pipeline step 9), not in F13.
This is a known lab divergence from T10's last sentence and S8-29 (a)/(c).
Both O7 outcomes are unreachable while an earlier row refuses, pending O7 /
LIP-0026 Q1. The existing `VerifyGrant` parent precondition is kept; no
partial parent reader or deferred-parent admission is implemented. Section
8.7 explicitly plans a second reader after the document pipeline.

Required composition: F3, then F5 in the caller's own copy (F6 needs its
identifier), then F6, then F7 (yielding the F11 facts), then this function.
Hold any refusal until the observation's closing tip read; then F19, A1 and
F20 to F24. A nil error is not admission. At the pin F6(b) ends every
predicate without a code (T1, O4), so every result here is a result on stated
facts. F3/F6/F7/F19/A1/F20-F24 remain caller/other-layer obligations.

`ChildAttenuationFailure.Again` is typed: `no` for signed-octet refusals,
`state` for F11 channel-key hits, and `input` for F2 WIRE_ID when a child is
presented without its parent. F17 is `no` under this unchanged empty profile
set. No evaluated row uses `pending`. See STEPS for exact per-row quotations.

For a by-name parent, the admission/junction caller supplies a
`ParentNameObservation`: exact recipient name, pinned `Genesis`, observed
`TipHash` and `TipHeight`, and explicit `ValueState`:
- `ParentNameValueKeys` (K): complete nonempty `ChannelKeys`, lowercase x-only
  BIP-340 keys. A different key passes; an equal x coordinate refuses
  `DELEGATE_KEY_REUSE`, Again=`state`.
- `ParentNameValueNoKey` (A): the value was read and yielded no key under
  LIP-0010 section 4. It gives `ChildImplementationFailure`, a typed
  **IMPLEMENTATION** outcome, no Link code, no closure or revocation,
  Again=`state`, not `input`. ISSUE must sign nothing.
- `ParentNameValueRefused` (B): the whole value was refused under section 2 /
  D5. The same typed outcome preserves B and is permanent. Zero/unset,
  unknown state and absent by-name observation also fail closed; an omitted
  state is never A, even with supplied keys.

Per the Lead ruling of 2026-11-19, section 3, recorded in PR #158's description, A is a
declared deviation pending the clarifying spec sentence: the expected result
after adoption is **pass**. Switching `childNoKeyPassV4` to `true` is the
one-line product-code change; B remains closed. Adoption also flips nine
public-path A expectations (two fixture and seven reader cases). The spec pin
does not move. The bool policy function is exercised with both values,
including every reader A/B case.
Nonempty `ChannelKeys` under A, B, unset or unknown are contradictory local
facts: `ParentNameObservationError`, before and after adoption, never a pass.
All four states and octet-plus-contradictory joints run under both policies in
`TestChildV4Generated`: matching octets win as DELEGATE_KEY_REUSE, Again=no.
No ordering among local metadata input errors is claimed.

For a by-key parent, pass nil: no channel comparison applies. Child seal and
recipient-key/owner octet comparisons precede all observation handling;
matching x coordinates always give `DELEGATE_KEY_REUSE`, Again=`no`, even
with A, B or unset. Hash identities use lowercase 32-byte node display order.
Unexpected observations, name/chain/identity mismatch, empty or nil lists
**declared as K**, duplicate keys and malformed keys remain typed local
`ParentNameObservationError`s, not representations of A or B. All K entries
are validated before membership. The child's recipient key need not be in
the set: this is key separation, not authentication. Inputs are neither
modified nor retained. Passing F11 still requires all later slice rows.

`identity.ReadR1Value` is already reachable through the unchanged identity
dependency. `TestChildV4ParentNameValueReader` exercises absent `nostr`, npub,
uppercase hex, missing `names._`, duplicate `names` (all A), and duplicate
top-level `nostr` whose second member is the delegation key (B), with a valid
different-key control for each. No new parser or dependency is introduced.
The error-to-B branch is confined to that test table's section-2 violation:
`err != nil` is not a general B predicate. Missing `swarma` with a valid
`nostr` key is the counterexample (section 2 rule 5; section 4 rule 6), pinned
by `TestChildV4ReaderErrorIsNotB`. The caller must classify section 2 itself.
`STEPS-B3a-CHILD.md` lists all ordered precedence pairs, their isolated
controls and named plants. Generate the table with
`go run scripts/generate-child-v4.go --precedence-table`; it writes Markdown
to stdout, not the fixture. The ordinary generator command writes JSON.

The caller establishes that these facts are from F7.3 in this observation,
including completeness, name-owner control, node health and tip rechecks. The
typed value does not prove those facts, and the evaluator makes no chain/name
read. Tip identity is metadata for that caller contract, not either grant's
`recent_block` or a new observation-health predicate.
See the exact quotations and row map in
[STEPS-B3a-CHILD.md](../../../STEPS-B3a-CHILD.md).

F14–F18 have private comparisons also tested through public selected-row
wiring. This side adopts no LIP-0031 profile: its 0.1.58 entries remain
proposals and define no kind at a side that runs none. Amount 0, equal and
one-over amounts under a known template key refuse `LIMIT_KIND_UNDEFINED`;
an absent template key refuses `CHILD_BUDGET_OVER` first. No ceiling/floor
relation is invented. F6(a) document presentation, (b) identifier recomputation,
(c) confirmed contract/framework seal and (d) contract-profile terms are all
outside the slice. No node or seal is read. Class recipients pass only the
by-name shape check here; ownership, holders, certification, liveness and full
contract admission remain independent obligations.

### Child attenuation tools

From this module, with `GOTOOLCHAIN=local`:

```sh
go run scripts/generate-child-v4.go > testdata/child-v4.json
go run scripts/generate-child-v4.go --precedence-table
go run scripts/generate-child-v4.go --quantifier-table
go vet ./...
go test -count=1 ./...
go build ./...
python3 -B scripts/check-child-mutants.py --scratch .temp/child-mutants
```

The generator signs documents using only public test scalars 1, 2 and 3
and zero auxiliary randomness, as declared in the sibling vectors module.
Coherent three-entry channel controls additionally use public 4G/5G x
coordinates, never additional document-signing scalars. The JSON corpus is
generated and never hand-edited. Section 8.7's planned `v4-steps.json` is
absent at the pin, so fixtures derive the listed case descriptions; cases
requiring a stand-in ceiling profile are explicitly replaced by the real
undefined-kind result. Existing pinned document and J9/J12 vectors remain
unchanged. The corpus preserves all 312 fix-5 IDs and their exact signed octets, and adds
786 generated trigger/quantifier/probe entries (1098 total). Q1/Q2 entries
reference independently verified source vectors rather than new signed pairs.
The generated coverage tables in STEPS describe every added form and position.
Existing selected-row positive/negative controls include every position of the nine-row J12
example (quoted exactly in corpus metadata), numeric rather than octet index
ordering, invalid bounds and F12–F18 precedence.
Controls retain JSON test streams and real exits in the requested
scratch. Their bounds, including positive evaluated-slice outcomes without admission,
are recorded in the producer report. The controls include always-in-set and never-in-set plants, all-key iteration,
name/chain/identity validation, malformed K-set refusal, A/B/unset distinctions,
reader-backed classification, A-pass and B-to-A/empty-list plants, and
precedence plants, reversed groups/ranges/coins, octet-order coin counting,
zero-based counting and a template-read-before-bound plant. Their required named test failures and actual exits are
recorded in `results.json`; no survivor is accepted. Hosted wire CI checks regeneration,
controls, Go 1.26.10 vet/race tests, and a Go 1.26.8 build.

Experimental implementation of the [LIP-0020 wire registry](https://github.com/relux-works/swarma-link-spec/blob/3bef542fc8c0a5dedeeaaa990bd7f93abe194813/lips/LIP-0020-grant-v4-wire-registry.md), with grant documents at version 0.1.53.
This module grants no authority and performs no node reads, private-key signing,
persistence or external effects. It has no dependencies on earlier grant modules.

The module implements:

- Restricted RFC 8785 parsing and encoding with UTF-16 member order, exact
  integer tokens, Unicode scalar validation, size/depth bounds and the
  whole-document refusal order of W9.2.
- The seven registry strings and BIP-340 tagged hashes; the tag comes from
  the payload's own type. Arithmetic on a reserved type does not admit it.
- Strict signature length and range preflight before library parsing,
  x-only signing-key forms, even-Y verification and valid high-s signatures.
- Canonical signed assents, opaque contract/chain/party binding, stable
  payload identifiers, wrapper content addresses and checked references.
- Fixed-order NIP-01 consent events and the five W7.4 steps against stated
  inputs. The issuer checks are pure predicates on supplied clock, snapshot
  and consumed-id facts, not an issuer implementation.
- Stored unsigned issuance preparations, preparation construction and
  frame/commitment comparisons on supplied parts (W8.1–W8.6).
- Immutable root/child grant documents through `VerifyGrant`, with W9/W11
  refusal stages, typed signatures and J9/J12 document semantics. Proposals
  remain an explicit laboratory interpretation, never admission policy.
- Explicit place-selected dispatch: signed grant/assent, unsigned preparation,
  consent and the stated-input composed issuance check described below.

`ReadSigned(..., Grant)` uses the complete `VerifyGrant` pipeline; children
require its explicit parent context. Grant results are documents, not authority.
Other signed reads check wire/schema/signature validity. `ReadAssent` additionally
checks references and the issuing-party binding; the signed-class dispatcher
uses this binding-aware entry point. Every refused reader returns no object;
`ParseSignature` returns no signature on a length/range refusal. Returned byte
slices are copies. An id, digest or signature does not establish replay safety.

## Composed issuance on stated inputs

The composed check implements LIP-0020 §9 W9.4 with the boundaries of its
“What can be built” list. `CheckIssuance(IssuanceInput)` checks:

1. The grant step remains supplied as facts. This composed helper does not
   invoke the new grant document parser and does not establish admission.
   `GrantFacts` is a typed input of independently established values, never an
   assertion accepted from a presenter. A valid document alone cannot supply
   current chain observations or independently trusted authority.
2. Recipient mode and evidence-outpoint presence (W8.4): `ISSUANCE_MODE`.
3. The signed issuer assent's complete pipeline and W7.2 binding/party checks.
4. The consent event's five W7.4 steps, using facts about the supplied evidence
   outpoint for a recipient by name (W7.6).
5. The frame, including value, output count, version and grant content-address
   pointer (W8.5).
6. The rebuilt preparation's commitment (W8.2–W8.3, W8.6).

The first failing step wins. Success returns only a preparation conditional on
those grant and evidence facts; it does not admit a real grant. All refusals
return no preparation, signed part or signature, and perform no writes.
`Read(IssuanceClass, nil, ReadContext{Issuance: &input})` selects this check.
The octet argument must be nil: the LIP leaves presentation encoding open.
Non-nil octets (even an empty slice), absent facts and raw grant stand-ins
refuse as `WIRE_TYPE`. No JSON presentation schema or grant-check callback is
introduced. The other dispatch classes keep their existing pipelines.

`TestV4IssuanceFirstRefusalPairs` covers all ten pairs among steps 2–6,
with a valid control and each defect alone beside every compound case. There
is no step-1 pair at this unchanged stated-fact seam. The fourteen
`composed-*` vectors exercise both this API and its dispatcher. Existing
`CheckIssuanceAnchor` remains an arithmetic helper for already checked parts.

The consent tags bind the exact contract, chain, issuer and recipient
(W7.3–W7.5). `CheckIssuerConditions` tests supplied issuer-clock seconds,
snapshot facts and consumed event ids: exactly 259200 seconds is accepted,
one second older refuses, and any supplied consumed id refuses a second
grant, re-issue or successor (W7.8–W7.9). The tests also cover a fresh event
and a reconstructed consumed-id record. This function does not store that
record, implement restart safety or authorize signing. Durable consumption
before signing, concurrent reservation and never re-presenting an event are
issuer duties beyond these pure predicates. A verifier checks future time,
with no maximum age and no claim to detect global reuse from one issuance.

## Return ownership and snapshot regression

The ownership audit found no exposed internal-memory alias. The second slice
strengthens executable evidence without changing protocol behavior or adding
an API. Opaque returned objects have private fields and newly owned trees;
callers can replace their own object, but cannot mutate another read's tree.

| Returning API | Ownership | Regression coverage |
| --- | --- | --- |
| `ParseDocument` | Fresh parsed tree; input bytes copied into immutable strings | `TestV4ParsedObjectIsolation`, `TestV4InputOwnership` |
| `Document.Bytes` | Fresh encoding | `TestV4ReturnedBytesIsolation` |
| `EncodeDocument` | Fresh encoding; nested input maps/slices are not retained | `TestV4ReturnedBytesIsolation`, `TestV4InputOwnership` |
| `ReadSigned`, `ReadAssent` | Fresh opaque object; wrapper and payload privately share one read's tree | `TestV4ParsedObjectIsolation`, `TestV4InputOwnership` |
| `SignedObject.Bytes`, `SignedObject.Payload` | Fresh encoding | `TestV4ReturnedBytesIsolation` |
| `SignedObject.ID`, `ContentAddress`, `Signature` | Immutable string values | `TestV4ScalarReturnIsolation` |
| `SignedObject.Digest` | Array by value | `TestV4ReturnedHashIsolation` |
| `EncodeAssentPayload`, `EncodeSignedAssent` | Fresh encoding | `TestV4ReturnedBytesIsolation` |
| `ReadConsent` | Fresh opaque tree; context/evidence not retained | `TestV4ParsedObjectIsolation`, `TestV4InputOwnership` |
| `Consent.Bytes`, `EncodeConsentEvent` | Fresh encoding, including nested tags | `TestV4ReturnedBytesIsolation` |
| `Consent.ID`, `Signature`, `PublicKey`, `CreatedAt` | Immutable strings and integer by value | `TestV4ScalarReturnIsolation` |
| `ReadUnsigned`, `BuildPreparation`, `CheckIssuanceAnchor` | Fresh opaque preparation; outpoint/frame not retained | `TestV4ParsedObjectIsolation`, `TestV4InputOwnership` |
| `Preparation.Bytes`, `EncodeIssuanceFrame` | Fresh encoding | `TestV4ReturnedBytesIsolation` |
| `Preparation.Commitment`, `TaggedHash`, `TypedDigest` | Array by value | `TestV4ReturnedHashIsolation` |
| `CheckIssuance` | Fresh preparation; supplied parts and evidence are not retained | `TestV4ComposedDispatchBoundary`, `TestV4IssuanceFirstRefusalPairs` |
| `Read` | Delegates to a fresh reader in each supported class | `TestV4ParsedObjectIsolation` |
| `ParseSignature` | New object holding a copied fixed array | `TestV4ParsedObjectIsolation`, `TestV4InputOwnership` |
| `Signature.Bytes` | Explicit byte copy | `TestV4ReturnedBytesIsolation` |
| `PayloadID`, `ParseInteger`, `Code.Error` | Immutable string/integer values | `TestV4ScalarReturnIsolation` |
| `CheckIssuerConditions` | Error only; snapshot is caller input, not a returned value | Fixed live-input assertion in the vector suite; `TestV4ConsentSnapshotPostReturn`, `TestV4SnapshotValueCopyIsolation` |

Private construction helpers (`parseDocument`, parser `read`, `fromGo`,
`numberValue`, `parseConsent`, `decodeSignature`) allocate owned trees/arrays;
parser string/number conversions copy input bytes. `value.get` aliases a private
child within the owning tree; the assent payload has the same private alias.
Neither alias escapes through an exported mutable field. `serialize`,
`eventBytes` and `eventPreimage` allocate output; `appendString` and `appendValue`
may reuse only the explicitly supplied output buffer. Other helpers return
scalar values or errors; there are no returned maps or retained parser buffers.

Every returned byte and hash-array element is mutated beside an unchanged valid
control. Tests compare subsequent output, retained canonical bytes, stable
payload/event ids, wrapper content addresses and typed digests. Opaque pointer
replacement uses another valid object with different encoding and identity.
Nested encoder maps/slices and copied snapshot fields are exercised separately.
A changed byte's content hash must differ even when those bytes are no longer a
valid wire object. A signature-only wrapper change preserves the payload id
and changes the content address, as required by `TestV4StableObjectID`.
Signature bytes, frame bytes and snapshots have no standalone protocol object
id: their mutation controls use content fingerprints, without inventing one.

The issuer regression captures the actual decoded context, snapshot, consumed
ids and event bytes before and after the call. The former raw-fixture comparison
could not see a write through `snapshot.Name.Height`. Success and refusal cases,
a second call, and a copied `Name.Height++` are covered after deferred work has
run; original event encodings and ids remain unchanged.

## Source pin and vector scope

`testdata/grant-v4.json` is the unmodified 0.1.53 file at the current pin:
SHA-256 `66d4a5b1738b746bd5403e30ed1bbd30be9aac256a2559795d038f3455b2b106`.
`TestGrantVectors` asserts all 112 cases: 11 valid, 84 invalid, 13 compound
and 4 undetermined. It checks exact bytes/digests and refusal stages, with both
proposal interpretations. The four undetermined cases report both mandatory and proposed outcomes.
`tools/grantv4` independently checks `grant-v4.json` only; it does not
independently check wire or holders-list vectors.

This API slice lands before the configured grantcheck consumer in #154;
that consumer is separate work and must pin the landed main snapshot.
The wire module uses only identity's existing `ParsePin` API, published on main
at `80bcaa527f51b1f4910fc84d9f78d51abad4139c`, and pins
`v0.0.0-20261116164432-80bcaa527f51` without a local replacement.
Grant document checks use heights only and introduce no clock member.


`testdata/wire-vectors.json` is an unmodified copy of the public specification
repository's `vectors/LIP-0020/wire-vectors.json`:

- Commit: `adae6e7669601f271f7d0d9cdd91ecee7d19bf02`.
- Git blob: `bf107e5fbed5946e8ce168aaa056bb661ef664dd`.
- Length: 384615 octets.
- SHA-256: `0d14f471e4a0a39c99455fab663bdce5c05f2c97fe2383ecbe95717721d53ae0`.

`TestV4CanonicalVectors` runs all **219** vectors with **zero skips**, verifies this file hash,
rejects duplicate or missing vector ids and runs each supplied negative beside
its stated valid neighbour. The seven stages retain the specification's
boundaries: the grant stand-ins are arithmetic only, and node/snapshot facts
are supplied inputs. There is no real-chain, durable-consumption or cross-language
qualification. The three other required tests are `TestV4TypedDomains`,
`TestV4StableObjectID` and `TestV4StrictBIP340`.

## Tools and commands

Run from the repository root with Go 1.26.10, `GOTOOLCHAIN=local`, `GOWORK=off`
and private scratch/cache directories. Acquisition of the pinned public Go
dependencies is separate from offline validation:

```sh
go -C experiments/grant-v4/wire mod download
go -C experiments/grant-v4/wire mod verify
gofmt -l experiments/grant-v4/wire/*.go
go -C experiments/grant-v4/wire vet ./...
go -C experiments/grant-v4/wire test -race -count=1 ./...
go -C experiments/grant-v4/wire build ./...
python3 -B .scripts/check-module-graph.py
python3 -B .github/scripts/check-public-hygiene.py
python3 -B experiments/grant-v4/wire/scripts/check-mutants.py --scratch .temp/wire-mutants
```

Use `GOPROXY=off` for the validation commands after downloading. Python 3
standard-library tooling reuses the repository's existing orchestration language;
all protocol implementation and tests are Go. The mutant runner leaves complete
JSON test streams, input hashes, commands, exits and verdicts in its scratch
directory, and retains source replacements plus Go overlay mappings in its scratch directory.
It never changes the candidate source files.
The dedicated workflow runs race tests, vet, build and these control plants;
its test and mutation evidence is uploaded as an artifact. The public-hygiene
check covers tracked identifiers, not arbitrary secrets or commit history.

| Plant | Property narrowed | Required failing test |
| --- | --- | --- |
| Remove both domain-hash prefixes | Type-bound digest, rather than a plain payload hash | `TestV4TypedDomains/swarma-grant/4` |
| Route a parsed integer through binary64 | Exact string-form integer at 9007199254740993 | `TestV4CanonicalVectors/int-v-05` |
| Remove the explicit s < n preflight | No out-of-range scalar admitted by the signature parser | `TestV4StrictBIP340/s=n` |
| Permit unlisted object members | Closed assent member set even with an otherwise valid signature | `TestV4CanonicalVectors/assent-i-01` |
| Relax only canonical member order | Order refuses while all 28 non-order invalid canonical vectors retain their exact refusals | `TestV4CanonicalVectors/canon-i-04` |
| Increase vout bound by one | Reject 4294967296 beside the valid bound | `TestV4CanonicalVectors/issuance-s-03` |
| Defer `snapshot.Name.Height++` at successful return | Observe the actual caller snapshot after deferred mutation | `TestV4ConsentSnapshotPostReturn/issuer-c-07` |
| Return the signature's internal byte slice | Returned bytes cannot alter retained signature state | `TestV4ReturnedBytesIsolation/Signature.Bytes` |
| Skip the consent pipeline after shape parsing | A consent by another key cannot reach the anchor check | `TestV4CanonicalVectors/composed-i-05` |
| Skip issuer-assent binding | Another party's valid assent cannot reach the anchor check | `TestV4CanonicalVectors/composed-i-04` |

Each row below transposes two first-refusal steps in an overlay. The required
failing test has prefix `TestV4IssuanceFirstRefusalPairs/` and the suffix shown.
The controls evaluate independently invalid steps so that a correctly refused
reader need not expose an object. The untransposed probe must first pass the
whole suite. These probes bound refusal precedence on supplied facts; they do
not validate a grant schema or observe a chain.

| Plant | Property narrowed / required test suffix |
| --- | --- |
| `swap-mode-before-assent` | `mode-before-assent` |
| `swap-mode-before-consent` | `mode-before-consent` |
| `swap-mode-before-frame` | `mode-before-frame` |
| `swap-mode-before-commitment` | `mode-before-commitment` |
| `swap-assent-before-consent` | `assent-before-consent` |
| `swap-assent-before-frame` | `assent-before-frame` |
| `swap-assent-before-commitment` | `assent-before-commitment` |
| `swap-consent-before-frame` | `consent-before-frame` |
| `swap-consent-before-commitment` | `consent-before-commitment` |
| `swap-frame-before-commitment` | `frame-before-commitment` |

Each plant must produce exit 1, the exact named failing subtest and its intended
diagnostic. A compile/setup error or missing witness fails the runner. There
are no accepted survivors. These twenty controls establish these bounds, not
exhaustive mutation coverage of the module.

## Remaining scope and deliberate exclusions

W9.4 now specifies the composed check order. The grant still has no member
schema and its octets always refuse. The stated-input composition above must
never be mistaken for whole-grant admission or real transaction validation.

The five reserved schemas await the LIPs listed under LIP-0020's “What can be
built from this LIP”. The contract identifier remains opaque (LIP-0017 §2).
Node ownership/history reads await LIP-0008 §3; durable consumption, ledger,
seals, kernels, real transaction validation and activation are outside this
wire slice. Earlier formats remain separate. See [open questions](UNRESOLVED_QUESTIONS.md).
