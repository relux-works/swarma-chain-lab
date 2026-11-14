# Grant v4 wire primitives

Experimental implementation of the proposed [LIP-0020 wire registry](https://github.com/relux-works/swarma-link-spec/blob/eaf7dc6c4b36e8170a0525c80b66ca1de150fe92/lips/LIP-0020-grant-v4-wire-registry.md).
This module grants no authority and performs no node reads, private-key signing,
persistence or external effects. It has no dependencies on earlier grant modules.

The first slice implements:

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
- Explicit place-selected dispatch: signed assent, unsigned preparation and
  consent pipelines. The composed issuance class fails closed as `WIRE_TYPE`.

`ReadSigned` checks wire/schema/signature validity. `ReadAssent` additionally
checks references and the issuing-party binding; the signed-class dispatcher
uses this binding-aware entry point. Every refused reader returns no object;
`ParseSignature` returns no signature on a length/range refusal. Returned byte
slices are copies. An id, digest or signature does not establish replay safety.

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

`testdata/wire-vectors.json` is an unmodified copy of the public specification
repository's `vectors/LIP-0020/wire-vectors.json`:

- Commit: `eaf7dc6c4b36e8170a0525c80b66ca1de150fe92`.
- Git blob: `c7e88437237529edad0ba0791eb261130c32a7d3`.
- Length: 335667 octets.
- SHA-256: `0e610d1528cb07375b00459618c3f33d79b58adc3dcd9e8bbf4b41c8bdb9a636`.

`TestV4CanonicalVectors` runs all **205** vectors, verifies this file hash,
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
| Relax canonical member order | Noncanonical object order cannot be admitted | `TestV4CanonicalVectors/canon-i-01` |
| Increase vout bound by one | Reject 4294967296 beside the valid bound | `TestV4CanonicalVectors/issuance-s-03` |
| Defer `snapshot.Name.Height++` at successful return | Observe the actual caller snapshot after deferred mutation | `TestV4ConsentSnapshotPostReturn/issuer-c-07` |
| Return the signature's internal byte slice | Returned bytes cannot alter retained signature state | `TestV4ReturnedBytesIsolation/Signature.Bytes` |

Each plant must produce exit 1, the exact named failing subtest and its intended
diagnostic. A compile/setup error or missing witness fails the runner. There
are no accepted survivors. These eight controls establish these bounds, not
exhaustive mutation coverage of the module.

## Remaining scope and deliberate exclusions

The implementation plan calls for a later composed-issuance integration. This
slice does not invent its first-refusal precedence between independently invalid
parts; LIP-0020 W9.1 leaves the order between those parts unspecified. The grant
itself has no member schema and is always refused. Preparation arithmetic must
never be mistaken for whole-issuance admission.

The five reserved schemas await the LIPs listed under LIP-0020's “What can be
built from this LIP”. The contract identifier remains opaque (LIP-0017 §2).
Node ownership/history reads await LIP-0008 §3; durable consumption, ledger,
seals, kernels, real transaction validation and activation are outside this
wire slice. Earlier formats remain separate. See [open questions](UNRESOLVED_QUESTIONS.md).
