# Grant v4 primitive and stated-fact vectors

**No valid swarma-grant/4 vectors until LIP-0020 defines its members.**

`vectors.json` contains 241 unique cases: 77 successful primitive/stated-fact
cases and 164 refusals, covering the 27 refusal classes in the pinned wire lab.
Go generates the fixture through the lab APIs. Independent standard-library
Python derives specified outputs and explicitly lists verdicts the specification
does not determine as **not judged**. All published valid bytes are checked,
including bytes attached to a lab-choice verdict. Success never admits a grant.

Canonical encoding covers the complete assent and unsigned preparation schemas
and W1's restricted generic document grammar. Arithmetic covers the seven
registry entries at the pinned revision. Type-only payloads are arithmetic,
not admitted objects. The six signed registry digests use each public scalar
1, 2 and 3 with 32 zero auxiliary bytes. Nobody signs an issuance commitment:
there are no issuance-signing vectors. Complete assent payloads have separate
signature witnesses. Every test signer rejects scalars outside {1,2,3}.

`stated_grant_facts` and `stated_evidence` are supplied test facts, not a grant
schema, a presentation format or authenticated node evidence. Conditional
issuance exercises W9.4 steps 2–6. Step 1, grant parsing and delegation remain
unavailable. The contract identifier and grant signature/content address are
opaque supplied facts whose provenance is outside this fixture.

## Format and checking

The root format is `swarma-lab-primitives/1`. It records `spec_revision`, the
exact qualified `lab_revision`, the lab's own `lab_spec_revision`, public test
scalars, fixed auxiliary randomness and an ordered `vectors` list.

| Field | Meaning |
| --- | --- |
| `id` | Unique content-named case; never computed from its position in the list. |
| `purpose`, `reason` | Claim exercised, including compound qualifications. |
| `spec` | Pinned LIP-0020 rule, with other normative sources where needed. |
| `basis` | `spec`, `lab-choice`, or `contingent:<decision>`. A contingency is evaluated at the current pin and warns that the registry/member decision may change. |
| `operation` | Explicit laboratory adapter, independent of the supplied object type. |
| `input` | Stated inputs; `*_hex` is exact lowercase hex; integer `bound` strings retain uint64 precision. |
| `output` | Exact API result and `code`; refusals publish no admitted output bytes. A lab-choice code is an observation, not a normative verdict. |
| `valid_neighbour` | Existing successful vector for each refusal. Memberless types point to their corresponding arithmetic witness because no admitted signed-object neighbour exists. |
| `defects` | Concrete defective fields or raw-byte changes relative to that neighbour; compounds explicitly retain multiple defects. Fresh signing bytes and derived event IDs support a mutation and are not extra defects. |

The transport uses the specification vectors' language-neutral vocabulary:
`issuer_public_key`, `request_public_key`, `party_public_key`, `genesis`,
`contract`, `grant_id`, `grant_signature`, `recent_block_height`, `clock`,
`consumed_event_ids`, `snapshot.name.live`, and `name_output.{txid,vout}`.
`stated_grant_facts.mode`, `recipient_name` and `content_address` and evidence
predicates (`confirmed`, `height`, `operation_of_name`, `live_at_recent_block`,
`owner_matches`, `yields_public_key`, `spent_at_height`) are stated adapter facts.
Each is a test transport shape only: a height is not a proposed recent-block
member, an opaque key is not a proposed issuer pin, and a string is not a name
profile. The Go adapter translates these names to its internal structs.
Irrelevant recipient facts may coexist in the fixture; this proposes no union
encoding for a grant.

`Generate` checks each lab result against the fixture expectation. The drift
test compares the entire generated JSON byte for byte and names the first
differing vector. Python imports no Go code and executes no lab binary. It
implements canonical encoding, integer grammar, BIP340 arithmetic, hash roles,
consent IDs/signatures and conditional preparation independently.

Python derives the applicability of **not judged** from the operation and actual
inputs, rather than trusting an expected code, case ID or the `basis` label.
It does not copy the nil-grant code, evidence-outpoint validation placement,
age-before-consumption ordering, long-name acceptance or preflight API verdicts.
For a lab-choice success it still independently compares every published byte.
Exit 0 means agreement on judged results and valid bytes; exit 1 means a named
`FINDING`; exit 2 means setup or fixture-contract failure. It prints each
unjudged case and reason. A regression plant confirms that changing bytes in an
unjudged-success row still produces a finding.

### Lab-determined verdict inventory

| Cases | Why the verdict is not judged |
| --- | --- |
| `issuance-no-facts` | No grant octets and no specified W9.4 step-1 API result. |
| `issuance-vout-4294967296` | W9.4 does not place evidence-outpoint form/bounds; the frame additionally commits vout 4294967295. Stored preparation bounds are separately specified and judged. |
| `issuer-age-before-consumed` | W7.8 and W7.9 do not order these simultaneous refusals. |
| `consent-size-plus-0`, `consent-size-plus-1` | Artificial long names test the lab's 2048/2049-byte API boundary. The name profile and LIP-0013 tag-value-limit inheritance remain unresolved. |
| `signature-length-*`, `r-p*`, `s-n*` | ParseSignature is a lab preflight; W5.2 specifies verification, not that API's successful range result. Verification vectors remain judged. |

There are 14 not-judged verdicts. The seal arithmetic/signature and signed
memberless witnesses carry `contingent:LIP-0008-SB4/LIP-0024`; notary memberless
witnesses carry `contingent:LIP-0014-J5/J2`. Those are current-pin observations,
not a promise that the registry or unsupported-member status survives a revision.

## Boundaries and evidence limits

| Contract | Valid control | Refused neighbour |
| --- | --- | --- |
| W1 caller byte limits | Canonical generic documents at 1024/2048 bytes | 1025/2049, `WIRE_SIZE`; these do not claim schema-valid maximum-size objects. |
| W1 document depth | 16 containers, including the root | 17, `WIRE_SIZE`; syntax/truncation/UTF-8 competitors have separate witnesses. |
| W2 number form | 9007199254740991 | +1, `WIRE_NUMBER`. |
| W2 integer strings | 0, 2^32−1, 2^53−1, 2^64−1 at supplied bounds | Bound+1 and forbidden grammar, `WIRE_INTEGER`. |
| W1 strings | U+0020, non-ASCII, astral UTF-16 sort order, decomposed strings | U+001F, unpaired surrogate and malformed UTF-8. |
| W3 key | Valid x-only public keys | Wrong length/case, nonpoint, x=p/p+1. |
| W5 verification | Published BIP340 rows and complete assents | Wrong key, altered/zero signature, r/s and length defects. Preflight-only verdicts are labelled separately. |
| W7 timestamp | 1 and 253402300799 | 0 and upper+1, `CONSENT_SHAPE`. |
| W7 future time | created_at equals supplied clock | One second ahead, `CONSENT_TIME`. |
| W7 issuer age | 259200 seconds | 259201, `CONSENT_AGE`; ordinary verifier has no age limit. |
| W7 name evidence | Height=recent=100, spent above snapshot at 101 | Height=101 or spent at snapshot=100, `CONSENT_EVIDENCE`. |
| W8 outpoint | 0 and 4294967295 | Evidence bound+1 is lab-choice; stored outpoint bound is specified. |
| W8 frame | 72 bytes, zero value, one OP_RETURN, exact commitment and address | 71/73 bytes, nonzero value, wrong count/framing/address or commitment. |

All ten pairs of W7.4's key-mode stages and all ten pairs of buildable W9.4
steps 2–6 have distinct inputs. Shape-order pairs use nonempty content in an
otherwise readable event with re-derived ID/signature; later defects survive.
`TestConsentPairsDiscriminateOrder` repairs only the earlier defect and requires
the later refusal for every pair. Python independently checks the four shape
pairs. W9.4 assent defects use a freshly signed wrong-party assent, leaving the
stated grant's issuer/party relationship unchanged. Single schema-defect assents
have re-signed variants; original stale-signature compounds are labelled.

`memberless_signed` parses the actual canonical signed envelope and verifies
its signature against the stated public place key before invoking unsupported
type dispatch. Both implementations reject malformed bytes and a zero signature
in regression controls. These fixture checks do not extend the wire reader.
No valid signed-object control exists for a memberless type. The removed bare
`memberless-type-0` dispatch witness would become `WIRE_MEMBER` once a grant
schema exists; signed type-only grant bytes will then lack required members.

No live node, ownership/history authentication, issuer journal, replay recovery,
real grant admission, name-mode issuer snapshot path or delegation is qualified.
Caller-limit documents are not schema-valid assent/preparation size boundaries.
No formal surface table was supplied; this inventory states the actual scope.
Out-of-contract cases are whole-grant bytes (W3.1/W9.4 step 1), row/group octets
(LIP-0026 §8), and node/journal provenance (W7.6/W7.9).

## Tools and commands

Use Go 1.26.10, `GOTOOLCHAIN=local`, `GOWORK=off`, and short absolute scratch
paths. `.github/workflows/grant-v4-vectors.yml` runs on every PR touching
`experiments/grant-v4/**`, so sibling changes cannot bypass drift detection.
The same entrypoint downloads/verifies modules, checks formatting, runs vet,
tests, build, Python and checker regressions, then plants one output byte and
requires both detectors to fail before restoring and rechecking green controls.
It copies both sibling modules and isolates HOME/config/caches/TMPDIR in a
unique scratch root, removes that root after execution, and preserves command
logs and real exit codes in the caller's evidence directory.

```sh
python3 -I experiments/grant-v4/vectors/scripts/check-ci.py --scratch .temp/vector-checks
# The ordinary CI gate must exit 1 when its fixture is planted before testing:
python3 -I experiments/grant-v4/vectors/scripts/check-ci.py --scratch .temp/vector-plant --plant-drift
```

For an already isolated sibling checkout, the individual commands are:

```sh
go -C experiments/grant-v4/vectors mod download
go -C experiments/grant-v4/vectors mod verify
go -C experiments/grant-v4/vectors run ./cmd/generate > .temp/vectors-regenerated.json
cmp experiments/grant-v4/vectors/vectors.json .temp/vectors-regenerated.json
go -C experiments/grant-v4/vectors test -count=1 ./...
go -C experiments/grant-v4/vectors vet ./...
go -C experiments/grant-v4/vectors build ./...
python3 -I experiments/grant-v4/vectors/scripts/check-vectors.py
python3 -I experiments/grant-v4/vectors/scripts/test-check-vectors.py
python3 -I .github/scripts/check-public-hygiene.py
python3 -I .scripts/check-module-graph.py
```

The generator writes stdout; validation never overwrites the original fixture.
The one-byte plant changes an ASCII digit of `arithmetic-0.output.payload_id`.
Go must exit 1 naming the first differing vector; Python must exit 1 naming that
vector and field. This control proves output-drift detection, not all mutations.

## Source pins and qualification

The qualified laboratory revision is
[`8a47f1a984cd93864402f7fdc09d2eba0d890b90`](https://github.com/relux-works/swarma-chain-lab/tree/8a47f1a984cd93864402f7fdc09d2eba0d890b90).
The wire module's published floor
`v0.0.0-20261115082735-f1936aa1117a` contains `GrantFacts`, `IssuanceInput`,
`CheckIssuance` and `EncodeConsentEvent`. Building this vectors module after
removing its local `replace` succeeds at that floor. The normal replacement
checks the sibling source; the module graph records the published dependency.

The lab pins LIP-0020 at `adae6e7669601f271f7d0d9cdd91ecee7d19bf02`.
The fixture also records specification revision
`bd3bc80e5543d8a563343ec05abd1a5f3f67284c` (v0.1.51). A byte comparison of
`vectors/LIP-0020/wire-vectors.json` at both revisions gives the same Git blob
`bf107e5fbed5946e8ce168aaa056bb661ef664dd` and SHA-256
`0d14f471e4a0a39c99455fab663bdce5c05f2c97fe2383ecbe95717721d53ae0`.
The LIP text is not identical: the later revision updates row/attestation status,
adds LIP-0024 and SB4 registry contingencies, and links ownership/journal drafts.
The implementation and fixture retain the earlier lab pin; no later grant
schema or removed registry entry is claimed implemented.

| Source | Used sections |
| --- | --- |
| [Swarma book chapter 6](https://github.com/relux-works/swarma-docs/blob/b57a9be633c245373b448c3786bcbd49d636fe8a/book/ru/06-granty.md#общая-модель-и-брокер-v0) | General grant model and broker format are separate; no v4 member schema is supplied. The source repository is public. |
| [LIP-0020](https://github.com/relux-works/swarma-link-spec/blob/bd3bc80e5543d8a563343ec05abd1a5f3f67284c/lips/LIP-0020-grant-v4-wire-registry.md) | W1–W6 canonical/arithmetic/signature rules; W7 assent and consent; W8 preparation/frame; W9 precedence; §10 vector requirements. |
| [LIP-0013](https://github.com/relux-works/swarma-link-spec/blob/bd3bc80e5543d8a563343ec05abd1a5f3f67284c/lips/LIP-0013-trust-contract.md#31-event) | §3.1 event order/timestamps; §3.2 tag-value limit remains an inheritance question. |
| [LIP-0026](https://github.com/relux-works/swarma-link-spec/blob/bd3bc80e5543d8a563343ec05abd1a5f3f67284c/lips/LIP-0026-rows-and-accounts.md) | §8 group/template/range forms remain unspecified at the pin; J12 limits and J9/J10 semantics must be preserved. |
| [LIP-0014](https://github.com/relux-works/swarma-link-spec/blob/bd3bc80e5543d8a563343ec05abd1a5f3f67284c/lips/LIP-0014-notary-certified-redelegation.md) | §8.3 no-certifier semantics; J5/J2 notary contingencies; child assent signing question. |
| [BIP340](https://github.com/bitcoin/bips/blob/2885f13d3f37890e328683166dbcbc60b488d13a/bip-0340.mediawiki) | Default signing and verification; public verification rows 0–14 from its test-vectors.csv. Python also checks external vector 0 and an altered-message negative. |

## Specification decisions and integration requirements

The following distinguishes absent encodings from already settled semantics.
It does not reopen decisions or invent grant members.

1. Define required/optional grant members and their exact forms: issuer/owner
   pins, recipient modes, executor, limits, window, recent block, seal, delegation
   capability and owner-control binding. Terms use block heights. There is no
   separate statement key; statements use the name/device mechanism. A separate
   child seal key is distinct from the grant and delegation keys.
2. Define group/template/range member names, forms and traversal, no-certifier
   representation and group stop coins. Preserve J9's own-landlord restriction.
   Carry the decided 64 KiB document, 16 groups, 16 ranges/group and 4096
   coins/range limits into the member schema; the byte encodings are still absent
   at the qualified pin. Holder lists use a hash/version-pinned external list;
   changing it does not terminate existing grants.
3. Specify per-type member counts, maximum sizes and new-shape refusal order and
   codes. W1.1 already fixes document depth at 16; depth is not an open decision.
4. Specify the absent-grant/API result when W9.4 step 1 becomes buildable.
   `issuance-no-facts` currently observes a lab nil check only.
5. Locate evidence-outpoint form/bounds within W9.4 and state the refusal. W7.6
   evidence failure and W8 stored integer bounds do not settle that API order.
6. Specify whether W7.8 age or W7.9 consumption takes precedence when both fail.
7. Pin the consent name profile and whether LIP-0013 §3.2's 512-byte tag-value
   limit is inherited; artificial 2048-byte names are not real-name qualification.
8. Reconcile SB4's removal of seal endorsement with LIP-0024's proposed members,
   and integrate notary J5/J2 decisions. The labelled registry arithmetic is
   qualified only at its current revision.
9. Specify the child's assent signing key. Root wrong-party witnesses use a
   genuinely re-signed assent rather than changing the stated grant party key.
10. A later member-schema revision requires new lab qualification and new
    metadata pins. Current exact pins and their compared vector bytes are
    recorded above; no claim covers unqualified future specification revisions.

## Per-vector purpose, citation and verdict

| ID | Purpose | Spec | Basis | Code |
| --- | --- | --- | --- | --- |
| encode-assent | canonical specified assent payload | LIP-0020 W1.1-W1.6; W7.1 | spec | ok |
| encode-restricted-grammar | restricted document grammar, not grant bytes | LIP-0020 W1.1-W1.6 | spec | ok |
| encode-restricted-unicode-order | restricted document grammar, not grant bytes | LIP-0020 W1.1-W1.6 | spec | ok |
| arithmetic-0 | registry arithmetic only; no object/schema admission | LIP-0020 W3.1; W4.1; W6.1; section 10 primitive stage | spec | ok |
| signature-0-1 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | spec | ok |
| signature-0-2 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | spec | ok |
| signature-0-3 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | spec | ok |
| arithmetic-1 | registry arithmetic only; no object/schema admission | LIP-0020 W3.1; W4.1; W6.1; section 10 primitive stage | spec | ok |
| signature-1-1 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | spec | ok |
| signature-1-2 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | spec | ok |
| signature-1-3 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | spec | ok |
| arithmetic-2 | registry arithmetic only; no object/schema admission | LIP-0020 W3.1; W4.1; W6.1; section 10 primitive stage | spec | ok |
| signature-2-1 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | spec | ok |
| signature-2-2 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | spec | ok |
| signature-2-3 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | spec | ok |
| arithmetic-3 | registry arithmetic only; no object/schema admission | LIP-0020 W3.1; W4.1; W6.1; section 10 primitive stage | contingent:LIP-0008-SB4/LIP-0024 | ok |
| signature-3-1 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | contingent:LIP-0008-SB4/LIP-0024 | ok |
| signature-3-2 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | contingent:LIP-0008-SB4/LIP-0024 | ok |
| signature-3-3 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | contingent:LIP-0008-SB4/LIP-0024 | ok |
| arithmetic-4 | registry arithmetic only; no object/schema admission | LIP-0020 W3.1; W4.1; W6.1; section 10 primitive stage | spec | ok |
| signature-4-1 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | spec | ok |
| signature-4-2 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | spec | ok |
| signature-4-3 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | spec | ok |
| arithmetic-5 | registry arithmetic only; no object/schema admission | LIP-0020 W3.1; W4.1; W6.1; section 10 primitive stage | spec | ok |
| arithmetic-6 | registry arithmetic only; no object/schema admission | LIP-0020 W3.1; W4.1; W6.1; section 10 primitive stage | spec | ok |
| signature-6-1 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | spec | ok |
| signature-6-2 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | spec | ok |
| signature-6-3 | BIP340 over arithmetic typed digest, public scalar, zero aux_rand; no object admission | LIP-0020 W4.1; W5.1-W5.2 | spec | ok |
| signature-assent-1 | deterministic signature over a specified assent payload | LIP-0020 W7.1; W5.1-W5.2 | spec | ok |
| signature-assent-2 | deterministic signature over a specified assent payload | LIP-0020 W7.1; W5.1-W5.2 | spec | ok |
| signature-assent-3 | deterministic signature over a specified assent payload | LIP-0020 W7.1; W5.1-W5.2 | spec | ok |
| arithmetic-type-missing | unsupported type in arithmetic | LIP-0020 W3.1 | spec | WIRE_TYPE |
| arithmetic-type-nonstring | unsupported type in arithmetic | LIP-0020 W3.1 | spec | WIRE_TYPE |
| arithmetic-type-grant3 | unsupported type in arithmetic | LIP-0020 W3.1 | spec | WIRE_TYPE |
| size-1024-plus-0 | canonical refusal/boundary or precedence control | LIP-0020 W1.1; W9.2 | spec | ok |
| size-1024-plus-1 | canonical refusal/boundary or precedence control | LIP-0020 W1.1; W9.2 | spec | WIRE_SIZE |
| size-2048-plus-0 | canonical refusal/boundary or precedence control | LIP-0020 W1.1; W9.2 | spec | ok |
| size-2048-plus-1 | canonical refusal/boundary or precedence control | LIP-0020 W1.1; W9.2 | spec | WIRE_SIZE |
| depth-16 | canonical refusal/boundary or precedence control | LIP-0020 W1.1; W9.2 | spec | ok |
| depth-17 | canonical refusal/boundary or precedence control | LIP-0020 W1.1; W9.2 | spec | WIRE_SIZE |
| parse-empty-object | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6 | spec | ok |
| parse-zero | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6 | spec | ok |
| parse-two-members | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6 | spec | ok |
| size-before-json | canonical refusal/boundary or precedence control | LIP-0020 W1.1; W9.2 | spec | WIRE_SIZE |
| depth-before-truncated | canonical refusal/boundary or precedence control | LIP-0020 W1.1; W9.2 | spec | WIRE_SIZE |
| syntax-before-depth | canonical refusal/boundary or precedence control | LIP-0020 W1.2; W9.2 | spec | WIRE_JSON |
| utf8-before-depth | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.2; W9.2 | spec | WIRE_JSON |
| depth-before-utf8 | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.2; W9.2 | spec | WIRE_SIZE |
| json-empty | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_JSON |
| json-array | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_JSON |
| json-bom | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_JSON |
| json-utf8 | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_JSON |
| json-trailing | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_JSON |
| duplicate | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_DUPLICATE |
| duplicate-escaped | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_DUPLICATE |
| null | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_VALUE |
| null-number-string | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_VALUE |
| number-bound | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | ok |
| number-bound-plus-one | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_NUMBER |
| number-negative | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_NUMBER |
| number-negative-zero | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_NUMBER |
| number-fraction | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_NUMBER |
| number-exponent | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_NUMBER |
| number-leading-zero | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_JSON |
| string-lower-bound | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | ok |
| string-below-bound | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_STRING |
| string-surrogate | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_STRING |
| canonical-space | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_NOT_CANONICAL |
| canonical-order | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_NOT_CANONICAL |
| canonical-escape | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_NOT_CANONICAL |
| json-before-duplicate | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_JSON |
| duplicate-before-null | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_DUPLICATE |
| number-before-string | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_NUMBER |
| string-before-canonical | canonical refusal/boundary or precedence control | LIP-0020 W1.1-W1.6; W2.2; W9.2 | spec | WIRE_STRING |
| integer-4294967295-0 | exact digit parsing at bound and bound+1 | LIP-0020 W2.3-W2.4 | spec | ok |
| integer-4294967295-4294967295 | exact digit parsing at bound and bound+1 | LIP-0020 W2.3-W2.4 | spec | ok |
| integer-4294967295-4294967296 | exact digit parsing at bound and bound+1 | LIP-0020 W2.3-W2.4 | spec | WIRE_INTEGER |
| integer-9007199254740991-0 | exact digit parsing at bound and bound+1 | LIP-0020 W2.3-W2.4 | spec | ok |
| integer-9007199254740991-9007199254740991 | exact digit parsing at bound and bound+1 | LIP-0020 W2.3-W2.4 | spec | ok |
| integer-9007199254740991-9007199254740992 | exact digit parsing at bound and bound+1 | LIP-0020 W2.3-W2.4 | spec | WIRE_INTEGER |
| integer-18446744073709551615-0 | exact digit parsing at bound and bound+1 | LIP-0020 W2.3-W2.4 | spec | ok |
| integer-18446744073709551615-18446744073709551615 | exact digit parsing at bound and bound+1 | LIP-0020 W2.3-W2.4 | spec | ok |
| integer-18446744073709551615-18446744073709551616 | exact digit parsing at bound and bound+1 | LIP-0020 W2.3-W2.4 | spec | WIRE_INTEGER |
| integer-grammar-empty | string integer grammar refusal | LIP-0020 W2.3 | spec | WIRE_INTEGER |
| integer-grammar-double-zero | string integer grammar refusal | LIP-0020 W2.3 | spec | WIRE_INTEGER |
| integer-grammar-leading-zero | string integer grammar refusal | LIP-0020 W2.3 | spec | WIRE_INTEGER |
| integer-grammar-negative | string integer grammar refusal | LIP-0020 W2.3 | spec | WIRE_INTEGER |
| integer-grammar-plus | string integer grammar refusal | LIP-0020 W2.3 | spec | WIRE_INTEGER |
| integer-grammar-fraction | string integer grammar refusal | LIP-0020 W2.3 | spec | WIRE_INTEGER |
| integer-grammar-exponent | string integer grammar refusal | LIP-0020 W2.3 | spec | WIRE_INTEGER |
| integer-grammar-leading-space | string integer grammar refusal | LIP-0020 W2.3 | spec | WIRE_INTEGER |
| integer-grammar-trailing-space | string integer grammar refusal | LIP-0020 W2.3 | spec | WIRE_INTEGER |
| integer-grammar-nonascii | string integer grammar refusal | LIP-0020 W2.3 | spec | WIRE_INTEGER |
| signature-length-63 | strict raw signature length (range preflight only) | LIP-0020 W5.2 | lab-choice | WIRE_SIGNATURE_FORM |
| signature-length-64 | strict raw signature length (range preflight only) | LIP-0020 W5.2 | lab-choice | ok |
| signature-length-65 | strict raw signature length (range preflight only) | LIP-0020 W5.2 | lab-choice | WIRE_SIGNATURE_FORM |
| r-p-minus-one | field/scalar preflight boundary, not verification admission | LIP-0020 W5.2 | lab-choice | ok |
| r-p | field/scalar preflight boundary, not verification admission | LIP-0020 W5.2 | lab-choice | WIRE_SIGNATURE |
| r-p-plus-one | field/scalar preflight boundary, not verification admission | LIP-0020 W5.2 | lab-choice | WIRE_SIGNATURE |
| s-n-minus-one | field/scalar preflight boundary, not verification admission | LIP-0020 W5.2 | lab-choice | ok |
| s-n | field/scalar preflight boundary, not verification admission | LIP-0020 W5.2 | lab-choice | WIRE_SIGNATURE |
| s-n-plus-one | field/scalar preflight boundary, not verification admission | LIP-0020 W5.2 | lab-choice | WIRE_SIGNATURE |
| key-valid | x-only signing key form and lift_x | LIP-0020 W3.6 | spec | ok |
| key-short | x-only signing key form and lift_x | LIP-0020 W3.6 | spec | WIRE_MEMBER |
| key-long | x-only signing key form and lift_x | LIP-0020 W3.6 | spec | WIRE_MEMBER |
| key-upper | x-only signing key form and lift_x | LIP-0020 W3.6 | spec | WIRE_MEMBER |
| key-nonpoint | x-only signing key form and lift_x | LIP-0020 W3.6 | spec | WIRE_KEY |
| key-p | x-only signing key form and lift_x | LIP-0020 W3.6 | spec | WIRE_KEY |
| key-p-plus-one | x-only signing key form and lift_x | LIP-0020 W3.6 | spec | WIRE_KEY |
| verify-valid | strict verification and preflight order | LIP-0020 W5.2; W5.5 | spec | ok |
| verify-other-key | strict verification and preflight order | LIP-0020 W5.2; W5.5 | spec | WIRE_SIGNATURE |
| verify-zero | strict verification and preflight order | LIP-0020 W5.2; W5.5 | spec | WIRE_SIGNATURE |
| verify-signature-before-key | strict verification and preflight order | LIP-0020 W5.2; W5.5 | spec | WIRE_SIGNATURE_FORM |
| assent-valid | specified signed assent and all three hash roles | LIP-0020 W5.1-W5.3; W6.1-W6.4; W7.1-W7.2 | spec | ok |
| assent-reference | binding/refusal precedence on valid signed bytes | LIP-0020 W6.3; W7.2; W9.3 | spec | WIRE_ID |
| assent-binding | binding/refusal precedence on valid signed bytes | LIP-0020 W6.3; W7.2; W9.3 | spec | ASSENT_BINDING |
| assent-party | binding/refusal precedence on valid signed bytes | LIP-0020 W6.3; W7.2; W9.3 | spec | ASSENT_PARTY |
| assent-binding-before-party | binding/refusal precedence on valid signed bytes | LIP-0020 W6.3; W7.2; W9.3 | spec | ASSENT_BINDING |
| member-extra | closed specified assent schema before verification | LIP-0020 W3.1-W3.6; W9.3 | spec | WIRE_MEMBER |
| member-extra-resigned | single schema defect with a freshly signed payload | LIP-0020 W3.1-W3.6; W9.3 | spec | WIRE_MEMBER |
| member-missing | closed specified assent schema before verification | LIP-0020 W3.1-W3.6; W9.3 | spec | WIRE_MEMBER |
| member-missing-resigned | single schema defect with a freshly signed payload | LIP-0020 W3.1-W3.6; W9.3 | spec | WIRE_MEMBER |
| member-form | closed specified assent schema before verification | LIP-0020 W3.1-W3.6; W9.3 | spec | WIRE_MEMBER |
| member-form-resigned | single schema defect with a freshly signed payload | LIP-0020 W3.1-W3.6; W9.3 | spec | WIRE_MEMBER |
| member-key | closed specified assent schema before verification | LIP-0020 W3.1-W3.6; W9.3 | spec | WIRE_KEY |
| member-key-resigned | single schema defect with a freshly signed payload | LIP-0020 W3.1-W3.6; W9.3 | spec | WIRE_KEY |
| type-missing | closed specified assent schema before verification | LIP-0020 W3.1-W3.6; W9.3 | spec | WIRE_TYPE |
| type-missing-resigned | single schema defect with a freshly signed payload | LIP-0020 W3.1-W3.6; W9.3 | spec | WIRE_TYPE |
| type-wrong | closed specified assent schema before verification | LIP-0020 W3.1-W3.6; W9.3 | spec | WIRE_TYPE |
| type-wrong-resigned | single schema defect with a freshly signed payload | LIP-0020 W3.1-W3.6; W9.3 | spec | WIRE_TYPE |
| signature-text-length-126 | signature text form versus failed verification | LIP-0020 W5.2; W9.3 | spec | WIRE_SIGNATURE_FORM |
| signature-text-length-127 | signature text form versus failed verification | LIP-0020 W5.2; W9.3 | spec | WIRE_SIGNATURE_FORM |
| signature-text-length-128 | signature text form versus failed verification | LIP-0020 W5.2; W9.3 | spec | WIRE_SIGNATURE |
| signature-text-length-129 | signature text form versus failed verification | LIP-0020 W5.2; W9.3 | spec | WIRE_SIGNATURE_FORM |
| signature-text-length-130 | signature text form versus failed verification | LIP-0020 W5.2; W9.3 | spec | WIRE_SIGNATURE_FORM |
| memberless-signed-swarma-grant/4 | canonical signed arithmetic payload with verified public place key still has no member schema | LIP-0020 W3.1; section 10 primitive boundary | spec | WIRE_TYPE |
| memberless-signed-swarma-invocation/1 | canonical signed arithmetic payload with verified public place key still has no member schema | LIP-0020 W3.1; section 10 primitive boundary | spec | WIRE_TYPE |
| memberless-signed-swarma-receipt/1 | canonical signed arithmetic payload with verified public place key still has no member schema | LIP-0020 W3.1; section 10 primitive boundary | spec | WIRE_TYPE |
| memberless-signed-swarma-seal-endorsement/1 | canonical signed arithmetic payload with verified public place key still has no member schema | LIP-0020 W3.1; section 10 primitive boundary | contingent:LIP-0008-SB4/LIP-0024 | WIRE_TYPE |
| memberless-signed-swarma-notary-attestation/2 | canonical signed arithmetic payload with verified public place key still has no member schema | LIP-0020 W3.1; section 10 primitive boundary | contingent:LIP-0014-J5/J2 | WIRE_TYPE |
| bip340-verify-0 | official BIP340 verification witness; no fixture signing key imported | LIP-0020 W5.2; BIP340 test vector 0 | spec | ok |
| bip340-verify-1 | official BIP340 verification witness; no fixture signing key imported | LIP-0020 W5.2; BIP340 test vector 1 | spec | ok |
| bip340-verify-2 | official BIP340 verification witness; no fixture signing key imported | LIP-0020 W5.2; BIP340 test vector 2 | spec | ok |
| bip340-verify-3 | official BIP340 verification witness; no fixture signing key imported | LIP-0020 W5.2; BIP340 test vector 3 | spec | ok |
| bip340-verify-4 | official BIP340 verification witness; no fixture signing key imported | LIP-0020 W5.2; BIP340 test vector 4 | spec | ok |
| bip340-verify-5 | official BIP340 verification witness; no fixture signing key imported | LIP-0020 W5.2; BIP340 test vector 5 | spec | WIRE_KEY |
| bip340-verify-6 | official BIP340 verification witness; no fixture signing key imported | LIP-0020 W5.2; BIP340 test vector 6 | spec | WIRE_SIGNATURE |
| bip340-verify-7 | official BIP340 verification witness; no fixture signing key imported | LIP-0020 W5.2; BIP340 test vector 7 | spec | WIRE_SIGNATURE |
| bip340-verify-8 | official BIP340 verification witness; no fixture signing key imported | LIP-0020 W5.2; BIP340 test vector 8 | spec | WIRE_SIGNATURE |
| bip340-verify-9 | official BIP340 verification witness; no fixture signing key imported | LIP-0020 W5.2; BIP340 test vector 9 | spec | WIRE_SIGNATURE |
| bip340-verify-10 | official BIP340 verification witness; no fixture signing key imported | LIP-0020 W5.2; BIP340 test vector 10 | spec | WIRE_SIGNATURE |
| bip340-verify-11 | official BIP340 verification witness; no fixture signing key imported | LIP-0020 W5.2; BIP340 test vector 11 | spec | WIRE_SIGNATURE |
| bip340-verify-12 | official BIP340 verification witness; no fixture signing key imported | LIP-0020 W5.2; BIP340 test vector 12 | spec | WIRE_SIGNATURE |
| bip340-verify-13 | official BIP340 verification witness; no fixture signing key imported | LIP-0020 W5.2; BIP340 test vector 13 | spec | WIRE_SIGNATURE |
| bip340-verify-14 | official BIP340 verification witness; no fixture signing key imported | LIP-0020 W5.2; BIP340 test vector 14 | spec | WIRE_KEY |
| assent-reference-correct | payload id is the reference, never another hash role | LIP-0020 W6.1-W6.4 | spec | ok |
| assent-reference-one-byte | payload id is the reference, never another hash role | LIP-0020 W6.1-W6.4 | spec | WIRE_ID |
| assent-reference-digest | payload id is the reference, never another hash role | LIP-0020 W6.1-W6.4 | spec | WIRE_ID |
| assent-reference-address | payload id is the reference, never another hash role | LIP-0020 W6.1-W6.4 | spec | WIRE_ID |
| consent-encode-key | specified consent event from public scalar 2 and zero aux_rand | LIP-0020 W7.3; LIP-0013 2.1 and 3.1; NIP-01 | spec | ok |
| consent-encode-name | specified consent event from public scalar 2 and zero aux_rand | LIP-0020 W7.3; LIP-0013 2.1 and 3.1; NIP-01 | spec | ok |
| consent-timestamp-1 | specified consent event from public scalar 2 and zero aux_rand | LIP-0020 W7.3; LIP-0013 2.1 and 3.1; NIP-01 | spec | ok |
| consent-read-timestamp-1 | inclusive inherited consent timestamp bound | LIP-0020 W7.3-W7.4; LIP-0013 3.1 | spec | ok |
| consent-timestamp-253402300799 | specified consent event from public scalar 2 and zero aux_rand | LIP-0020 W7.3; LIP-0013 2.1 and 3.1; NIP-01 | spec | ok |
| consent-read-timestamp-253402300799 | inclusive inherited consent timestamp bound | LIP-0020 W7.3-W7.4; LIP-0013 3.1 | spec | ok |
| consent-timestamp-refuse-0 | outside inherited timestamp range | LIP-0020 W7.3-W7.4; LIP-0013 3.1 | spec | CONSENT_SHAPE |
| consent-timestamp-refuse-253402300800 | outside inherited timestamp range | LIP-0020 W7.3-W7.4; LIP-0013 3.1 | spec | CONSENT_SHAPE |
| consent-read-key | consent by key from stated context | LIP-0020 W7.3-W7.5 | spec | ok |
| consent-read-name | consent by name from stated evidence, no chain authentication | LIP-0020 W7.4; W7.6 | spec | ok |
| consent-shape | consent first-refusal/boundary on stated context | LIP-0020 W7.4 step 1 | spec | CONSENT_SHAPE |
| consent-binding | consent first-refusal/boundary on stated context | LIP-0020 W7.4 step 2 | spec | CONSENT_BINDING |
| consent-key | consent first-refusal/boundary on stated context | LIP-0020 W7.4 step 3; W7.5 | spec | CONSENT_KEY |
| consent-evidence-missing | consent first-refusal/boundary on stated context | LIP-0020 W7.6 | spec | CONSENT_EVIDENCE |
| consent-evidence-confirmed | consent first-refusal/boundary on stated context | LIP-0020 W7.6 | spec | CONSENT_EVIDENCE |
| consent-evidence-operation_of_name | consent first-refusal/boundary on stated context | LIP-0020 W7.6 | spec | CONSENT_EVIDENCE |
| consent-evidence-live_at_recent_block | consent first-refusal/boundary on stated context | LIP-0020 W7.6 | spec | CONSENT_EVIDENCE |
| consent-evidence-owner_matches | consent first-refusal/boundary on stated context | LIP-0020 W7.6 | spec | CONSENT_EVIDENCE |
| consent-evidence-height-101 | consent first-refusal/boundary on stated context | LIP-0020 W7.6 condition 1 | spec | CONSENT_EVIDENCE |
| consent-evidence-spent-100 | consent first-refusal/boundary on stated context | LIP-0020 W7.6 condition 4; W7.7 | spec | CONSENT_EVIDENCE |
| consent-evidence-spent-101 | consent first-refusal/boundary on stated context | LIP-0020 W7.6 condition 4; W7.7 | spec | ok |
| consent-name-key | consent first-refusal/boundary on stated context | LIP-0020 W7.6 condition 5 | spec | CONSENT_KEY |
| consent-signature | consent first-refusal/boundary on stated context | LIP-0020 W7.4 step 4 | spec | CONSENT_SIGNATURE |
| consent-time | consent first-refusal/boundary on stated context | LIP-0020 W7.4 step 5; W7.8 | spec | CONSENT_TIME |
| consent-verifier-no-age-limit | consent first-refusal/boundary on stated context | LIP-0020 W7.8 | spec | ok |
| consent-shape-before-binding | consent first-refusal/boundary on stated context | LIP-0020 W7.4 first refusal | spec | CONSENT_SHAPE |
| consent-shape-before-key | consent first-refusal/boundary on stated context | LIP-0020 W7.4 first refusal | spec | CONSENT_SHAPE |
| consent-shape-before-signature | consent first-refusal/boundary on stated context | LIP-0020 W7.4 first refusal | spec | CONSENT_SHAPE |
| consent-shape-before-time | consent first-refusal/boundary on stated context | LIP-0020 W7.4 first refusal | spec | CONSENT_SHAPE |
| consent-binding-before-key | consent first-refusal/boundary on stated context | LIP-0020 W7.4 first refusal | spec | CONSENT_BINDING |
| consent-binding-before-signature | consent first-refusal/boundary on stated context | LIP-0020 W7.4 first refusal | spec | CONSENT_BINDING |
| consent-binding-before-time | consent first-refusal/boundary on stated context | LIP-0020 W7.4 first refusal | spec | CONSENT_BINDING |
| consent-key-before-signature | consent first-refusal/boundary on stated context | LIP-0020 W7.4 first refusal | spec | CONSENT_KEY |
| consent-key-before-time | consent first-refusal/boundary on stated context | LIP-0020 W7.4 first refusal | spec | CONSENT_KEY |
| consent-signature-before-time | consent first-refusal/boundary on stated context | LIP-0020 W7.4 first refusal | spec | CONSENT_SIGNATURE |
| consent-signature-one-byte | consent first-refusal/boundary on stated context | LIP-0020 W7.4 step 4 | spec | CONSENT_SIGNATURE |
| consent-size-plus-0 | consent exact 2048 and 2049 octets | LIP-0020 W7.3-W7.4 | lab-choice | ok |
| consent-size-plus-1 | consent exact 2048 and 2049 octets | LIP-0020 W7.3-W7.4 | lab-choice | CONSENT_SHAPE |
| issuer-age-0 | issuer age inclusive; stated clock only | LIP-0020 W7.8 | spec | ok |
| issuer-age-259200 | issuer age inclusive; stated clock only | LIP-0020 W7.8 | spec | ok |
| issuer-age-259201 | issuer age inclusive; stated clock only | LIP-0020 W7.8 | spec | CONSENT_AGE |
| issuer-consumed | consumed id refuses; no durable journal claim | LIP-0020 W7.9 | spec | CONSENT_CONSUMED |
| issuer-time-before-age-consumed | issuer first refusal on supplied clock and consumed ids | LIP-0020 W7.8-W7.9 | spec | CONSENT_TIME |
| issuer-age-before-consumed | issuer first refusal on supplied clock and consumed ids | LIP-0020 W7.8-W7.9 | lab-choice | CONSENT_AGE |
| issuance-stated-key | conditional preparation from stated facts, not authenticated grant bytes | LIP-0020 W8.1-W8.6; W9.4 steps 2-6 | spec | ok |
| encode-preparation-key | canonical specified unsigned preparation on stated parts | LIP-0020 W1.1-W1.6; W8.1 | spec | ok |
| stored-preparation-key | unsigned preparation; no authentication of its named parts | LIP-0020 W8.1; W9.2-W9.3 | spec | ok |
| issuance-stated-name | conditional preparation from stated facts, not authenticated grant bytes | LIP-0020 W8.1-W8.6; W9.4 steps 2-6 | spec | ok |
| encode-preparation-name | canonical specified unsigned preparation on stated parts | LIP-0020 W1.1-W1.6; W8.1 | spec | ok |
| stored-preparation-name | unsigned preparation; no authentication of its named parts | LIP-0020 W8.1; W9.2-W9.3 | spec | ok |
| issuance-no-facts | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | lab-choice | WIRE_TYPE |
| issuance-mode-name-missing | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_MODE |
| issuance-vout-0 | number-form outpoint index at zero, bound and bound+1 | LIP-0020 W2.1-W2.2; W8.1 | spec | ok |
| issuance-vout-4294967296 | number-form outpoint index at zero, bound and bound+1 | LIP-0020 W2.1-W2.2; W8.1 | lab-choice | WIRE_INTEGER |
| issuance-mode | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_MODE |
| issuance-mode-before-assent | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_MODE |
| issuance-mode-before-consent | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_MODE |
| issuance-mode-before-frame | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_MODE |
| issuance-mode-before-commitment | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_MODE |
| issuance-assent | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ASSENT_PARTY |
| issuance-assent-before-consent | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ASSENT_PARTY |
| issuance-assent-before-frame | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ASSENT_PARTY |
| issuance-assent-before-commitment | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ASSENT_PARTY |
| issuance-consent | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | CONSENT_TIME |
| issuance-consent-before-frame | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | CONSENT_TIME |
| issuance-consent-before-commitment | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | CONSENT_TIME |
| issuance-frame | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_FRAME |
| issuance-frame-before-commitment | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_FRAME |
| issuance-commitment | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_COMMITMENT |
| frame-count-0 | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_FRAME |
| frame-count-2 | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_FRAME |
| frame-length-71 | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_FRAME |
| frame-length-73 | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_FRAME |
| frame-byte-0 | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_FRAME |
| frame-byte-1 | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_FRAME |
| frame-byte-2 | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_FRAME |
| frame-byte-3 | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_FRAME |
| frame-byte-4 | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_FRAME |
| frame-byte-5 | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_FRAME |
| frame-byte-6 | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_FRAME |
| frame-byte-39 | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_FRAME |
| frame-byte-40 | conditional issuance refusal/boundary on stated facts | LIP-0020 W8.1-W8.6; W9.4 | spec | ISSUANCE_FRAME |
