# B1 candidate vector set: blocked before generation

B1 cannot supply valid v4 grant document bytes from the requested source
revisions. The spec and lab agree that the grant has no member schema. This
directory records that prerequisite; it contains no candidate vector set.
Lab behavior is unchanged.

## Book and specification sources

All references below are immutable source revisions, inspected for this unit.

| Source | Exact section and consequence |
| --- | --- |
| [Swarma book, chapter 6, “Гранты и полномочия”](https://github.com/relux-works/swarma-docs/blob/b57a9be633c245373b448c3786bcbd49d636fe8a/book/ru/06-granty.md#общая-модель-и-брокер-v0), commit `b57a9be633c245373b448c3786bcbd49d636fe8a` | “Общая модель и брокер v0”, table and following paragraph, lines 13–24: the general grant model and credential-broker format are distinct. This chapter supplies no `swarma-grant/4` member schema; broker bytes cannot fill the gap. |
| [LIP-0020 at v0.1.51](https://github.com/relux-works/swarma-link-spec/blob/bd3bc80e5543d8a563343ec05abd1a5f3f67284c/lips/LIP-0020-grant-v4-wire-registry.md), commit `bd3bc80e5543d8a563343ec05abd1a5f3f67284c` | Summary; “What can be built from this LIP”; §3 W3.1–W3.2 and registry: no grant members exist, and a grant reader must refuse `WIRE_TYPE`. §4's type-only grant example is explicitly arithmetic, not a valid grant. §9 W9.4 step 1 has no content until members exist. |
| [Wire README's pinned LIP-0020 draft](https://github.com/relux-works/swarma-link-spec/blob/adae6e7669601f271f7d0d9cdd91ecee7d19bf02/lips/LIP-0020-grant-v4-wire-registry.md), commit `adae6e7669601f271f7d0d9cdd91ecee7d19bf02` | Same Summary, buildability table, §3 W3.1, §4 and §9 W9.4 constraints. The later release changes dependency status and adds cross-references, but still supplies no grant schema. These revisions are distinct. |
| [LIP-0026 at v0.1.51](https://github.com/relux-works/swarma-link-spec/blob/bd3bc80e5543d8a563343ec05abd1a5f3f67284c/lips/LIP-0026-rows-and-accounts.md) | “What can be built from this LIP” rules out row octets. §1 R1.1 defines row meaning; §8 J12/R8.1–R8.3 defines grouped row meaning. §8 explicitly leaves group/template/range octets open; R8.4's size/count limits are proposed. §11 says the groups vectors contain no octets because the parent has none. §§9–10 carry J10/J9 recipient and certifier constraints; these do not define bytes. |
| [LIP-0014 at v0.1.51](https://github.com/relux-works/swarma-link-spec/blob/bd3bc80e5543d8a563343ec05abd1a5f3f67284c/lips/LIP-0014-notary-certified-redelegation.md) | §8.3 J9.1–J9.4: no certifier is allowed only under the own-landlord recipient constraint, with no stop coin; a request key alone does not satisfy J9.2. These semantic decisions do not define a serialized null, omitted field or discriminator. |

Lab source pin: chain-lab
[`8a47f1a984cd93864402f7fdc09d2eba0d890b90`](https://github.com/relux-works/swarma-chain-lab/tree/8a47f1a984cd93864402f7fdc09d2eba0d890b90).
The relevant lab sections and symbols are:

- [wire README](../wire/README.md), “Composed issuance on stated inputs” and
  “Source pin and vector scope”: `GrantFacts` is independently established
  input; existing grant stand-ins are arithmetic only.
- [canonical.go](../wire/canonical.go), `EncodeDocument` and `ParseDocument`:
  generic restricted canonical JSON, with a caller-supplied size limit.
  Successful canonical encoding does not establish a grant schema.
- [crypto.go](../wire/crypto.go), `TaggedHash`, `TypedDigest`, `PayloadID`,
  `VerifyBIP340`: hash arithmetic and signature verification cannot admit a
  grant. `TypedDigest` explicitly does not check a member schema.
- [objects.go](../wire/objects.go), `ReadSigned`: only `ContractAssent`
  is supported; requesting `Grant` returns `WIRE_TYPE`.
- [composed.go](../wire/composed.go), `GrantFacts` and `CheckIssuance`:
  the supplied facts are not parsed/authenticated grant bytes. The function
  implements only W9.4 steps 2–6.
- [composed_test.go](../wire/composed_test.go),
  `TestV4ComposedDispatchBoundary`: raw issuance octets refuse `WIRE_TYPE`;
  supplied-fact success is explicitly separate from grant admission.
- [identity decision map](../identity/R1-DECISIONS-051.md), “OPEN QUESTIONS”
  Q1–Q4; [r1_profile.go](../identity/r1_profile.go), `R1InForce051` rules;
  [r1_groups.go](../identity/r1_groups.go), `RowGroup`, `RowTemplate`,
  `RowRange`: stated facts, not grant wire members. `SelectRow` and the
  whole-parent check are unavailable in the in-force profile.

## Mapping “grant-member”

For this brief the term means the `swarma-grant/4` payload and its JSON
members, within the signed form of LIP-0020 §5 W5.3 (`payload`, `signature`).
For a parent, the row meaning is LIP-0026 §1 R1.1, represented conceptually
by J12's groups, templates and ranges (§8). It names no additional registry
type. A single-row case would require the same missing member schema as a
grouped parent; it cannot be substituted with a type-only hash example or
the identity package's Go struct field names.

## Requested outputs and current coverage

| Requested B1 artifact | State and reason |
| --- | --- |
| `vectors.json`: valid single-row grant and J12 case | Not generated: no defined member names/forms or group octets. |
| Grant `TaggedHash`, `TypedDigest`, `PayloadID` and signatures | Not generated: no valid grant preimage. Arbitrary JSON would only prove arithmetic. |
| `CheckIssuance` inputs and `Preparation` outputs | Existing stated-fact lab support; no B1 set generated after the prerequisite failed. |
| Consent bytes, `ReadConsent`, issuer predicates | Existing lab support, outside the stopped generation unit. No new B1 coverage claimed. |
| Every object's first-refusal vectors and size boundaries | Not generated. Grant member and maximum-size contracts are absent; proposed R8.4 bounds cannot become an adopted grant boundary through a fixture. |
| Independent stdlib Python with `python3 -I` | Not implemented or run: no defined valid grant bytes to independently derive. No cross-language agreement claimed. |
| Go regeneration/drift test; one-byte plants against both readers | Not implemented or run: no B1 vector file or independent reader exists. |

The existing wire test suite is baseline evidence only, not B1 acceptance.
No Go/Python disagreement was observed because B1 generation never began;
no lab/spec disagreement was found at this stop point. Delegation and
re-delegation bytes remain B5 and B6 and were not investigated or implemented.

## Decisions needed from the spec seat

1. Publish/pin a candidate `swarma-grant/4` member schema: required/optional
   members, nested shapes, exact integer and key forms, recipient modes,
   issuer/owner pins, executor, limits, window, recent block and seal.
2. Define J12 group/template/range member names, forms and traversal, and
   the representation of “no certifier” and any group stop coins. Preserve
   J9's semantic restriction; encoding alone must not broaden it.
3. Fix candidate grant size/depth/count limits and refusal precedence/codes
   for those shapes. LIP-0026 §8 R8.4 proposals do not resolve this.
4. Reconcile the lab's unsupported-grant reader with that pinned schema in
   a separately authorized behavior change, or explicitly redefine B1 as
   arithmetic-only primitives with no VALID grant claim. The latter cannot
   satisfy the current brief's grant-document requirement.

The clean approaches checked were the released spec, the lab-pinned draft,
the book, the generic canonical encoder and the R1 stated-fact structures.
None supplies the missing wire schema. Inventing local member names would
create a protocol design decision rather than derive bytes from the named
sources. No such workaround was made.

## Tools and evidence

No B1 generator or vector format is defined at this blocked stage. Existing
commands remain in the [wire tool documentation](../wire/README.md#tools-and-commands).
The producer report records the exact baseline commands, exits, omissions
and delivery state. Logs live in task-owned `.temp/` scratch and are not
publication artifacts.
