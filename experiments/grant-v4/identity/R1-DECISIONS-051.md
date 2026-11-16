# R1 decision map at v0.1.51

Normative source: [swarma-link-spec v0.1.51](https://github.com/relux-works/swarma-link-spec/tree/v0.1.51),
verified signed tag at `bd3bc80e5543d8a563343ec05abd1a5f3f67284c`.
Line numbers below refer to the exact files at that commit. This map covers
all R1 rules and vector families introduced by chain-lab PR #130. IN FORCE
includes the already-decided dependencies explicitly incorporated by J9–J12.
An undecided addition is never enabled merely because it shares a section
with a decision.

Source abbreviations:
[A](https://github.com/relux-works/swarma-link-spec/blob/bd3bc80e5543d8a563343ec05abd1a5f3f67284c/lips/LIP-0026-rows-and-accounts.md) = LIP-0026;
[B](https://github.com/relux-works/swarma-link-spec/blob/bd3bc80e5543d8a563343ec05abd1a5f3f67284c/lips/LIP-0010-name-value.md) = LIP-0010;
[C](https://github.com/relux-works/swarma-link-spec/blob/bd3bc80e5543d8a563343ec05abd1a5f3f67284c/lips/LIP-0014-notary-certified-redelegation.md) = LIP-0014.

| Rule / implemented predicate | Classification | Exact section and lines | Profile family / consequence |
| --- | --- | --- | --- |
| R1.1, R8.1 template: executor, recipient, row limits, certifier or none | IN FORCE, J12/J10/J9 | A §1 L197,203–217; §8 L509–518,526 | `CheckRowTemplate` checks nonempty executor name and valid signing key under both profiles, independently of draft whole-parent composition; `TestR1ExecutorShape` and executor-shape/key plants |
| R1.2 typed limit identity, inherited by R8.1 | IN FORCE as a stated template dependency | A §1 L198; §8 R8.1 L526 | `pools`, `row-fit`; period identity remains externally established |
| R1.3 / R8.5 exact weighted sums, exactly the used pool keys | IN FORCE, J12 | A §8 L514–515,530,545–549 | `pools` |
| R1.4 / R8.6 distinct coins, disjoint ranges, parent seal exclusion | IN FORCE, J12 | A §8 L516,531 | `distinct-coins` |
| R1.5 / R8.7 whole-parent atomic refusal, including all templates | DRAFT, conservative ambiguity Q1 | A §1 L201; §8 L532; decision summary L509–518 does not decide this extension as a whole | `parent-atomic` unavailable |
| R2.1 ordinal bounds before reading any row | IN FORCE, incorporated J1.2/J12 | A §2 L231,237–241; §8 L533; C §9.1 J1.2 L1404 | `row-fit` on independently selected facts |
| R2.2 exact executor name/key | IN FORCE, incorporated J1.2/J12 | A §2 L232,237–241; C §9.1 L1404 | `row-fit` |
| R2.3 key/name equality and class by-name mode | IN FORCE, J10 and incorporated J1.2 | A §2 L233,252–254; §9 L599–609,633 | `row-fit`, `class` |
| R2.4 typed limit ceilings; R2.5 ordinal/executor/recipient/ceiling order | IN FORCE, incorporated J1.2 | A §2 L234–246; C §9.1 L1404 | `row-fit`; no floor arithmetic |
| R8.2 range tuple, positive count, 32-bit last index | IN FORCE, J12 | A §8 L511–512,527 | `ranges`; scripts remain opaque stated octets |
| R3.1 / R8.2 witness-key-hash script requirement | DRAFT, explicitly added | A §8 L520–522,527; §3 L264 | `range-witness` unavailable |
| R8.3 one global ordinal and total count | IN FORCE, J12 | A §8 L512–513,528 | total count enabled |
| R8.3 group/range/output traversal order; R8.8 concrete selection | DRAFT, explicit order addition | A §8 L520–522,528,533 | `ordinal-order` unavailable; `SelectRow` refuses |
| R8.4 minimum/maximum groups/ranges, 4096 coins, parent size | DRAFT, proposed bounds | A §8 L520,529,551–554,578–579 | `group-bounds` unavailable; size not implemented in #130 |
| R9.1 exclusive recipient modes, nonempty exact landlord pins, distinct names | IN FORCE, J10 | A §9 L599–601,631 | `templates` |
| R9.2 checkpoint equals parent's recent block | DRAFT, explicit addition | A §9 L623–627,632 | `recent-checkpoint` unavailable; require separately established per-landlord checkpoint |
| R9.4 check (a), exact agent landlord pointer | IN FORCE, J10 | A §9 L602–604,634 | `class` |
| R9.5 check (b): live, pinned registration/owner, checkpoint history, transfer-return, pending spend | IN FORCE, J10 | A §9 L604–606,635,654–660 | `class`; explicit checkpoint, no inferred recent block |
| R9.5 fifth step: pinned owner wrote landlord's current value | DRAFT, explicit addition | A §9 L623–627,635 | `landlord-writer` unavailable |
| R9.6 check (c), current owner in selected landlord's current holders | IN FORCE, J10/J11 | A §9 L606–608,636; B §10 L436–451 | `class`, `holders`; no union across landlords |
| R9.7 check (d), current recipient value written by any listed holder | IN FORCE, J10 | A §9 L608–621,637 | `class`; writer need not be current owner |
| R9.8 unavailable/unsupported facts refuse; R9.9 order (a),(b),(c),(d) | IN FORCE, J10 plus ownership proof dependency | A §9 L602,638–639 | `class`; recipient ownership proof precedes these predicates |
| Eight proposed class codes and internal six-step refusal precedence | DRAFT, explicit addition | A §9 L610–611,623–627,644–652 | `class-codes-order` unavailable; existing strings are local diagnostics only |
| R9.10 coherent observation and channel from the checked recipient value | IN FORCE dependency of J10 checks on current facts | A §9 L602–609,640 | `class`; no separately supplied channel key |
| R9.11 holder adoption policy; R9.12 issuer prechecks | DRAFT, explicit additions; not implemented in #130 | A §9 L623–627,641–642 | Signer rules outside this verifier |
| R10.1 pinned certifier or explicit none; R10.2 issuer-only no-certifier scope | IN FORCE, J9 | A §10 L723–744,763–764,769–772; C decision table L146 | `no-certifier`, `templates` |
| R10.3 exact-name shortcut: reuse four issuer checks, retain writer/pending | DRAFT, explicit addition | A §10 L750–759,765,769–772 | `exact-shortcut` unavailable; in-force exact-name path runs full decided class predicates |
| R10.4 first sentence, no attestation required without certifier | IN FORCE, J9 | A §10 L723–730,766,769 | `no-certifier`; result means not required |
| R10.4 second sentence, never read a presented attestation | DRAFT, explicit addition | A §10 L758–759,766,769–772 | `ignore-attestation` unavailable; API has no attestation input |
| R10.5 no stop coin without certifier | IN FORCE, J9 | A §10 L730–731,767,769 | `no-certifier` |
| J11 holder shape, compressed owner pins, absent/empty means none; no authority inferred | IN FORCE | B §10 L400–418,420–430,436–451 | `holders` |
| J11 ascending/different holder pins and corresponding refusals | DRAFT, explicit proposal | B §10 L415–418,431–435 | `holder-order` unavailable; core reader preserves list order and multiplicity |
| J11 strict value envelope, 520 bytes, computed capacity | IN FORCE dependencies / product arithmetic, not a new holder-count rule | B §10 L420–430,461–478; §§2–3 | `ReadR1Value`, `HoldersCapacity`; `TestR1Holders`, `TestR1Profiles` capacity fixtures and `TestR1HoldersCapacity`, capacity off-by-one plant; all prior strict envelope tests retained |
| J11 holder changes alter issuer swarma and existing issuer-history result | IN FORCE dependency; closure recording remains outside #130 | B §10 L452–460 | Existing issuer-history predicates unchanged |

For a no-certifier template, standalone `CheckRowRecipient` rechecks
`CheckRowTemplate`, including R8.1. An invalid executor therefore refuses before
node facts: this is fail-closed tightening of the existing standalone path,
covered by `TestR1NoCertifierExecutorRecheck` in both profiles.
`TestR1ExecutorRecipientOrder` establishes R8.1 before R9.1 for a template with
both defects, with single-defect and valid controls, in both standalone profiles
and draft parent/child composition. In-force composition retains its prior
`R1_DRAFT_RULE_UNAVAILABLE` gate before template evaluation. The Python reader
compares all 24 outcomes without treating that gate as template acceptance.

Despite LIP-0010 L417's qualification of rule 3's proposed refusals, the in-force reader refuses “no array” and “element without a pin” because they violate the decided shape in rule 2 (L426–430).

| #130 vector family | Classification at this pin |
| --- | --- |
| 26 groups parents | Mixed: range/count/pool/disjointness IN FORCE; bound/WPKH cases DRAFT. Core profile evaluates only decided predicates. |
| 12 ordinals | Bounds IN FORCE; concrete mapping DRAFT. `SelectRow` unavailable; `CheckR1Fit` independently tests ordinal bounds. |
| 15 class templates | IN FORCE J10/J9, including rejection of foreign no-certifier scope. |
| 39 class admissions | Mixed: four class predicates IN FORCE; recent-checkpoint derivation, landlord writer, proposed code/inner-order claims DRAFT. |
| 11 certifier admissions | Mixed: scope/attestation requirement IN FORCE; exact shortcut and no-read guarantee DRAFT. |
| 28 holder values | Mixed: shape/pins/envelope IN FORCE; duplicate/descending-holder refusals DRAFT (value-23/24). |
| 5 holder capacity rows | IN FORCE product arithmetic through `HoldersCapacity` in both profile tests, independently computed by Python; no universal count cap. |
| 15 local row-fit rows | IN FORCE comparisons; composed group-selection path depends on DRAFT order. Test selected facts separately. |
| 276 revision controls and 13 absence/whitespace controls | IN FORCE envelope/absence/unsupported-fact dependencies; exact shortcut and local class diagnostic claims retain their DRAFT qualification. |

`TestR1HoldersCapacityRange` additionally compares Go and Python for every
input size 0–520, fifteen invalid-shape/envelope inputs and a UTF-8 positive
control (537 cases). Below the 100-byte canonical minimum the size controls
refuse; all remaining sizes have valid values padded outside the binding.
Independent enumeration bounds the maximum, including no room for one holder:
`most` is clamped to zero and `with` retains the original size. The
`r1-a4-old-python-capacity` plant restores the former formula and must fail both
`R1ReaderControls.test_capacity_full_range` and actual Go/Python agreement
(`r1_reader.agree`), including sizes 440 and 520. No universal count cap or
admission authority follows from these arithmetic checks.

## OPEN QUESTIONS

Q1. Does adoption of J12 also adopt R8.7 whole-parent atomic refusal in its
entirety, despite the bounded proposals and other additions that it references?
The decision summary does not explicitly say so. Conservative classification:
DRAFT. `CheckR1Parent` and therefore `CheckR1Child` are unavailable under
`R1InForce051`. Individual decided checks remain callable and never imply a
whole parent or child passed.

Q2. R8.3's detailed ordinal traversal is explicitly an addition. A future
released decision must fix a mapping before the in-force profile can select a
row from groups. `CheckR1Fit` takes already-established selected facts and
cannot establish their signed binding.

Q3. The class checkpoint exists in the decision, but its v4 derivation remains
proposed. The in-force API requires an independently pinned checkpoint for
each landlord; absence refuses. It never substitutes the parent's recent block.

Q4. The proposed class strings are retained as local diagnostic identifiers
for compatibility and reader comparison. The in-force profile does not claim
adoption of their normative taxonomy or inner-step precedence. The four
ordered class predicates themselves are decided.
