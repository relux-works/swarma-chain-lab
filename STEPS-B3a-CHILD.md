# B3a-CHILD step map — written before implementation

Pinned specification: [464c445fd52ce0ec8bdc52c0ead8a866a7b77f56](https://github.com/relux-works/swarma-link-spec/tree/464c445fd52ce0ec8bdc52c0ead8a866a7b77f56), version 0.1.61. Quotations below are from LIP-0014 §8.4 unless explicitly marked otherwise. The pure API compares documents and caller-supplied F7.3 facts; it grants no authority and does not replace the full admission table.

F13(a) count order RESOLVED: Ivan Oparin explicitly accepted the count order on 2026-11-17, in force since 0.1.57 (CHANGELOG 0.1.57; LIP-0026 §8). The rest of Q2 remains PROPOSED. Groups and ranges retain signed order; coins have ascending output index, counted from 1. F13(a) checks the full ordinal bound before reading any template, then selects the group/range/coin and evaluates F14–F18 in order. No node or seal is read. The exported `ChildAttenuationEvaluation` records only this evaluated slice, not admission.

Re-pin audit: every row sentence below is re-quoted from §8.4 at v0.1.61. **CHANGED** marks a row whose full specification row changed from 0.1.55; unmarked row sentences are unchanged. F6 remains outside the slice, including its new seal part (c); the former part (c) is now (d).

F11 caller contract follows the Lead ruling of 2026-11-19, Appendix A
section 3, recorded in PR #158's description (supersedes fix-3 D2).
`ParentNameObservation` carries the exact F7.3 recipient name, pinned genesis,
tip identity and explicit `ValueState`: K has a complete nonempty set of
lowercase x-only signing keys; A is read/no key under LIP-0010 section 4;
B is whole-value refusal under section 2 / D5. Zero/unset is not A. The pure
evaluator makes no read; provenance, completeness, owner control and healthy
observation are caller duties. Child seal and recipient-key/owner octet
comparisons run first: a matching x coordinate gives DELEGATE_KEY_REUSE,
Again=no regardless of the value state. A parent by key has no channel
comparison. For K, all keys are validated before membership: equal gives
DELEGATE_KEY_REUSE, Again=state; differing keys pass F11. Invalid metadata
or malformed K sets remain typed local input errors, not A/B classification.
A, B and unset give typed IMPLEMENTATION outcomes, no Link code, no closure
or revocation, Again=state, not input. ISSUE must sign nothing.

F17 remains unchanged: no LIP-0031 proposal profile is adopted; equal, zero
and one-over amounts under an existing row key refuse LIMIT_KIND_UNDEFINED.
Missing keys refuse CHILD_BUDGET_OVER first.

| Step | Spec sentence quoted | Inputs | Exact refusal / OPEN | Precedence | Function and test / boundary |
| --- | --- | --- | --- | --- | --- |
| F1 | “The parent as a document: the pipeline of a signed object (LIP-0020 W9.1, W11.8), steps 1 to 8, and of step 9 the rules of every grant (W11.9) and then rules 1 and 3 of W11.10, the forms of `delegate.actions` and of `notaries`. The row reads no fact of a chain. Rules 2 and 4 to 8 of W11.10, the rules of the pools, the groups and the ranges, are no part of this row at an admission: F13 judges rules 4 and 5 for the group and the range of the child, and open point O7 holds the rest (rule T10)” | Verified parent | Pipeline codes; GRANT_SHAPE; GRANT_DELEGATE | Before F2 | VerifyGrant / TestGrantVectors; precondition |
| F2 | “The child as a document. At `ADMIT`: the signed form, through the pipeline of a signed object with the points of W11.8 for a child. At `ISSUE`: the payload, read in the five steps of rule T7” | Verified child, matching parent identity; parent ancestry | WIRE_ID → CHAIN_DEPTH → NOT_DELEGABLE → CHILD_SIGNER | Before F5 | CheckChildAttenuationV4 / TestChildV4Documents |
| F3 | “The observation: the reads of this admission belong to one healthy observation on the pinned chain (LIP-0022 sections 1 to 3). The pinned chain is that of `genesis` of `P`, which F1 read” | Healthy node observation | Observation codes in B6.1 order | Before F5 in whole admission | Out of two-document scope; no observation asserted |
| F4 | “Not used. The first draft of this table put the authentication of the operation here. It is A1 at `ADMIT`, after F19, and I0 with I2 of section 8.5 at `ISSUE`. The steps after it keep their numbers” | None | None | Withdrawn | No implementation |
| F5 | “The same contract: the member `contract` of `C` equals the member `contract` of `P`. The comparison is of the two values of that member as the two payloads hold them, 64 hexadecimal characters each (LIP-0020 W11.2), and of no octet of a contract document (LIP-0020 W11.11, rule 1)” | P.contract, C.contract | CHILD_CONTRACT_DIFFERS | Before F8 | CheckChildAttenuationV4 / TestChildV4Prefix |
| F6 | “The contract binding, in four parts in this order. (a) The contract document for the identifier F5 found in both grants, and any framework document it names, are presented or resolved. (b) Their complete octets, as presented and without normalisation, recompute to their respective identifiers under LIP-0017 section 2. (c) The bound contract, then its named framework contract, each names a seal that the side's own node shows confirmed as named in this observation, under LIP-0017 section 6, rule 6, and T11 below. (d) The bound document is a valid contract of its profile and mirrors the terms of each grant (LIP-0008 sections 2 and 7.1; LIP-0017 section 5)” **CHANGED** | Contract document and profile | (a) CONTRACT_NOT_PRESENTED; (b) CONTRACT_ID; (c) CONTRACT_SEAL_MISSING / CONTRACT_SEAL_UNAVAILABLE; (d) profile rule/code OPEN | After F5, before F7 in whole admission | Outside attenuation-only API; whole admission remains impossible (T1) |
| F7 | “The parent is live: `P` passes, on the side's own node, the rules that admit a v4 grant, in the six parts and in the order of the table "Inside F7" below. The row judges `P` as a grant. It reads no coin, no stop coin and no name of any row (LIP-0026 R8.8)” | Node, journals, parent issuer/recipient/seal | First code of 7.1–7.6; OPEN O1/O5/O6 | Before F8 in whole admission | Outside two-document scope; no parent liveness asserted |
| F8 | “The subject: `genesis` of `C` equals `genesis` of `P`” | P.genesis, C.genesis | SUBJECT_MISMATCH | F5 before F8 before F9 | CheckChildAttenuationV4 / TestChildV4Prefix |
| F9 | “The keys of the parent, J4.3 (a): the delegation key differs, by x coordinate, from `issuer.grant_key`, from `recipient.key` or `recipient.owner`, from `issuer.owner`, from the `owner` of every entry of `notaries` and from `seal.key` of `P`” | P delegation, issuer grant/owner, recipient, notary owner and own seal keys | DELEGATE_KEY_REUSE | Before F10 | CheckChildAttenuationV4 / TestChildV4RoleKeys |
| F10 | “The child-seal key of the parent: first `delegate.child_seal_key` is present (CS1); then it differs, by x coordinate, from the delegation key and from the keys of F9 (CS3)” | P child-seal key and every F9 key | CHILD_SEAL_KEY; then DELEGATE_KEY_REUSE | Presence before comparisons, before F11 | CheckChildAttenuationV4 / TestChildV4RoleKeys |
| F11 | “The keys of the child, J4.3 (b), as far as no attestation is read: the delegation key differs, by x coordinate, from `seal.key` of `C`, from `recipient.key` or `recipient.owner` of `C`, and then, where `P` names its recipient by name, from every channel key that the value of that name yields. That value is the one that part 7.3 of F7 read in this observation, and F11 makes no read of its own. The comparison with the attestation key of the row's notary stands in F23” | P delegation key; C seal and recipient keys; explicit K/A/B ParentNameObservation from the same F7.3 read | DELEGATE_KEY_REUSE; codeless IMPLEMENTATION for A/B/unset (state, no closure, not input); malformed K facts are input errors | F5/F8/F9/F10 and F11 octets before observation validation, then channel-key comparison; before F12 | CheckChildAttenuationV4 / TestChildV4RoleKeys, TestChildV4ParentNameObservation, TestChildV4ParentNameValueReader; A-pass, B-to-A/empty-list, always/never-in-set plants |
| F12 | “The seal key of the child, CS2 as far as octets decide it: `seal.key` of `C` equals `delegate.child_seal_key` of `P`, octet for octet, the parity octet included” | C.seal.key, P.delegate.child_seal_key | CHILD_SEAL_KEY | Before ordinal, parity included | CheckChildAttenuationV4 / TestChildV4Prefix |
| F13 | “The row of the child, in two parts in this order. (a) The ordinal lies between 1 and the number of rows of `P`, the sum of the counts of all its ranges. No template is read before this. The ordinal then selects the group, the range and the coin (LIP-0026 R2.1, R8.3, R8.8). (b) The selected group and the selected range meet rules 4 and 5 of LIP-0020 W11.10: the template of that group, and that range with its `stop`” **CHANGED** | Signed range counts, ordinal, selected group/range/coin | CHILD_ORDINAL for F13(a); F13(b) not evaluated at its place; selected rule 4/5 finding in F1 (parent pipeline step 9) | Bound before all template reads; F12 before F13(a) before F14; known T10/S8-29 (a)/(c) divergence; both O7 outcomes unreachable while an earlier row refuses, pending O7 / LIP-0026 Q1 | CheckChildAttenuationV4 / TestChildV4Ordinal, TestChildV4Selection, TestChildV4BoundBeforeTemplate |
| F14 | “The executor of `C` is that of the template of its row: the same name and the same key (R2.2)” | C.executor, selected template.executor | CHILD_AGENT_NOT_ALLOWED | Before F15 | checkChildTemplateV4 via selected row / TestChildV4Template, TestChildV4Selection |
| F15 | “The recipient of `C` is that of the template: the same mode, and in it the same request key or the same name with the same owner key; for a class, a recipient by name (R2.3, R9.3). No name is read here” | C.recipient and selected template recipient constraint | CHILD_GRANTEE_NOT_ALLOWED | Before F16; class proves by-name mode only here | checkChildTemplateV4 via selected row / TestChildV4Template, TestChildV4Selection |
| F16 | “Every entry of `actions` of `C` is an entry of `delegate.actions` of `P`, compared as texts (LIP-0020 W11.11, rule 2). An empty list passes” | C.actions, P.delegate.actions | CHILD_ACTIONS_WIDER | Before F17; empty set passes | checkChildTemplateV4 via selected row / TestChildV4Template, TestChildV4Selection |
| F17 | “The limits of `C` against the template of its row, in three parts in this order. (a) Every limit of `C` has the key of a limit of the template; a limit of `C` whose key the template lacks refuses at any amount, 0 included (R2.4). (b) The kind of every limit of `C` and of the template has a type profile at the side (LIP-0020 W11.4, W11.14). (c) Each amount of `C` stands to the amount of the template under the same key as the profile of its kind says: for a ceiling, it is at most that amount (R2.4); for a floor, the relation of its profile” | C.limits, template.limits; kind profiles | CHILD_BUDGET_OVER → LIMIT_KIND_UNDEFINED → CHILD_BUDGET_OVER | All keys before kinds before numeric relation | checkChildTemplateV4 via selected row / TestChildV4Template, TestChildV4Selection |
| F18 | “The window of `C` lies inside that of `P`, in heights: `P.not_before_height <= C.not_before_height` and `C.not_after_height <= P.not_after_height` (LIP-0020 W11.11, rule 3). F2 already holds `C.not_before_height < C.not_after_height`” | P/C window bounds in heights | CHILD_WINDOW_NOT_NESTED | After F17; equality passes | checkChildTemplateV4 via selected row / TestChildV4Template, TestChildV4Selection |
| F19 | “The recipient of the child on the node, in this order (LIP-0026 R9.9). (a) For a recipient by name, the proof of LIP-0021 O7.2. This is the one place of that proof for `C`. (b) For a row with a class, the checks (a) to (d) of LIP-0026 section 9. (c) For a row without a certifier and with an exact name, the full checks (a) to (d) of that section with the issuer of `P` as the landlord. A recipient by key reads nothing here” | Recipient/landlord names, owner control, hash-pinned holders, parent recent block | RECIPIENT_NAME_NOT_HELD; RECIPIENT_NAME_UNAVAILABLE; R9.9 codes | Proof before class before exact-name J9 checks | Not attenuated as signed members: W11.2: “no member for the owner's devices or for a statement key”; “no holder of a landlord.” Node/name/holder checks outside two-document scope, never asserted |
| A1 | “At `ADMIT` alone, and no step of the predicate: the request is authenticated under the recipient mode of `C` (LIP-0008 section 4, step 2). By key: under the signed request key. By name: under the key that the value read in F19 yields for the channel of the request; for a row with a class that is the value whose writer check (d) judged (LIP-0026 R9.10)” | Authenticated request | OPEN O2 | After F19, before F20 | Outside scope: no invocation |
| F20 | “The child is live as a grant, in four parts in this order. (a) The side's journal holds no closure of `C` (LIP-0008 section 5.1). (b) The recent block of `C` is a block of the active chain of the observation, with the height `R` (LIP-0022 B4.2). (c) `R <= C.not_before_height` (LIP-0008 section 7.1, rule 3). (d) The tip `H` against the window (LIP-0008 section 7.1, rule 2; section 12.5). At `ADMIT`: `C.not_before_height <= H < C.not_after_height`. At `ISSUE`: `H < C.not_after_height` alone” | Child closure, active recent block, tip | CHILD_NOT_LIVE; RECENT_BLOCK; OPEN O5 | Journal before recent block before window | Outside scope: no node or journal |
| F21 | “The seal and the issuance of the child, in three blocs. The blocs are unordered against each other: the letters name them and state no order (open point O1). (s) The output at `seal.outpoint` exists with the single-key script of the profile for `seal.key`, and the profile and the kind are supported (LIP-0008 SB2; CS2). (w) The seal transaction and the anchor pass LIP-0023, in the order of its C7.1. (i) A reference to the grant from another object of the presentation, the `grant_id` of a preparation, equals the identifier of `C` (step 8 of the pipeline, LIP-0020 W11.8 and W8.1); then the presentation passes steps 2 to 6 of LIP-0020 W9.4 in their order; and the anchor stands in the window of the recent block (LIP-0022 B4.3). A validated spend of the seal closes `C` (CS5)” | Seal output/script, construction profile, issuance presentation | SEAL_OUTPUT; SEAL_SCRIPT; SEAL_PROFILE; issuance codes; OPEN O1/O6 | After F20, before F22; internal blocs unordered | C seal key checked at F12; no seal/child construction equality invented; node script uses parent profile, not a signed-profile inference |
| F22 | “The coin of the row, in the order of LIP-0026 R6.1: it is no output of the child's seal transaction (R3.4); it is on the active chain as the range states it, at or below the recent block of `P` (R3.2); one input of the confirmed anchor of `C` spends it (R3.3)” | Selected row coin, C seal transaction and issuance anchor | ROW_COIN_IN_SEAL_TRANSACTION → ROW_COIN → ROW_COIN_REQUIRED | Before F23 | Selected signed coin recorded; node/anchor checks outside scope |
| F23 | “The certifier. A row without a certifier ends the predicate here: F23 and F24 are not made, and an attestation that is presented is not read (J9.1; LIP-0026 R10.4). For a row with a certifier, steps V10 to V17 of section 8 in their order, with the notary of the row in V12 (J2.2, section 10.1), and after V12 the last comparison of J4.3 (b): the delegation key differs from the attestation key that this notary yields” | Selected row certifier, notary pins, attestation, node | CHILD_NOT_CERTIFIED; V11/V12; DELEGATE_KEY_REUSE; V13–V17 | No-certifier ends predicate without reading attestation | J9 template validity already checked by VerifyGrant; attestation and attestation-key separation outside scope |
| F24 | “The end of the row and of the attestation: the checks of the stop coin in the order of LIP-0027 H2.7, and then step V18” | Selected row stop coin, closure journal and attestation seal | JOURNAL_LOST → JOURNAL_FENCED → ROW_CLOSED_FOR_CAUSE; ROW_STOP_ALIAS; ROW_STOP; NOTARY_WITHDRAWN | After F23, absent for no-certifier row | Outside scope: row stop and certification, not pair attenuation |


## F11 input contract: pinned sentences and surrounding contracts

LIP-0014 §8.4 F11 (all three sentences, also in the row above):

> The keys of the child, J4.3 (b), as far as no attestation is read: the delegation key differs, by x coordinate, from `seal.key` of `C`, from `recipient.key` or `recipient.owner` of `C`, and then, where `P` names its recipient by name, from every channel key that the value of that name yields.
>
> That value is the one that part 7.3 of F7 read in this observation, and F11 makes no read of its own.
>
> The comparison with the attestation key of the row's notary stands in F23.

F7 part 7.3:

> Where `P` names its recipient by name: the current output of that name reads as controlled by the signed owner key (LIP-0021 O7.2)

§8.4 identifies the observation by reference to LIP-0022. Its B1.1 defines the identity:

> An observation is a set of reads of the verifier's own node, the reading node, that begins and ends with a read of its tip: the hash and the height of the last block of its active chain.
>
> Where the two reads differ, the observation is void.

B1.3 binds the chain:

> The observation is on the pinned chain: the node gives the pinned genesis hash for the block of height 0 (LIP-0008 section 4).

The typed input records that tip identity and checks the supplied genesis against `P.genesis`; it does not perform F3, reobserve the tip, or equate the tip with either grant's older `recent_block`.

LIP-0020 §11.11 W11.11 introductory sentences:

> A child lies within its parent in four comparisons of signed octets.
>
> Each is made by the signing service before it signs a child and by every verifier at admission, at the step that LIP-0014 section 8.4 gives it, and with the same code on both sides: the observation of a side stands before all four at the signing service and at a verifier alike (LIP-0014 section 8.4, pair Q3; section 8.5, I3 before I4).

Its four quoted comparison rules (unchanged):

> The member `contract` of the child equals the member `contract` of the parent. The comparison is of the two values as the two payloads hold them, 64 hexadecimal characters each (W11.2), and of no octet of a contract document
>
> Every text of `actions` of the child is a text of `delegate.actions` of the parent. The texts are compared as octets, and an empty list passes
>
> `not_before_height` of the parent is at most `not_before_height` of the child, and `not_after_height` of the child is at most `not_after_height` of the parent. The comparison is of heights and of nothing else
>
> `genesis` of the child equals `genesis` of the parent

LIP-0020 §11.14 W11.14 rule 2 (all four sentences):

> A limit of an undefined kind is never read as no limit.
>
> At the admission of a child, the signing service and a verifier MUST refuse a child where the kind of a limit of the child or of the template of its row has no type profile at that side (LIP-0014 section 8.4, row F17, part (b)).
>
> An executor MUST refuse a request that consumes a limit kind for which it has no type profile (row E2).
>
> A request that needs `policy` refuses in this way

The registry now also lists proposed LIP-0031 profiles. This side runs none. Its unchanged no-profile bound is:

> No limit kind is defined: a child that states a limit, and a child of a row whose template states one, refuses as `LIMIT_KIND_UNDEFINED` at every side, and only a pair without limits passes row F17.

There is no adopted profile or F23 attestation comparison. Success of the evaluated slice is not admission. No attack-surface table was supplied (brief gap); the F1–F24 row map above remains the coverage boundary. The out-of-contract rows are unchanged: F3, F6, F7, F19, A1 and F20–F24 require their independently established inputs.

## F13 and F17 basis at v0.1.61

LIP-0026 §8 (state and exact R8.3):

> **The order of the count: in force since version 0.1.57, by the owner's decision of 2026-11-17.**

> Each coin of a range is one row, with the template of its group. The rows of a parent are counted group by group in the order of the groups, inside a group range by range in the order of the ranges, and inside a range by ascending output index. The ordinal of a row is its position in that count, from 1. The number of rows of a parent is the sum of the counts of all its ranges.

LIP-0020 W11.6:

> An array keeps its order (section 1). The order of `groups` and of the `ranges` of a group in the octets is the signed order in which LIP-0026 R8.3 counts the rows, and the coins of a range stand in ascending order of their output index. A change of that order is another payload with another identifier.

LIP-0020 W11.4 (new proposal qualification):

> The texts of a limit are identifiers. Their registry, the meaning of each kind, its unit, its period and its arithmetic come with the type profile of the kind (LIP-0008 section 2; LIP-0018 section 2), and none is in force yet; the first three profiles stand proposed by version 0.1.58 in LIP-0031 and in the registry of W11.14, and a proposal defines no kind at a side that runs none of it.

The nine-row J12 example below is reproduced verbatim from LIP-0026 §8 in the generated corpus metadata; each of its nine positions is exercised with its stated group/range/coin offset. Example labels and relative indices are preserved; signed test grants use public test keys and deterministic transaction hashes, not invented on-chain observations. F14–F18 also run through the selected row, with separate negative neighbours for each exact refusal and precedence. No template is read at an invalid ordinal; the instrumented bound test empties a private template after verification while preserving serializability and rebinding the private child identifier to detect an early read. That isolated test plant is not a public input contract.

The input types establish existing verified-document preconditions, not full
admission. `ChildAttenuationEvaluation` directly evaluates F5, F8 to F12, F13(a), F14 to F18.

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

### F6 remains outside the slice

The changed F6 row above carries all four parts and the two new 0.1.61 seal
codes. Its part (c) is rule T11 / pair Q28, with cases S8-30–S8-33 and
step-f-39–step-f-44; the issuer repeat adds I4(c). None is implemented here:
there is no contract, framework, node, confirmation or seal read in this API.
The former profile part is now F6(d), not removed or implemented by a stub.

W11.14's explicit no-profile continuation at this pin is:

> Since version 0.1.58 the three kinds of the registry above have a proposed profile, LIP-0031: at a side that runs it, a limit of one of those kinds is judged under that profile in row F17 and in row E2, and rule 2 refuses the kinds that still have no profile there; at a side that runs none, the sentence before stands whole.

The proposed `swarma/coins`, `swarma/model-cost` and `swarma/model-tokens`
profiles are not enabled. Named generated cases refuse each as
`LIMIT_KIND_UNDEFINED` at F17 before the invalid window; missing keys still
refuse as `CHILD_BUDGET_OVER` before kind lookup. F13(b) is not evaluated at its place. The composed path reports a
selected-group rule 4/5 finding in F1 (parent pipeline step 9), not in F13.
This is a known lab divergence from T10's last sentence and S8-29 (a)/(c).
Both O7 outcomes are unreachable while an earlier row refuses, pending O7 /
LIP-0026 Q1. The existing `VerifyGrant` parent precondition is kept; no
partial parent reader or deferred-parent admission is implemented. Section
8.7 explicitly plans a second reader after the document pipeline.

## Fix 3: pinned composition, preconditions and Again

The chain-lab owner's decision for this slice is recorded in the PR #158
description (2026-11-19): keep the verified-parent precondition; do not change
`grant.go` or `grant_rules.go`. Generated S8-29 composition vectors pin the
parent's `GRANT_DELEGATE` at pipeline step 9 rule 4 under both `JudgeProposals`
values. With the certifier listed in notaries, the valid control passes,
ordinal 0 yields `CHILD_ORDINAL` at F13(a), and a wrong-signer child yields
`CHILD_SIGNER` at child pipeline step 7 (F2). These are document-composition
tests, not admission vectors or implementations of F13(b).

### Exact pin quotations

T10 (last sentence):

> A reader of documents that judged all eight rules in step 9, as LIP-0020 W11.8 has a reader do, knows more than this rule asks, and at the admission of a child it reports a finding of rules 4 and 5 for the selected group and range in F13 and not in F1

Q27:

> Inside F13: (a), then (b)

S8-29:

> Q27; rule T10

O7:

> What a side does, at the admission of a child, with a finding of rules 2 and 6 to 8 of LIP-0020 W11.10, whether or not octets of the group or the range of the child take part in the finding, and with a finding of rules 4 and 5 in another group or range. A finding of rules 2 and 6 to 8 can be caused by the coin of the selected range itself, which is the outpoint of the seal, meets another range or shares its stop coin, and by the pool sum, which is taken over the selected group as well; it is held here all the same, and no row of this table judges it. Two outcomes conform until the owner decides proposal Q1 of LIP-0026: a side that judged the rule refuses in F13, part (b), as `GRANT_DELEGATE`, and a side that judges rules 4 and 5 for the group and the range of its child alone goes on. The two sides of one path may therefore differ on such a parent, a parent whose defect is the child's own coin included. LIP-0020 W11.10 leaves that question to the pending proposal and states two outcomes only for its two proposal points

Section 8.7:

> The vectors on octets need a second reader in the tool, after the pipeline:
> the steps F5 and F8 to F18 as functions of two grants that were read and,
> for F17, of a stated set of profiles. It adds a file and a subcommand and
> leaves the generator of `vectors/LIP-0020/grant-v4.json` and its octets as
> they are. The vectors on stated facts wait for the forms of an observation
> and of a presentation, as the admission vectors of LIP-0020 section 12 do.
>
> No vector is planned for a defect or a pair that depends on one of the
> eight open points of section 8.4 (O1 to O8). None is planned for part (b)
> of F13 either: a parent that breaks rule 4 or 5 of LIP-0020 W11.10 is
> refused as a document by the pipeline of LIP-0020 section 12, whose
> vectors hold such parents, and the vectors on octets of this plan hold
> parents that the pipeline reads without a refusal; a vector of an
> admission for it waits with O7.

Section 8.4 composition:

> The consumer makes the steps in the order of the rows: F1 to F19, then A1, then F20 to F24

> A side therefore ends its observation before it reports a refusal of F5 to F24 or of A1, and where a code of F3 then applies it reports that code and not the later one (LIP-0022 B6.1)

### Again column and executable claims

`ChildAgain` has the marks used in this slice: `no`, `state`, `input`.
No evaluated row uses `pending`. F17(b) remains `no` under the stated empty
profile set, not a claim that a change of profiles cannot change a result.
The following cells quote the pin's Again column verbatim.

| Row | Again (quoted) | Executable evidence |
| --- | --- | --- |
| F2 | “no; input for a child that is presented without its parent (`WIRE_ID`): the same child, presented with its parent, is decided anew” | TestChildV4InputPrecedence; TestChildV4Documents |
| F5 | “no” | TestChildV4Prefix / TestChildV4Template / TestChildV4Selection; ChildAgainNo |
| F8 | “no” | TestChildV4Prefix / TestChildV4Template / TestChildV4Selection; ChildAgainNo |
| F9 | “no” | TestChildV4Prefix / TestChildV4Template / TestChildV4Selection; ChildAgainNo |
| F10 | “no” | TestChildV4Prefix / TestChildV4Template / TestChildV4Selection; ChildAgainNo |
| F11 | “no for the octets; state for a channel key”; ruling section 3 adds state for codeless A/B/unset outcomes, not input | TestChildV4Again (octets=no, channel=state); TestChildV4ParentNameObservation and TestChildV4ParentNameValueReader (IMPLEMENTATION/state) |
| F12 | “no” | TestChildV4Prefix / TestChildV4Template / TestChildV4Selection; ChildAgainNo |
| F13 | “no” | TestChildV4Prefix / TestChildV4Template / TestChildV4Selection; ChildAgainNo |
| F14 | “no” | TestChildV4Prefix / TestChildV4Template / TestChildV4Selection; ChildAgainNo |
| F15 | “no” | TestChildV4Prefix / TestChildV4Template / TestChildV4Selection; ChildAgainNo |
| F16 | “no” | TestChildV4Prefix / TestChildV4Template / TestChildV4Selection; ChildAgainNo |
| F17 | “no; for (b) and (c), no under one set of profiles” | TestChildV4Prefix / TestChildV4Template / TestChildV4Selection; ChildAgainNo |
| F18 | “no” | TestChildV4Prefix / TestChildV4Template / TestChildV4Selection; ChildAgainNo |

B1's generated `missing-childseal-before-delegation-reuse` is beside
`missing-childseal` and `child-seal-reuses-delegation-false`: F10's
`CHILD_SEAL_KEY` precedes the F11 defect (Q9). Plant `f11-before-f10` must fail
`TestChildV4RoleKeys/missing-childseal-before-delegation-reuse`.

B2's generated `limit-later-missing-key-true` has a known first key and a
missing second key at amount 0; its single-limit missing-key control is
`limit-later-missing-key-false`. Both give `CHILD_BUDGET_OVER` at F17(a),
before kind lookup. Plant `f17a-first-limit-only` must fail the two-limit case.
The nearby `limit-5` control reaches F17(b); `template-valid` passes.

Plant `f11-again-mark-conflated` must fail
`TestChildV4Again/delegation-in-set`; `missing-parent-again-no` must fail
`TestChildV4InputPrecedence/missing-parent`. Existing plants are retained.
The retained nil/empty list tests explicitly declare K: these are malformed
K sets, not A. Explicit A/B/unset fixtures and reader-backed cases replace
the old no-key ambiguity.

## Declared F11 deviation and reader coverage (fix 4)

The Lead ruling of 2026-11-19, Appendix A section 3, recorded in PR #158's
description, keeps A closed pending the clarifying spec sentence. This is a
declared deviation alongside the unchanged F13(b) divergence above: the
expected result after adoption is **pass**. Changing `childNoKeyPassV4` to
`true` is the one-line switch; B remains permanently refused. The pin stays
v0.1.61. No invented Link code, closure or revocation is reported; state is
decided anew at a later observation, and ISSUE signs nothing.

Classification belongs to the F7.3 reader (the caller). Search found the
existing `identity.ReadR1Value` in the wire module's already-pinned dependency;
there is no new parser, dependency, or F11 read. Tests run these six forms
through that reader: absent nostr, npub, uppercase hex, missing names._,
duplicate names (all A), and duplicate top-level nostr with the delegation
key second (B). Extra controls cover duplicate _ and a non-string nostr as A.
Each has a valid differing-key control beside its exact typed refusal.
Generated A/B/unset cases also pair each state with child seal, recipient key
and recipient owner reuse, including opposite output-key parity: octets win
with Again=no. Parent-by-key and differing/equal K neighbours are retained.

`f11-no-key-passes` must fail the A reader test; `f11-refused-as-no-key` and
`f11-refused-as-empty-keys` must fail the duplicate-top-level-nostr B test.
`f11-unset-as-no-key` must fail value-unset. All old plants remain.
