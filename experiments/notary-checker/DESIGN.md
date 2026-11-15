# Deterministic notary checker (LAB)

Specification: **v0.1.48**, commit
`2012ac9155568af80d610bdf9b7683881a46e5cb` of
[swarma-link-spec](https://github.com/relux-works/swarma-link-spec/tree/2012ac9155568af80d610bdf9b7683881a46e5cb).
All section references below refer to that immutable tree. The relevant LIPs
are Draft proposals; the checker pins their bytes without claiming adoption.

This module computes the mechanical part of certification for Grant v3,
contract profile `swarma-trust-contract/2`, one parent and one child. It returns
an **unsigned attestation candidate and signing digest**. `ATTEST` is the
CLI spelling of that offline decision. It is not a signed attestation, an
`attestation_id`, live admission, or permission to sign without the remaining
checks. LIP-0014 section 6.2 explicitly calls a pre-clearance no attestation.
No key enters the production API, and nothing is signed by this module.

## Exact inputs

Every file is read as bytes, without trimming, normalization or fetching.
The library accepts the same bytes in `Input`; it performs no direct I/O.
MVP checking also calls the explicit `NameSource` dependency described below.

| Input | Exact octets / meaning | Source |
| --- | --- | --- |
| Parent and child | Complete canonical presentations `{"signed_grant":{"grant":...,"signature":...},"issuance":{"txid":...}}`. Each contains the complete v3 grant and consent, not an asserted hash or a request for a child signature. The unsigned issuance locator is outside `grant_id`. | LIP-0004 sections 2–4; LIP-0014 section 8 V2 |
| Both contracts | All fifteen members of profile `/2` in their prescribed order, including the six-member `delegate`, four-member rows, three-member notary pins, and signed checkpoint. SHA-256 must equal the respective grant's `contract_sha256`. | LIP-0014 sections 2, 3, 3.1, 3.2; LIP-0013 sections 2.1–2.5 |
| Delegation request | Complete canonical kind-8186 NIP-01 event, signed by the parent's `grantee_key`, with empty content and the five ordered tags `t,parent,contract,ordinal,nonce`. | LIP-0014 section 5; LIP-0013 section 3.1 |
| Both scope texts | Exact bytes if the corresponding signed hash is nonempty; equal hashes are required by this checker's conservative text policy. No text is interpreted. Empty hashes require absent/empty text inputs. | LIP-0014 sections 3.3, 3.4 J5.1–J5.3, 8 V2 |
| Local policy | Canonical local configuration binding both recomputed grant IDs, `issuer_owner`, `delegator_owner`, selected `notary_name`, its `notary_owner`, and sorted distinct `agreed_by` owner identifiers. Owner identifiers use valid compressed public keys. This is a trusted affiliation/agreement mapping, not a protocol object or presenter evidence. The optional MVP deployment mode adds local owner signatures as described below. | D8; LIP-0014 section 7; OPEN QUESTION O2 below; local MVP policy below |
| Notary value | Complete UTF-8 JSON name value, at most 520 bytes, from a trusted caller. Top-level extensions are skipped; duplicate/aliased `swarma` or `nostr` refuse. The exact `swarma` byte span must be the canonical `{"notary":{"attest":"<x-only key>"}}` binding. | LIP-0010 sections 2, 3, 9 |
| Statement | Canonical local input `{"notary_seal":{"txid":...,"vout":...,"script":...},"tip_height":...,"tip_hash":...}`. These are claims to bind into a candidate, not established observations. | LIP-0014 sections 6.1, 6.2, 6.4 |
| `-at` | Required explicit Unix seconds, 1 through 253402300799; the only time source. | LIP-0004 sections 2, 3, 5; LIP-0014 section 6.1 |

The grant signatures cover
`SHA-256("swarma-grant-v3" || canonical grant bytes)`. The fixed ASCII prefix
has no terminator. The grant ID is SHA-256 of the exact canonical signed
envelope. The consent event's NIP-01 ID is recomputed and verified under the
grantee key; the landlord countersignature covers the raw 32-byte contract
hash. Booking and privacy tags are recomputed from the contract, including
`SHA-256(contract bytes || "booking")` and
`SHA-256("swarma-trust-privacy-v1")`. These are distinct signing domains
(LIP-0004 sections 2–3; LIP-0013 sections 2.4–2.5). The request's NIP-01
signature is verified over its recomputed ID (LIP-0014 section 5).

Only verification uses the pinned BIP-340 library already used elsewhere in
this repository: `btcec/v2 v2.3.5`. The checker explicitly enforces `r < p` and
`s < n` before verification. Test fixture signing uses only the deliberately
public fixed test secrets in `testdata/keys.json`.

## Decision and refusal order

Before comparing grants, the checker validates canonical presentations, grant
fields and signatures, their explicit-time windows, consent signatures, and
contract binding. This is the offline subset of LIP-0004 sections 2–5 and
LIP-0013 section 2.5. The parent is checked before the child. Contract rules
1–9 run exactly in the order of LIP-0014 section 3.1. Rule 1 owns lexical
properties at every depth; rule 9 owns nested member sets and semantic types.
No parsed value is normalized into an accepted substitute for signed bytes.

| Condition | Refusal | Specification |
| --- | --- | --- |
| Canonical presentation and ordered v3 members | `GRANT_ENCODING` | LIP-0004 section 2 |
| Supported v3 fields, fixed main/regtest genesis, valid keys, hashes, scope, window | `GRANT_FIELD` | LIP-0004 sections 2, 5 |
| Grant signature verifies under its stated issuer key | `GRANT_SIGNATURE` | LIP-0004 section 2 |
| `not_before <= at < not_after` | `GRANT_NOT_YET_VALID`, `GRANT_EXPIRED` | LIP-0004 section 5 |
| Consent event, countersignature, grantee and contract match; no future consent | `GRANT_CONSENT` | LIP-0004 section 3 |
| Contract hash, canonical profile rules, common fields, derived scope, budget, consent tags | `CONTRACT_HASH`, the rule 1–9 code, `CONTRACT_MISMATCH`, `SCOPE_MISMATCH`, `BUDGET_MISMATCH`, `CONSENT_TAGS` | LIP-0013 section 2.5; LIP-0014 sections 3.1–3.2 |
| Child parent ID equals recomputed signed parent ID | `PARENT_ID_MISMATCH` | LIP-0014 sections 4, 8 V3 |
| Parent is a root; no repeated ID; parent has depth 1 | `CHAIN_DEPTH`, `NOT_DELEGABLE` | D7; LIP-0014 sections 4, 8 V4 |
| Same network, genesis, principal and v3 issuer key | `SUBJECT_MISMATCH` | LIP-0004 section 2; LIP-0014 sections 1, 4, 8 V6 |
| Complete kind-8186 request has correct signature, signer, parent, contract, ordinal, nonce shape and creation time within the parent's window | `DELEGATION_REQUEST` | LIP-0014 sections 5, 8 V7 |
| Ordinal is 1 through row count **before indexing**, then selects that exact row | `CHILD_ORDINAL` | LIP-0026 R2.1, R2.5; LIP-0014 sections 4, 8 V8, 9.1 J1.2 |
| Child executor equals selected row executor | `CHILD_AGENT_NOT_ALLOWED` | LIP-0026 R2.2; LIP-0014 sections 4, 8 V8 |
| Child grantee key equals selected row grantee | `CHILD_GRANTEE_NOT_ALLOWED` | LIP-0026 R2.3; LIP-0014 sections 4, 8 V8 |
| Child actions are a subset of the **delegable** actions, themselves a subset of the parent's own actions | `CHILD_ACTIONS_WIDER` | LIP-0014 sections 2, 4, 8 V9 |
| Child repositories are an exact-byte subset of parent repositories; no URL equivalence or `.git` rewriting | `CHILD_REPOS_WIDER` | LIP-0014 section 4; LIP-0013 section 2.3 rule 5 |
| Child spend budget is at most the selected row cap | `CHILD_BUDGET_OVER` | LIP-0026 R2.4; LIP-0014 sections 4, 8 V9, 9.1 |
| `P.not_before <= C.not_before < C.not_after <= P.not_after` | `CHILD_WINDOW_NOT_NESTED` | LIP-0014 sections 4, 8 V9 |
| Text hashes are identical and supplied text bytes match them | `TEXT_JUDGEMENT_REQUIRED`, `DELEGATION_BUNDLE` | Conservative restriction under LIP-0014 sections 3.3–3.4, 8 V2; O1 below |
| Explicit policy binds both grant IDs and provides valid owner identifiers | `OWNER_EVIDENCE_REQUIRED` | D8; LIP-0014 section 7; local evidence boundary O2 |
| Selected notary is designated and its configured owner equals the signed owner pin | `NOTARY_NOT_DESIGNATED`, `NOTARY_NAME_CHANGED` | LIP-0014 sections 2, 7, 7.1 J3.1; this comparison alone does not perform J3.2–J3.5 |
| By default, same-owner delegation uses the issuer's notary; cross-owner delegation uses a third owner, distinct from **both** parties | `NOTARY_OWNER_RELATION` | D8; LIP-0014 section 7; stricter interpretation O2 |
| Cross-owner policy explicitly records both owners' agreement to the selected certifier | `CROSS_OWNER_CERTIFIER_REQUIRED` | D8; LIP-0014 section 7 |
| The exact notary authority span yields a valid key | `NOTARY_KEY` | LIP-0010 sections 2, 3, 9 |
| Notary key differs from delegator, then delegatee; name differs from both executors | `NOTARY_IS_DELEGATOR`, `NOTARY_IS_DELEGATEE`, `NOTARY_IS_EXECUTOR` | LIP-0014 section 8 V13; LIP-0012 section 7 |
| Explicit seal and tip fields have their required integer/hex types | `STATEMENT_FIELD` | LIP-0014 section 6.1; local candidate input |

`AT_TIME`, `INPUT_REQUIRED`, `INPUT_READ`, and `ARGUMENTS` are local input
codes. The `GRANT_*`, `OWNER_*`, `CROSS_OWNER_*`, `TEXT_JUDGEMENT_REQUIRED`
and `STATEMENT_FIELD` names above describe this library's offline refusals;
they do not replace the online verifier's refusal order or pending states.
Contract, row and request codes retain the meanings cited above.

D12 applies without an override: the parent cannot delegate `spend`, so its
pool and all row caps are zero. A nonzero budget without `spend` fails
`CONTRACT_BUDGET`; adding `spend` to the child fails `CHILD_ACTIONS_WIDER`.
A parent's own spend allowance is separate from the delegation pool
(LIP-0014 sections 2, 9, 9.1 J1.5). The isolated `row-budget-over` vector
exercises the defensive inequality with counterfactual typed inputs; it is
not admission of a spend contract. There is no counterfactual spend flag in
the library or CLI. Parent row caps cannot overflow a sum here because every
admitted cap and the pool are zero. No sibling sum is computed.

The v3 profile carries a key-only grantee and an executor name. R2's v4
executor key pin, named-recipient mode and typed limit keys have no v3
members. This module implements their **v3 mapping explicitly stated in
LIP-0014 section 9.1 and LIP-0026's conformance section**, not fabricated v4
bytes. It refuses every grant version other than 3. Coins, groups, landlord
classes and optional certifiers from pending v4 directions are unsupported.

D9 is in force: any parent-designated notary may certify, even one other
than the row's `notary`. Pending J2 would narrow that rule; it is not
silently applied (LIP-0014 sections 2, 8 V12, 10.1). Every v3 row still names
a designated notary, and a depth-1 right without any notary refuses
`DELEGATE_NO_NOTARY`. Pending J9 changes v4 only (LIP-0014 section 8.3).

## Output octets

On success `Result.Attestation` is the canonical **eighteen-member**
`swarma-notary-attestation/1` object in LIP-0014 section 6.1's exact order:
`profile,kind,network,genesis,landlord_name,notary_name,notary_key,
parent_grant_id,parent_contract_sha256,child_grant_id,child_contract_sha256,
ordinal,textual,mechanical,notary_seal,tip_height,tip_hash,attested_at`.
`kind` is `child-within-parent`; `mechanical` is `pass`. `textual` is `none`
or `identical`, never `within`. Seal and tip claims come from `Statement`;
`attested_at` is the explicit `at` argument. Both grant IDs and both contract
hashes are recomputed, rather than accepted as claims from that statement.

`Result.Digest` and `ATTEST <digest>` are:

```text
SHA-256("swarma-notary-v1" || exact attestation bytes)
```

The fixed ASCII prefix is 16 bytes, without a NUL, length or padding
(LIP-0014 section 6.1).

The complete canonical attestation must be at most 8192 bytes (LIP-0014
section 6.1 inherits LIP-0013 section 2.1). `MaxAttestationBytes` is shared by
`Check` and `SignedAttestation`'s candidate decoder. The statement's separate
input bound does not bound the composed document. After composition and before
computing a digest, an oversized candidate refuses as `ATTESTATION_TOO_LARGE`
with an empty `Result`. The independent reader enforces the same invariant
using its own shared producer/decoder constant.

### Produced-object size audit

| Produced object | Size and receiving constraint | Alignment |
| --- | --- | --- |
| Canonical attestation | At most 8192 bytes; signed helper decodes with `MaxAttestationBytes` | Producer now enforces that same constant before returning bytes or digest; 8191/8192 accepted, 8193 refused |
| Signing digest | SHA-256, 32 octets represented by 64 lowercase hex characters | Signature helper checks the exact digest against the candidate; the prefix preimage is not a separately decoded document |
| Signed envelope and `attestation_id` | Candidate plus exactly 159 bytes for fixed member names and the 128-character BIP-340 signature; at most 8351 bytes. ID is SHA-256, 64 lowercase hex characters | Section 6.1 applies the document cap to the inner eighteen-member attestation; it defines the envelope separately for hashing. No envelope decoder or conflicting envelope cap is implemented here. Boundary tests preserve exact inner bytes and hash the whole envelope |
| Anchor script | Exactly 72 bytes; three input IDs must each decode from 64 lowercase hex characters to 32 bytes | Fixed framing and SHA-256 commitment match section 6.4/LIP-0005; positive vectors assert exact frame bytes and length, malformed IDs yield no script |
| Parsed contracts and nested delegates | Input contract is at most 8192 bytes; nested delegate is a span within it, also decoded at 8192 | Canonical equality preserves the input size. No contract producer exists in the runtime library |
| Grant/consent/request hash encodings | Canonical projections of previously bounded, exactly re-encoded input objects: presentations 32768 bytes, requests 16384 | Only hashes escape these internal encodings. No expanded grant, consent or request is produced for a capped decoder |
| Name authority, policy and statement | Reader-only inputs, respectively 520, 8192 and 8192 bytes | No separate runtime encoders; their selected fields feed the now-bounded attestation |
| CLI success line | Strict: `ATTEST `, a 64-character digest and newline, 72 bytes; explicit offline fixture mode adds ` offline-fixture`, 88 bytes | Overflow prints only `REFUSED ATTESTATION_TOO_LARGE` with exit 1; no candidate/digest is printed |

This audit covers this module's encoders and decoders, not a downstream online
service's transport or node admission. No other producer/decoder size mismatch
was found; no additional protocol cap or live qualification is implied.

A later service signs that 32-byte digest with the key yielded by the
notary's own name (LIP-0010 section 9; LIP-0012 section 2). The helper
`SignedAttestation` verifies a supplied signature, constructs exactly
`{"attestation":...,"signature":...}`, and returns its SHA-256 as
`attestation_id`. It is a wrapping/signature helper, not a verifier of live
attestations. It never calls a signer. `AnchorScript` constructs the exact
72-byte action-`0x04`, locator-`0x01` frame of LIP-0014 section 6.4 and
LIP-0005 section 2:

```text
commitment = SHA-256("swarma-attest-v1" || decoded attestation_id
                    || decoded child_grant_id || decoded parent_grant_id)
script = 6a03534c044201 || commitment || 01 || attestation_id
```

The anchor preimage is 112 bytes: the 16-byte literal followed by three
32-byte decoded IDs, without separators (LIP-0014 section 6.4).
Malformed IDs or signatures return named refusals with no partial envelope
or script. A `Check` refusal returns an empty `Result` and CLI exit 1; local
argument/file failures exit 2. No attestation candidate is output on refusal.

## What remains outside this unit

The notary's authority is additional to the grant path and creates no rights
(LIP-0012 sections 1–2, N10). These are **unperformed obligations**, not
booleans a request can assert to bypass a check:

- Establish issuer/delegator ownership and bilateral D8 agreement through
  authenticated policy provisioning. Caller-provided policy is not proof.
- Check both grants on an own node: correct current names and issuer key,
  confirmed issuance commitments, live seals, closures, and all node-pinned
  subjects (LIP-0004 sections 4–5; LIP-0014 section 8 V5).
- Resolve the selected notary's name on that node, reach its signed
  registration, validate the checkpoint and uninterrupted owner stretch,
  and prove the current value's writer. A presenter-supplied history is
  explicitly insufficient. Parsing a pin, matching a configured owner, or
  reading this CLI's value file proves none of these (LIP-0014 section 7.1
  J3.2–J3.8; V12).
- Confirm child issuance before signing; prove the named seal is controlled
  by the notary; bind validated tip data; atomically consult and update the
  durable per-parent/ordinal record before signing (LIP-0014 sections 6.2,
  6.4, 9.1 J1.6). The pure function has no equivocation or replay journal.
- Sign, anchor and fund each actual attestation; on admission validate its
  signature/bindings, chain tip, anchor, live seal and durable withdrawals
  (LIP-0014 section 8 V10–V18, section 10). This unit constructs candidates
  and frames but admits no presented attestation as live.
- Interpret no instructions, contracts, notes or scope prose. It makes no
  assertion that work follows text and never emits `textual:within`
  (LIP-0014 sections 3.3–3.4 J5; LIP-0013 section 2.3).

A future public endpoint must construct trusted policy, name observations,
statement claims and time itself, and perform the outstanding node/journal
steps before using the candidate. It must not expose this CLI's trusted
inputs as an unchecked public signing API.

## OPEN QUESTIONS and conservative choices

**O1 — Pending J5.** LIP-0014 section 3.3 in force permits differing text
hashes after the notary's judgement. Pending section 3.4 instead requires
identical inherited text. Both readings are stated in the pin. This unit
requires equal hashes and matching supplied octets, refusing
`TEXT_JUDGEMENT_REQUIRED` otherwise. It claims no adoption of J5 and performs
no text interpretation. Identical text does not prove compliant work.

**O2 — D8 affiliation evidence.** D8 and section 7 say "owner", "third party"
and "both agree" but specify no v3 signed encoding or mechanical proof of
these affiliations. One reading accepts issuer designation plus grantee
consent as sufficient agreement and treats organizational affiliation as
external policy; another requires explicit owner-level agreement and
independent owner affiliation. By default this checker takes the stricter reading:
local policy must bind the exact pair, identify all owners, match the
selected notary's signed owner pin, require its issuer affiliation within
one owner, and require a distinct third owner plus both approvals across
owners. A compressed key here is a configured owner identifier, not a
claim that unequal keys prove unequal people. The strict default retains its
authenticated provisioning boundary; MVP approvals additionally resolve owner
names and registrations through the chain dependency below. A policy file supplied by an adversary can lie. The
production evidence/provisioning contract remains an open service decision.

## MVP deployment policy (not protocol)

The explicit local `"mode":"mvp-pair-owned-notary"` is an MVP deployment
policy. It is **not in the specification** and does not change the protocol.
The specification default stays strict: omitting `mode` retains every existing
rule, including a distinct third owner for cross-owner certification. No
approval, owner relation or other input infers the mode; unknown strings refuse
`POLICY_MODE_UNSUPPORTED` (an explicitly empty mode is noncanonical).

Each MVP approval has exactly `owner,name,registration,signature`, in that
order. `owner` matches one configured role identifier; `name` is an `id/`
name, and `registration` is its `{txid,vout}` registration identity, following
the registration pinning used by J3 (LIP-0014 section 7.1). Approvals are sorted
by their distinct compressed owner identifiers. The existing opposite-parity
alias guard also remains. Neither unequal keys nor operator policy establishes
two owner identities: the two names and their registrations must both differ.
This is the deployment identity boundary, not proof of distinct natural persons
behind independently registered names.

`Check` calls `NameSource.Lookup(name, statement.tip_height, statement.tip_hash)`
for each approval. The result supplies the registration, current raw value,
observed height and hash. Both reads must match that one explicit statement
view; mismatch refuses `MVP_NAME_VIEW_MISMATCH`, and a changed registration
refuses `MVP_NAME_REGISTRATION_MISMATCH`. A failed lookup refuses
`MVP_NAME_UNREADABLE`. Reused names and registrations refuse
`MVP_OWNER_NAME_REUSED` and `MVP_OWNER_REGISTRATION_REUSED` respectively.

The current value is parsed with LIP-0010 sections 2 and 3: valid UTF-8, at most
520 bytes, unambiguous `swarma`/`nostr`, top-level extensions skipped, and an
exact canonical `{"landlord":{"grant":"<x-only key>"}}` authority span.
No missing, malformed, aliased, additional or noncanonical authority member
is tolerated (`MVP_NAME_VALUE`). The resolved grant key must verify the approval. The compressed owner
role identifier selects the policy role; it is not the grant key, and no
equality between those different roles is required. The chain provides this mapping
because an operator-supplied mapping is self-asserted: the notary operator may
be one of the two owners. Policy keys, signatures alone, and a mapping file
cannot establish the required current name-to-key relation.

The approval digest is exactly
`SHA-256("swarma-notary-local-policy-v1" || canonical_policy_without_mode_approvals || canonical_identity_array)`.
The identity array contains ordered `{owner,name,registration}` objects from
both approvals. This binds mode, grant pair, owner roles, notary name/pin,
`agreed_by`, and both name/registration claims. A change of name with the same
key still requires new signatures. These local signatures are never grant or
attestation signatures. Wrong signatures or noncurrent keys refuse
`MVP_MODE_APPROVAL_REQUIRED`; one-owner pairs refuse `MVP_MODE_PAIR_REQUIRED`.

**OFFLINE VECTOR PRECONDITION:** all supplied observations are assumed to be
an accurate, complete snapshot of the pinned synthetic chain view. They are
fabricated test inputs, not authenticated chain evidence. The LAB's observation
is supplied input; no node read is implemented in this unit. The reproducible
`testdata/mvp-names.json` is the pinned positive fixture, while each negative
vector pins its own deliberate counterexample. A file is permitted only under
this offline precondition, never as running-mode evidence.

The CLI requires `-offline-name-fixture FILE` to supply these observations. It
prints a `LAB/OFFLINE` banner and appends `offline-fixture` to its `ATTEST` line.
The fixture implementation is unexported inside the CLI's offline path; test
fixtures are unexported test-only types. The running entry point `CheckRunning`
rejects **any** injected source and uses the declared `NodeNameReader`. That
adapter is unwired pending N3 and always returns `MVP_CHAIN_READ_REQUIRED`.
Running MVP therefore refuses without a chain read and never falls back to a
fixture. N3 must implement current-value/registration reads and consistent-view
validation on its own node before enabling the running mode. Strict default
checking requires neither a source nor an offline flag.

Approvals without a mode refuse `POLICY_MODE_REQUIRED`. Wrong grant bindings,
designation and owner pins retain `OWNER_EVIDENCE_REQUIRED`,
`NOTARY_NOT_DESIGNATED` and `NOTARY_NAME_CHANGED`. Canonical parsing and these
bindings precede mode approval; mode approval precedes the ownership relation.
Both configured cross-owner agreements remain required. A third-party notary
with this mode still passes the strict affiliation/agreement path, with the
additional chain-resolved mode approvals required. No other check is relaxed.
This remains a deployment policy, not protocol or a claim of live qualification.

Future directions are a jointly held notary name (2-of-2 now, t-of-n for a
federation) and external notaries. They are future work, not implemented modes
or claims of protocol adoption.

## Request-side context and pin differences

The external request-side snapshot at
`dee83bdee21617ac11e2178f85d529b17395ef0b` is frozen to v0.1.46
(`d0b2dcc6465fc856e334ddeef7a22f3e1dceb81b`). It provides
`delegation_request_v3`, purpose 7, kind 8186; it is neither a child-grant
signer nor a notary verifier. Its `/2` contract set is already the same
fifteen/six/four/three-member row/checkpoint set. Pending J2/J4/J5 do not
silently change its request rules, and it does not require equal text hashes.

This checker independently pins v0.1.48. The profile `/2` contract-vector corpus is byte-identical between the two
pins. At v0.1.48 LIP-0026 also describes pending **v4-only** groups, classes and optional certifiers; none changes
profile `/2`. The conservative equal-text policy above is deliberately
narrower than the request side. A valid request can therefore be refused
here for needing text judgement. Issuance, notary history, D8 provisioning,
attestation signing and durable row checks are not delivered by that request
side, and are not inferred from possession of its event. No change to that
snapshot is made or required by this module.

The intervening spec revisions also add the pending client-session direction
J13 (LIP-0028), landlord holder entries (LIP-0010 section 10), and their
service/key registry cross-references. They add no v3 child-grant, request or
notary byte changes for this module. The request-side snapshot is preserved.
