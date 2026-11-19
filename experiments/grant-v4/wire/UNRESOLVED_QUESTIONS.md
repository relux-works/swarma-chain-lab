# Unresolved wire integration questions

- W9.4 fixes first-refusal precedence. Its grant step still has no content:
  no grant schema or presentation encoding exists. The composed check and
  dispatch accept typed stated facts only, and no raw grant. They cannot
  authenticate those facts or constitute whole-grant admission.
- The five reserved registry types have no complete member schemas. They
  remain unsupported under W3.1; tagged-hash vectors do not make them objects.
- The contract preimage remains open in LIP-0017 §2. This module takes the
  contract identifier as opaque 32 octets and performs no contract semantics.
- Ownership, snapshot evidence acquisition and recent-block policy await the
  profiles identified by LIP-0020 §7 and LIP-0008 §3. Supplied facts are not
  independently observed chain evidence.
- The key that assents to a child contract remains open in LIP-0020 §7.1.
  Supplying a party key here establishes no child-grant profile.
- Durable consent consumption before signing needs a separately designed
  issuer journal and concurrency/recovery contract (LIP-0020 W7.9). Pure fact
  predicates here neither reserve an id nor authorize a signature.
- LIP-0020 remains Draft. Passing its pinned vectors does not constitute owner
  acceptance, independent cross-language conformance or production activation.

## B3a-CHILD at spec 0.1.61

- F13 ordinal selection is resolved by Ivan Oparin's explicit decision of
  2026-11-17 (CHANGELOG 0.1.57; LIP-0026 section 8). Signed group/range order,
  ascending coin output indices and counting from 1 are implemented. The
  rest of Q2 remains PROPOSED; success of this slice is never admission.
- F11 follows the Lead ruling relayed on 2026-11-19, Appendix A section 3,
  recorded in PR #158's description; it supersedes fix-3 D2. F7.3 supplies
  explicit K (keys), A (read, no key under LIP-0010 section 4), or B (whole
  value refused under section 2 / D5). A, B and unset give a codeless typed
  IMPLEMENTATION outcome, Again=state, no closure/revocation, not input;
  ISSUE signs nothing. Octet reuse still precedes it and gives
  DELEGATE_KEY_REUSE, Again=no. Acquisition, provenance, completeness,
  owner control and observation health remain caller duties; no new read.
- F17: this side adopts no proposed LIP-0031 profile (T9/W11.14). Numeric attenuation
  awaits a real type profile; equality and one-over currently have the same
  `LIMIT_KIND_UNDEFINED` result after the missing-key check.
- F6 stays entirely outside this slice, including 0.1.61 part (c), the
  confirmed contract/framework seal (CONTRACT_SEAL_MISSING /
  CONTRACT_SEAL_UNAVAILABLE). Complete admission needs its contract profile
  and independent node/journal facts. This document-and-facts slice never
  supplies them or admits a grant.

## Declared deviations and pending spec sentence

The evaluated rows are F5, F8 to F12, F13(a), F14 to F18.

F13(b) is not evaluated at its place. The composed path reports a
selected-group rule 4/5 finding in F1 (parent pipeline step 9), not in F13.
This is a known lab divergence from T10's last sentence and S8-29 (a)/(c).
Both O7 outcomes are unreachable while an earlier row refuses, pending O7 /
LIP-0026 Q1. The existing `VerifyGrant` parent precondition is kept; no
partial parent reader or deferred-parent admission is implemented. Section
8.7 explicitly plans a second reader after the document pipeline.

F11 A is a declared deviation under the Lead ruling of 2026-11-19 section 3,
recorded in PR #158's description. The clarifying spec sentence is pending;
the expected post-adoption result is **pass**, implemented by changing only
`childNoKeyPassV4` to `true`. Until adoption A refuses as IMPLEMENTATION,
Again=state, no Link code or closure, not input. B permanently refuses in
the same typed way and is never converted into A or an empty set. An unset
state also refuses and never denotes A. Parent by key passes F11 after the
octet comparisons. This ruling replaces the fix-3 open question, not the pin.

LIP-0010 says:

> A `nostr` member that yields no key removes the agent's address and no authority.

> When an agent value yields no key, a reader still reads `swarma.agent.landlord`, and the closure rules that depend on the pointer keep working. Every step that needs the agent key refuses. This refusal records no closure.

Classification belongs to the F7.3 reader (the caller). The existing pinned
identity dependency exposes `ReadR1Value`, so the wire tests exercise it
without a new dependency. The six required forms are: absent `nostr`, npub,
uppercase hex, missing `names._`, and duplicate `names` classify as A;
duplicate top-level `nostr` with the delegation key second classifies as B.
Extra neighbours cover duplicate `_` and a non-string `nostr` as A. Every
case has a differing-key positive control. `nil-set` and `empty-set` now
explicitly declare K and test malformed K lists, not no-key classification.
Exact F13/T10/Q27/S8-29/O7/section 8.7 quotations and composition constraints
remain in `STEPS-B3a-CHILD.md`. No other deviation is changed.
