# Open boundaries

- LIP-0021 and LIP-0022 remain Draft; owners' acceptance and co-author agreement
  remain pending. The older ownership predicates implement proposals on stated facts only.
  The decided R1 subset is separately gated by the v0.1.51 profile.
- Node reads and observation consistency await a run on the pinned build;
  transaction validity and the provenance of stated inputs are caller duties.
- Grant/notary/pointer pin members, action profiles, evidence classes and
  `swarma` extraction are unspecified here. No placeholder passes these checks.
- R as the issuer history start and cache-predicate input is the draft's choice
  and still needs confirmation. Walks and recipient union here judge stated facts
  only; they do not supply a node/RPC adapter or a whole grant admission pipeline.
- Consent uses the stated channel key in the coherent snapshot. Its event
  signatures, binding, seconds/age checks and durable single-use storage require
  separate integration; created_at is never compared to a height here.
- Cache storage and reorg detection, pending-operation reads and durable closure
  journals remain unimplemented. Notary compound walk findings have no specified
  priority and are exposed as a set, rather than assigning a new order.
- Measurement-dependent observation numbers remain parameters in their future
  module, without production defaults in this identity module.

## R1 at specification v0.1.51

- J9–J12 are in force. Additions explicitly marked as the draft's remain
  unavailable in `R1InForce051`; `R1DraftLab` retains all prior behavior.
  Zero, unknown and the legacy `R1InForce` placeholder remain closed.
- OPEN QUESTIONS Q1–Q4 and exact normative line references are recorded in
  [the decided/draft map](R1-DECISIONS-051.md#open-questions). They concern
  whole-parent atomic refusal, ordinal traversal, checkpoint derivation and
  proposed class diagnostic codes/inner precedence. Ambiguities stay DRAFT.
- Group, template, row and full-grant octets remain undefined, so the 65536-byte
  parent bound is unverified. Stop coins of certified groups are not placed.
- The class fixture uses a compressed request key, while Nostr authenticates an
  x-only key. R2 compares opaque established identities exactly, without key
  conversion or authentication. Name-mode channel keys still validate as x-only.
- Signer adoption of gifted names, row-account custody, coin funding, issuer
  pre-sign checks and persistent accounting require their own implementations.
- `ClassObservation` is stated coherent node evidence. No adapter proves that
  a value, opaque registration ID, history and signed pin belong together yet.
  Whole-parent issuer admission, observation provenance, coin/anchor reads and
  certified-row attestation verification are mandatory external prerequisites.
