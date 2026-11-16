# Open boundaries

- LIP-0021 and LIP-0022 remain Draft; owners' acceptance and co-author agreement
  remain pending. All functions implement proposals on stated facts only.
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

## R1 at specification v0.1.49

- J9 is in force; J10/J11/J12 and R8/R9/R10 profile proposals remain pending.
  The stricter interpretation enables them only in `R1DraftLab`; zero,
  unknown and `R1InForce` profiles refuse. No production admission is claimed.
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
