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
