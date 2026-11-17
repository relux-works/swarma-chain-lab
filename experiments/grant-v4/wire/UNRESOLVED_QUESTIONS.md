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

## B3a-CHILD at spec 0.1.55

- F13 ordinal selection is OPEN: W11.6 calls the signed array order "the signed
  order in which LIP-0026 R8.3 counts the rows"; LIP-0026 section 8 says "the
  order binds no reader" until explicit owner acceptance. The draft evaluator
  stops with no invented protocol code. The needed input is an authoritative
  resolution of those sentences, not an implementation-specific order.
- F11 requires current parent-recipient channel keys from F7.3 when the parent
  names its recipient. Two verified documents supply none. The API refuses
  OPEN for such a parent rather than omitting that key-separation duty.
- F17: no limit kind is defined in 0.1.55 (T9/W11.14). Numeric attenuation
  awaits a real type profile; equality and one-over currently have the same
  `LIMIT_KIND_UNDEFINED` result after the missing-key check.
- Complete admission needs F6's missing v4 contract profile and independent
  node/journal facts. This document slice never supplies them or admits a grant.
