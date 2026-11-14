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
