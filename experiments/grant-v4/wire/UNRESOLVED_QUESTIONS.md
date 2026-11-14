# Unresolved wire integration questions

- LIP-0020 W9.1 orders the composed issuance stages but does not order failures
  between its independently checked signed parts. No precedence is invented
  here. The issuance dispatch class remains closed until that contract and the
  grant schema exist; `CheckIssuanceAnchor` is arithmetic on stated values.
- The five reserved registry types have no complete member schemas. They
  remain unsupported under W3.1; tagged-hash vectors do not make them objects.
- The contract preimage remains open in LIP-0017 §2. This module takes the
  contract identifier as opaque 32 octets and performs no contract semantics.
- Ownership, snapshot evidence acquisition and recent-block policy await the
  profiles identified by LIP-0020 §7 and LIP-0008 §3. Supplied facts are not
  independently observed chain evidence.
- Durable consent consumption before signing needs a separately designed
  issuer journal and concurrency/recovery contract (LIP-0020 W7.9). Pure fact
  predicates here neither reserve an id nor authorize a signature.
- LIP-0020 remains Draft. Passing its pinned vectors does not constitute owner
  acceptance, independent cross-language conformance or production activation.
