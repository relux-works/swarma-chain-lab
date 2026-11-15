# Open questions

The detailed readings, conservative choices, and their limits are in
[DESIGN.md](DESIGN.md#open-questions-and-conservative-choices).

- **O1:** Pending J5 text equality versus the in-force notary judgement of
  differing text. This checker accepts identical hashes and matching octets
  only and performs no interpretation.
- **O2:** D8 has no v3 octets for owner affiliation or bilateral owner
  agreement. This checker requires explicit, pair-bound trusted local policy,
  distinct cross-owner certifier affiliation, and both approvals. Production
  authentication/provisioning of that policy remains unresolved.

Online name history, issuance, seal and journal checks are deferred service
work, not ambiguous rules and not claimed by an offline positive vector.
