# Open questions

The detailed readings, conservative choices, and their limits are in
[DESIGN.md](DESIGN.md#open-questions-and-conservative-choices).

- **O1:** Pending J5 text equality versus the in-force notary judgement of
  differing text. This checker accepts identical hashes and matching octets
  only and performs no interpretation.
- **O2:** D8 has no v3 octets for owner affiliation or bilateral owner
  agreement. This checker requires explicit, pair-bound trusted local policy,
  distinct cross-owner certifier affiliation by default, and both agreements.
  The explicit MVP deployment mode instead permits pair-owned affiliation with
  both owners' signed exact-scope approvals; this is not in the specification.
  MVP signatures must verify under current chain grant keys for two distinct
  names and registrations at one explicit view. File observations are offline
  fixtures only. NodeNameReader implementation and authenticated provisioning
  remain N3 service obligations; running MVP refuses until that is wired.

Online name history, issuance, seal and journal checks are deferred service
work, not ambiguous rules and not claimed by an offline positive vector.
