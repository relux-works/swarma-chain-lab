# Open questions

- **NOTARY1-PACK:** The lead requires the regtest public key in the private
  install receipt only, with no name binding. v0.1.1's real-node path requires
  that same key in the selected on-chain name before `ATTEST`; the installed
  node also disables wallet RPC. Positive host smoke therefore needs an owner
  decision and a reviewed VM-local registration/request procedure. The release
  verifier at the pack base also lacks mandatory Python `-I` invocation;
  installation waits for the reviewed isolated follow-up pin. See the precise
  abort points and alternatives in [INSTALL.md](deploy/notary1/INSTALL.md).

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
  fixtures only. The service now wires the concrete regtest NodeNameReader. Authenticated
  provisioning remains an operator obligation; the unconfigured checker path
  continues to refuse MVP_CHAIN_READ_REQUIRED.

Current values, registration histories and tip coordinates now have a concrete
regtest reader. Historical owner/checkpoint proof, issuance, live seals and
durable row/withdrawal journals remain deferred operational obligations, not
claimed by offline vectors or the bounded service regtest evidence.

J9 and J10/J11/J12 are in force in the v0.1.51 pin. Eligible v4 rows
without a certifier need no attestation; v4 admission remains outside this
v3-only notary module, which continues to support only Grant v3 and profile `/2`.
No v4 child admission or certifier-free signing path is added.
