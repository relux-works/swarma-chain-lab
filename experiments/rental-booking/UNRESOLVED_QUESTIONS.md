# Integration boundaries

No mainnet or public deployment is authorized by this regtest module.

- Branch publication, independent review, hosted checks and landing happen
  outside this module. Producer tests are not review acceptance.
- M1 must admit only before signed hold expiry and independently recheck the
  signed package plus current payment. M1's independent frozen-wire cross-check
  passed on 2026-11-08. This is
  interoperability evidence, not independent review acceptance of M3.
- Cross-host authenticated outbox transport, revoke delivery/acknowledgement,
  actual issuance and refund handling belong to M1/M4/deployment integration.
  An issuance intent is conservatively considered handed off once persisted.
- Bounded scans can refuse large/history-heavy observations. Production scale
  needs a reviewed index/checkpoint design; do not silently raise caps.
- Kinds 8181/8182 are experimental local allocations, not public NIP reservations.
- The inline browser adapter uses NIP-07; automation verifies the server and
  protocol flow, not a human extension's permission UI.
- USD/NMC rates are explicit operator configuration. An external rate feed and
  its policy are outside v1. No mainnet wallet or spending authority is implied.

- M3-02 requires active confirmation for both payment policies. Existing
  zero-confirmation issuance state from M3-01 refuses startup and needs operator
  reconciliation; no automatic migration is supplied. No real service state
  is migrated by this lab revision.
- Start-now scheduling must coordinate an immutable signed contract interval
  with actual anchor confirmation. M3 does not retime signed contracts; station
  start waits for the confirmed anchor and the signed not_before boundary.
- Pre-checkpoint and post-slot payments require the operator inventory/sweep
  process documented in README; the watcher does not discover them. Renter name
  binding remains a booking-time attribution; authority is always the key.

## CC1 deployment decisions

- CH1-B output-default injection is separate work; current Responses requires an explicit limit.
- Operator migration/provisioning must preserve old model-slot cleanup and booking receiving-branch/index continuity. CC1 does not migrate live config-only rentals or authorize resetting state.
