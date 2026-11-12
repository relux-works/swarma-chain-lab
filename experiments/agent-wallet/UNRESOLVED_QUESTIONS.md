# Deployment decisions and limits

- Curator must pin actual wallet directory, memory-zone directory, installed
  executable and private operator config paths. This package is a draft skill;
  it neither installs nor proves enforcement of those restrictions.
- Operator issuance must explicitly produce this wallet-terms profile and the
  matching K1 consent/issuance proof. The complete booking-UI contract is not
  implicitly convertible into wallet terms; a shared future contract profile
  requires its own reviewed change.
- Automated reconciliation, refunds/reclaim of incomplete name commitments,
  journal garbage collection, safe backup restoration and anti-rollback storage
  are outside this bounded demo. Reserved uncertain effects never retry.
- W2 supplies the separate service-user boundary and templates, but local
  macOS socket fixtures run under one UID. Actual Linux different-UID denied
  reads/socket isolation and systemd enforcement remain Infra qualification;
  no local users/services were created. W1 legacy remains unsandboxed.
- W2 v1 rejects name registration/update. W2b requires explicit commit/reveal
  continuation semantics; terminal duplicate replay must not be weakened.
- Receipt keys, peer UIDs/groups, private roots and client action keys require
  operator provisioning. There is no automatic key/journal migration or rotation.
- Observed key rotation is sticky; an unobserved rotate-away-and-back is not
  reconstructed by the current K1 resolver. A complete historical name walk
  would require a separate bounded design and evidence.

## PX1 (G2 pay limits), open at the interface freeze

- Public cap values, float, bounty window and the phase-2 switch to recipient
  mode `any` are Ivan's decisions; PX1 fixtures carry only the smoke values.
- Real pay-grant issuance waits for the rotated landlord grant key in Ivan's
  Mac Keychain (G1 Q4); the exec1 M5 key must not sign it.
- The terms-v2 LIP (Q11) lands in swarma-link-spec, outside this repository.
- Stream ownership, fixtures and test owners: `PX1-INTERFACES.md`.

## PX1, open after the integration follow-up

- **T10 blocked by the S3 tracker on genuine Core (open, S3).** The Core
  layers of T3, T5, T8, T9 and T10 are written (`px1_s2_core_test.go`), and
  the gate manifest requires every layer of the test table, with no open
  T-id. T10 still fails at its two crash points before the broadcast
  (`TestPX1CoreS2Crash/after-reservation` and `/after-service-reservation`,
  marker `T10_TRACKER_UNKNOWN_TX`). After the restart the tracker reloads the
  reservation, whose transaction the node never saw. `getrawtransaction` for
  an unknown txid makes Core answer HTTP 500 with a JSON-RPC error object
  (legacy JSON-RPC 1.0). The node client reports that as `RPC_RESPONSE`, but
  `px1oRemoteNo` (`px1_observe.go`) treats only `RPC_REMOTE_ERROR` and
  `RPC_REMOTE_REFUSAL` as "absent". Every observation pass therefore fails
  `RPC_RESPONSE`. The tracker stops at that payment, so no payment is tracked
  any more and the reservation is never marked conflicted. The same applies
  to a broadcast the node rejects (`BROADCAST_UNCERTAIN`). Funds stay safe:
  the debit stays retained, nothing is re-sent, and the operator release
  works. The fix belongs to S3, the owner of `px1_observe.go`, or to the
  owner of the node client. Until it lands, the hosted gate fails on T10.
- **F6 (matrix row 20 negative test):** not routed to the integration
  follow-up; open.
- **Replay after a release.** `px1Prior` skips `track` records only. After a
  `reconcile` record, a wallet-layer replay reports that record's phase
  (`released`), also for a partial release, whose accounting phase is
  unchanged. Whether a replay should keep the execution phase there too is
  an S1/S2 decision.
- **Status socket after a crash.** Removal of the stale `status.sock` stays
  manual (W2 rule, SERVICE.md runbook). An `ExecStopPost=` cleanup is a PX2
  candidate and needs its own decision.
- **ProjectStatus and release authorization.** `ProjectStatus` does not
  verify a reconcile with `VerifyReconcileV2`; the ledger fold does. Whether
  the projection should verify too is the lead's decision (S3 step B, item 8).
- **Service account after the apply (S5 R10)** and **the slot's own `Group=`
  resolution (S5 R11):** no check binds `swarma-wallet` to `service_uid`
  after the sysusers apply, and T18 does not show how the slot resolves
  `Group=<agent_user>`. Condition 9 (the agent's groups are exactly
  {`agent_uid`, `agent_socket_gid`}) now closes the agent-side half.
