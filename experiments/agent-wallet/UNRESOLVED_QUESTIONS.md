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

- **T10 tracker on genuine Core (resolved in PX1 S2 completion r2).** For
  an unknown txid, Core answers `getrawtransaction` (JSON-RPC 1.0) with HTTP
  500 and an error object. The S3 tracker now reads it through its own lookup
  route (`newTxLookupRPC`, `rpc.go`), which maps exactly Core's reply
  `{"result":null,"error":{"code":-5,"message":"No such mempool or blockchain
  transaction. Use gettransaction for wallet transactions."},"id":1}` to
  `RPC_NO_SUCH_TX`. `px1oRemoteNo` reads only that code as "absent". Every
  other answer still fails the pass: another code, another -5 message (no
  transaction index, index still syncing), a 500 without that body, 401, 503.
  The wallet and broadcast routes and W2's own observer reads are unchanged.
  Bounds: a node without `-txindex`, or one whose index is still syncing,
  answers another -5 message, so the pass fails there (fail-closed); the
  deploy kit's node config sets `txindex=1`. Resolved: step 23 also
  enqueues a spend whose outcome is uncertain, including a broadcast the node
  refused (`BROADCAST_UNCERTAIN`), so a running service tracks it to
  `conflicted` without a restart; the debit stays retained until an operator
  release.
- **F6 (matrix row 20 negative test):** not routed to the integration
  follow-up. The [runbook](RECONCILE-RUNBOOK.md), operator reconcile CLI and
  separate alert forwarder now implement the approved conflict-only policy:
  release at six active-chain confirmations, receipt-key signing, service UID,
  one-hour gate, no wire action and no absent release. Function/unit and real
  socket evidence are separate from installed-CLI qualification and T18.
  A no-root local fixture cannot supply the root-owned signed DK5 set; the
  rehearsal records the actual binary refusal rather than adding a bypass.
  Keeper-confirmed human/backup assignment, measured delivery to both watched
  destinations, independent review and post-install station readback remain
  open. No frozen PX1 interface change is made.
- **F6 startup after a conflict release.** Startup's known-send set includes
  `record.txid` but not `reconcile.conflict_txid`. An out-of-band conflict can
  therefore still return `STATE_RECONCILE_REQUIRED` after a valid signed
  release. The operator command deliberately preserves this guard. QA must
  decide whether verified signed conflict evidence should qualify a known send
  in a separate bounded change, or retain an explicit station recovery hold.
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
