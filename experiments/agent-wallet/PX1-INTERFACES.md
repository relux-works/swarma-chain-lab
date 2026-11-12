# PX1 frozen interfaces: agent-walletd G2 pay limits

PX1-S0 freezes the shared contracts that five producer streams build in parallel.
It sits on top of agent-walletd W2. Design: G2-PAYMENT-EXECUTOR-v1 §2-§5. The
co-lead review (COLEAD-REVIEW-PX1, 2026-11-12) is binding.

- **What is frozen:** every `px1_*_api.go` file in this module, plus
  `experiments/rental/paygrant_v2_api.go`, `deploy/g2_pay_api.go`, the golden
  fixtures listed below, and the freeze tests (`px1_freeze_test.go`,
  `px1_freeze_fixture_test.go`, `px1_freeze_amend1_test.go`,
  `rental/paygrant_v2_freeze_test.go`, `deploy/g2_pay_freeze_test.go`), with
  the S0 plant manifests `testdata/px1-mutations-s0.json` in agent-wallet and
  in `deploy/`.
- **Amendment rule:** a type, member order, JSON name, code or signature changes
  only through a freeze-amendment PR. All stream owners review it. The
  compile-time assertions (`var _ func(...) = F`) in the API files fail the
  build if an implementation drifts from its frozen signature.
- **Stubs:** each stream's implementation files start as stubs. Each stub
  returns the sentinel `ErrNotImplemented` (`PX1_NOT_IMPLEMENTED`, a bounded wire
  code), or a zero value that can never pass. No W2 path calls a stub. A G2
  profile that reaches a stub refuses, so it fails closed.
- **Amendments:** freeze amendment 1 (A1-A8) is summarized in
  [Freeze amendment 1](#freeze-amendment-1), with its MIGRATION list.
- **Behaviour at the freeze:** unchanged. The only existing file this unit edits
  is `mutation_test.go`, which now also loads `testdata/px1-mutations-s*.json`.
  That runner is skipped unless `W1_MUTATIONS=1`.

## Binding decisions carried into the contracts

| Decision | Where it is frozen |
| --- | --- |
| Q1(a), **two grants**: (1) the renter's rental grant (scope `deliver`, renter consent), issued through the existing booking/issuance V2 path and unchanged; (2) Cedar's **pay grant**, from the landlord to Cedar's action key, with Cedar's own kind-8181 consent and terms v2 | `rental/paygrant_v2_api.go` header; `PayGrantV2Input.GranteeKey` |
| Q2: `allow` at launch; `any` later with lower caps (Ivan decides) | `G2OperatorConfig.AllowAnyRecipients=false`; code `TERMS_RECIPIENT_MODE`; fixture `terms-v2-any.json` for phase 2 |
| Q4: UTC calendar day | `TermsV2.DayBasis == "utc-calendar"`, `UTCDay`, `UTCDaysSpanned` |
| Q5(a): a new issuer entry point, signed with the **rotated** landlord key in Ivan's Mac Keychain, never the exec1 M5 key | `IssuePayGrantV2` takes `DigestSigner`s and never a key path; `NewFileExchangeSigner` is the offline transport |
| Q7: single-use disabled | `AllowSingleUse` must be false; code `SINGLE_USE_DISABLED` |
| Q8: operator reconciliation only | `ReconcileRecordV2`: signed by the receipt key (`JournalHeaderV2.ReceiptKey`) over `ReconcileDigestV2`, which binds the journal binding and the record's grant_id, nonce and seq; rate-limited, citing chain evidence; nothing releases a debit automatically |
| Q9: same host, separate UID | `deploy.G2PayParameters.AgentUID != ServiceUID` and `agent_user` bound to `agent_uid` on the target host (`ValidateG2PayIdentity` before the sysusers apply, `VerifyG2AgentAccount` after it); T18 `CustodySpecV1` |
| Q10: retire the rental-executor `pay` path | S4 marks it superseded in `experiments/rental-executor/README.md` (docs only, no code) |
| Q12: k=2, for alerts only | `DefaultConfirmationsK = 2`; tracker states never grant or restore authority |
| Fee rate ~110 sat/vB (relay floor 100), never 200 | `G2PayParameters.FeeRateSatVB`; the existing wallet `fee_rate_sat_vb` stays the only fee source |

## Module rules (published graph)

- No new module require edges. `agent-wallet` already requires `rental`. `deploy`
  requires neither of them and keeps structural mirrors instead.
- `agent-wallet` must **not** use the new `rental` PX1 symbols, not even in
  tests. That changes only when its `rental` require is refreshed to a published
  snapshot that contains them (see `experiments/MODULE-GRAPH.md`). `rental` never
  imports `agent-wallet`.
- Each pair of mirrors pins the same golden bytes:
  - `wallet.TermsV2` and `rental.PayTermsV2`;
  - `wallet.G2OperatorConfig` and `deploy.G2OperatorParameters`.
- The agent-wallet parser is the authority on terms v2.

## Contracts at a glance

| Stream | Frozen surface (file) | Main entry points |
| --- | --- | --- |
| S1: terms v2, caps, executor binding | `px1_terms_api.go`, `px1_api.go` (codes) | `ParseTermsV2(raw, TermsV2Pins)`, with a 10-row refusal table; `ValidateG2OperatorConfig`; `EffectiveLimitsFor` (min of terms and operator ceiling); `CapChecker{CheckExecutor, CheckRecipient, CheckPrePlan, CheckPostPlan}`; `NewCapCheckerFor(network, genesis)` (frozen network binding over `NewCapChecker`); `SpendIntent` |
| S2: journal v2, day buckets | `px1_journal_api.go` | `JournalRecordV2` (kinds `admit, reserve, service-reserve, complete, uncertain, refuse-retained, terminal, track, reconcile`); `JournalHeaderV2{Version, Layer, Binding, ReceiptKey}`; `ReconcileDigestV2` and `VerifyReconcileV2` (frozen, `RECONCILE_AUTHORIZATION`); `JournalV2{Header, Append, Iterate, Usage, Poisoned, Close}`; `OpenJournalV2`; `JournalSegmentV2` hash chain; capacity rules in `JournalLimitsV2`; `RequiredSpendCapacity`; `LedgerView` and `FoldLedgerV2`; `ClockGuard` and `NewClockGuard` (`CLOCK_ROLLBACK`); `ReadLimiter` (`READ_RATE_LIMITED`) |
| S3: tracker, canary, status | `px1_observe_api.go` | `Tracker{Enqueue, Tick, Snapshot}`; `Canary{Excluded, Check}`; `FloatMonitor`; `StartupReconciler` (`STATE_RECONCILE_REQUIRED`); `AlertSink`; `StatusProjectionV1` and `ProjectStatus`; `ServeStatus` on `StatusSocketPath` (`/run/swarma-wallet-status/status.sock`, its own 0750 directory, amendment 1, A8) |
| S4: terms-v2 issuance helper | `rental/paygrant_v2_api.go` | `IssuePayGrantV2(ctx, in, grantee, landlord DigestSigner)`; signer call order: consent, then contract countersign, then grant; `PayGrantSigningRequest` and `PayGrantSignature`; `EncodePayTermsV2`; `PayGrantBookingRef`; `NewFileExchangeSigner`; the issuance tx is planned by the existing `MakeGrantIssuancePlan` |
| S5: deploy, T18 | `deploy/g2_pay_api.go` | `G2PayParameters` (with `service_uid`, `agent_user`, `agent_key_file`, `node_datadir`); `ValidateG2PayParameters`; the frozen identity helpers `ValidateG2PayIdentityDomain`, `ValidateG2PayIdentity`, `G2AgentSysusers`, `VerifyG2AgentAccount`, `G2AccountDB`, `G2HostAccounts`, `ErrG2AccountAbsent`; the socket placement `G2WalletSocketPath`, `G2StatusSocketDir`, `G2StatusSocketPath` and the group names `G2AgentSocketGroup`, `G2OperatorGroup`; `RenderG2PayTemplates`, which renders exactly the `G2File*` set; `CustodySpecV1`; `RunCustodyProbe`; `VerifyCustodyReport` |
| Cross-stream seams | `px1_seams_api.go` | `Wallet.PX1Journal/PX1Ledger` (S1); `ActionService.PX1ServiceJournal/PX1Profile` (S2); `ActionService.PX1Enqueue/PX1Tick/PX1Status` (S3) |

### Spend path: §3.5 steps by owner

| Steps | What | Owner | File |
| --- | --- | --- | --- |
| 1-6 | peer UID, frame, signature, grantee, poison, nonce lookup | existing (S2 keeps them) | `service.go` |
| 7 | first admission: skew, journal v2 capacity, `CLOCK_ROLLBACK`, `admit` record | S2 | `service.go` |
| 8 | grant resolve; `SINGLE_USE_DISABLED` under G2 | S2 | `service.go` |
| 9 | `GRANT_GRANTEE_MISMATCH` | existing (S2) | `service.go` |
| 10 | terms by `contract_sha256`, then `ParseTermsV2` | S1 | `single_use.go` (`termsForNetwork` dispatch) |
| 11 | own-node observation | existing (S2) | `service.go` |
| 12 | binding, recipient by mode | S1 | `grant.go` |
| 13, 15, 17 | dust, transfer, total/spend, day, count caps | S1 | `wallet.go` via `CapChecker` and `PX1Ledger` |
| 14, 18, 21 | kernel checks #1, #3, #4, input re-reads | existing (S1 keeps them) | `wallet.go` |
| 16 | plan: canary exclusion (`Canary.Excluded`), fee ≤ min(fee_limit, fee_cap) | S1 | `plan.go` |
| 19 | wallet reservation, `reserve` record with `day` | S1 | `wallet.go` via `PX1Journal` |
| 20 | `service-reserve` record | S2 | `service.go` |
| 22 | `sendrawtransaction`, txid equality | existing (S1) | `wallet.go` |
| 23 | `complete` record (S1, wallet layer); `terminal` receipt and `PX1Enqueue` (S2) | S1, S2 | `wallet.go`, `service.go` |

## Ownership map (no file has two owners)

A seat edits only the files in its own row. Each new test file and doc file is
owned by the stream that creates it. That includes new own-package test files
and testdata in the stream's own module (amendment 1, A2): its Core and
mutation test files, and its own mutation manifest
`testdata/px1-mutations-s<N>.json` with its own runner when the plants live in
a module the agent-wallet runner does not copy (`rental`, `deploy`). Such files
belong to the stream that creates them, never to S0, and never change a frozen
file. A seat that needs a change in another stream's file asks that owner. A
seat that needs a change in a frozen file opens a freeze-amendment PR.

| Owner | Files (paths relative to the repository root) |
| --- | --- |
| **S0 (frozen)** | `experiments/agent-wallet/px1_api.go`, `px1_terms_api.go`, `px1_journal_api.go`, `px1_observe_api.go`, `px1_seams_api.go`, `px1_freeze_test.go`, `px1_freeze_fixture_test.go`, `px1_freeze_amend1_test.go`, `PX1-INTERFACES.md`, `testdata/px1/*`, `testdata/px1-mutations-s0.json`; `experiments/rental/paygrant_v2_api.go`, `paygrant_v2_freeze_test.go`, `testdata/px1/*`; `deploy/g2_pay_api.go`, `g2_pay_freeze_test.go`, `testdata/px1-mutations-s0.json`; the PX1 loader block in `experiments/agent-wallet/mutation_test.go` |
| **S1** terms, caps, binding | new: `experiments/agent-wallet/px1_terms.go`, `px1_wallet_seams.go`, `px1_terms_test.go`, `px1_fixture_test.go` (shared Core helpers that issue grants with terms v2: S1 writes them, the other streams only call them), `FORMAT-TERMS-V2.md`, `testdata/px1-mutations-s1.json`. Existing: `wallet.go`, `grant.go`, `plan.go`, `single_use.go`, `service_config.go` (the `G2` member and its validation), `wire.go` (only if needed; terms v1 behaviour unchanged) |
| **S2** journal v2, day buckets | new: `experiments/agent-wallet/px1_journal.go`, `px1_service_seams.go`, `px1_journal_test.go`, `FORMAT-JOURNAL-V2.md`, `testdata/px1-mutations-s2.json`. Existing: `service.go` (admission, service-layer journal v2, reads out of the lifetime journal, `SINGLE_USE_DISABLED`, the `px1 px1Runtime` field for S3 and, beside it, S2's own `g2` field for the G2 service state, the same pattern S1 uses with `Wallet.g2` (amendment 1, A7), the `PX1Enqueue` call), `read.go` (read limiter), `service_receipt.go` (only if a receipt field is needed; wire stays unchanged) |
| **S3** tracker, canary, status | new: `experiments/agent-wallet/px1_observe.go`, `px1_runtime.go`, `px1_observe_test.go`, `STATUS.md`, `testdata/px1-mutations-s3.json`, the status socket listener (in `px1_runtime.go` or a new `px1_status_socket.go`). Existing: `cmd/agent-walletd/main.go` (tick loop and status socket), `SERVICE.md` (a G2 operations section) |
| **S4** issuance helper | new: `experiments/rental/paygrant_v2.go`, `paygrant_v2_test.go`, `paygrant_v2_core_test.go`, `paygrant_v2_mutation_test.go` (runner `TestPayGrantV2GuardPlants`), `testdata/px1-mutations-s4.json`, `cmd/paygrant-v2/` (the ceremony CLI), `PAYGRANT-V2.md`. Existing: `experiments/rental-executor/README.md` (Q10 superseded note only) |
| **S5** deploy, T18 | new: `deploy/g2_pay.go`, `g2_pay_test.go`, `templates/g2-pay/*`, `SMOKE-G2.md`, the T18 host script `deploy/g2-custody-check.sh` (it wraps `RunCustodyProbe` and the agent-client positive request). Existing: `deploy/wallet_config.go` (accepts and validates the `g2` member), `deploy/cmd/deploy-kit/*` (render and probe subcommands), `deploy/README.md` |
| **Integrator** (S2 seat, after all PRs land) | `experiments/agent-wallet/README.md`, `UNRESOLVED_QUESTIONS.md`, `.github/workflows/agent-wallet.yml` (only if a Core lane is added) |

Shared docs (`README.md`, `SERVICE.md`, `FORMAT.md`) are not split between
seats. Each stream writes its own doc file, and the integrator links them from
the README.

## Shared fixtures (frozen)

| Fixture | Content | Pinned by |
| --- | --- | --- |
| `experiments/agent-wallet/testdata/px1/terms-v2-allow.json` (also an identical copy in `experiments/rental/testdata/px1/`) | smoke values: allow-list of 2 main P2PKH addresses, spend 500000, transfer 100000, day 300000, count 5, fee 100000 | SHA-256 `8fd808bf05a15ce5bc3d2be0a3086f1d8ccd64c6b4224b66def6e10b22fa28d0` (both modules) |
| `.../testdata/px1/terms-v2-any.json` (also copied in rental) | phase-2 any mode, lower caps | SHA-256 `2479f6741191ca7f318164866ba3d913436367229bb02265d4d6539f68acb039` |
| `experiments/agent-wallet/testdata/px1/g2-operator.json` | launch operator block (allow only, single-use off, k=2, capacity 2048) | SHA-256 `ed001683d2751865d4b339214bc668edfa977d1d0d50e5e0005354dc07df2dde` (agent-wallet and deploy) |
| `experiments/agent-wallet/testdata/px1/status-projection-v1.json` | a populated `StatusProjectionV1`; grant `day` is `UTCDay(generated_at)` = `2026-11-06` (amendment 1, A1) | `TestPX1StatusProjectionGolden`, `TestPX1StatusFixtureDayMatchesGeneratedAt`; SHA-256 `caaa67ae645f950259b1f5a7b3c7b0253d71701d43d9941c5d446e30f2f3fffc` |
| `experiments/agent-wallet/testdata/px1/reconcile-v2-vectors.json` | header A/B (same receipt key, different binding), a reconcile record, its canonical header bytes, preimage and digest (amendment 1, A5/A6) | `TestPX1JournalHeaderReceiptKey`, `TestPX1ReconcileDigestVector`, `TestPX1ReconcileBinding`, `TestPX1ReconcileReceiptKey` |
| `experiments/agent-wallet/testdata/px1/status-projection-v1.schema.json` | JSON Schema 2020-12 for the projection (for the public status page) | `TestPX1StatusSchemaMatchesStructs` (`required` order equals the struct member order) |
| Go helpers in `px1_freeze_fixture_test.go` | `px1TermsAllow()`, `px1TermsAny()`, `px1Operator()`, `px1StatusFixture()`, `px1Golden()`; executor key `testKey(9)`; allow-list `testKey(5)` and `testKey(3)`; outsider `testKey(4)` | the frozen tests |

The fixture keys are trivial test scalars and are never used on a live network.

## Test ids (§3.8) and owners

The owner writes the test and its narrowing mutants in its own
`testdata/px1-mutations-s<N>.json`. "Depends" lists the streams that must land
before the Core layer can pass. Unit layers use fakes of the frozen interfaces.

| Id | Case | Owner | Layer | Depends |
| --- | --- | --- | --- | --- |
| T1 | positive: allow-listed transfer at exactly `transfer_cap`, fee-inclusive | S1 | Core | S2 |
| T2 | over-cap transfer by 1 atom, pre-plan and post-plan | S1 | unit + Core | S2 |
| T3 | day cap, day count, rollover only after UTC midnight, uncertain still charged after rollover | S2 | unit (injected clock) + Core | S1 |
| T4 | total budget; budget-absent grant with terms v2 (`CONTRACT_BUDGET`) | S1 | unit + Core | S2 |
| T5 | wrong grantee, grant for another grantee, wrong peer UID | S2 | unit + Core | S1 |
| T6 | seal spent before the request, and injected after reservation | S1 | Core | S2 |
| T7 | expired window; expiry between reservation and broadcast | S1 | Core | S2 |
| T8 | replay after success and after restart; same nonce with other bytes; new nonce after exhaustion | S2 | Core | S1 |
| T9 | 32 parallel spends over the day cap; 2 parallel requests with the same nonce (race, `-count=50`) | S2 | Core | S1 |
| T10 | crash after wallet reservation, after service reservation, after broadcast; tracker later confirmed | S2 | Core subprocess | S1, S3 |
| T11 | reorg (`invalidateblock`); conflicting spend from the admin route | S3 | Core | S1, S2 |
| T12 | terms naming another receipt key; a second instance with a fresh `state_dir` | S1 | unit + Core | S2 |
| T13 | journal rollback: an older journal restored after a spend | S3 | Core | S1, S2 |
| T14 | canary spent out of band | S3 | Core | S1, S2 |
| T15 | allow mode: non-listed, P2SH, bech32, testnet and mixed-case addresses | S1 | unit | none |
| T16 | clock rollback | S2 | unit | none |
| T17 | read flood: 10,000 `balance` requests | S2 | unit | none |
| T18 | different-UID custody: denied reads plus one positive own-agent request | S5 | host script on an agents1-class VM (users pre-provisioned by the owner, or created from the rendered `sysusers.conf` and confirmed by `VerifyG2AgentAccount`) | S1-S3 for the positive request |

S4 owns no T-id. It owns the issuance tests:
- signer call order;
- digest recomputation by a conforming signer;
- refusal on a wrong key or an invalid signature, with no partial result;
- a `ParseSignedGrant` round trip and the `IssuanceCommitment` value;
- terms bytes equal to the golden fixture.

S4 also owns step 2 of the mainnet smoke, once Ivan approves and funds it.

## Integration order

1. **S0** (this PR) lands on `main`. Every stream branches from that head.
2. **In parallel**, each stream works on its own branch and PR, touching only
   the files in its row. Its unit tests run against fakes of the frozen
   interfaces. Any merge order compiles, because stubs fail closed and W2 never
   reaches them.
3. **Recommended landing order:**
   1. S2 journal engine (`px1_journal.go`);
   2. S1 (terms, caps, `wallet.go` on journal v2);
   3. S2 `service.go` wiring;
   4. S3 (runtime, tracker, status, `cmd/agent-walletd`).

   S4 (rental) and S5 (deploy) are independent and land whenever they are ready.
4. **Integrator (S2 seat):**
   - the full Core suite T1-T17 on regtest;
   - every PX1 mutation manifest under `W1_MUTATIONS=1`, each with the runner
     of its module: agent-wallet `TestGuardPlants` (loads
     `testdata/px1-mutations-s*.json`, S0 included), rental
     `TestPayGrantV2GuardPlants` (S4), deploy `TestPX1S0GuardPlants` (S0) and
     the S5 deploy runner;
   - docs linked from the README.
5. **S5 runs T18** on an agents1-class VM, with the users provisioned by the owner.
6. **Mainnet-safe smoke (§3.8)** runs only after Ivan approves and funds it.
   Nothing in PX1 authorizes it.

## Freeze amendment 1

One PR into `px1/interfaces`; it changes only the frozen layer. All stream
owners review it.

| Id | Request | Frozen change | S0 tests and plants |
| --- | --- | --- | --- |
| A1 | S3-A1 | `status-projection-v1.json` and `px1StatusFixture()`: grant `day` `2026-11-12` -> `2026-11-06`, the UTC day of `generated_at` 1794000600. No other fixture member changes; no other hash pinned these bytes. | `TestPX1StatusProjectionGolden`, `TestPX1StatusFixtureDayMatchesGeneratedAt` (the old day is refused) |
| A2 | S4 R1 | Docs: new own-package test files and testdata, including a stream's own manifest and runner in its own module, belong to that stream; S4 row lists its Core/mutation tests and manifest; integration runs every module's runner. | docs only |
| A3 | S5 R1, rev 2 | `G2PayParameters` gains `service_uid`, `agent_user`, `agent_key_file`, `node_datadir` after `operator_gid`. Pure `ValidateG2PayIdentityDomain(p)`: the four IDs refuse 0, 65534, 65535 and 2^32-1 (`G2ReservedID`); `service_uid != agent_uid`; strict sysusers name, not root, nobody or `swarma-wallet*`; absolute clean paths, key file != datadir. `ValidateG2PayParameters` returns its error first and reads no account database. On the TARGET host (`G2AccountDB`; `G2HostAccounts` over os/user, where only `UnknownUserError`/`UnknownUserIdError` are `ErrG2AccountAbsent` and any other error is an outage): the preflight `ValidateG2PayIdentity(p, db)` admits an existing `agent_user` only at exactly `agent_uid`, and an absent `agent_user` only when no other name owns `agent_uid`; an outage or a nil db refuses. `G2AgentSysusers(p)` is the rendered declaration `u <agent_user> <agent_uid>` plus `m <agent_user> swarma-wallet-peer` (never `m`-only). `VerifyG2AgentAccount(p, db)` is REQUIRED after the apply and before any service activation: `agent_user` at exactly `agent_uid` (sysusers substitutes a UID on a collision and keeps an existing name at its UID), in `agent_socket_gid`, not in `operator_gid`. | `TestPX1PayParametersOrder`, `TestPX1PayIdentityDomain`, `TestPX1PayIdentityBinding` (existing, first install, outage branches), `TestPX1AgentSysusers`, `TestPX1AgentAccountPostApply`, `TestPX1HostAccountErrors`, `TestPX1HostAccounts`; plants `s0-a3-*` (deploy) |
| A4 | S1 FA-S1-2 | Frozen `NewCapCheckerFor(network, genesis)`, implemented in `px1_terms_api.go` around S1's `NewCapChecker()`: an unpinned network refuses `NETWORK_PIN` on every method; recipients must be canonical P2PKH of the pinned network; `any` admits those, `allow` keeps membership. `NewCapChecker()` stays (the S1 request is additive), is deprecated for callers, and admits no `any`-mode recipient. | `TestPX1PublicCapCheckerPin` (rev 2: main/regtest positives, opposite-network and malformed/empty pins through `NewCapCheckerFor` itself), `TestPX1CapCheckerForNetwork` (wrapper isolated over fake rules), `TestPX1CapCheckerNoNetworkRefuses`, `TestPX1NetworklessCapCheckerNoAnyMode`; plants `s0-a4-*`, including the public pin substitution `s0-a4-public-pin-substitution` |
| A5 | S2 receipt key | `JournalHeaderV2.ReceiptKey` (`receipt_key`, 64-hex x-only). `""` refuses every reconcile; the `JOURNAL_SEGMENT` header check pins it; `FoldLedgerV2` reads `j.Header().ReceiptKey`. No signature changes. New code `RECONCILE_AUTHORIZATION`. | `TestPX1JournalHeaderReceiptKey`, `TestPX1ReconcileReceiptKey`; plants `s0-a5-*` |
| A6 | S2 hardening | `ReconcileRecordV2` is signed by the receipt key (the decision for this stage) over `ReconcileDigestV2` = SHA256(`swarma-wallet-reconcile-v2` \|\| canonical(`ReconcilePreimageV2{binding, grant_id, nonce, seq, reconcile with signature ""}`)). `VerifyReconcileV2` is the one verifier. | `TestPX1ReconcileDigestVector`, `TestPX1ReconcileBinding` (cross-journal, cross-grant, cross-nonce, cross-seq); plants `s0-a6-drop-*` |
| A7 | S2 | Docs: `ActionService` may carry S2's `g2` field beside S3's `px1` field. | docs only |
| A8 | slot AF_UNIX confinement design | The operator status socket moves to its own directory: `StatusSocketDir` / `G2StatusSocketDir` = `/run/swarma-wallet-status` (0750, owner service UID, operator group), `StatusSocketPath` / `G2StatusSocketPath` = `/run/swarma-wallet-status/status.sock` (0660, operator group). `/run/swarma-wallet` (`G2WalletSocketDir`) holds only `wallet.sock` and is the only directory bound into a slot; the status directory is never bound. No frozen agent-facing path shares a directory with the status socket. | `TestPX1StatusSocketSplit` in agent-wallet and deploy (placement, modes, no shared directory, no non-test source naming the old path); plants `s0-a8-status-in-wallet-dir` |

### MIGRATION (what each stream changes at integration)

- **S1:** set `ReceiptKey: receiptKey` in the `px1Attach` wallet-layer header.
  Build every checker with `NewCapCheckerFor(network, genesis)` (replacing
  `newCapCheckerFor`). Make the networkless `NewCapChecker()` admit no `any`
  recipient (today its zero value admits a main or regtest P2PKH); allow mode
  is unchanged. Update `FORMAT-TERMS-V2.md` to match.
- **S2:** drop the interim keyless refusal (`OpenJournalV2` without a key).
  In `OpenJournalV2`, refuse `JOURNAL_SEGMENT` for a `ReceiptKey` that is
  neither `""` nor a valid x-only key; keep the whole-header comparison, now
  including `receipt_key`. Verify every reconcile with
  `VerifyReconcileV2(header, rec)` at Append (after assigning Seq, before the
  record is durable), at open/replay and in `FoldLedgerV2`
  (`j.Header().ReceiptKey`); replace the v1 preimage helpers. The service layer
  sets `ReceiptKey: ""`. An operator CLI signs `ReconcileDigestV2` for
  `Usage().LastSeq+1` while it holds the journal lock. The `g2` field on
  `ActionService` is confirmed (A7).
- **S5:** add the four parameters to `templates/g2-pay/parameters.json` and
  render them: no placeholder remains (`client.json` UID and key path,
  `custody-spec.json` service UID and node datadir, the `u swarma-wallet`
  UID). `ValidateG2PayParameters` returns `ValidateG2PayIdentityDomain(p)`'s
  error first and stays a pure function (no account lookup at render time);
  `G2ReservedID` may replace the local `reservedID`/`sysusersGID`.
  `sysusers.conf` contains `G2AgentSysusers(p)` verbatim in place of the
  placeholder `m` line: the explicit numeric declaration
  `u <agent_user> <agent_uid>` and `m <agent_user> swarma-wallet-peer`. The
  operator is never put into `swarma-wallet-peer`; the operator's only G2
  group is `swarma-wallet-status`. `tmpfiles.conf` renders the status
  directory `d /run/swarma-wallet-status 0750 swarma-wallet swarma-wallet-status -`.
  The host flow, on the TARGET host, in this order: the preflight
  `ValidateG2PayIdentity(p, G2HostAccounts{})`; `systemd-sysusers` applies
  `sysusers.conf`; the REQUIRED `VerifyG2AgentAccount(p, G2HostAccounts{})`;
  only then any service activation and T18. A failed check stops the flow
  before activation. T18's `custody-spec.json` adds `G2StatusSocketDir` to
  `denied_reads` (the agent UID gets `EACCES`; it is not in the operator
  group). Tests use the fixture `G2AccountDB` seam or an account that exists
  on the test host. The placeholder consumer tests become resolved-render
  tests.
- **S3 (A8):** the status listener binds `StatusSocketPath`
  (`/run/swarma-wallet-status/status.sock`, 0660, operator group) in place of
  its own `/run/swarma-wallet/status.sock` constant; no non-test source names
  the old path (`TestPX1StatusSocketSplit` enforces it). The status runtime
  directory is 0750 with the operator group. `SERVICE.md` drops the
  operator's `swarma-wallet-peer` membership: the operator is a member of
  `swarma-wallet-status` only, and the unit example uses the new path.
- **S3 (A1, A5):** the interim one-member substitution in
  `TestPX1ProjectStatusGolden` becomes a no-op and may be removed. Fakes that
  fold a reconcile set `ReceiptKey` and sign with `ReconcileDigestV2`.
- **S4:** nothing beyond the ownership-map entries above.

## Clarifications (non-normative)

These notes explain the frozen contracts. They change no type, code,
signature, fixture or test.

- **`fee_limit_sat` and the transfer cap (integration).** `CheckPrePlan`
  counts the request's `fee_limit` against the effective transfer cap, so a
  spend can be admitted only with `fee_limit_sat <= transfer_cap_sat -
  amount_sat`; otherwise it refuses `TRANSFER_CAP_EXCEEDED` before any node
  call. The Cedar client's default `fee_limit_sat` is 30000, enough for a
  1-in, 2-out spend at ~110 sat/vB (about 24,900 sat). Details:
  `FORMAT-TERMS-V2.md`, "Request fee limit".

## Open items (not decided here)

- Public cap values, the float, the bounty window and Q2 phase 2 are Ivan's.
  The fixtures carry the §3.8 smoke values only.
- The rotated landlord key in Ivan's Mac Keychain (G1 Q4) is still pending.
  S4 can finish and test with a fake `DigestSigner`, but the real issuance waits
  for that key.
- The short LIP "wallet.nmc pay limits (terms v2)" (Q11) is drafted on agents1
  and lands in swarma-link-spec. It is not part of this repository's streams.
- Infra provides the executor host's own mainnet node (txindex, listen=0, the
  hot wallet, nc32.1 before going public). PX1 only consumes it.
