# PX1 frozen interfaces: agent-walletd G2 pay limits

PX1-S0 freezes the shared contracts that five producer streams build in parallel.
It sits on top of agent-walletd W2. Design: G2-PAYMENT-EXECUTOR-v1 §2-§5. The
co-lead review (COLEAD-REVIEW-PX1, 2026-11-12) is binding.

- **What is frozen:** every `px1_*_api.go` file in this module, plus
  `experiments/rental/paygrant_v2_api.go`, `deploy/g2_pay_api.go`, the golden
  fixtures listed below, and the freeze tests (`px1_freeze_test.go`,
  `px1_freeze_fixture_test.go`, `rental/paygrant_v2_freeze_test.go`,
  `deploy/g2_pay_freeze_test.go`).
- **Amendment rule:** a type, member order, JSON name, code or signature changes
  only through a freeze-amendment PR. All stream owners review it. The
  compile-time assertions (`var _ func(...) = F`) in the API files fail the
  build if an implementation drifts from its frozen signature.
- **Stubs:** each stream's implementation files start as stubs. Each stub
  returns the sentinel `ErrNotImplemented` (`PX1_NOT_IMPLEMENTED`, a bounded wire
  code), or a zero value that can never pass. No W2 path calls a stub. A G2
  profile that reaches a stub refuses, so it fails closed.
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
| Q8: operator reconciliation only | `ReconcileRecordV2`: signed, rate-limited, citing chain evidence; nothing releases a debit automatically |
| Q9: same host, separate UID | `deploy.G2PayParameters.AgentUID != service UID`; T18 `CustodySpecV1` |
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
| S1: terms v2, caps, executor binding | `px1_terms_api.go`, `px1_api.go` (codes) | `ParseTermsV2(raw, TermsV2Pins)`, with a 10-row refusal table; `ValidateG2OperatorConfig`; `EffectiveLimitsFor` (min of terms and operator ceiling); `CapChecker{CheckExecutor, CheckRecipient, CheckPrePlan, CheckPostPlan}`; `SpendIntent` |
| S2: journal v2, day buckets | `px1_journal_api.go` | `JournalRecordV2` (kinds `admit, reserve, service-reserve, complete, uncertain, refuse-retained, terminal, track, reconcile`); `JournalV2{Header, Append, Iterate, Usage, Poisoned, Close}`; `OpenJournalV2`; `JournalSegmentV2` hash chain; capacity rules in `JournalLimitsV2`; `RequiredSpendCapacity`; `LedgerView` and `FoldLedgerV2`; `ClockGuard` and `NewClockGuard` (`CLOCK_ROLLBACK`); `ReadLimiter` (`READ_RATE_LIMITED`) |
| S3: tracker, canary, status | `px1_observe_api.go` | `Tracker{Enqueue, Tick, Snapshot}`; `Canary{Excluded, Check}`; `FloatMonitor`; `StartupReconciler` (`STATE_RECONCILE_REQUIRED`); `AlertSink`; `StatusProjectionV1` and `ProjectStatus`; `ServeStatus` on `/run/swarma-wallet/status.sock` |
| S4: terms-v2 issuance helper | `rental/paygrant_v2_api.go` | `IssuePayGrantV2(ctx, in, grantee, landlord DigestSigner)`; signer call order: consent, then contract countersign, then grant; `PayGrantSigningRequest` and `PayGrantSignature`; `EncodePayTermsV2`; `PayGrantBookingRef`; `NewFileExchangeSigner`; the issuance tx is planned by the existing `MakeGrantIssuancePlan` |
| S5: deploy, T18 | `deploy/g2_pay_api.go` | `G2PayParameters`; `ValidateG2PayParameters`; `RenderG2PayTemplates`, which renders exactly the `G2File*` set; `CustodySpecV1`; `RunCustodyProbe`; `VerifyCustodyReport` |
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
owned by the stream that creates it. A seat that needs a change in another
stream's file asks that owner. A seat that needs a change in a frozen file
opens a freeze-amendment PR.

| Owner | Files (paths relative to the repository root) |
| --- | --- |
| **S0 (frozen)** | `experiments/agent-wallet/px1_api.go`, `px1_terms_api.go`, `px1_journal_api.go`, `px1_observe_api.go`, `px1_seams_api.go`, `px1_freeze_test.go`, `px1_freeze_fixture_test.go`, `PX1-INTERFACES.md`, `testdata/px1/*`; `experiments/rental/paygrant_v2_api.go`, `paygrant_v2_freeze_test.go`, `testdata/px1/*`; `deploy/g2_pay_api.go`, `g2_pay_freeze_test.go`; the PX1 loader block in `experiments/agent-wallet/mutation_test.go` |
| **S1** terms, caps, binding | new: `experiments/agent-wallet/px1_terms.go`, `px1_wallet_seams.go`, `px1_terms_test.go`, `px1_fixture_test.go` (shared Core helpers that issue grants with terms v2: S1 writes them, the other streams only call them), `FORMAT-TERMS-V2.md`, `testdata/px1-mutations-s1.json`. Existing: `wallet.go`, `grant.go`, `plan.go`, `single_use.go`, `service_config.go` (the `G2` member and its validation), `wire.go` (only if needed; terms v1 behaviour unchanged) |
| **S2** journal v2, day buckets | new: `experiments/agent-wallet/px1_journal.go`, `px1_service_seams.go`, `px1_journal_test.go`, `FORMAT-JOURNAL-V2.md`, `testdata/px1-mutations-s2.json`. Existing: `service.go` (admission, service-layer journal v2, reads out of the lifetime journal, `SINGLE_USE_DISABLED`, the single `px1 px1Runtime` field, the `PX1Enqueue` call), `read.go` (read limiter), `service_receipt.go` (only if a receipt field is needed; wire stays unchanged) |
| **S3** tracker, canary, status | new: `experiments/agent-wallet/px1_observe.go`, `px1_runtime.go`, `px1_observe_test.go`, `STATUS.md`, `testdata/px1-mutations-s3.json`, the status socket listener (in `px1_runtime.go` or a new `px1_status_socket.go`). Existing: `cmd/agent-walletd/main.go` (tick loop and status socket), `SERVICE.md` (a G2 operations section) |
| **S4** issuance helper | new: `experiments/rental/paygrant_v2.go`, `paygrant_v2_test.go`, `cmd/paygrant-v2/` (the ceremony CLI), `PAYGRANT-V2.md`. Existing: `experiments/rental-executor/README.md` (Q10 superseded note only) |
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
| `experiments/agent-wallet/testdata/px1/status-projection-v1.json` | a populated `StatusProjectionV1` | `TestPX1StatusProjectionGolden` |
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
| T18 | different-UID custody: denied reads plus one positive own-agent request | S5 | host script on an agents1-class VM (users pre-provisioned by the owner) | S1-S3 for the positive request |

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
   - every PX1 mutation manifest under `W1_MUTATIONS=1`;
   - docs linked from the README.
5. **S5 runs T18** on an agents1-class VM, with the users provisioned by the owner.
6. **Mainnet-safe smoke (§3.8)** runs only after Ivan approves and funds it.
   Nothing in PX1 authorizes it.

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
