# Terms v2, operator ceilings and the G2 spend path (PX1 stream S1)

This document covers the S1 part of the PX1 G2 pay-limits profile for
`agent-walletd`: the terms v2 object, the operator `g2` block, the effective
limits, the cap checker and the wallet-layer spend path. The frozen contracts
are in `px1_terms_api.go`, `px1_api.go` and `px1_seams_api.go` (see
`PX1-INTERFACES.md`). The design source is G2-PAYMENT-EXECUTOR-v1 §3.2-§3.6.

## Profile selection

`ServiceConfig` has an optional `g2` member (`G2 *G2OperatorConfig`,
`omitempty`).

- **Absent:** the service config bytes, the W2 journal binding and W2
  behaviour are unchanged. Terms v1 keeps its parser.
- **Present:** `validServiceConfig` runs `ValidateG2OperatorConfig`. Then
  `OpenActionService` opens the wallet through `px1OpenServiceWallet`
  (`px1_wallet_seams.go`). That function attaches the wallet to the G2 profile
  with `px1Attach(operator, receiptKey)` before the service is built or serves
  anything. The receipt key is the service receipt x-only key. The attachment
  validates the block and the receipt key, opens the canary watcher and opens
  the wallet-layer journal v2.

Attachment fails closed, and so does startup. A present `g2` block selects the
G2 profile, or `OpenActionService` refuses and returns the attach error
unchanged after closing the wallet. It never returns a W2 wallet for a G2
config. A wallet whose W2 `wallet.json` already has records is never continued
under G2 (`SERVICE_PROFILE`). An attach that reports success but leaves the
wallet on W2 also refuses `SERVICE_PROFILE`. The attach returns the first
failing product constructor's refusal unchanged (`px1ProductDeps` is exactly
`OpenJournalV2`, `FoldLedgerV2`, `UTCDay` and `NewCanary`). While the S2 and S3
stubs are present, a service with a `g2` block therefore refuses to start with
`PX1_NOT_IMPLEMENTED`; once they land, it refuses with their own code (for
example `RPC_UNAVAILABLE` from `NewCanary` without an observer node) or
attaches.

The call site in `service.go` (an S2 file) is one changed line:
`openWallet(wc)` became `px1OpenServiceWallet(wc, c, key)`. PR 76 revision 2
made that change at the review's request, for finding
g2-profile-falls-through-to-w2. Before it, a G2 config opened a W2 wallet,
which paid terms-v1 spends past the G2 ceilings.

## Terms v2 object

The terms are exact compact JSON in Go `json.Marshal` member order. They are
stored as `<sha256>.json` in the service-owned objects directory, and their
SHA-256 equals the grant's `contract_sha256`:

```json
{"version":2,"service":"wallet.nmc","executor_key":"<64 hex>","network":"main","genesis":"<64 hex>","recipient_mode":"allow","recipients":["N..."],"spend_cap_sat":500000,"transfer_cap_sat":100000,"day_cap_sat":300000,"day_count_cap":5,"fee_cap_sat":100000,"day_basis":"utc-calendar"}
```

The golden fixtures are `testdata/px1/terms-v2-allow.json` and
`terms-v2-any.json`. Every cap is fee-inclusive: cost = `amount_sat` + actual
fee.

### Parser refusal order (`ParseTermsV2`)

The first failing row wins.

| Row | Condition | Code |
| --- | --- | --- |
| 1 | empty, over 65536 bytes, or not a JSON object | `CONTRACT_SCHEMA` |
| 2 | member `version` is `1` (a terms v1 object) | `TERMS_VERSION_REQUIRED` |
| 3 | not SJ1-strict, unknown or duplicate member, not byte-equal to canonical | `CONTRACT_SCHEMA` |
| 4 | `version != 2`, `service != "wallet.nmc"`, `day_basis != "utc-calendar"`, `executor_key` not a lowercase BIP-340 x-only key | `CONTRACT_SCHEMA` |
| 5 | `network`/`genesis` differ from the service pins | `TERMS_NETWORK` |
| 6 | `executor_key` differs from this instance's receipt key | `TERMS_EXECUTOR_MISMATCH` |
| 7 | mode not `allow`/`any`; `recipients` null; `allow` with 0 or more than 32 entries, or unsorted; `any` with a non-empty list | `CONTRACT_SCHEMA` |
| 8 | an allow-list entry is not a canonical P2PKH of the pinned network (checked over the whole list first) | `ADDRESS_MAIN` / `ADDRESS_REGTEST` / `ADDRESS_P2PKH_ONLY` |
| 9 | duplicate allow-list entry | `CONTRACT_RECIPIENTS` |
| 10 | not `0 < transfer <= day <= spend <= grant budget`; `day_count_cap` outside 1..1000; `fee_cap_sat` outside 1..`MaxFee`; grant budget above `MaxMoney` | `CONTRACT_BUDGET` |

A grant without a budget has budget 0, so its terms v2 always refuse
`CONTRACT_BUDGET` (LIP-0004: no budget means zero).

## Operator block (`ValidateG2OperatorConfig`)

Every violation refuses `SERVICE_CONFIG`.

| Member | Accepted |
| --- | --- |
| `require_terms_version` | `2` |
| `allow_single_use` | `false` (Q7) |
| `allow_any_recipients` | `false` at launch; `true` is valid for phase 2 (Q2, Ivan decides) |
| `max_transfer_sat`, `max_day_sat` | `1 <= max_transfer <= max_day <= MaxMoney` |
| `max_day_count` | 1..1000 |
| `max_fee_sat` | 1..`MaxFee` |
| `max_float_sat`, `low_float_sat` | `1 <= max_float <= MaxMoney`, `0 <= low_float < max_float` |
| `canary` | 64-hex txid, `value_sat` from 546 up to `MaxMoney` |
| `confirmations_k` | 1..100 (alerts only, Q12) |
| `conflict_blocks_n` | 1..1000 |
| `read_rate_per_hour` | 1..3600 |
| `journal_spend_capacity` | 65..1000000; S2 additionally checks it against `RequiredSpendCapacity` at startup |

## Effective limits (`EffectiveLimitsFor`)

Each cap is the minimum of the terms value and the operator ceiling. The
operator block lowers values and never raises one (LIP-0008).

- `transfer`, `day`, `day_count` and `fee` take that minimum.
- `spend` comes from the terms and `total` from the grant budget.
- Recipients and the mode come from the terms only.
- Terms in `any` mode refuse `TERMS_RECIPIENT_MODE` unless the operator block
  allows any recipients.
- The function re-checks the budget binding (`CONTRACT_BUDGET`) and the
  operator block (`SERVICE_CONFIG`) as defence in depth.

## Cap checker (`NewCapCheckerFor`)

Every caller, the wallet included, builds its checker with the frozen
`NewCapCheckerFor(network, genesis)` (freeze amendment 1, A4). The wallet
passes its own config `network`/`genesis` when it attaches to G2. The frozen
wrapper refuses `NETWORK_PIN` on every method unless network/genesis is a
pinned pair, then applies the S1 rules of `NewCapChecker()` below. Every
method is pure: it makes no node call and no write.

| Method | Order of refusals |
| --- | --- |
| `CheckExecutor` | `NETWORK_PIN`; `TERMS_EXECUTOR_MISMATCH` if the receipt key is invalid or differs |
| `CheckRecipient` | `NETWORK_PIN`; `ADDRESS_NOT_ALLOWED` unless the address is a canonical P2PKH of the pinned network; then `allow`: exact string membership, `any`: admitted. Any other mode: `ADDRESS_NOT_ALLOWED` |
| `CheckPrePlan` | `NETWORK_PIN`; `AMOUNT_DUST` (below 546), `TRANSFER_CAP_EXCEEDED` (amount + fee_limit), then `TOTAL_BUDGET_EXCEEDED`, `SPEND_BUDGET_EXCEEDED`, `DAY_CAP_EXCEEDED`, `DAY_COUNT_EXCEEDED` on the amount alone |
| `CheckPostPlan` | `NETWORK_PIN`; `FEE_LIMIT`, `FEE_CAP_EXCEEDED`, `TRANSFER_CAP_EXCEEDED`, then the same four cumulative caps on amount + actual fee |

`CheckPrePlan` and `CheckPostPlan` refuse `STATE_UNAVAILABLE` for an intent
that cannot belong to the limits: a nil ledger, another grant, a malformed UTC
day, or an out-of-range amount or fee limit. A nil error means "within
limits", never "authorized".

### Request fee limit (`fee_limit_sat`)

The pre-plan transfer cap counts the request's `fee_limit` in full, before
any plan exists. A spend is therefore admitted only when

    fee_limit_sat <= transfer_cap_sat - amount_sat

with `transfer_cap_sat` the effective transfer cap (`EffectiveLimitsFor`: the
smaller of the terms value and the operator ceiling). A larger `fee_limit`
refuses `TRANSFER_CAP_EXCEEDED` before any node call, even when the actual fee
would fit. The actual fee is then held to min(`fee_limit`, fee cap) by the plan
(`FEE_LIMIT`, `FEE_CAP_EXCEEDED`). The Cedar client sends a default
`fee_limit_sat` of 30000: at the operator fee rate of ~110 sat/vB a 1-in,
2-out P2PKH spend costs about 24,900 sat, and the largest amount it can then
send under a 100000 transfer cap is 70000.

The frozen `NewCapChecker()` carries no network. It stays because
`NewCapCheckerFor` wraps it, and it is deprecated for callers. Its
`CheckRecipient` admits no `any`-mode recipient at all, whatever the address
(`ADDRESS_NOT_ALLOWED`), so a caller that passes no network never gets an
allow-all checker. Its `allow` mode keeps exact string membership. Before
amendment 1 it admitted a canonical main or regtest P2PKH in `any` mode, and
the wallet used an unexported bound form; both are gone.

## Wallet-layer spend path (G2)

`executeAuthenticated` dispatches to `executeG2` when the wallet is attached.
Steps follow §3.5. Steps 1-7 and 20 belong to the service layer (S2).

| Step | What S1 does | Refusal or outcome |
| --- | --- | --- |
| 8 | single-use grant or a use proof | `SINGLE_USE_DISABLED` |
| 10 | terms by `contract_sha256`, `ParseTermsV2`, `CheckExecutor`, `EffectiveLimitsFor` | `CONTRACT_HASH`, the parser codes, `TERMS_RECIPIENT_MODE` |
| 12 | grant ID, sender, `created_at` in [`not_before`, `not_after`) and not in the future, `pay` in scope, recipient by mode | `REQUEST_GRANTEE_BINDING`, `REQUEST_TIME`, `GRANT_SCOPE`, `ADDRESS_NOT_ALLOWED` |
| replay | prior wallet-layer record of (grant, wallet nonce) | same bytes: `already-executed` / `DURABLE_RESERVATION_NO_RETRY`; other bytes: `NONCE_CONFLICT` |
| 13 + 15 | `CheckPrePlan` against the folded ledger (`PX1Ledger`), before any node call | cap codes |
| 14 | kernel check #1 (`rental.Check`) | `GRANT_*` |
| 16 | plan at the operator fee rate; the canary outpoint and every retained-record input are never planned; fee at most min(fee_limit, fee cap) before signing; kernel check #2 | `PLAN_RESERVED_INPUT`, `FEE_LIMIT`, `FEE_CAP_EXCEEDED` |
| 17 | `CheckPostPlan` | cap codes |
| 18 | kernel check #3, re-read of every input | `GRANT_*`, `UTXO_*` |
| 19 | `reserve` record: debit = amount + fee, `day` = UTC day of the executor clock at admission, inputs, txid | debit charged from here on |
| 21 | kernel check #4, re-read of every input | `refuse-retained` record; debit retained; no broadcast |
| 22 | `sendrawtransaction`; the returned txid must equal the plan txid | otherwise an `uncertain` record, `BROADCAST_UNCERTAIN` |
| 23 | `complete` record | `EXECUTED`; a write failure gives `uncertain`, `JOURNAL_WRITE_UNCERTAIN`; a clock step back below the reservation's `last_time` gives `uncertain`, `CLOCK_ROLLBACK` |

Follow-up records copy the reserve record's debit, fee, day, inputs and txid,
so a fold sees one retained debit per request. A follow-up's `last_time` is
the executor clock when it is appended. If the clock stepped back after the
reservation, the journal refuses the follow-up with `CLOCK_ROLLBACK`. That
refusal does not poison the journal. The reserve record keeps the debit
retained on every day, and the step-23 receipt names `CLOCK_ROLLBACK`
(`px1FollowFailure`) instead of the misleading `JOURNAL_WRITE_UNCERTAIN`.
While the clock stays behind, the next reservation refuses `CLOCK_ROLLBACK`
before any broadcast. Nothing is ever released by
S1. Only an operator `reconcile` record releases a debit (S2/S3, Q8).

Wallet-layer records use these values:

- `action` is `"spend"`.
- `nonce` is the derived 64-hex wallet nonce from `walletRequest()`.
- `created` is the request's `created_at`.
- `last_time` is the wallet clock.

The journal lives in the wallet `state_dir` under the lock
`journal-v2.lock`. Its header is
`{version: 2, layer: "wallet", binding, receipt_key}`:

- `binding` is `SHA256(canonical({domain, wallet_binding, receipt_key}))`, so
  a second executor key never adopts another executor's debits.
- `receipt_key` (freeze amendment 1, A5) is this executor's 64-hex x-only
  receipt key, the one that signs the service receipts. It is the only key
  whose reconcile records (`VerifyReconcileV2` over `ReconcileDigestV2`)
  release a debit in this journal.

The attach compares the whole header the journal reports with the one it
asked for. A journal written without `receipt_key` (before amendment 1) or
under another key refuses `JOURNAL_SEGMENT`, so the reconcile key is pinned
on disk.

## Budget read under G2

`px1Budget` returns `BudgetV2`, the extended §3.3 effect:
`{grant_id, total_cap_sat, spend_cap_sat, spend_reserved_sat,
total_remaining_sat, transfer_cap_sat, day, day_used_sat, day_count,
day_remaining_sat, day_count_remaining, uncertain_sat, live, reason}`.

Until S2 dispatches the service `budget` read to it, the W2 `Budget` method
returns the W2-shaped projection of the same G2 ledger. It carries no name
budget.

## Tests and controls

- **Unit layer:** `px1_terms_test.go`. It covers T1, T2, T4, T6, T7, T12 and
  T15, plus the parser, operator, limits and checker contracts. The wallet
  cases use fakes of the frozen S2/S3 interfaces and a fake wallet node that
  signs genuine P2PKH transactions.
- **Core layer:** `px1_core_test.go`. It runs T1, T2, T4, T6, T7 and T12 on a
  genuine Namecoin Core 28 regtest node, with the genuine K1 kernel under the
  W construction profile. Until S2/S3 land, the journal, fold, day and canary
  are fakes.
- **Freeze amendment 1 migration:** `TestPX1WalletAttach` (the header carries
  `receipt_key`; a keyless or other-key journal refuses `JOURNAL_SEGMENT`;
  the checker is `NewCapCheckerFor` of the wallet network, main and regtest),
  `TestPX1WalletAttachProductDeps` (the production attach uses exactly the
  frozen S2/S3 entry points and returns their refusal unchanged, on this branch
  and composed with S2/S3), `TestPX1WalletRecipientAnyMode` (phase-2 any mode
  at the wallet layer) and `TestPX1NetworklessCapCheckerAnyMode`.
- **Service opener:** `px1_service_test.go`. It covers profile selection at the
  public `OpenActionService` boundary. There is a unit test with installed
  files and no node call. There is also a genuine Core 28 pair adapted from
  the reviewer's tests: a G2 config attaches both layers and never pays a
  terms-v1 spend (before the first observation pass the S3 halt refuses
  `SERVICE_STATE_UNAVAILABLE`, after a pass with a real unspent canary the
  spend refuses `TERMS_VERSION_REQUIRED`, and after an out-of-band canary
  spend a new spend refuses `FLOAT_CANARY_SPENT`, T14 on the wire); the W2
  neighbour pays 50000 atoms. The file also has the step-23 clock step-back
  test.
- **Shared helpers:** `px1_fixture_test.go` (`newPX1Core`, `px1IssueGrant`,
  `px1OpenG2`, `px1OpenG2With`, `px1Spend`, `px1Revoke`, `px1QuoteFee`, the
  fakes). Other streams call them and do not edit them.

```sh
go test -count=1 -run 'PX1' .
W1_REGTEST=1 W1_RUN_ROOT=FRESH_ABSOLUTE_DIRECTORY \
W1_CORE_CLI=ABSOLUTE_NAMECOIN_CLI W1_CORE_DAEMON=ABSOLUTE_NAMECOIND \
go test -count=1 -run '^TestPX1CoreS1$' -v .
# fresh W1_RUN_ROOT per invocation, likewise:
go test -count=1 -run '^TestPX1CoreServiceG2FailClosed$' -v .
go test -count=1 -run '^TestPX1CoreServiceW2Positive$' -v .
W1_MUTATIONS=1 W1_MUTATION_ROOT=FRESH_ABSOLUTE_DIRECTORY \
W1_DEP_ROOT=ABSOLUTE_EXPERIMENTS_DIRECTORY \
W1_CORE_CLI=ABSOLUTE_NAMECOIN_CLI W1_CORE_DAEMON=ABSOLUTE_NAMECOIND \
go test -count=1 -run '^TestGuardPlants$/^s1-' -v .
```

`testdata/px1-mutations-s1.json` lists the S1 plants (unit and Core). Each
plant must fail its named assertion.

The Core lab accepts the macOS Core 28.0 pair that the W2 harness pins and the
Linux x86_64 release pair. Regtest names expire after 30 blocks, so the lab
renews the agent and landlord names before each grant issuance.

## Coverage notes

- **Post-plan `TRANSFER_CAP_EXCEEDED` is mutant-only coverage.** The T2 row
  of the S1 coverage map ("over cap by 1 atom, pre- and post-plan") rests on
  the checker for its post-plan half. In the wallet path the post-plan
  transfer cap is unreachable once the pre-plan cap and `FEE_LIMIT` hold,
  because amount + fee <= amount + fee_limit <= transfer_cap. No wallet,
  service or Core request reaches it. It is covered only by
  `TestPX1CheckPostPlan/transfer-plus-one` and the plant
  `s1-postplan-transfer`; the wallet relies on the pre-plan cap, which is
  planted (`s1-preplan-transfer`, `s1-wallet-preplan-call`).

## Limits

- `TestPX1CoreS1` does not exercise the service layer (peer UID, admission,
  `service-reserve`, receipts). The `TestPX1CoreService*` pair does exercise
  the production opener and handler, with injected peer metadata, for
  profile selection, the S3 halt and T14 on the wire, but no positive G2
  spend.
- The Core layer does not exercise the real journal v2, its capacity rules or
  `CLOCK_ROLLBACK`; those are S2's.
- The Core layer does not exercise the real canary watcher; that is S3's.
- The fake fold implements the frozen LedgerView rules only as a test
  stand-in.
- An injected agent can still spend within the caps to an allow-listed
  address, or to any address in `any` mode. This is A1, out of bounty scope.
