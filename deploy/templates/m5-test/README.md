# M5 test config

This template selects Namecoin mainnet explicitly. These are M5 test limits,
not public-demo caps and not permission to fund, start or spend. No mainnet
operation has been qualified by the local test suite. BTC/LTC main payments,
legacy/prize/name executors and demo-30 remain outside this release's main path.

Every `PLACEHOLDER` must be replaced from operator-owned public inputs. Numeric
placeholders must become JSON numbers. Never put credentials in these public
files. Retain the native canonical field order for model, stations and payload
pairing JSON; the corresponding validators reject reordered encodings.

| Setting | Explicit test value | Native location |
| --- | ---: | --- |
| Transaction movement | 1,000,000 NMC atoms (0.01 NMC) | issuer `config.spending.moved_per_tx` |
| Maximum fee | 200,000 atoms | issuer `config.caps.fee_per_tx` |
| Worst-case legacy fee rate | 200 atoms/vB | issuer `config.policy.policy.fee_rate` |
| Daily movement | 10,000,000 atoms | issuer `config.spending.moved_day` |
| Enrolled hot exposure | 20,000,000 atoms | issuer `config.spending.enrolled_hot` |
| Issuances | 4/hour, 12/day | issuer `config.caps.count_hour/count_day` |
| Aggregate issued budgets | 6,000,000/hour, 10,000,000/day atoms | issuer `config.caps.budget_hour/budget_day` |
| Pool | 4 seals, 200,000 atoms each, low-water 2 | issuer `config.caps` |
| Rental budget | 3,000,000 atoms | booking `config.template.budget_sat` |
| Payment depth | 1 confirmation | booking `config.coins.nmc` and issuer `config.payment_policies.nmc` |
| Single offer | demo-60, 3,600 seconds, 1,000 USD cents | booking template, slot interval and price |
| Model output per request | 8,192 tokens | gateway `model_proxy.caps.max_tokens`, payload pairing |
| Model per slot | 200 requests, 4,000,000 input / 300,000 output tokens | gateway `model_proxy.caps` |
| Model cost per slot | 3,000,000,000 nanoUSD ($3.00) | gateway `model_proxy.caps.cost_nano_usd` |

Movement is non-change funded outputs plus the reserved fee. Only the exact
pinned funding change is excluded. Issue, refill and revoke share one UTC
calendar-day accounting bucket. Pending and uncertain reservations remain
charged across bucket changes and restart. Grant count/budget ceilings are
aggregate UTC hour/day limits, not per-grantee accounting.

The hot cap measures enrolled exposure, including reserved seals and uncertain
inputs. Accepted transactions replace spent inputs with their custody outputs.
It does not discover or constrain coins sent to custody outside this inventory.
Infra owns funding and monitoring; there is no sweep, drain or automatic cap
increase. State/config changes require an explicit operator migration; never
reset the ledger to recover capacity.

The operator supplies exact model ID, reviewed input/output prices and source,
context window, payment exchange rate/as-of time, main public branch and hash,
keys/scripts/names, route and binary pins, TLS pins, payload hash, distinct UIDs,
and slot start time. Set `not_after = not_before + 3600`. Recompute template and
profile hashes from the native canonical bytes after editing. Choose Messages
or the explicit Responses profile as described in `deploy/README.md`; payload
pairing must match the actual model config. No model or exchange-rate default is
provided here.

Private provisioning remains separate: read-only observer routes, the isolated
signer broadcaster, grant/funding scalar files, model API credential and wallet
RPC routes. The wallet's private native `Config` must explicitly use `network`
`main`, the exact genesis from `wallet/service.json`, a matching nested policy,
a main P2PKH `change_address`, and positive `fee_rate_sat_vb` (test value 200).
The service refuses a private wallet network that differs from its public pins.
The client pins independently select the same network; legacy CLI entrypoints
remain regtest-only. The wallet service exposes spend, balance, receive, history
and budget, not name registration.

## Validation tools

From the deploy module, after resolving public inputs:

```sh
go run ./cmd/deploy-kit validate -config "$PUBLIC_DIR/issuer/deploy.json" -public "$PUBLIC_DIR/issuer/service.json"
go run ./cmd/deploy-kit validate -config "$PUBLIC_DIR/booking/deploy.json" -public "$PUBLIC_DIR/booking/service.json"
go run ./cmd/deploy-kit validate -config "$PUBLIC_DIR/gateway/deploy.json" -public "$PUBLIC_DIR/gateway/service.json"
go run ./cmd/deploy-kit validate -config "$PUBLIC_DIR/wallet/deploy.json" -public "$PUBLIC_DIR/wallet/service.json"
```

Use the same descriptor/native-config pair for model, stations, store and relay.
Payload requires its pairing file and actual model config as the two public
inputs. These commands perform public structural validation and never open
custody files or contact nodes. Native startup and later live own-node checks
remain required. Keep validation evidence under the task's `.temp/` directory.
