# MA1-03 main issuance route audit

Scope: static call-site inspection of the main-admitted M5 routes, followed by
the public issuer regression and existing rental/signer controls. The base is
`ca074ca645bc69d7bba41e7889504612eaa7f7d4`. This is a producer inventory for
independent review, not an independent ACCEPT or production qualification.

## Defect and correction

`IssueGrantWithNodes` and `IssueGrant` share `issueGrantRouted`. The base called
`grantFundingShape(..., true)` before looking up a completed record. That helper
correctly rejects bare plans on main with `LEGACY_REGTEST_ONLY`, so even fresh
V2 main issuance stopped there. The fix checks encoding-independent funding
inputs first, resolves exact completed replay, then uses the framed projection
for fresh issuance before any burn or signature. Completed main replay cannot
try the bare fallback; completed regtest replay retains its original bytes.
Input roles, duplicate inputs, pool exclusions, current funding reservations,
separate funding/change scripts and the full stored-plan comparison remain.

## Route inventory and verdicts

Paths are relative to `experiments/`, except `../deploy/` below. A regtest default
or historical error label is distinguished from an unconditional regtest gate.

| Public route | Helper path and verdict |
| --- | --- |
| V2 grant issuance | `rental/grant_payment.go:IssueGrantWithNodes` → `grant_issuer.go:issueGrantRouted` → `grant_plan.go`. **Fixed** unconditional bare projection. `VerifyIssuancePackageV2` and `AdmitIssuanceV2` select explicit network/genesis and trusted payment observers. Full public V2 success is exercised by the new Core witness. |
| Legacy payment issuance | `IssueGrant` → `verifyGrantIntent` → `VerifyIssuancePackage` → `Policy.validate`. **Intentionally refused on main**, as `ISSUER_POLICY`; V1 is not the M5 main route. New public-entry negative has a valid regtest positive control. |
| Fresh and replay grant plans | `MakeGrantIssuancePlan` always passes `legacy=false`. `matchesIssuedGrantPlan` tries bare only for completed regtest records. `GrantFeeRate` defaults to 200 only for regtest; main requires a positive explicit rate. **Admitted**, with explicit framed fee and replay checks. |
| Grant verification and names | `rental/grant_kernel.go:Check`, `ResolveLandlord`, `GrantNameGeneration` use the grant policy and selected observation pins. `validateGrant` calls `validateDetachedFields`, not the regtest-only `validateDetached`. **Admitted**. `issuanceScriptMatches` still reads exact historical bare commitments as well as frames; this reader compatibility is not permission for main writers or journal replay to produce bare plans. |
| Pool refill/revoke and CLI planning | `rental/planner.go:MakePlan` selects `makeGrantPoolPlan` when the landlord pin is present. `cmd/rental-plan` sends `grant-issue` to `MakeGrantIssuancePlan`. **Admitted** for grant plans. Detached/station-anchor plans and `MakeBatchAnchorPlan` retain their explicit legacy policy gates; batch anchoring is optional and not on the M5 main issuance path. |
| Legacy verification/issuance commands | `CheckLegacy`, `CheckV2`, detached issuance, `cmd/rental-issue`, and `cmd/rental-kernel` keep their regtest boundaries. **Not main-admitted**; these commands are not the native M5 signer/gateway entrypoints. |
| Native signer | `signer-service` config requires main V2 profile, explicit fee and spending limits. `V2Issuer.Prepare` calls `IssueGrantWithNodes`; `Check` calls `AdmitIssuanceV2`. `config_file.go` uses `NewRPCBroadcastForNetwork`; the `NewRPCBroadcast` wrapper is a regtest compatibility constructor with no native main caller. **Admitted** after this issuer fix. The `REGTEST_ONLY` error label in config validation does not replace its actual `NetworkPinned` predicate. |
| Booking V2 | `rental-booking/service_v2.go:NetworkPins` defaults only when both pins are absent. Main uses `paymentProfile` → `ForNetwork` and `CheckRenterNameForNetwork`. The native CLI supplies V2 config pins. **Admitted**. V1 `Service` uses `CheckRenterName` and stays outside the main route. |
| Payment selection | `payment-chain:ForNetwork` calls `ForCoin` for coin constants, then explicitly installs the NMC main pins or checks the selected regtest pins. This is **not a regtest rejection on main**. `Profile.Validate` and terms validation use `ForNetwork`; no production caller of the legacy `Coin.Profile` wrapper was found in the inspected routes. |
| Native gateway | `rental-gateway/cmd/gateway` validates matching mode/network and calls `kernelbind.NewForNetwork`, then the v3 kernel. The `kernelbind.New` regtest wrapper is not used by this main route. V2 booking exchange uses the V2 binding. **Admitted**. |
| Native wallet service/client | `agent-wallet` config and action client carry explicit pins into `ParseActionForNetwork`, `SignActionForNetwork`, `ExchangeActionForNetwork`, and wallet `termsForNetwork`. **Admitted** for the supported spend action. Legacy `Wallet.Execute` refuses main with `LEGACY_REGTEST_ONLY`; only the legacy CLI calls it. Main name actions refuse `MAIN_ACTION_UNSUPPORTED` before `nameReady` can use its historical regtest observation. The RPC address type `legacy` means P2PKH, not a network. |
| Store, relay, model proxy, station manager/payload | The native `grant-store`, `relay`, `model-proxy`, `station-lifecycle`, and `station-payload` production source does not select a regtest chain observer. These components consume configured capabilities/proofs or transport data; the gateway/signer own the relevant chain checks. **No unconditional regtest helper found** in this sweep; this does not prove Linux helper/isolation readiness. |
| Deploy descriptors | `../deploy/main_profile.go` accepts explicit matching main pins and checks nested documents. Regtest defaults/constants and its regtest-only RPC-port restriction are conditional. **Main profile admitted** with complete operator inputs. Config validation alone did not expose the runtime issuer defect. |
| Other legacy consumers | `grantcheck` and `rental-executor` explicitly select regtest. **Not main-admitted** and not part of the M5 native route; they are not silently broadened by this fix. |

Searches covered production `regtest`, `RegtestGenesis`, `REGTEST_ONLY`, bare/
legacy projections, `ForCoin`, and compatibility constructor call sites; each
relevant hit was checked in its caller. Static inspection does not establish
all runtime behavior or eliminate the need for independent review.

## Executable evidence and limits

- `TestMainPublicGrantFundingAdmission` calls both public wrappers. Exact
  insufficient framed fees, seal funding, pool inputs, and wrong change refuse
  without returned authority or burns. A funded control reaches the fake node's
  first observation. Restoring the base's unconditional bare call must fail it
  with `LEGACY_REGTEST_ONLY`, not a setup error.
- `TestCoreMainPublicGrantV2` uses real isolated regtest name/payment/funding
  observations. Its explicit seam changes only chain/genesis replies, and the
  public V2 terms are re-signed for main. The result is a signed framed grant,
  explicit fee, independent payment evidence, and byte-identical offline replay.
  Wrong identity/payment chains refuse without burns. It does not contact main,
  broadcast the main-labelled plan, validate main consensus, or use live funds.
- `TestCoreMainLegacyPaymentRefusal` exercises `IssueGrant` with authentic V1
  inputs: projected main refuses at `ISSUER_POLICY`, unmodified regtest prepares.
- `TestCoreGrantLocatorReplay`, with the pinned historical issuer, preserves
  actual old bare plan bytes at the fee/dust boundary, refuses corruption, and
  pairs them with fresh framed issuance. L5 controls intentionally break the
  replay fee gate and fresh fee gate as well as restoring the main bug.
- Rental and signer race suites/guard controls and one IT2 Responses leg are
  recorded with exit codes and exact source binding in the producer packet.
  The IT2 lane remains local regtest composition with its declared Darwin
  isolation seams; it is not the separate three-host Linux smoke.
