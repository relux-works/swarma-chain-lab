# Regtest booking-payment observation

Development module for separately routed BTC, LTC and NMC booking fees. It
never signs, spends, broadcasts or grants execution authority. The existing
Namecoin seal verifier remains a separate module and profile.

Closed profiles bind coin, regtest genesis, address family, monetary limits and
runtime product/protocol tuple. BTC/NMC deliberately share regtest genesis and
the Satoshi label; their pinned protocol versions differ. The tuple detects an
accidentally swapped route, not a malicious daemon. Trusted routing and isolated
read-only credentials remain required. Unknown protocol upgrades fail closed.

`NewAddressDeriver` accepts a hash-pinned public tpub branch, derives only
non-hardened children, and returns canonical P2PKH (NMC) or P2WPKH (BTC/LTC).
Callers must atomically reserve each per-coin index with the global calendar
before exposing an address. This module owns no reservation ledger.

`Terms.ValidateAt` checks the exact integer ceiling quote, dust and maximum
supply bounds, address family and trusted rate-age/confirmation policy. Quotes
are frozen at hold creation; transaction fees do not reduce the received value.
Execution budget remains NMC-denominated in the enclosing contract.

`Discover` projects unrelated outputs before parsing candidate amounts/inputs.
It scans bounded linked active blocks and a stable mempool, returning pending
and confirmed payments separately. A discovered payment is not admission.
`Admit` authenticates no package: callers first authenticate the enclosing
contract/hold. It independently resolves the claimed height through the active
chain, checks block membership and raw txid/output bytes twice, enforces the full
confirmation threshold and unexpired hold, and rechecks the tip. It requires an
explicit block hash for historical raw lookup, not txindex. Unavailable pruned
history refuses. Surplus is reported, never spent or refunded automatically.

RPC transport requires a loopback route and `payment-observer` credential. The
node must restrict that user to getnetworkinfo, getblockchaininfo, getblockhash,
getblockheader, getblock, getrawtransaction and getrawmempool. Neither discovery
nor admission can call wallet or mutation methods. Never place route passwords
or private Core fixture directories in an evidence export.

## Tools

- Go 1.26.8: `go test -race -count=1 ./...`, `go vet ./...`, `go mod verify`.
  Unit tests include positive controls and specific refusal/zero-result checks.
- Genuine Core: `P1_REGTEST=1 P1_RUN_ROOT=/absolute/new/run P1_BTC_DAEMON=...
  P1_BTC_CLI=... P1_LTC_DAEMON=... P1_LTC_CLI=... P1_NMC_DAEMON=...
  P1_NMC_CLI=... go test -count=1 -run '^TestCorePayments$' -v .` Supply all
  explicit binary paths; hashes are pinned in core_test.go. Releases are BTC
  32.1 arm64, LTC 0.21.5.8 x86_64 and NMC 28 arm64 on macOS. The test creates
  isolated network-disabled regtest nodes, txindex=0, prune=550. It records
  owned PIDs and waits for shutdown. Public observations go under
  `$P1_RUN_ROOT/<coin>/public`; private wallets/config/logs stay under private/.
  Each invocation needs a new root. No existing node is reset or reused.

P1 booking-service v2, signed-wire integration and issuer integration are still
in development. Current tests do not establish that complete workflow, wallet
custody, MWEB payment support, or behavior on actually pruned-away history.

Adapters can use the closed string `Coin` type with `CoinNMC`, `CoinBTC` and
`CoinLTC`; parse external input with `ParseCoin` rather than a bare cast.
`Coin.Profile()` resolves the closed profile. Run
`go test -race -count=1 -run '^(TestCoinBoundary|TestProfiles)$' .` for that boundary.

The booking and rental modules consume this package through ServiceV2 and
IssueGrantWithNodes. Provision distinct read-only payment-observer and
payment-issuer principals and secrets; NewRPC and NewIssuerRPC enforce those
closed principal names. Neither wrapper permits name or wallet operations.
Namecoin identity/seal/funding operations use a separate explicit route.

Pinned Litecoin 0.21.5.8 requires mempoolreplacement=1 for genuine BIP125 RBF.
Non-signalling full-RBF is unavailable on this pin; the accepted control instead
also mines a conflicting non-signalling transaction directly and verifies no
issuance for the original payment. See UNRESOLVED_QUESTIONS.md for source and
scope limits. BTC/NMC non-signalling full-RBF is tested separately.

Run the consumer integration suite from ../rental as documented there. Its
TestCorePaymentLifecycle uses real booking contracts and independently routed
issuer observations, with txindex=0 on all three payment nodes. Keep private
wallet/config/log subdirectories out of any public evidence packet.
