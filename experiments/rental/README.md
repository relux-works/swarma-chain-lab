# Landlord rental grants laboratory

## SW1 witness construction

V3 issuer, planner and checker policies now require explicit `construction_profile: "W"` from authenticated configuration. Funding/change must be native P2WPKH. The issuer authenticates T before grant signing; admission verifies T and A from raw transactions and actual prevouts. Only exact T:L may be unconfirmed.

See [the W boundary/reason inventory](../WITNESS-PROFILE.md). This first delivery is linkage-only: unconfirmed payment Q is deferred to SW1b with an authenticated GV4 proof contract. Existing signed v3 grant bytes are unchanged.

This implementation prepares landlord-signed v3 grants,
checks two Namecoin identities and a confirmed per-grant consent commitment,
and plans unsigned issuance/pool transactions. The agent name points to its
landlord; only the landlord name carries the grant key. Production ceremony
commands prepare offline artifacts. The explicitly rehearsal-only
`rt-grant-fixture` below signs and broadcasts only on loopback regtest. Opt-in
Core tests use isolated throwaway wallets.

The renter's unchanged M3 Nostr consent event and the landlord's contract
countersignature are embedded in each grant. A separate issuance locator lets
an independent verifier find the commitment on its own node without an issuer
journal. A pool seal is referenced, never consumed by issuance. Expiry needs no
transaction; spending the seal closes the grant. Scope and budget are outputs
for a separate executor, not authorization for an external effect.

New issuance uses the LIP-0005 v0.1.3 two-direct-push frame:
`6a03534c014201<commitment32>01<grant_id32>` (72 bytes). Checking accepts this
exact issuance/blob binding or the exact historical `6a20<commitment32>` form.
Completed regtest journals replay either complete original plan byte-for-byte,
including its fee; main journals require the frame, and fresh preparation uses
only the frame. See the v3 profile below for
strict rejection rules and the reusable `oplocator` package's location types.

V3 signatures use Grant.SigningHash() with the fixed swarma-grant-v3 prefix;
untagged development signatures refuse. Legacy v1/v2 scopes retain their original
five actions. Issuer and v3 pool-planner policies require funding_script distinct
from seal_script: all funding and change use that separate pin, including
refill; only explicit seal outputs/revocations use the grant key. Actual prevouts
are checked independently. Reservation and optional known-pool exclusions add
defence in depth. Old seal-funded plans cannot replay. See the profile for the
separate signer's final recheck requirements.

See [the v3 implementation profile](LIP-0004-PROFILE.md), [dependency pins](DEPENDENCIES.md)
and [integration limits](UNRESOLVED_QUESTIONS.md). [LIP-0003](LIP-0003-PROFILE.md)
records the explicit v2 regression profile. Earlier CIP drafts are historical;
these laboratory profiles do not publish or amend the public specifications.

Optional N1 social metadata and the separate local d/ discovery sync tool are
defined in [N1 name values](N1-VALUES.md), with exact publisher fixtures and the
required consumer-upgrade-before-name-update procedure.

## Rehearsal-only standing grant fixture

`cmd/rt-grant-fixture` provisions one G2 standing grant on an operator-owned,
fresh private Namecoin Core regtest node. It belongs in this module because
`rental.IssuePayGrantV2`, the name value encoders and all required crypto and
chain packages are already in this module graph. No dependency is added to
`deploy`. It is excluded from the signed release: Infra builds it separately
from the **same pinned source head** and records its binary SHA-256 alongside
the rehearsal evidence. See the
[installed rehearsal procedure](../agent-wallet/RECONCILE-RUNBOOK.md#regtest-standing-grant-provisioning).

From `experiments/rental` (the node and its existing disposable funding/name
wallet must already be running):

```sh
mkdir -p .temp/bin
go build -trimpath -o .temp/bin/rt-grant-fixture ./cmd/rt-grant-fixture
.temp/bin/rt-grant-fixture --rpc-host 127.0.0.1 --rpc-port "$RPC_PORT" \
  --rpc-cookie "$PRIVATE_DATADIR/regtest/.cookie" --wallet "$FIXTURE_WALLET" \
  --out-dir "$FIXTURE_OUT" --executor-key "$RECEIPT_PUBKEY" \
  --recipient "$RECIPIENT" --allowance-sat 20000 --fee-limit-sat 30000
```

Only numeric loopback IPs are accepted (including `::1`); DNS, proxies and
redirects cannot move an RPC elsewhere. Before any output creation or write
RPC, the tool requires `getblockchaininfo.chain == regtest` and
`getblockhash(0) == single-use.RegtestGenesis` (Core's blockchain-info response
has no genesis member). Main/test chains and a mismatched genesis refuse.
`--agent-name` and `--landlord-name` can only be `id/rt-agent` and
`id/rt-landlord`; both must be absent on this fresh node. An existing output
directory, file or symlink refuses without overwrite. The cookie must be a
private regular file. RPC bodies, credentials and filesystem paths are never
included in diagnostics.

The tool creates the output directory as `0700`, generates normalized
throwaway issuer/landlord and grantee keys as `issuer.key` and `grantee.key`
(`0600`), mines 101 blocks for mature native witness funding, reserves both
names with `name_new`, mines 12 blocks, calls `name_firstupdate` for both and
confirms them. Name values use `AgentBindingValue` and `LandlordValue`
([landlord_value.go:25](landlord_value.go#L25),
[landlord_value.go:75](landlord_value.go#L75)); the agent's `swarma.agent`
contains `nostr` (the throwaway grantee public key) and `landlord`, while the
landlord's `swarma.landlord.grant` contains the issuer public key. These are
the same encoders used by the tested fixture
([px1_fixture_test.go:459](../agent-wallet/px1_fixture_test.go#L459)).
The kernel resolves names with
[`currentName`, kernel.go:287](kernel.go#L287).

The seal is a confirmed 1,000,000-sat P2PKH output to the even-y issuer key,
locked with `lockunspent`. Seal and issuance transactions are funded only
from confirmed native P2WPKH inputs, with native witness change. Signatures
come from `IssuePayGrantV2`; the confirmed issuance uses the same
`IssuanceCommitment`/Core funding/signing/broadcast recipe as
[coreLab.issueProof, core_test.go:370](../agent-wallet/core_test.go#L370),
which the standing-grant fixtures use. This intentionally regtest-only
recipe uses the historical bare issuance commitment accepted on regtest.
It does not change production issuance or wallet behavior.

`--allowance-sat` is payment principal (minimum 20000), default 20000;
`--fee-limit-sat` defaults to 30000. All caps and the grant budget are
**fee-inclusive**, so their defaults are 50000 sat, not 20000. The fee cap is
30000 and day-count cap is 10. The one allow-listed P2PKH recipient and the
installed service's receipt **public** key are required flags: terms bind to
that exact executor. `--valid-for` defaults to 24h (1m..24h). Regtest names
expire after 30 blocks: finish before expiry; this tool does not renew names.

Exit 0 prints exactly `RT_GRANT_ID <64 lowercase hex>`. Exit 1 emits only a
fixed refusal code on stderr. `fixture.json` contains the grant/contract IDs,
public keys, seal, names, `seal_script`, W profile, parameters, canonical terms
and presentation. The two hash-addressed `.json` files are the exact canonical
objects for the installed wallet's object directory. **Never print or publish
the key files or node cookie.** Transfer the grantee key only through the
rehearsal's private provisioning process; the issuer key controls revocation.
Partial output is retained after failure: preserve it for diagnosis, stop and
discard that private rehearsal node through its owner, and use a fresh node
and output directory. Do not rerun against its names or erase keys to retry.
The command starts no node and stops no process.

Safety tests: `go test -race ./cmd/rt-grant-fixture`. The genuine built-command
integration test lives in the existing wallet Core harness:

```sh
cd ../agent-wallet
W1_REGTEST=1 W1_RUN_ROOT="$FRESH_ABSOLUTE_RUN_ROOT" \
  W1_CORE_DAEMON="$NAMECOIND" W1_CORE_CLI="$NMC" \
  go test -count=1 -v -run '^TestRTGrantFixtureCore$' .
```

That test checks KernelAuthority acceptance and spends through the installed
G2 service, with off-list and over-budget controls. It uses the existing
labelled root-ownership test seam, not native separate-UID qualification.
Hosted `px1-core-gate` runs it with verified Core 28 binaries and rejects
skipped/missing/failed tests through `.scripts/rt-grant-fixture-core-gate.json`.
Local logs/builds belong in `.temp/`; private Core roots and keys must be kept
outside source publication and removed after stopping the exact owned PID.

## Tools and exact entry points

Go 1.26.8; macOS/Linux (flock and fsync). From this module:

```sh
go mod verify
go vet ./...
go test -race ./...
go run .scripts/l5-guards.go -out .temp/l5-guards
go run .scripts/n1-guards.go -out .temp/n1-guards
go run .scripts/n1-dependencies.go -out .temp/n1-dependencies
mkdir -p .temp/bin
go build -trimpath -o .temp/bin/rental-kernel ./cmd/rental-kernel
go build -trimpath -o .temp/bin/rental-plan ./cmd/rental-plan
go build -trimpath -o .temp/bin/rental-issue ./cmd/rental-issue
go build -trimpath -o .temp/bin/name-discovery ./cmd/name-discovery
```

`testdata/` contains official BIP-340 vectors, independently generated M3 wire
fixtures and public v2/v3 fixtures. btcec v2.3.5 supplies this 32-byte-message
BIP-340 profile; variable-length signature messages are outside it.

```sh
.temp/bin/rental-issue --policy issuer-policy.json --route observer-route.json \
  --request issuance-request.json --package-event package-event.json \
  --seal seal-point.json --spec funding.json --grant-key-file /absolute/private/grant-scalar
.temp/bin/rental-plan grant-issue --policy issuer-policy.json \
  --spec funding.json --grant signed-grant.json
.temp/bin/rental-kernel check --policy policy.json --route observer-route.json \
  --grant presentation.json --agent id/agent-one --sender PUBLIC_HEX_KEY
.temp/bin/rental-kernel present --policy policy.json --route observer-route.json \
  --grant presentation.json --id SIGNED_GRANT_SHA256 \
  --agent id/agent-one --sender PUBLIC_HEX_KEY
.temp/bin/rental-plan refill --policy issuer-policy.json --spec refill.json
.temp/bin/rental-plan revoke --policy issuer-policy.json --spec revoke.json
.temp/bin/rental-plan batch-anchor --policy issuer-policy.json --spec batch.json \
  --ids grant-ids.json --enable-batch
```

All commands emit JSON to stdout; redirect public outputs into task `.temp/`
artifacts. Issuer exits 0/**prepared**, 1/refused: preparation is not live.
A separately authorized signer must validate and broadcast the unsigned plan.
`PresentIssuedGrant(signedBytes, txid)` attaches that transaction's public locator.
Kernel exits 0/live, 2/pending, 1/refused. No unconfirmed issuance is live.
`--at UNIX_SECONDS` supplies a trusted regtest clock; `checked_at` records its
start, while elapsed expiry is rechecked. Kernel `--operator-route` selects an
existing hash-pinned CLI observer. Routes and keys stay in private local files.
V3 grant policies admit explicitly pinned NMC main and regtest; main funding
planners require an explicit fee rate. Legacy v1/v2 policies remain regtest-only. The authenticated sender is the **inner
NIP-17 seal key**, not an outer gift-wrap key.

Policy pins `network`, `genesis`, `agent_name`, `landlord_name`, `seal_script`
and an absolute canonical `state_dir`. Issuer policy wraps it plus
`provider_pubkey`. Existing M3 `station_name` means the agent name; its signed
bytes are never rewritten. The issuer maps the current agent Nostr key and
landlord grant key into the unchanged admission API. Payment must be confirmed
and at least the price; surplus is reported for refund review, never transferred.
The standalone `admit-issuance` command still takes its legacy-shaped policy.

The default APIs are `Check`, `Present`, `CachedGrant`, `IssueGrant` and
`MakeGrantIssuancePlan`. Explicit `CheckV2`, `PresentV2`, `CachedCertificateV2`,
`IssueDetached`, CLI `check-v2`/`present-v2` and `--v2-regression` retain v2.
`CheckLegacy`, `MakeLegacyPlan` and `check-legacy` retain v1. Default checking
never falls back. Existing `MakePlan` rejects old `issue`; refill/revoke and
optional batch planning remain available. Batch anchoring is off by default
and never replaces the mandatory v3 per-grant issuance commitment.

`ResolveLandlordGrantKey(ctx,node,policy,landlordName) (string, Anchor, error)`
exports the shared strict read-only landlord lookup for separate authority
families. It requires only chain/name pins, not an agent or live rental seal.
It does not own a closure journal; see the v3 profile for caller obligations.

## Genuine Core tests

Use hash-pinned Namecoin Core 28 binaries (pins are checked by the harness).
Each test needs a **fresh, non-existing absolute root** with a canonical parent.
The harness creates `private/` for wallets, routes and throwaway keys, and
`public/` for sanitized receipts/plans and process evidence. Never export
`private/`. Run each suite with its own root, for example:

```sh
M1_REGTEST=1 M1_RUN_ROOT=/absolute/fresh/test-root \
M1_CORE_CLI=/absolute/namecoin-cli M1_CORE_DAEMON=/absolute/namecoind \
go test -count=1 -run '^TestCoreGrantMatrix$' -v .
```

V3 suites are `GrantMatrix`, `GrantLifecycle`, `GrantLandlordRotation`,
`GrantPointerRotation`, `GrantNameRecovery`, `GrantState`, `GrantPresentation`,
`GrantIssuanceSealInput`, `GrantIssuer`, `GrantIssuerDenials`, `GrantIssuerCrash`
and `GrantCLI` (each prefixed `TestCore`). The CLI suite also needs absolute
`M1_KERNEL`, `M1_ISSUER`, `M1_PLANNER` paths. Old v2/v1 suites remain regression
checks; `TestCoreDetachedCLI` needs the first two binary paths, `TestCoreCLI`
needs the kernel. Nodes are recorded and stopped by their own PIDs.
`TestCoreLandlordResolver` exercises the separate read-only lookup.

The 31-row matrix binds real Core identities/seals/issuance and labels pre-node
wire checks and transport mutations separately. Tests explicitly permit a
one-satoshi regtest burn only for the forbidden nonzero-commitment fixture.
Pending/drop/reorg, name expiry, crash recovery and valid neighboring cases
are exercised on actual Core. Guard-removal experiments belong in isolated
scratch copies with their exact source hashes, patches and intended failures.

The historical replay control `TestCoreGrantLegacyReplay` additionally requires
`M1_OLD_ISSUER` pointing to the hash-pinned pre-domain c8d7 development issuer
(Darwin arm64). It creates a genuine old completed record with throwaway Core
funds, then checks refusal by the revised issuer without broadcasting the old
plan or altering the record. Its private inputs/journal remain under the test
run root; only the refusal summary and process metadata are public evidence.

`TestCoreGrantLocator` exercises actual framed issuance, historical bare
verification and mined malformed transactions beside live neighbors.
`TestCoreGrantLocatorReplay` requires `L5_OLD_ISSUER`, the pinned Darwin arm64
issuer built from base `bbcf014478ea60a4a78f9614cea287c5ba911523` with Go 1.26.8
and `go build -buildvcs=false -trimpath ./cmd/rental-issue` (binary SHA-256
`ec0ea6d732aaba05069ee35dc3ff70ff5c9f4a84e6980ef51bf92ba7f950f664`).
Build only from a clean checkout of that exact base. VCS stamping is disabled
for this historical test binary so an enclosing worktree cannot change its pin;
the source revision is verified separately before building.
It creates a real completed bare record at the former minimum funding boundary,
checks byte-identical replay and corrupt-record refusal, then checks the new
pre-sign fee gate beside a funded framed preparation. This differs from the
pre-domain historical rejection control above.

To run the L5 guard-removal controls including genuine Core, use:

```sh
M1_CORE_CLI=/absolute/namecoin-cli M1_CORE_DAEMON=/absolute/namecoind \
L5_OLD_ISSUER=/absolute/pinned-base-issuer \
go run .scripts/l5-guards.go -core -out .temp/l5-guards
```

The runner first requires passing baselines, mutates only an isolated copy,
and requires each intended test assertion to fail. Build failures, panics and
skips do not count. Its fresh `run-*` directory contains logs and `results.json`
with source hashes and exact replacements. Core roots include private wallets;
export only logs/results and each root's `public/` evidence, never `private/`.

## Payment contract v2 development

`VerifyIssuancePackageV2` independently authenticates the version2 payment wire;
`AdmitIssuanceV2` selects a trusted per-coin observer and checks current payment
bytes/block membership. Both are read-only gates. `IssueGrantWithNodes` connects v2
payments to the shared durable grant issuer, keeping Namecoin identity/seal/
funding on its explicit node and fee admission on the trusted per-coin map.
Use separate `payment-observer` and `payment-issuer` RPC principals/secrets.
`payment_admission` carries the fee coin and atom-denominated observation;
`budget_sat` remains NMC execution authority. Main issuance requires the V2
payment route `IssueGrantWithNodes`; the legacy payment API `IssueGrant` remains
regtest-only (`ISSUER_POLICY` at package admission on main). Completed bare-plan
replay remains available only on regtest. Shared preflight checks funding facts;
fresh issuance then checks the framed fee before any burn or signature. See
[the v2 wire contract](../rental-booking/PAYMENT-V2.md). Run
`GOWORK=off go test -race -count=1 ./...` for independent consumer and legacy
regression tests. Frozen public input vectors are in `testdata/payment-v2/`.


`TestCorePaymentLifecycle` exercises actual ServiceV2 bookings and independent
issuer admission on pinned BTC/LTC/NMC regtest payment nodes (txindex=0,
prune=550), plus a distinct Namecoin identity/funding node. Enable P1_REGTEST=1
and M1_REGTEST=1; supply fresh absolute P1_RUN_ROOT and M1_RUN_ROOT, explicit
P1_{BTC,LTC,NMC}_{DAEMON,CLI} and M1_CORE_{DAEMON,CLI} binary paths. Run
`GOWORK=off go test -race -count=1 -run '^TestCorePaymentLifecycle$' -v .`.
Each run preserves private credentials/wallets/logs separately from public
control/result/process metadata under its configured roots. Never publish the
private subdirectories. Routine CI skips this opt-in genuine-node lane.

The [MA1-03 route audit](MAIN-ISSUANCE-AUDIT.md) distinguishes main-admitted
routes from frozen regtest adapters. `TestMainPublicGrantFundingAdmission` is
an offline public-entry regression. `TestCoreMainPublicGrantV2` additionally
prepares a signed main-labelled V2 grant and checks exact replay, using isolated
regtest nodes with explicit chain/genesis reply projections and re-signed public
terms. It does not contact mainnet or broadcast the resulting plan.
`TestCoreMainLegacyPaymentRefusal` pairs the V1 main refusal with regtest success.
Run each test in a separate invocation with a new absolute `M1_RUN_ROOT`:

```sh
# Set M1_REGTEST=1, M1_CORE_DAEMON and M1_CORE_CLI as for the other Core tests.
# For V2 also set P1_REGTEST=1, a fresh P1_RUN_ROOT, P1_NMC_DAEMON/P1_NMC_CLI.
go test -race -count=1 -run '^TestCoreMainPublicGrantV2$' -v -timeout 5m .
# Use another fresh M1_RUN_ROOT for this separate legacy boundary control.
go test -race -count=1 -run '^TestCoreMainLegacyPaymentRefusal$' -v -timeout 5m .
```

Public results go under each configured root's `public/`; private fixture
wallets and journals must not be exported. L5 controls include a mutation that
restores unconditional bare preflight; the public-entry regression must detect
it. The historical binary replay control separately preserves old regtest bytes.

## Signed model limits

The independent ContractV2 decoder also authenticates and validates optional `model_caps`; non-model vectors remain byte-identical. See [signed model limits](../rental-booking/MODEL-CAPS.md). The extension does not change MA1-03 funding or main-network admission.

## Installed static inputs (DK5)

Installed daemon configs/secrets now require root:exclusive-service-group0640,
root:same-group0750 parents and the signed manifest/root anchor in
[the install contract](../../deploy/INSTALL-CONFIG.md). Legacy owner0600/0400
examples below or in historical smoke fixtures are not installed-service inputs.
Mutable state, standalone tool/client keys and dynamic payload bootstrap retain
their separate contracts. No production mode fallback exists. Full signed
admission tests live in `single-use/configguard`; local ownership seams are
synthetic and do not qualify Linux deployment. See the deploy runbook for
same-binary preflight and the separate DK5b payload launch gate.
