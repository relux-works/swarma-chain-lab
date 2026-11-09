# Landlord rental grants laboratory

This **regtest-only** implementation prepares landlord-signed v3 grants,
checks two Namecoin identities and a confirmed per-grant consent commitment,
and plans unsigned issuance/pool transactions. The agent name points to its
landlord; only the landlord name carries the grant key. No command signs or
broadcasts a chain transaction. Opt-in Core tests use isolated throwaway wallets.

The renter's unchanged M3 Nostr consent event and the landlord's contract
countersignature are embedded in each grant. A separate issuance locator lets
an independent verifier find the commitment on its own node without an issuer
journal. A pool seal is referenced, never consumed by issuance. Expiry needs no
transaction; spending the seal closes the grant. Scope and budget are outputs
for a separate executor, not authorization for an external effect.

New issuance uses the LIP-0005 v0.1.3 two-direct-push frame:
`6a03534c014201<commitment32>01<grant_id32>` (72 bytes). Checking accepts this
exact issuance/blob binding or the exact historical `6a20<commitment32>` form.
Completed journals replay either complete original plan byte-for-byte, including
its fee; fresh preparation uses only the frame. See the v3 profile below for
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

## Tools and exact entry points

Go 1.26.8; macOS/Linux (flock and fsync). From this module:

```sh
go mod verify
go vet ./...
go test -race ./...
go run .scripts/l5-guards.go -out .temp/l5-guards
mkdir -p .temp/bin
go build -trimpath -o .temp/bin/rental-kernel ./cmd/rental-kernel
go build -trimpath -o .temp/bin/rental-plan ./cmd/rental-plan
go build -trimpath -o .temp/bin/rental-issue ./cmd/rental-issue
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
All runtime policies reject mainnet. The authenticated sender is the **inner
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
