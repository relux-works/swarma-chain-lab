# Detached rental grants laboratory

This **regtest-only** implementation issues detached LIP-0003 certificates,
checks them against an agent name and revocation seal, and plans unsigned pool
transactions. `rental-issue` signs certificates with an explicitly supplied
private grant key. None of the three commands signs or broadcasts a chain
transaction. Only opt-in Core tests use throwaway wallet signing/broadcast.

The exact agent name value contains independent `nostr` and `grant` public
keys. A BIP-340 certificate binds its issuer/grantee, contract, scope, time
window, optional budget and one confirmed seal. It needs **no per-grant name
update or anchor**. Payment must already be actively confirmed. Expiry needs
no transaction; spending the seal ends a grant early. Scope and budget are
outputs for the separate executor, never authorization for an external effect.

See [the implemented profile](LIP-0003-PROFILE.md), [dependency pins](DEPENDENCIES.md)
and [integration limits](UNRESOLVED_QUESTIONS.md). The older [CIP-0003](CIP-0003-DRAFT.md)
and [CIP-0004](CIP-0004-DRAFT.md) drafts describe explicit legacy regression APIs.
They are not the default protocol and have not been republished as specifications.

## Tools and exact entry points

Go 1.26.8; macOS/Linux (flock and fsync). From this module:

```sh
go mod verify
go vet ./...
go test -race ./...
mkdir -p .temp/bin
go build -trimpath -o .temp/bin/rental-kernel ./cmd/rental-kernel
go build -trimpath -o .temp/bin/rental-plan ./cmd/rental-plan
go build -trimpath -o .temp/bin/rental-issue ./cmd/rental-issue
```

Ordinary tests skip genuine Core integration. `testdata/` contains official
BIP-340 vectors, independently generated M3 signed wire fixtures and detached
public fixtures. btcec v2.3.5 supports this 32-byte-message BIP-340 profile;
the later variable-length-message extension is outside this implementation.

```sh
.temp/bin/rental-kernel check --policy policy.json --route observer-route.json \
  --certificate certificate.json --agent id/agent-one --sender PUBLIC_HEX_KEY
.temp/bin/rental-kernel present --policy policy.json --route observer-route.json \
  --certificate certificate.json --id ENVELOPE_SHA256 \
  --agent id/agent-one --sender PUBLIC_HEX_KEY
.temp/bin/rental-issue --policy issuer-policy.json --route observer-route.json \
  --request issuance-request.json --package-event package-event.json \
  --seal seal-point.json --grant-key-file /absolute/private/grant-scalar
.temp/bin/rental-plan refill --policy issuer-policy.json --spec refill.json
.temp/bin/rental-plan revoke --policy issuer-policy.json --spec revoke.json
.temp/bin/rental-plan batch-anchor --policy issuer-policy.json --spec batch.json \
  --ids certificate-ids.json --enable-batch
```

All commands emit JSON to stdout; redirect public outputs into a task's `.temp/`
artifacts. Kernel exits 0/live, 2/pending, 1/refused. Issuer exits 0/issued,
1/refused. `--at UNIX_SECONDS` supplies a trusted regtest clock; default is the
current clock. `checked_at` is the caller's start time, not completion time.
Elapsed expiry is rechecked internally. Kernel `--operator-route` selects an
existing hash-pinned CLI observer. Routes and keys remain private local files.
No mainnet runtime mode exists. The authenticated sender must be the **inner
NIP-17 seal key**, not the outer gift-wrap key.

Policy pins `network`, `genesis`, `agent_name`, `seal_script` and an absolute,
canonical `state_dir`. Issuer policy wraps that policy plus `provider_pubkey`.
Old policy fields remain for package/legacy API compatibility. The M3 signed
`station_name` means the agent name at this boundary; its signed bytes are
never rewritten. `admit-issuance` is the existing read-only M3 admission CLI
with its legacy-shaped policy; detached issuance maps current agent keys into
that admission policy internally. Surplus payment is reported for refund
review; this package never transfers money.

`MakePlan` rejects `issue` with `LEGACY_ISSUANCE_DISABLED`. `CheckLegacy`,
`MakeLegacyPlan` and CLI `check-legacy` retain the old station-anchor profile
only for explicit regression callers. New `check` never falls back to it.
Refill/revoke and optional batch plans require independently checked prevouts,
reservation status and signing policy before any separate signer uses them.

## Genuine Core tests

Use hash-pinned Namecoin Core 28 binaries (pins checked by the harness). Each
test needs a **fresh, non-existing absolute root**, whose parent resolves
without symlinks. Tests create `private/` for wallets, routes and throwaway keys
and `public/` for sanitized receipts/plans and process evidence. Never export
`private/`. Run Core tests one at a time with distinct roots, for example:

```sh
M1_REGTEST=1 M1_RUN_ROOT=/absolute/fresh/test-root \
M1_CORE_CLI=/absolute/namecoin-cli M1_CORE_DAEMON=/absolute/namecoind \
go test -count=1 -run '^TestCoreDetachedMatrix$' -v .
```

`TestCoreDetachedCLI` additionally requires absolute `M1_KERNEL` and `M1_ISSUER`
binary paths; old `TestCoreCLI` requires `M1_KERNEL`. The harness records node
PIDs and stops only its own nodes. The detached matrix, lifecycle, rotation,
rollback, dropped-transaction, presentation, firstupdate, issuer, issuer-denial,
issuer-crash and batch suites exercise actual Core state. Malformed RPC reply
controls are explicitly transport mutations, not claimed consensus-valid
transactions. Guard-removal experiments belong in isolated task scratch copies.
