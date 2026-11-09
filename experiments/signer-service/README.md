# Swarma signer service (SG1)

Regtest landlord custody service with exactly three transaction templates:
`grant-issue`, `revoke`, and `refill`. It runs under its own OS user/state root,
uses its own Namecoin node and independently rechecks payment through trusted
P1 issuer routes. There is no arbitrary signing, executor, execproxy, sweep,
station update, renewal, end-session or destroy endpoint. Mainnet always refuses.

The service calls the existing K1/P1 issuer and L5 planners; it does not copy
an issuer or kernel implementation. The real V2 binding is `issuer_v2.go`:
`VerifyIssuancePackageV2`, `AdmitIssuanceV2`, `IssueGrantWithNodes`. The explicit
`v1-nmc` profile remains available for the original NMC signed wire.

## Custody and configuration

Build `cmd/swarma-signer` and supply `-config /absolute/private/config.json`.
The configuration is the `FileConfig` JSON type in `config_file.go`; its nested
`config` is the `Config` type in `types.go`. Required inputs are explicit:

- `config.profile`: `v2` or `v1-nmc`; network and genesis are pinned to NMC regtest.
- `config.policy`: existing rental `IssuerPolicy`, with separate issuer state,
  landlord/agent names, provider key, grant key and seal/funding scripts.
- `config.payment_policies`: V2 per-coin confirmation/rate-age/observation limits.
- `config.state_dir`: service ledger root, distinct from K1's `policy.state_dir`.
- `config.presentation_dir`: optional canonical absolute public output directory,
  existing mode0755 and owned by the signer uid; included in the ledger binding.
  Omit it to preserve the original custody-only behavior. Do not change the
  binding of an existing ledger to enable it; provision a fresh configured root.
- `config.grant_key_path` and `config.funding_key_path`: exactly 32 binary scalar
  bytes, regular single-link files, current uid, mode0600, no symlink components.
  Both P2PKH scripts use even-y compressed public points. The transaction signer
  normalizes the secret; the same grant file remains directly compatible with K1.
- `config.historical_seal_scripts`: explicitly pinned former grant-key scripts;
  none may be the funding script. Current/configured known seals are also excluded.
- `read_route_file`: private `singleuse.Route`, username `w3-observer`.
- `broadcast_route_file`: private route, username `sg1-broadcaster`, same literal
  loopback host/port as the read route. Core must whitelist only
  `sendrawtransaction` for this principal; it never receives a wallet signing key.
- `payment_route_files`: V2 coin-to-private-route-file map. Each uses P1's
  `payment-issuer` principal, independently from the booking watcher's credentials.
- `booking_outbox` and optional `operator_outbox`: separate trusted private roots.
- `store_url`, `store_landlord_reader`, `store_agent_reader`: pinned S1 endpoint
  and reader keys. This unit allows literal-loopback HTTP only; no redirects,
  proxies or URLs from outbox data. S1 auth uses the service grant key.
- `interval_seconds`: 1..3600; `inventory`: explicit initial confirmed points
  (`singleuse.PlanInput` with role `seal` or `funding`). No balance discovery.

Create state/outbox roots as canonical absolute, owner-only mode0700 paths.
Config, routes, index and item files must be owner-only regular single-link
mode0600 files. Never pass credentials or scalars as CLI arguments. Changing
bound custody configuration refuses the existing ledger; it does not reset it.
A confirmed observed grant-key rotation freezes custody durably. A pending
rotation refuses while pending. Reconfiguration/migration is outside this unit.

`RegtestCaps()` supplies placeholders: fee/tx100000sat, issuance count4/hour and
16/day, authority budget100000000sat/hour and400000000sat/day, refill4 seals of
200000sat, refill value800000sat, low-water2. Counts and budgets use UTC windows.
Budget means sum of grant `budget_sat` authority, separate from fee/funding debit.
Zero budget (K1's unbounded authority) is refused. Pending/uncertain reservations
remain charged across window rollover; retries of the same operation do not
charge twice. Mainnet refuses even when every cap has a non-default value.

## Pull outbox contract

`FileSource` reads an append-only `index.json` array of lowercase SHA256 hashes.
Each hash names an immutable `<hash>.json` containing an `Item`. A producer must
write/fsync the immutable item before atomically publishing the appended index.
There are at most4096 index entries; the index is at most1MiB, each item64KiB.

`Item.id` is a stable lowercase SHA256 identifier. `kind` is `grant-issue` or
`revoke`; external refill/arbitrary templates refuse. `request` and `publication`
are **JSON strings containing the exact original JSON bytes**, not nested JSON
objects. Create them with `string(originalRequest)` and
`string(originalPackageEvent)` and marshal the outer Item. This preserves the
original provider-signed kind8182 event byte-for-byte without rebuilding or
re-signing it. P1's exported PackageV2 object is not that signed event: the trusted
producer must supply the original `BookingV2.PackageEvent` companion from Get.

A revoke item has only `revoke`, using the P1 V2 revoke fields. Booking input
accepts exactly reason `payment_reorged`, bound to the issued booking, contract
and full payment tuple. A private operator source instead requires reason
`operator` plus booking/contract binding. Source class is local configuration,
never a received authority flag. A revoke arriving first suppresses the booking;
it does not guess/spend a seal. Post-issue revokes spend its permanently bound
seal. Repeating the revoke returns the same txid. Payment restoration does not
clear a sticky revoke.

The opaque cursor commits the source root and consumed index prefix. A changed,
truncated, foreign or malformed prefix/cursor refuses. Intake blobs and their
references are durable before the cursor advances. IDs cannot change bytes or
source class. Each step processes revokes first, then issuance, then internal
low-water refill. Transient refusals retain input for retry.

## Recovery and limits

The service atomically reserves operation, booking/seal/funding and cap charge
before calling K1. K1 owns its separate pre-sign burns and exact completed replay.
Service phases are reserved, prepared, signing_uncertain, signed, broadcast and
stored. The marker `signing_uncertain` is fsynced before any chain signature;
missing signed bytes after a crash permanently refuse another signature. Exact
signed bytes, txid and presentation are durable before broadcast. Recovery
rechecks the whole allowed plan and every ECDSA signature; a self-consistent txid
alone is insufficient. Lost ACKs retry only those bytes. Already observed exact
transactions recover without another send. Fresh payment/time checks also follow
key reads and the uncertainty-marker fsync, so latency cannot reuse an expired
admission. Chain observations cannot be atomic with the subsequent signature.

S1 uploads only the original signed grant; its exact hash/receipt and external
issuance presentation are retained separately. Upload/broadcast receipt is not a
live verdict. The existing kernel must independently confirm the commitment,
identities, time window and seal. Newly generated inventory waits for own-node
confirmation before use. Refills consume funding only; outputs intentionally
include seal scripts. Expiry does not create a transaction.

This bounded unit retains at most64 operations,64 inventory entries (including
spent/reserved points),64 intake items and64 suppressions, with a64KiB ledger.
It refuses capacity exhaustion before a new reservation. Content-addressed old
snapshots/orphan intake blobs are retained; no automatic GC or journal reset.
Operator archival/migration needs a separately reviewed contract. Never delete a
ledger to make room: that would erase custody history. Uncertain reservations
are not automatically released. No production remote pull, mTLS, VM deployment
or real wallet operations are included.

## Tools and verification

Use Go1.26.8, `GOWORK=off`; sibling modules are in-tree local replacements.

```sh
go mod download
go mod verify
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off go vet ./...
GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off go test -race -count=1 ./...
go build -trimpath -o .temp/swarma-signer ./cmd/swarma-signer
.temp/swarma-signer -config /absolute/private/config.json -once
```

Without `-once`, the command runs until SIGINT/SIGTERM. Diagnostics contain only
closed reasons and public operation/grant/transaction IDs. State/evidence lives
in explicitly configured roots, never an ambient user wallet.

Genuine Core tests require `SG1_REGTEST=1`, a fresh absolute `SG1_RUN_ROOT`,
`SG1_CORE_DAEMON`/`SG1_CORE_CLI` for identity NMC, and for `TestCoreV2Payments`
`SG1_BTC_DAEMON`/`SG1_BTC_CLI`, corresponding LTC and NMC variables. Binaries are
pinned in the fixtures: Namecoin28, Bitcoin32.1, Litecoin0.21.5.8. Each suite
needs a separate nonexistent run root. The nodes are isolated, networkactive0;
all owned PIDs are stopped. Only `public/` metadata is suitable for export;
`private/` contains fixture wallets/config and must remain local.

```sh
go test -race -count=1 -run '^TestCoreService$' -v .
go test -race -count=1 -run '^TestCoreCrashRecovery$' -v .
go test -race -count=1 -run '^TestCoreAdmissionBoundaries$' -v .
go test -race -count=1 -run '^TestCoreV2Payments$' -v .
go run .scripts/sg1-guards.go -out .temp/sg1-guards -core
```

The guard driver mutates only isolated copies, provisions every local replacement
sibling, records source/mutant hashes, requires passing baseline neighbors and
specific assertion failures, and rejects skips, crashes or compile failures as
control evidence. Its non-Core mode runs the12 unit plants; `-core` adds three
actual subprocess/payment/durable-record guard-removal controls. Tests describe their specific
claims and limits beside the exercised paths.

### Booking V2 producer composition

Set `booking_outbox` to the private ServiceV2 state root. Its exporter now writes
this service's existing index/hashed Item format, with original request and
PackageEvent JSON strings and complete sticky revoke tuples. It never converts
v1 booking state: a legacy root without an index returns `PRIVATE_FILE` on pull.
The explicit SG1 v1 input contract remains available for other provisioned sources.
`TestCoreV2Payments` exercises actual exporter → FileSource → Engine.Pull → P1
issuance for BTC/LTC/NMC, plus malformed/partial/duplicate file refusals and
repeat intake. `TestLegacyBookingRootRefused` checks the closed no-index boundary.

### Confirmed presentation publication

With `config.presentation_dir` configured, a stored grant retries publication on
subsequent service steps. `stored` still means an S1 receipt, not confirmation.
Until its exact durable transaction has at least one confirmation on the own
Namecoin active chain, publication returns `PRESENTATION_UNCONFIRMED` (or the
closed node-observation refusal) and creates no file. The observation binds raw
transaction bytes/txid, active block and transaction membership, and an unchanged
tip. The durable record already binds that transaction to the exact signed plan
and grant commitment. Publication does not wait for the rental start time.

A successful observation writes canonical GrantPresentation bytes to
`<booking_id>.json`, mode0644, with file fsync, an atomic no-replace rename and
directory fsync. Existing identical bytes are idempotent; conflicting/partial or
unsafe existing files refuse and remain untouched. Symlink and hardlink outputs
are forbidden. Temporary files do not match booking IDs and are ignored by the
gateway. Restart rechecks confirmation and reconciles the same output; it never
re-signs to recover publication. A failed final fsync may leave the exact file
visible; retry verifies it and fsyncs again. Linux uses renameat2(RENAME_NOREPLACE),
Darwin renameatx_np(RENAME_EXCL); unsupported filesystem semantics fail closed.

The actual gateway command and these integration tests share
`rental-gateway/presentationdir.Open`. No file copy or handwritten presentation
bridges the producer/consumer test. A published proof is immutable issuance
history: later reorg, expiry or revocation does not delete it. Every action still
requires the gateway kernel's current chain/time/seal checks. This output is
public metadata, not a secret; cross-host distribution remains an external
adapter and is not enabled here.

```sh
# Build the actual booking process from this source tree.
(cd ../rental-booking && go build -trimpath -o ../signer-service/.temp/booking-cli ./cmd/rental-booking)
# Use fresh absolute roots and the pinned SG1_* Core binaries documented above.
SG1_REGTEST=1 BG1_BOOKING_CLI="$PWD/.temp/booking-cli" \
  SG1_RUN_ROOT="$PWD/.temp/composition-core" \
  go test -race -count=1 -run '^TestCoreBookingComposition$' -v .
go test -race -count=1 -run '^TestPresentation' .
go run .scripts/sg1-guards.go -out .temp/publication-guards
# The same binary env is required by these genuine-Core guard controls:
go run .scripts/sg1-guards.go -core -only presentation_confirmation -out .temp/confirmation-guard
go run .scripts/sg1-guards.go -core -only presentation_stability -out .temp/stability-guard
```

The full process fixture uses BTC payment and separate Namecoin identity/issuance
nodes. It covers HTTP booking/consent, actual watcher/export, CLI restart,
unconfirmed and orphan absence, active-membership/stable-tip refusals, confirmed
publication read by the gateway and signer restart. TestCoreV2Payments separately
covers the exporter/issuer seam for BTC, LTC and NMC. Fixture wallets are disposable
regtest-only; runtime credentials stay in private evidence directories.
