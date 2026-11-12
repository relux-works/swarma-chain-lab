# Rental executor laboratory (M4a)

Regtest only. This deterministic service verifies kind-8183 renter requests,
rechecks M1 on its own node, reserves nonce/budget/inputs durably, then performs
one bounded effect. It also exposes the intentionally unguarded Track B claim
endpoint. No production wallet, public deployment or live spending is admitted.

> **Superseded for G2 payments (PX1, Q10).** The `pay` action of this
> laboratory is retired for the G2 demo: it is not the G2 payment executor
> and nothing in G2 builds on it. G2 payments go through `agent-walletd`
> (`experiments/agent-wallet`, the terms-v2 pay-limits profile) with a pay
> grant issued by the terms-v2 helper (`experiments/rental/PAYGRANT-V2.md`).
> This note changes no code; the M4a `pay` path keeps its regtest evidence.
> The Prize-A canary and Track B ideas remain inputs to the G2 bounty canary.

## Authority and effects

The incoming body supplies only a signed Nostr event and optional file bytes.
It cannot select a certificate, node route, policy, clock, wallet or signer.
Trusted configuration binds a 64-hex booking ID to an issuer-signed M1 envelope
and policy. M1 certificates do not contain a booking ID; this local mapping and
matching signed contract hash provide that binding. Every new effect gets two
fresh `rental.Check` calls (before planning and immediately before reservation);
only `live` passes. Chain state can still change after the final read: neither
fsync nor broadcast is atomic with consensus.

[FORMAT-PROPOSAL.md](FORMAT-PROPOSAL.md) defines the accepted request shape:
kind **8183**, empty content, exactly action/target/slot/nonce/contract tags,
and amount only for pay. Tag order is signed but semantically immaterial.
Amounts are canonical positive decimal Namecoin atoms. Event id and BIP-340
signature are independently checked. Missing/duplicate/extra/null/aliased
fields and tags refuse. Scope is a closed list, never inferred from prose.
Request created_at must be inside the signed interval and not in the future.

- **pay:** ordinary legacy regtest P2PKH only. Build/sign locally using only
  the configured slot input set, verified through gettxout. Reserve amount plus
  the explicit fixed fee against the certificate's cumulative budget. The fee
  is 1,000..100,000 atoms per transaction and must satisfy the node's relay
  policy for the selected input count. The genuine Core fixture uses 30,000
  atoms for one input; 2,000 failed its minimum relay fee. There is no wallet
  coin selection or fee top-up. At most 16 inputs are selected; inputs must be
  confirmed and non-coinbase or mature. Dust change refuses. Change goes to the
  slot key, but is **not** automatically enrolled as a new budget input. The
  original finite input set can therefore exhaust before the nominal budget.
- **deliver:** bytes (maximum 1 MiB) must match the renter-signed sha256 target.
  Store under a private per-request filename and return hash, file:// local
  link and seven-day retention deadline. Metadata is supplied; a retention
  worker and cross-host download proxy are outside this module.
- **publish/repository.push:** only harmless private local records containing
  field hashes. No external publishing or Git network operation exists.
- **secret.release:** always refused, including when present in scope.

Prize A has its own configured key/address and one exact outpoint. It is
excluded at configuration validation and payment input selection/signing;
exhaustion never falls back to it. `--prize-check` reports a proven spend txid
from the active chain or stable mempool, or unspent. It scans at most 256 blocks
including the funding block and at most 512 mempool transactions, subject to
M1/W3 call/byte bounds. Failure/bounds are unknown, never proof of theft. A test
spends a disposable prize deliberately and verifies detection; the watcher
does not prevent an out-of-band spend by someone who already holds its key.

## Durable state and recovery

Use existing canonical absolute 0700 directories owned by the service UID;
state files are 0600, regular, one hardlink, no symlink following. The store
holds a lifetime exclusive flock. Exclusive lock-file creation followed by
reopen handles concurrent first creation. Files commit with temporary-file
fsync, rename and directory fsync. An uncertain write poisons the handle.

A reservation burns slot+nonce, selected inputs and amount+fee before any
broadcast/file/record. It survives crash and never retries, even if the outcome
is unknown. Duplicates return `already-executed` with `reserved` or `complete`,
after request authentication and a fresh kernel observation. A closed or
unavailable kernel does not erase that durable receipt: `authority_reason`
reports the current kernel refusal while `event_id`, phase and artifact fields
refer to the original reservation. New nonces still require live authority.
This status is a no-retry statement, not evidence that an uncertain effect
happened. Reusing a nonce with another event never creates a second effect. Journal capacity is 10,000 reservations; exhaustion fails closed.
Restart checks configuration commitment and journal invariants. Do not delete,
copy, rewind or restore stale state to retry: operator reconciliation is
required. Same-UID hostile processes and restoration of old backups are outside
the permission boundary. Kernel policy state is shared per policy across calls
and restarts and stays away from rented station access.

## Track B interface for M2

Separate Unix sockets in a private 0700 service directory, socket mode 0600:
admin belongs to the trusted station driver; claim may be exposed to the rented
station by the future proxy. The proxy/OS identity boundary is deployment work.
All requests use `Content-Type: application/json`. Responses set `no-store`.

| Socket | POST path | Request | Success |
| --- | --- | --- | --- |
| admin | /mint | `{"slot":"<64 lower hex>"}` | `{"status":"ok","token":"<64 lower hex>"}` |
| admin | /revoke | same slot object | `{"status":"ok"}` |
| admin | /list | `{}` | status plus `tokens` array: slot, token_sha256, revoked |
| claim | /claim | `{"slot":"<64 lower hex>","token":"<64 lower hex>"}` | `{"status":"ok","private_key":"<regtest scalar>"}` |

M2 mints at slot start, stores the returned token privately, and revokes at
close. One mint per preconfigured slot; repeat mint refuses, revoked slots never
resurrect, revoke is idempotent for an existing slot. Raw tokens are returned
once and never persisted by the endpoint. If the mint reply is lost, do not
remint: close/reconcile the slot. Unknown/revoked/cross-slot tokens refuse.
The claim endpoint deliberately does **not** call the kernel: a valid token
returns the configured per-slot throwaway prize B private scalar. Repeated valid
claims return the same key; the sweep is outside this service.

Successful claims and ordinary admin/claim attempts commit time, operation,
slot, token hash and outcome with token state before response/key release.
Each configured slot has a durable 60-second window: up to 32 valid-token claims
and 8 invalid-token attempts. These allowances are separate; guessed tokens
cannot consume the valid-token allowance. Unknown slots and malformed calls
share one bounded invalid bucket. The first over-limit attempt is logged as
RATE_LIMITED; subsequent attempts in that window are coalesced and return 429
without further disk writes. Restart or backward clock movement cannot reset a
window. Admin mint/revoke/list bypass claim throttling.

The audit rolls independently: last 32 claim records per configured slot,
last 32 malformed/unknown records, and last 128 admin records. `audit_dropped`
counts evicted records (saturating); token/revocation state is never evicted.
Existing full historical audits are compacted on open. No global count freezes
claims. This bounded local tail is not a complete forensic archive; deployment
can collect it separately if needed. Unwritable/uncertain state still fails closed
before releasing a key. No raw token, key, message or file content enters audit.

Executor socket: `POST /execute` with
`{"event":<kind8183 event>,"file_base64":""}` (canonical base64 for deliver).
Response is a receipt with status/reason, slot/event ID, phase, txid or file
hash/local link/retention deadline and action. HTTP 200 is reserved for executed
or already-executed receipts. Refusals use 400 for shape/input errors, 403 for
authority/scope denial, 404 for unknown slot, 409 for budget/limit conflicts and
503 for unavailable state/node or uncertain effects. Track B uses 400 for schema,
403 for token refusal, 429 for claim throttling and 503 for unavailable audit.
Always read the status/reason/phase too; a reserved phase never proves execution.
All errors are bounded codes without secret values.

Read-only closer export: `GET /slots/<64-lower-hex-slot>` on the executor socket,
with no query or body. Response is `{slot,effects:[receipts],deliverables:[receipts]}`.
`effects` includes every recorded action for only that slot, with original event
ID, phase, txid or file metadata. `deliverables` includes only complete deliveries
with sha256, local_link and retain_until. Reserved entries have no delivery link.
The receipt status `recorded` describes journal evidence, not a fresh grant check.
The Go method is `ListSlot(slot) (SlotExport, error)`. Both paths only project the
journal: no node call, state write, effect, key release or file-body read. They
work after closure/expiry and node outage and preserve evidence across restart.
Links are local metadata, not a promise that retention/deployment still keeps
the file. Socket ownership limits access; a cross-host proxy is still external.

## Configuration and CLI

`rental-executor --config /absolute/private/config.json` serves all three
sockets. SIGINT/SIGTERM stops listeners and closes state. Existing sockets are
never deleted/replaced. `--prize-check` reads the configured prize and exits with
a public observation, or a nonzero refusal. No test clock flag exists.

Config is an owner-UID 0600 regular single-link file. Exact top-level keys:
`executor,state_dir,socket,observer,broadcast,trackb_state,trackb_admin_socket,
trackb_claim_socket,prize_b_keys`. Nested executor contains `network` (regtest),
`slots`, `prize_a`. Each slot contains `slot,envelope,policy,wallet`. Envelope
and policy use the M1 interface. Grant-v3 policy requires
`construction_profile: "W"` (see compatibility limits below). Wallet contains `private_key` (64-hex scalar),
`inputs` (txid/vout objects), `fee_sat`. Prize A contains `outpoint,address,
private_key`. `prize_b_keys` maps slot IDs to throwaway scalars.

Observer and broadcast routes contain host/port/username/password and must
address the same numeric loopback node. Observer uses `w3-observer` and the
W3 read whitelist. Broadcast uses separate `m4a-broadcast`, whitelisted in Core
for **sendrawtransaction only**. Neither can use wallet RPC. Do not pass keys,
passwords or tokens in argv, logs, task messages or the public evidence packet.

## Dependencies, tools and reproduction

Integrated M1 baseline: **c94b116d2ddda3aebf634fbec8059b721197e0a5** (signed).
M4a-02 is rebased onto this landed main. The `rental`, `single-use` and
`sealwatch` sibling modules are present and build directly with `GOWORK=off`.
No workspace override or external dependency checkout is required. The original
M4a-01 evidence used 63087f31; the new delivery reruns integration against the
landed baseline. No source changes are made in those dependency modules.

Go 1.26.8, btcec/v2 2.3.5, decred secp256k1/v4 4.4.0, btcd 0.24.2,
btcutil 1.1.5; full graph/checksums in go.mod/go.sum and delivery dependencies.
No go-nostr. W3 journal pattern is attributed in store.go; isolated Core helper
adaptations name their M1 source head. Protocol references are in SURVEY.md.

From this module, with the pinned sibling layout (or GOWORK override):

```
GOTOOLCHAIN=go1.26.8 go test -race -count=1 ./...
GOTOOLCHAIN=go1.26.8 go vet ./...
GOTOOLCHAIN=go1.26.8 go mod verify
GOTOOLCHAIN=go1.26.8 go build -trimpath -o ../../.temp/rental-executor ./cmd/rental-executor
```

Core suites require `M4A_REGTEST=1`, a fresh absolute `M4A_RUN_ROOT`, and
`M4A_CORE_CLI`/`M4A_CORE_DAEMON` pointing to the hash-pinned Core 28 binaries
in SURVEY.md. Select one suite per fresh root: `TestCoreExecutor`,
`TestCoreScopeAndPrize`, `TestCoreClosureReceiptsAndExport`, and
`TestCoreServiceProcess` (also set `M4A_BIN` to the
trimpath binary). They use own datadirs, `listen=0`, no peers and PID cleanup.
Only each run's `public/` is exportable; `private/` holds disposable credentials
and wallets. Unit tests never require Core; skipped suites are not passes.

Guard controls: set `M4A_MUTATIONS=1`, fresh `M4A_MUTATION_ROOT`,
`M4A_DEP_ROOT` to the pinned dependency checkout's experiments directory, plus
the Core binary variables; run `go test -count=1 -run '^TestGuardPlants$' -v`.
38 isolated plants must fail named assertions, not setup/build/panic/timeouts.
The manifest is `testdata/mutations.json`; results/logs remain in that scratch
root. Repeat `TestConcurrentStoreCreation` with `-race -count=200` on macOS
for the first-create concurrency regression. Build/log scratch belongs in
`.temp/`; external binaries, nodes and secrets never enter the repository.

## SW1 grant-v3 compatibility

This module consumes `rental.Check`. Its trusted rental policy must explicitly
set `"construction_profile": "W"`; missing or other values refuse
`W_PROFILE_REQUIRED` before node RPC or durable cache access. Existing v3 seals
and issuance anchors must also satisfy native P2WPKH / SIGHASH_ALL W construction;
adding the pin does not migrate legacy transactions. Preserve existing state.

SW1 does not qualify this module's historical opt-in Core fixtures or legacy
configs for W. They are knowingly incompatible until the named
`SW1-consumer-fixtures` follow-up migrates their funding, T/A graphs and trusted
policies and reruns both modules' Core suites. Default-suite success is not
consumer end-to-end qualification. Do not deploy those fixtures as W examples.
