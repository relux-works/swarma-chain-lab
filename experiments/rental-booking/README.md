# Rental booking laboratory (M3)

**Regtest experiment, not a public service or spending authorization.** A Go
booking/contract service with a bounded read-only Namecoin payment watcher,
NIP-07 signing page and a minimal local Nostr relay. It holds only a disposable
provider Nostr signing key and a pinned **public** HD branch; no chain signing
key, wallet RPC, mainnet route, external relay or real renter key is needed.

## Flow and guarantees

1. Configure station intervals (half-open, at most one hour), a profile-bound
   template, stable agent public key, provider key pin and operator-set rate.
2. A renter gets its key through NIP-07 and explicitly acknowledges the
   permanent key/station/time linkage **before** a payment address is allocated.
3. Atomically reserve an overlapping station interval and a never-reused
   BIP32 child index. Default hold: 1800 seconds; accepted explicit range:
   1200..1800. An unissued expired hold releases capacity; late money is kept
   in refund-review records, never assigned to the next renter.
4. Show the canonical contract. Verify renter consent's event id, BIP-340
   signature, exact tags/key/hash and time. Countersign its hash, persist the
   package and a provider-signed kind 8182 event, then publish that exact event.
   A missing/wrong relay ACK cannot mark the package published. Retry keeps the
   original event id; it never produces another contract or signature package.
5. Both `advance` and `start_now` require one active-chain confirmation first
   observed before expiry. Mempool-only payments remain pending. `start_now`
   describes slot scheduling after the anchor confirms, not weaker payment
   admission; contract times stay signed and cannot be rewritten. Any valid
   payment is one output at least the fixed amount; dust is not aggregated.
   Coinbase outputs are not renter payments. Duplicate/underpaid/late outputs
   are retained for operator refund review; this service never sends refunds.
6. Only a complete published package plus current eligible payment may create
   one issuance outbox record. No first emission at/after hold expiry. M1 must
   independently validate the package and payment, and admit only while
   `now < hold_expires_at` for either policy. Header time is not observation
   time; v1 has no signed watcher receipt enabling late admission.
7. An issued payment's block reorg or disappearance appends a revoke request
   and sets payment status to `revoked`. A replaced/dropped pending transaction
   never issues; a new confirmed payment can qualify before hold expiry. The old
   issuance is never rewritten or reissued, even if the same payment returns.
   Full-RBF replacement can affect non-signalling transactions too. A read
   failure or changing tip/mempool makes no payment-state change and proves
   neither payment absence nor revocation.

Public `agent_pubkey` is stable and belongs to the gateway; stations have no
Nostr key in this format. Optional renter Namecoin names must be unexpired and
have a value whose `swarma.nostr_pubkey` matches the renter. No name is required.
Empty allowed/scope `[]` is valid for chat-only slots; null is invalid.

The private file store holds one exclusive flock for its process lifetime.
Writes use a same-directory temporary file, fsync, rename and directory fsync.
An uncertain write poisons that handle until restart/reconciliation. All
bookings, address index and durable outbox intents share one atomic state file.
Outbox materialization is idempotent and fails on conflicting bytes. An emitted
intent counts as handed off even before a consumer acknowledgement; M1 burns
its own reservation when producing a plan. An issued slot remains reserved
through its interval even after a revoke request (M3 cannot prove closure).
The host UID and operator configuration are trusted; these files do not defend
against a hostile process with that same UID or against restoring old backups.

## Quotes and pins

All monetary arithmetic uses integers. `price_usd_cents` is the USD price;
`usd_micros_per_nmc` is the operator's rate. Reject nonpositive, future or stale
rates under `max_rate_age_seconds`, then fix the quote for the whole hold:

```
price_nmc_sat = ceil(price_usd_cents * 10^12 / usd_micros_per_nmc)
```

`*_sat` means Namecoin atoms, 10^-8 NMC. The effect budget is independent of the
booking fee and must be explicitly configured. Extended keys must be public,
regtest/testnet-version `tpub` branches, pinned by SHA-256 of the exact encoded
string. Derivation is `branch/index` for index < 2^31; no hardened derivation,
wallet call or implicit account path. Addresses are legacy regtest P2PKH.
`template_sha256` pins the canonical Template object in config; its profile
id/version/hash must match the actual profile bytes read at startup.

## Canonical wire format

[FORMAT-PROPOSAL.md](FORMAT-PROPOSAL.md) records the agreed interface and signed
hold-bounds amendment. This README defines the final wire contract. The
[wire-v1 fixture](testdata/wire-v1/README.md) is deterministic and public; its
payment coordinates are synthetic, so it proves encoding/signatures only.

Canonical encoding is compact UTF-8 JSON with exactly the field orders below,
no trailing newline, decimal integers, lowercase hex, printable ASCII string
values and non-null arrays. No unknown, duplicate or case-aliased fields.
General identifiers allow ASCII letters/digits and `-._/`; station names use
`id/[a-z0-9._-]+` with a 160-byte total bound. No arbitrary HTML/prose in
contract fields. Actions are lexicographically sorted and unique. The closed
set is `deliver`, `pay`, `publish`, `repository.push`, `secret.release`;
allowed and forbidden must partition it. M4, not the chat gateway or M3,
enforces structured actions, targets and budgets.

Contract (field order):

```
version, booking_id, renter_pubkey, renter_name, agent_pubkey, station_name,
not_before, not_after, allowed, forbidden, budget_sat,
template_id, template_sha256, profile_id, profile_version, profile_sha256,
price_usd_cents, usd_micros_per_nmc, rate_as_of, price_nmc_sat,
payment_policy, payment_address, privacy_sha256
```

Version is integer 1. Booking id, hashes, txids and x-only public keys are
32-byte lowercase hex; public keys must be valid BIP-340 points. Signatures
are 64-byte lowercase hex. Times are positive UTC Unix seconds. Optional
renter_name is the empty string. Policy is `advance` or `start_now`.
`contract_sha256` is SHA-256 of these exact canonical contract bytes.

Renter event: kind 8181, empty content, signer = renter_pubkey, created_at in
`[hold_created_at, hold_expires_at)` and not in the server's future when
received. Exact ordered tags:

```
[["t","swarma-rental-consent-v1"],["contract",contract_sha256],
 ["booking",booking_id],["privacy",privacy_sha256]]
```

Recompute the NIP-01 id from `[0,pubkey,created_at,kind,tags,content]`, then
verify BIP-340 over that id. These kinds are local experimental allocations,
not registered NIPs. Provider countersignature is BIP-340 over the same
32-byte contract_sha256 (not its textual hex). Package fields, in order:

```
version, contract, consent, provider_pubkey, provider_signature,
privacy_ack_at, privacy_sha256, hold_created_at, hold_expires_at
```

`privacy_ack_at == hold_created_at`. A provider-signed kind 8182 event contains
the canonical package JSON as content; exact ordered tags are `t` =
`swarma-rental-package-v1`, `contract` = hash, `booking` = id, `e` = consent id.
Consent and package events use field order
`id,pubkey,created_at,kind,tags,content,sig` when embedded. The provider event
signature protects the hold bounds and acknowledgement metadata in content.

Issuance request fields, in order (also see
[issuance-request.schema.json](issuance-request.schema.json)):

```
version, booking_id, station_name, agent_pubkey, renter_pubkey,
contract_sha256, scope, budget_sat, not_before, not_after, payment_policy,
payment_txid, payment_vout, payment_height, payment_block_hash,
observed_tip_hash, package_event_id
```

Scope equals contract.allowed; identity, interval, hash and budget equal the
contract. `payment_vout` is uint32. Both policies require positive payment
height and a nonempty block hash. Zero-confirmation issuance records from the
older prototype refuse on restart; operator reconciliation is required, never
silent migration or reissue. observed_tip_hash is a coherent active tip at emission; package_event_id
is the signed kind 8182 id. The request is not independently signed and does
not replace M1's online admission or authorize spending. Schema validation
alone does not prove canonical order, cryptography, uniqueness or chain facts.

Revoke fields:
`version,booking_id,contract_sha256,payment_txid,payment_vout,reason,observed_tip_hash`.
Reason is `payment_reorged` or `payment_disappeared`. The original payment
outpoint remains fixed; no automatic reissue on a replacement. Consumer
transport/authentication across hosts belongs to the deployment integration.

## Node reads and bounds

Only these verifier-whitelisted methods are used: getblockchaininfo,
getblockhash, getblock, getrawtransaction, getrawmempool and optional name_show.
The shared route also allows getblockheader/gettxout; the service cannot invoke
wallet/write methods. Network and genesis must match regtest; IBD is refused.
Core 28's headers counter may lag blocks after reconsiderblock, so it is not
used as a chain proof. Each scanned block must link to its predecessor and the
final block must match the observed tip. Both tip and mempool membership are
checked again before the whole observation commits. Discovery projects output
scripts first and only interprets amount/index/input metadata for candidates;
no raw transaction decoder is used. Genuine Core supplies decoded outputs and
transaction IDs for both legacy and witness-funded payments. The watcher binds
the RPC `txid`, not `hash` (wtxid), to mempool IDs and linked active blocks.
Malformed decoded candidate metadata refuses; validating serialized witness
stacks belongs to Core and M1's independent raw-payment admission.

Limits are explicit config: max_blocks <= 2016, max_mempool <= 100000,
max_calls <= 200000, max_bytes <= 512 MiB, and the underlying route's per-RPC
8 MiB response bound. Exceeding a bound refuses the observation without
changing state. This is a bounded laboratory watcher, not an unbounded chain
indexer; operators must monitor refused scans. Finished slots are not rescanned.

### Payments outside the observation window

An operator with the watch-only branch can derive future addresses. A payment
confirmed before its booking checkpoint is outside this watcher scan, as is
money arriving after the slot ends. Such funds may remain at a derived address
without an M3 refund-review receipt. The custody operator must inventory all
allocated indices (including expired bookings) and reconcile/sweep these
addresses using the separately authorized wallet/policy process. M3 does not
hold the private branch, sweep funds or infer spending permission. Preserve the
index and booking ledger during reconciliation; never reuse an address.
A watcher outage spanning hold expiry can also leave a real payment in
refund-review rather than issue late; block time does not replace a trusted
first-observation time.

## Tools and commands

Go 1.26.8, Namecoin Core 28 (hash pins in regtest_test.go), no JS dependencies.
Dependencies/checksums are in go.mod, go.sum and dependencies.json.

```sh
# From this module; build output remains in the repository's .temp directory.
go test -race ./...
go build -trimpath -o ../../.temp/rental-booking ./cmd/rental-booking
go build -trimpath -o ../../.temp/rental-relay ./cmd/rental-relay
go mod verify

# Both state directories must already exist, owned by this UID, mode 0700.
../../.temp/rental-relay -listen 127.0.0.1:18818 -state /absolute/relay-state
../../.temp/rental-booking -config /absolute/config.json \
  -profile /absolute/profile.bin -provider-key /absolute/throwaway-provider.hex \
  -route /absolute/operator-route.json -listen 127.0.0.1:18819 \
  -relay ws://127.0.0.1:18818 -poll 2s

# Opt-in genuine Core integration: new root for EACH test/run.
M3_REGTEST=1 M3_RUN_ROOT=/absolute/new/payment-run \
M3_CORE_CLI=/absolute/pinned/namecoin-cli M3_CORE_DAEMON=/absolute/pinned/namecoind \
  go test -run '^TestGenuineCorePayments$' -count=1 -v
# Repeat with a different new root and TestGenuineCoreNoise for the noise suite.
```

Config schema is the exported `Config`/`Template`/`Slot`/`Limits` structs in
service.go/contract.go/watcher.go; all fields except hold_seconds and
min_start_now_remaining_seconds are explicit.
The provider key file is 0600, a 32-byte test secret scalar encoded as hex; never
put it in argv, logs or evidence. OperatorRoute is the existing single-use
read-only capability with pinned CLI hash and private config/datadir references.
Neither server opens a browser or changes focus. The page depends on a NIP-07
extension; automated tests exercise server-side signing/verification and HTTP,
not a real user's extension permission dialog.

Tests document their claims and limitations beside each test. Genuine Core
runs retain public evidence separately from private node/credential state and
record/stop only their own node PIDs. Negative-test instrument controls remove
specific guards in isolated copies; compile errors and unrelated failures do
not count. See the delivery report for run hashes, commands and control results.

Instrument controls (new, task-owned scratch path under this bench):

```sh
M3_MUTATIONS=1 M3_MUTATION_ROOT=/absolute/new/mutations \
M3_CORE_CLI=/absolute/pinned/namecoin-cli M3_CORE_DAEMON=/absolute/pinned/namecoind \
  go test -run '^TestGuardRemovalControls$' -count=1 -v
```

Hosted `Rental booking checks` fetches/verifies pinned modules, disables module
network resolution during tests, runs unit/loopback/frozen-wire tests with the
race detector, and checks trimpath builds. Genuine Core and mutation runs are
explicit local gates with retained evidence; skipped CI tests are not passes.

The same Core variables with `TestGenuineCoreRenterName` exercise actual name
bindings; `TestGenuineCoreLateRelay` proves late relay recovery cannot issue.
For the actual executable control, first build the service, then additionally
set `M3_BOOKING_BIN=/absolute/path/to/rental-booking` and select
`TestGenuineCoreServiceProcess`. It records and stops its own service PID.


M3-02 adds `TestGenuineCoreWitnessPayments` to the opt-in Core suites. Run it
with the same explicit M3_REGTEST/M3_CORE_CLI/M3_CORE_DAEMON environment and a
fresh M3_RUN_ROOT as the payment suite, selecting
`go test -race -count=1 -run '^TestGenuineCoreWitnessPayments$' ./...`.
It verifies both policies with confirmed P2WPKH-funded payments, mempool
refusals, underpayment neighbours and distinct txid/wtxid evidence.

## M3-03 payment surplus and remaining time

A single confirmed output of at least the signed `price_nmc_sat` can pay the
booking. Each receipt exposes `surplus_sat = max(value_sat - price_nmc_sat, 0)`
and `refund_review`. A selected overpayment stays `selected` and paid, issues
only once, and sets refund_review=true for its excess. An exact selected payment
has zero surplus and false review. Receipts already marked `refund_review`
(including duplicate or insufficient payments) also set the flag; their full
value may need reconciliation. The flag requests operator review, never an
automatic refund or a change to the signed price. Per-receipt surplus is not a
sum or a second payment-selection rule.

Startup recomputes these fields from recorded value, signed price and
disposition, persisting any changed metadata before serving. This also restores
surplus review for old receipts that lack the fields. No chain read,
new payment verdict, signature, issuance or transfer is produced by backfill;
startup refuses if the durable write fails. Existing zero-confirmation issuance
state is still rejected under M3-02's rule.

`min_start_now_remaining_seconds` defaults to 1500 (25 minutes) when omitted or
zero. Explicit operator values must be 1..3600 seconds. Start-now booking refuses
with `SLOT_REMAINING_WINDOW` when `not_after - now` is smaller than that setting,
both before and after node reads. The exact threshold is allowed. Refusal
reserves no address or hold. Advance booking semantics are unchanged. This is an
admission-time margin, not a block-time guarantee; existing contracts and slot
ends are never retimed, and normal confirmation/expiry gates still apply.

The page explains that payment and rental activation confirmations may delay
start. Run the exact/over/under Core controls with a fresh test root and the same
Core variables above using `-run '^TestGenuineCoreSurplus$'`; unit boundary tests
are `TestStartNowRemainingWindow` and `TestStartNowWindowConfig`. The full guard
plant suite now includes amount, review, legacy backfill and both time checks.
