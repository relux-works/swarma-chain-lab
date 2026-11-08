# Rental certificate and issuer laboratory

M1 is an experimental **regtest-only** rental certificate, read-only kernel,
offline seal-pool planner and read-only issuance admission gate. It performs
no production effect, wallet signing, broadcast or deployment. Only the opt-in
test harness signs and broadcasts inside its isolated Core regtest wallet.

The issuer signs a compact BIP-340 certificate naming the stable agent key,
renter key, station, contract hash, scope, budget, time window and seal. The
station's current confirmed name_update commits to the complete envelope.
The gateway supplies the authenticated **inner NIP-17 seal key**; checking the
outer gift-wrap key is not authentication of the renter. Scope/budget are
returned as data for the separate executor. This package never judges text or
authorizes an effect.

See [CIP-0003 draft](CIP-0003-DRAFT.md), [CIP-0004 draft](CIP-0004-DRAFT.md),
[dependency pins](DEPENDENCIES.md) and [remaining integration work](UNRESOLVED_QUESTIONS.md).
The drafts are handoff material for swarma-link-spec, not a claim that its
published protocol has already been amended.

## Tools and exact entry points

Go 1.26.8 was used on Darwin arm64. The source targets macOS/Linux because
durable state uses flock and fsync. From this module:

```sh
go mod verify
go vet ./...
go test -race ./...
mkdir -p .temp/bin
go build -trimpath -o .temp/bin/rental-kernel ./cmd/rental-kernel
go build -trimpath -o .temp/bin/rental-plan ./cmd/rental-plan
```

The ordinary test run skips Core integration unless explicitly opted in.
Official BIP-340 test vectors and the independently generated M3 wire fixture
are checked in under `testdata/`; no production private key is included.
btcec v2.3.5 supports the 32-byte-message profile used here, not the later
variable-message-length extension. That limitation is explicitly tested.

Kernel:

```sh
.temp/bin/rental-kernel check --policy policy.json --route observer-route.json \
  --certificate certificate.json --station id/station-one --sender PUBLIC_HEX_KEY
.temp/bin/rental-kernel admit-issuance --policy issuer-policy.json \
  --route observer-route.json --request issuance-request.json \
  --package-event package-event.json
```

`check` exits 0 only for live, 2 for pending, 1 for refused. Admission exits 0
only for admit. Both print a JSON receipt. `--operator-route` selects the
existing hash-pinned CLI route. `--at UNIX_SECONDS` is a regtest clock override;
default is the current clock. There is no M1 mainnet runtime mode.

Policy fields: `network`, `genesis`, `issuer_pubkey`, `agent_pubkey`,
`station_name`, `station_script`, `state_dir`. Issuer policy wraps that object
under `policy` and adds the separately pinned `provider_pubkey`.
Station script is an ordinary legacy P2PKH script, independent of Nostr keys.
State root must already exist, be owned by the service UID and have mode 0700.
Use one persistent state root per admitted policy across processes/restarts.
The observer route contains a local credential: keep it private, never put it
in a public evidence packet. Its schema and operator route are reused from
`../single-use`; the laboratory observer username is `w3-observer`.
The complete read-method whitelist is `getblockchaininfo`, `getblockhash`,
`getblockheader`, `getrawtransaction`, `gettxout`, `name_show`,
`getrawmempool`, `getblock`. No wallet or write RPC is available to the kernel.

Planner:

```sh
.temp/bin/rental-plan refill --policy issuer-policy.json --spec refill.json
.temp/bin/rental-plan issue --policy issuer-policy.json --spec issue.json \
  --certificate certificate.json --request issuance-request.json \
  --package-event package-event.json
.temp/bin/rental-plan revoke --policy issuer-policy.json --spec revoke.json
```

PlanSpec fields are `kind`, `inputs`, `change_script`, `count`, `value_sat`,
`pool`; exported Go structs document the nested fields. Inputs explicitly
carry outpoint/value/script/role. The pool carries outpoint/value/script and
the operator's observed block/height. These are **offline claims**, not proofs
of current confirmations or ownership. The future signer must independently
check them and call AdmitIssuance immediately before signing. The planner
checks package/request/certificate bindings and signatures but has no RPC.
It emits an inert JSON plan, never signed transaction hex.

Issue burns both booking and pool reservations before returning a plan.
Failure after either write may leave a reservation with no emitted plan;
automatic retry is forbidden. A different seal cannot retry a burned booking,
and a different booking cannot reuse a burned seal. Refill/revoke do not
require a certificate signature and do not reserve a booking.

## Genuine Core controls

Only use hash-pinned Core 28 binaries, a new empty run root and no live datadir.
Set each run root to a distinct absolute directory. From this module:

```sh
M1_REGTEST=1 M1_RUN_ROOT=/absolute/new/m1/lifecycle \
M1_CORE_DAEMON=/absolute/pinned/namecoind \
M1_CORE_CLI=/absolute/pinned/namecoin-cli \
go test -count=1 -run '^TestCoreLifecycle$' -v
```

Run `TestCoreMatrix`, `TestCoreIssuanceAndPool`, `TestCoreWitnessPayment`, `TestCoreStateBoundaries`
separately with new roots. `TestCoreCLI` additionally requires
`M1_KERNEL=/absolute/path/to/rental-kernel` built from the tested source.
Do not enable all Core tests against one root: each intentionally refuses an
existing directory. The harness starts listen=0/networkactive=0, localhost RPC,
txindex, a dedicated read-only observer, and a fresh regtest wallet. It records
the daemon PID and stops that PID; private wallet/config/log files remain in
`private/`. Only `public/` receipts and sanitized command metadata are shareable.
State files beside it are local lifecycle evidence, not a reusable live grant.

Pinned daemon SHA256:
`86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f`.
Pinned CLI SHA256:
`5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d`.

## Reuse and limits

- Exact JSON projection: existing `sealwatch` helpers.
- Read-only routes, network pins, raw transaction binding, active-chain
  membership and stable-tip checks: the W3 `ReadObservation` facade.
- Durable locking/atomic rename/file and directory fsync: extracted
  `single-use/durable`, also used by W3's existing journal.
- Fee/change: shared conservative legacy finalizer at 200 sat/vB. Inputs
  reserve up to 140 scriptSig bytes; plans are bounded to 4096 signed vbytes.
- Relevant anchor/seal transactions retain the bounded legacy decoder.
  Payments accept legacy and witness serialization, bind stripped txid and
  raw outputs, and require active confirmation for both payment policies.
  Mempool payment refuses `payment_unconfirmed`; start_now waits a payment
  block and then an anchor block. Payment bounds are 64 inputs/outputs, 1 MiB,
  10 kB scripts/items and 1000 witness items per input. Witness framing is
  strict; Core validates input scripts/signatures. Unrelated witness traffic
  does not change rental admission. W3's legacy signer profile is unchanged.

The node, service UID, trusted clock and pinned policy are trust assumptions.
File permissions do not isolate hostile same-UID processes. There is no
atomic transaction joining a chain observation, fsync and a later effect.
Checks re-read relevant state and stable tip and recheck elapsed expiry;
the caller must obtain a fresh check for every effect. Time inputs have
one-second precision. Resource limits inherited from W3 are 30 seconds,
1024 calls, 8 MiB per reply and 32 MiB total; exhausted limits refuse.

A first observation cannot reconstruct unobserved historical generations.
Persisted accepted anchors allow proven later replacement to close permanently;
an unmatched current value always refuses even without prior history. A reorg
alone can suspend and recover; an observed spend or proved replacement cannot.
Node read failure refuses without durable closure in this rental profile,
explicitly differing from decisions/0002 F4. This preserves safety at the
failed read without permanently ending a paid slot on a transport outage.
