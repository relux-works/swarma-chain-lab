# Rental gateway + station manager (M2)

LAB experiment. The gateway half of the rental path
(`swarma-grants/docs/next-stage/architecture.md` §2, §3.3, §5 steps
8–9, §5.0, §5.0b, §5.2, §7): one stable agent Nostr identity held by
the gateway, NIP-17 routing to per-slot stations, screening outcomes
with deterministic slot ending, and station lifecycle. It does not
judge action scope (R3) and holds no chain keys.

## Tools: build and test

From `experiments/rental-gateway`:

```sh
go vet ./...
go test -race -count=1 ./...
go build -trimpath -o .temp/gateway ./cmd/gateway
```

Toolchain: `go 1.26.0` module (validated with go1.26.8 darwin/arm64
via GOTOOLCHAIN=go1.26.8). Default tests are offline and localhost-only; the
test relay binds `127.0.0.1` on an ephemeral port.

The nested `kernelbind/` module (real K1 v3 kernel binding)
builds and tests the same way from its own directory. Its
genuine-Core end-to-end test is opt-in and skipped unless
`GW_E2E_REGTEST=1` with `GW_E2E_RUN_ROOT`, `GW_E2E_CORE_DAEMON` and
`GW_E2E_CORE_CLI` point at a fresh run dir and the pinned Core
binaries. Run it with:

```sh
cd kernelbind
GW_E2E_REGTEST=1 GW_E2E_RUN_ROOT="$PWD/.temp/core-run-01" \
GW_E2E_CORE_DAEMON=/absolute/path/to/namecoind \
GW_E2E_CORE_CLI=/absolute/path/to/namecoin-cli \
GOWORK=off GOTOOLCHAIN=go1.26.8 go test -race -count=1 -v -run '^TestGatewayV3CoreE2E$' .
```

Create the parent `.temp/` directory first; the run directory must not exist.
Only the harness's isolated regtest wallet is used. Public issuance results,
presentations and `node.pid` are written at the run root; private node data
and temporary signing inputs remain under `private/` and must not be shared.

The CLI now takes one strict public config. See [SERVE.md](SERVE.md) for its
constructor chain, file permissions, current integration boundary and commands.
Legacy serve flags are rejected. The explicit local test route uses the real
kernel and exchange; optional stubs require `mode=test`, which deployment
validation refuses. Stop only the recorded process PID.

Station launch records durable `starting` before invoking the driver. A payload
may complete TLS/HMAC admission during that call; its application requests wait
until the journal promotes the slot to `started`. A failed launch closes the
bound connection and destroys the station, including when the caller cancelled
or journal writes failed. Failed cleanup is reported, never presented as success.
Starting admission also requires a live attempt in this gateway process, so a
crash-left record cannot authenticate. At startup the CLI serves manager RPC
first, then destroys interrupted launches through `RecoverStarting` and the
existing durable closer recovery, before serving payload/renter traffic. A
recovery error stops startup with `GATEWAY_START_RECOVERY`; payload execution is
never replayed. Existing terminal, credential and single-binding rules remain.

The startup regression uses real TLS/HMAC and an explicitly stubbed driver that
waits for Hello inside `StartSession`. It proves early admission, delayed first
request, failed-request suppression, slot isolation and crash recovery; it does
not claim genuine Core, model API or remote helper execution. Reproduce it and
the bounded guard-removal controls from this module:

```sh
go test -race -count=1 -run '^TestStartup' ./gateway ./journal
go test -race -count=1 -run '^TestServeStartupRecovery$' ./cmd/gateway
go run .scripts/sr1-guards.go -out .temp/sr1-guards
```

The guard runner modifies copied fixtures only and stores logs, source hashes
and mutation verdicts under the output directory. Its fsync probes wrap the real
file/directory `Sync` calls in the copy, verify their order for both start marks,
and detect removed calls. This is call-path evidence, not a storage power-loss
test. Bounded negative read deadlines test the pending-request barrier; there
are no launch sleeps, retries, polling or payload reconnects in the fix.

## Design pins

- **Nostr layer:** own small subset on `btcec/v2` (BIP-340, NIP-01
  ids, NIP-44 v2, strict NIP-59/NIP-17). go-nostr is *not* a
  dependency (see DEPENDENCIES.md and the M2 survey): its
  `GiftUnwrap` overwrites the rumor pubkey instead of refusing a
  seal mismatch. Interop was cross-checked both ways against
  go-nostr v0.52.3 in scratch during development.
- **Inbound order (fixed):** strict unwrap (sender = inner seal key,
  never the gift-wrap key) -> active-slot lookup -> slot window ->
  v3 presentation parse -> fresh grant check -> lazy station start ->
  durable replay journal -> screening (only explicit allow delivers; error/timeout/malformed
  refuse) -> station delivery queue.
- **Inline presentation (K1 v3 grants):** the renter attaches
  one rumor tag `["grant-cert", <grant_id>, <base64 presentation>]`
  (canonical `{signed_grant, issuance: {txid}}` JSON, ≤16384 decoded bytes)
  to its first message. `grant_id` is SHA-256 of the canonical signed grant, excluding
  the issuance locator. `GrantCertTag(presentation)` returns `(tag, error)`;
  it rejects malformed transport framing. The kernel checks the complete
  grant schema, signatures and locator against its own chain. The gateway
  runs kernel `Present` (a fresh `Check`
  inside; only `live` admits the bytes into the kernel's bounded
  64-sender cache; same-sender replacement only via a new live
  presentation; a 65th sender is refused). Later messages are
  `Check`ed fresh against the cached bytes — the cache is never a
  verdict — or against a slot-stored presentation when one was
  pre-provisioned. No known bytes refuse as `presentation_required`.
  Malformed tags refuse that message before screening (no strike,
  rumor id not burned). Presentation refusals DM the renter a
  deterministic gateway text (fixed strings, never the model). The
  tag is stripped: screening and the station only see content. The
  first live verdict for an in-window slot lazily starts that
  grantee's station instance (one per slot; many grantees in
  parallel). The tag's wire shape lives in one small function
  (`parseGrantPresentation`, using `kernel.PresentationID` for the
  shared transport/ID calculation). No legacy v2 admission path remains.
- **Screening outcomes (§5.0):** only an explicit model REFUSE
  spends a strike (counter fsynced before acting; warning DM +
  station notice; second strike ends the slot; counter survives
  restarts). Model outage/timeout/malformed refuses that one
  message with a "screening unavailable, retry" DM and no strike.
  The closer's final message goes through
  `Gateway.SendFinalMessage` (agent-signed, before Destroy only).
- **Closer operations (exactly-once):** `EndSlot`,
  `SendFinalMessage` and `DestroySlot` each carry a caller-chosen
  operation id with a durable journal record (started fsynced
  before the effect, done/failed after). A repeat with the same id
  returns the recorded result and performs nothing; a different id
  for a started/done kind conflicts; `LookupOperation` answers
  after an uncertain outcome. Crash-leftover started records
  complete on retry where the effect is idempotent: the final
  message re-publishes the one persisted event (never a second,
  different message), ending an ended slot is a no-op, and destroy
  proves already-gone by assertion. Destroy also works after a
  gateway restart from durable station facts (no persisted PID). Remote drivers
  may implement `station.Recoverer`; End and Destroy then resolve their opaque
  handle from the driver's durable mapping, even with no local home. Unknown
  mappings refuse. `station.ErrCleanupPending` keeps the operation started for
  same-ID retry; a timeout never marks the slot destroyed. See the separate
  [demo lifecycle adapter](../station-lifecycle/README.md).
  Agent-signed station replies additionally require a fresh live
  kernel check (current grantees only, no outbound screening); the
  final message is the deliberate exemption.
- **Kernel boundary:** `kernel.Checker` + `kernel.Presenter` bind
  the landed K1 v3 grant kernel:
  `Check`/`Present`/`CachedGrant` over v3 grant presentations. Receipts
  expose `GrantID`, `AgentName`, `LandlordName` and `Scope`; the gateway
  does not interpret scope as effect authority. `kernel.Stub` serves unit
  tests; the nested
  `kernelbind/` module binds the real `experiments/rental` package
  in-tree (`kernelbind.New` pins regtest + genesis, derives the
  seal script from the issuer grant key, and takes separate agent and
  landlord names
  plus the kernel state dir — which must exist at mode 0700). The
  genuine-Core regtest end-to-end (the real K1 issuer produces both
  grants; separate instances, revoke-one isolation, unconfirmed/wrong
  locator refusal, pending/confirmed landlord rotation)
  lives in `kernelbind/core_e2e_test.go`, opt-in via env. A kernel
  read failure refuses the message but never durably closes
  anything gateway-side. `FundingScript` is unnecessary here: the gateway
  neither prepares nor funds issuance.
- **Station channel:** stations initiate every connection (separate
  VM in deployment): pull deliveries, push replies, one
  length-prefixed-JSON protocol over `net.Conn` — unix socket
  locally, TCP in deployment with identical frames. Hello is a
  challenge-response: the station manager mints a 32-byte per-slot
  channel secret at Create (0600 in the slot home, registered
  gateway-side), the gateway challenges with a nonce, the station
  answers HMAC-SHA256(secret, nonce||slot||station) in constant
  time. One live binding per slot; no rebind on a bound connection;
  after disconnect only the same secret rebinds; the secret dies at
  slot end. Any mTLS proxy certificate never authenticates a
  station. The agent key never crosses the channel; session start
  delivers exactly one system frame (renter key, contract hash, end
  time). The agent may end early; extension is always refused. At
  `not_after` the session ends regardless of chain state.
- **Station drivers:** `local-test` (temp home 0700 + scripted stub
  child, killed by PID) for tests; `linux-user` (fresh hash-suffixed
  OS user per slot, home 0700, per-UID **nftables inet** egress —
  gateway, executor proxy, model API, optional package proxy, v4+v6,
  default DROP for that UID) built entirely through an injected
  command executor — argv-tested only, real execution on the Infra
  VM (nftables is the picked VM spelling). Track B tokens are minted
  per slot through the M4a admin contract (`POST /mint|/revoke` over
  a private unix socket, slot = 64-hex booking id) when configured,
  written 0600 exclusive, revoked at Destroy; local random minting
  is a test-only fallback. Create rolls back on partial failure.
  Destroy removes home + token + channel secret; retention §5.2.
- **Names:** the kernel pins the rented agent's name
  (`Policy.AgentName`, gateway config `AgentName`) against the
  grant and on-chain agent binding, and independently pins the landlord
  name (`Policy.LandlordName`) whose current name value carries the grant
  key. Pending rotation refuses without closing; confirmed key rotation
  yields the kernel's durable closed receipt and ends the slot. Station names are only
  the stationlink binding names; the `id/swarma-station-*` prefix
  is a deployment convention here, never a trust rule.

## Limitations

- The CLI wires the real kernel, typed V2 exchange and remote station-lifecycle
  adapter. The operator supplies the pinned real payload and Linux helper;
  local tests do not establish host deployment or Linux isolation.
- No relay redundancy/reconnect backoff yet (single relay client).
- Screening has an explicit logged `off` implementation and the existing
  `screen.Screener` injection boundary. A model proxy is not provided.
- The renter channel sits behind the `Transport` (Publisher)
  boundary so it can move to an a2a transport later; no a2a code
  exists in this milestone.

## Deterministic rental exchange (E1)

`exchange.Engine` optionally handles authenticated senders without a live grant.
The conversation and exact texts are specified in [EXCHANGE-PROFILE.md](EXCHANGE-PROFILE.md).
It requires first-contact inner-rumor NIP-13 work, bounds per-key buckets, replay
history, clients and queue, and persists counters, holds and exact pending replies.
At client capacity, fresh PoW senders can replace the oldest acknowledged,
unprogressed introduction. Booking/consent state and pending replies are protected;
evicted introductions must obtain terms again. Ambiguous bookings return a fixed
reconciliation notice; renters may wait or retry `terms`. See EXCHANGE-PROFILE.md
for limits.
Live grantees bypass the exchange. A full exchange queue drops immediately;
booking calls and exchange publication run off the relay read/ACK pump.

Library wiring (the CLI instantiates the same interfaces):

1. Construct the separate booking service, with its own provider signing key,
   private state and watcher/publication scheduling. `kernelbind/bookingbind.Adapter`
   maps its read-only Catalogue and Book/AcceptConsent/Get methods. AdapterV2
   supports explicit NMC/BTC/LTC selections offered by config. The legacy V1
   adapter supports NMC only and remains confined to test-mode wiring.
2. Supply `bookingbind.Grants` with a `PresentationSource` that reads already-issued
   presentations by booking ID from the external issuer. The exchange neither
   invokes issuance nor publishes to S1. The source has no signing or wallet API.
3. Fill `exchange.DefaultConfig()` with the private canonical 0700 state directory,
   pinned agent/landlord names, Backend and Grants; call `exchange.New`. Supply the
   result as `gateway.Config.Exchange` and the same agent name as `Config.AgentName`.
   `gateway.New` binds the messaging key, publisher and dormant-slot/current-kernel
   hooks and starts one exchange worker. Close the engine before its dependencies.
4. Supply the real `kernelbind.Adapter` as Kernel/Presenter. The issuer notification
   registers a dormant slot and delivers the inline presentation. At the slot start,
   a normal current-time Check emits `ready` only if live. Only a later admitted
   renter message starts the instance. Exchange-enabled lazy start does not send
   a second ready notice or await its relay ACK on the inbound read pump.

The booking service's `Catalogue(until, limit)` is read-only, bounds slot starts by
`until` (intersection with `[service-now, until)`), and lists configured slot lengths
independently of current availability. No signed booking/rental wire changed.

Additional tools and evidence (run Go commands with `GOTOOLCHAIN=go1.26.8`):

```sh
go test -race -count=1 ./exchange ./gateway
cd kernelbind
go test -race -count=1 ./bookingbind
```

From `kernelbind`, run each of `TestExchangeCoreLifecycle` and
`TestExchangeCoreNonLive` using the Core environment shown above and a distinct
fresh `GW_E2E_RUN_ROOT`. The first uses real booking, consent, regtest payment,
watcher, issuer and kernel through the first station delivery; the second spends
the real seal before start and proves refusal without an instance. Their NIP-17
publication collector is local; the independent websocket test
`TestExchangeSlowBackendDoesNotBlockRelayACK` exercises relay ACK concurrency.

From `rental-gateway`, mutation controls run in private copied modules:

```sh
go run .scripts/e1-guards.go -out .temp/e1-guards
GW_E2E_CORE_DAEMON=/absolute/path/to/namecoind \
GW_E2E_CORE_CLI=/absolute/path/to/namecoin-cli \
go run .scripts/e1-guards.go -core -out .temp/e1-guards-core
```

The runner requires offline cached dependencies, writes source/mutant hashes,
exact changes, exit codes and assertion logs under its output directory, and
rejects skips, build errors, panics and timeouts as detection evidence. Core
runs also create private wallet/node subdirectories; share only public evidence,
never `private/`. No real funds, external relays or deployed station are tested.
Relay-side IP/connection limits remain a deployment responsibility: NIP-01
subscriptions expose no trustworthy originating client IP.

## Configured serve

[SERVE.md](SERVE.md) documents the strict config, real kernel and HTTP booking
adapter, read-only issuer handoff, bounded inbound workers and controls.
Serve emits structured inbound status to stderr at startup, every30seconds and
shutdown, including admitted/full-queue-drop counters and queue/worker bounds.
Public SHA256 pins reject repeated-byte placeholders before startup effects.
[SERVE-SURVEY.md](SERVE-SURVEY.md) preserves the initial constructor evidence;
[UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md) records resolved boundaries and
the remaining payload/host deployment dependencies.

### Shared issued-presentation directory

The gateway command uses `presentationdir.Open` for the configured read-only
presentation directory. Direct callers also reject the filesystem root and paths
containing NUL, CR or LF before filesystem access. SG1 can publish canonical `<booking_id>.json` files there
after active-chain commitment confirmation; its publisher writes mode0644 in an
owner0755 directory. The reader retains its existing bounds, no-follow leaf
behavior and pending-on-absence contract. It grants no authority by itself:
bookingbind and the live kernel still validate bindings, signatures and chain
state. Cross-host file distribution is a deployment adapter. Run
`go test -race ./cmd/gateway ./presentationdir`; the producer-to-reader genuine
Core process fixture lives in signer-service's `TestCoreBookingComposition`.

## Optional relay AUTH and model bootstrap

[RELAY_MODEL.md](RELAY_MODEL.md) documents `relay_auth`, the explicit optional
`model_proxy` section, NIP-42 authentication and MP1 registrar wiring. Omitted
settings retain AUTH off and bootstrap v1. From this module, run
`go run .scripts/ga1-guards.go -out .temp/ga1-guards` for the bounded AUTH/config/pin
controls; logs and source hashes are written under that output directory.

### V2 booking exchange (G6)

Deploy `exchange.booking_version: 2` with an explicit `payment_coins` list that
matches the pinned template's ServiceV2 coin configuration. The HTTP client uses
existing catalogue/book/consent/status routes and validates typed V2 responses;
there is no downgrade or retry of an ambiguous booking. CatalogueV2 has no coin
list, so this is operator-provisioned metadata; see the deploy smoke check.

Send `book <template> <slot> <coin>` with an explicit `nmc`, `btc` or `ltc` offered
in terms. The contract response contains the exact canonical V2 bytes and hash.
Consent uses the existing kind-8181 wire and `CheckConsentV2`; the protocol's
`t` tag remains `swarma-rental-consent-v1`. The payment response adds
`min_confirmations` alongside address, atomic amount and coin, all frozen by the
contract. No renter input or upstream error is echoed. An unavailable coin gets
a fixed response, and cannot create a hold. Legacy V1 binding is test-only.

Validation commands from this module: `go test -race ./...`,
`go run .scripts/g6-guards.go -out .temp/g6-guards`, and existing GW1/GA1 guard
commands. `GW1_REGTEST=1` with the documented pinned Core binaries and a fresh
`GW1_RUN_ROOT` runs `go test -race ./cmd/gateway -run '^TestCoreServe$'`: the
actual CLI consumes V2 HTTP, exporter, SG1 and confirmed presentations before
issuing `ready`; the station remains an explicit local test fixture. Evidence
and isolated Core state go under the supplied `.temp/` root.

BTC/LTC Core payment checks: set `G6_REGTEST=1`, a fresh absolute
`G6_RUN_ROOT`, and `G6_BTC_DAEMON`, `G6_BTC_CLI`, `G6_LTC_DAEMON`,
`G6_LTC_CLI` to the repository-pinned binaries, then run
`go test -race ./cmd/gateway -run '^TestCoreV2BookingPayments$' -count=1`.
Each coin's isolated node stores public lifecycle evidence under
`$G6_RUN_ROOT/<coin>/public` and private node/wallet data under `private`.
Never publish the private directory.

Legacy V1 test-mode payment instructions report the service's fixed minimum of
one active-chain confirmation. V2 reports the minimum frozen in its contract;
these display values do not replace the service's payment admission checks.

## Relay recovery and expiry

`serve` uses `RelayClient.RunGiftWraps`: transient dial/read/write losses reconnect
with cancellable100ms exponential backoff capped at5s. The process and its
one-second expiry Tick remain alive through initial relay unavailability and
later disconnections. Config/authentication/policy/protocol failures remain fatal;
there is no automatic retry of a rejected subscription or ambiguous publication.
Publishing retains its one-attempt durable-ACK contract. Each replacement
connection re-establishes the configured GA1 AUTH before a required-auth REQ.
The reader records a permanent CLOSED refusal as the connection's terminal
cause before reading again; a following EOF or write failure cannot downgrade
that recorded cause to retryable transport loss. Auth-required CLOSED remains
recoverable only when AUTH is enabled. A refusal not received before transport
loss cannot be inferred from EOF.
Both client and native relay ping every30s by default, with90s read liveness;
only the reader changes read deadlines. The Go client exposes bounded duration
options for other deployments/tests; serve uses the defaults.

Recovery keeps the broad live inbox subscribed while a separate catchup
subscription pages backward. The conservative `since` floor includes NIP59's
48-hour outer-timestamp jitter, outage duration and a one-minute margin; an
uncertain partial replay never advances it. Each full page requests the oldest
outer timestamp inclusively as `until`. Existing journal rumor-ID/exchange dedup
owns application effects, so overlapping wrappers are not new deliveries.
`relay_replay_limit` defaults to32 (valid2..4096) and must not exceed the relay's
configured per-REQ backlog cap. The native relay defaults to32. A silently lower
third-party cap, expired/unretained events, full ingress queues or an unacknowledged
application delivery cannot be repaired by timestamp replay alone.

A full equal-timestamp page, a non-advancing boundary, the since boundary on a
full page, or128 replay pages emits fixed `REPLAY_OVERFLOW`, increments
`replay_overflows` in `relay_status`, ends catchup and keeps the live inbox.
This explicitly reports uncertain history; it does not claim lossless catchup.
Status also counts reconnects and contains no events, keys or credentials. A
missing EOSE beyond the bounded10s page wait is a protocol failure. The future
cursor/delivery-ack protocol is outside this unit.

Expiry End clears the channel credential and marks `Ended/not_after` while the
relay is unavailable. It does not imply the explicit closer `DestroySlot`
operation completed. The tests exercise actual `serve` and journal transitions
with explicit kernel/booking-node stubs; physical destruction and genuine Core
remain separate evidence. Run `go test -race ./...`; RK1 guard commands and
artifacts are documented in `../relay/README.md`.

The refusal/EOF interleaving witness and constrained-scheduler repetition run
from this module with
`GOMAXPROCS=1 go test -race ./gateway -run '^(TestRelayRefusalBeforeConsumer|TestReconnectRefusalAndBackoff)$' -count=200`
(repeat with `GOMAXPROCS=2`). The witness uses real WebSockets and waits for
terminal publication before consuming the result; ordinary EOF is its positive
transport control. Exact backoff capping is checked separately from the
time-window retry count, which cannot assume a minimum scheduler throughput.

## Signed model limits

Model-enabled gateway startup and slot start require exact equality with the six renter-signed contract caps. Canonical contract bytes are retained in the journal and used to reconstruct the original revoke binding after a config change. See [signed model limits and migration limits](../rental-booking/MODEL-CAPS.md).
