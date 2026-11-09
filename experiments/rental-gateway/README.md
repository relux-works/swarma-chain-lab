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

Local run (stub kernel; the real kernel binds library-side via
`kernelbind/`):

```sh
.temp/gateway keygen -out .temp/agent.key        # prints the agent npub hex
.temp/gateway serve -key .temp/agent.key -journal .temp/journal \
  -relay ws://127.0.0.1:<test-relay-port> -station-unix .temp/gateway.sock \
  -stations-root .temp/stations -slot-file slot.json -stub-agent
```

Stop by PID. `gateway station-stub` is the scripted agent the
local-test driver launches per station.

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
  gateway restart from durable station facts (no persisted PID).
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

- Stub kernel in `cmd/gateway serve` (`-stub-verdict`): local demos
  and tests only. The real kernel binds through `kernelbind`
  (library-side, exercised by the genuine-Core e2e); a production
  serve binary must additionally wire `kernelbind.New` + a node
  route and a real relay set.
- No relay redundancy/reconnect backoff yet (single relay client).
- Screening is an interface + stub; the real model call lands with
  its own prompt/host pinning outside this experiment.
- The renter channel sits behind the `Transport` (Publisher)
  boundary so it can move to an a2a transport later; no a2a code
  exists in this milestone.
