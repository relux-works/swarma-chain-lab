# Rental gateway + station manager (M2)

LAB experiment. The gateway half of the rental path
(`swarma-grants/docs/next-stage/architecture.md` §2, §3.3, §5 steps
8–9, §5.0, §5.0b, §5.2, §7): one stable agent Nostr identity held by
the gateway, NIP-17 routing to per-slot stations, screening outcomes
with deterministic slot ending, and station lifecycle. It does not
judge action scope (R3) and holds no chain keys.

## Build and test

From `experiments/rental-gateway`:

```sh
go vet ./...
go test -race -count=1 ./...
go build -trimpath -o .temp/gateway ./cmd/gateway
```

Toolchain: `go 1.26.0` module (recorded run: go1.26.0 darwin/arm64
via GOTOOLCHAIN=auto). All tests are offline and localhost-only; the
test relay binds `127.0.0.1` on an ephemeral port.

Local run (stub kernel until M1 binds via `kernelbind/`):

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
  never the gift-wrap key) -> active-slot lookup -> slot window +
  durable replay journal -> fresh kernel `Check` (only `live`
  admits; errors refuse) -> screening (only explicit allow delivers;
  error/timeout/malformed refuse) -> station delivery queue.
- **Screening outcomes (§5.0):** refusal counter is fsynced before
  acting; renter gets a warning DM, station gets a notice, message
  is not delivered; second refusal in a slot ends it. The counter
  survives gateway restarts.
- **Kernel boundary:** `kernel.Checker` mirrors the frozen M1
  interface; `kernel.Stub` serves unit tests, the nested
  `kernelbind/` module binds the real `experiments/rental` package
  once M1 lands. The genuine-Core regtest end-to-end test is
  **pending that landing** (orchestrator supplies the head); the
  stub-kernel relay end-to-end test runs now. A kernel read failure
  refuses the message but never durably closes anything gateway-side.
- **Station channel:** stations initiate every connection (separate
  VM in deployment): pull deliveries, push replies, one
  length-prefixed-JSON protocol over `net.Conn` — unix socket
  locally, TCP+mTLS in deployment with identical frames. The agent
  key never crosses it; session start delivers exactly one system
  frame (renter key, contract hash, end time). The agent may end
  early; extension requests are always refused. At `not_after` the
  session ends regardless of chain state.
- **Station drivers:** `local-test` (temp home 0700 + scripted stub
  child, killed by PID) for tests; `linux-user` (fresh OS user per
  slot, home 0700, per-UID egress allowlist: gateway, executor
  proxy, model API, optional package proxy; default DROP) built
  entirely through an injected command executor — unit-tested argv
  only, real execution belongs on the Infra VM. Destroy removes
  home + per-slot Track B token; retention follows §5.2.
- **Station names** are passed through to the kernel, which pins
  them against trusted policy; the `id/swarma-station-*` prefix is a
  deployment convention here, never a trust rule.

## Limitations

- Stub kernel in `cmd/gateway serve` (`-stub-verdict`): local demos
  and tests only. Production wiring needs `kernelbind` + M1 policy
  pins and a real relay set.
- No relay redundancy/reconnect backoff yet (single relay client).
- Screening is an interface + stub; the real model call lands with
  its own prompt/host pinning outside this experiment.
- `linux-user` token provisioning references
  `/etc/swarma/trackb-template` as the manager-side staging file;
  Infra owns how per-slot tokens are minted there.
