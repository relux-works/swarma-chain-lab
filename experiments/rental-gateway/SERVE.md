# Configured regtest gateway

`gateway serve -config /absolute/path/to/gateway.json` replaces the old flag-based
stub demo. The constructor wires a read-only Namecoin observer into the real
`kernelbind.Adapter`, the v1 HTTP booking client into `bookingbind.Adapter` and
`exchange.Engine`, an external public presentation directory into
`bookingbind.Grants`, and explicit `screen.Off`. No provider/issuer key or wallet
API belongs to the gateway. Privacy is the exact signed booking constant, pinned
by its hash; arbitrary replacement text is refused.

`mode=regtest` uses `station.driver=manager`: the signed station-lifecycle
gatewaybind adapter persists allocations and waits for authenticated manager
reports. Separate listeners provide manager mTLS and payload server TLS followed
by stationlink HMAC. `mode=test` additionally permits the local-test driver.
The deploy kit supplies gateway templates; operator payload, helper policy and
real Linux host acceptance remain required before deployment.

## Public config and protected inputs

Config version1 is strict JSON: unknown, duplicate or aliased fields and trailing
JSON refuse. The config is at most64KiB and contains file references and public
pins only. All local paths are canonical absolute paths. State directories are
0700 and distinct; symlink ancestry refuses before creating state through it.
The local-test socket is a fresh Unix path; startup never unlinks an existing
endpoint. Remote mode requires an empty station_socket and station.root.

Required top-level fields are `version`, `mode`, `agent_key_file`, `agent_pubkey`,
`relay_url`, `journal_dir`, `station_socket`, `screening`, `kernel`, `exchange`
and `station`. The typed schema is in `cmd/gateway/config.go`.

- `kernel`: kind (`real`, or explicit test-only `stub`), stub verdict (empty for
  real), regtest network/genesis, agent and landlord names, issuer public key,
  derived seal script pin, state directory, numeric loopback RPC host/port and
  private route-file reference. Genesis and seal script must match the landed
  kernel; they cannot override it. The route uses `single-use.NewRPC` and its
  exact observer username/route checks.
- `exchange`: state and presentation directories, loopback HTTP booking origin,
  signed privacy/template/profile hashes, proof-of-work bits, client/queue/burst/
  replay bounds and explicit refill/expiry/message-age/poll/call intervals. The
  validator rejects out-of-range values; no implicit zero defaults weaken them.
- `station`: driver and either local-test root/stub_agent, or `manager` containing
  private broker state_dir, payload_id/payload_sha256, inclusive slot_min/slot_max
  within 0..9999, start_milliseconds (1..5000), separate listen/payload_listen
  literal unicast IP:port addresses, and TLS cert_file/key_file/cert_sha256 plus
  manager_ca_file/manager_cert_sha256. No wildcard/hostname/zero port or shared
  endpoint is accepted. Payload labels match the lifecycle lower-case label
  contract. Root-owned user/home/egress/resource policy is never mirrored here.

The agent key file is exactly0600 and must match `agent_pubkey`. The read-only
RPC route is exactly0400. Both must be regular bounded files with canonical
parents and no symlink leaves; errors do not echo their contents. Booking and
relay origins are numeric loopback routes. The gateway private inputs and journal
(including per-slot channel secrets) must never be included in evidence packets.
The gateway TLS key is exactly0400; certificates/CA files must not be group/other
writable. Server leaf hash and validity are checked before state/listener effects.
The manager must present a verified client chain and the exact pinned leaf;
payloads receive no manager certificate or key. Their own trust roots, gateway
address and leaf pin are operator-pinned inputs outside the private bootstrap.

`screening=off` is logged at startup. It allows content only after grant authority
has passed; cancellation still refuses. The existing `screen.Screener` interface
is the future model-proxy hook. A stub screener/kernel or local driver cannot be
selected outside explicit test mode. `gateway validate` additionally refuses
all test-mode configs unless `-allow-test` is deliberately supplied.

## Booking and public issuance handoff

The HTTP client uses the existing v1 book/consent/status routes plus bounded
read-only `GET /catalogue`. It verifies the returned signed-contract and
catalogue pins, uses bounded requests/responses and timeouts, and follows neither
redirects nor proxies. Its HTTP timeout uses the configured exchange call budget,
including Catalogue/Get whose existing service interface has no context parameter.
It does not automatically retry ambiguous writes. Only
known definitive no-effect booking rejections are classified as rejected; other
failures remain ambiguous for the landed exchange recovery contract.

An external issuer atomically publishes `<booking_id>.json` into the configured
public presentation directory. The gateway opens the directory read-only and
reads at most16KiB from regular non-writable-by-group/other files, refusing
symlinks and invalid IDs. Missing files mean pending issuance. The existing
booking binding verifies authenticity and exact booking/grantee/window identity;
file arrival never asserts current grant liveness. Issuance transport between
hosts remains an operator adapter, not gateway issuance code.

Four fixed inbound workers and a bounded queue keep kernel/manager waits off the
relay ACK pump. Saturation drops the inbound event without claiming delivery.
Structured stderr JSON with `kind=inbound_status` reports process-local cumulative
`admitted` and `dropped_full` counts, instantaneous `queued`, configured `capacity`,
and `worker_limit=4`. It is emitted at startup, every30seconds, and shutdown by a
separate worker; the relay callback performs no status I/O. Nil events and offers
after cancellation are refused without counting as saturation. Counters reset on
restart, fields are sampled independently, and admission does not mean delivery.
At most `capacity+4` events can be queued or executing; no automatic retry is added.
The exchange retains its separate worker/queue. Shutdown cancels workers, closes
tracked sockets, stops only owned local test children and closes dependencies.
Manager HTTP admits at most4 simultaneous connections, with bounded header/body/
write/idle timeouts and a 64KiB protocol body limit. Payload admits at most32
connections with 5-second idle read/write deadlines; neither route has plaintext
fallback. A partial listener startup releases its earlier listener and broker
lock. Remote shutdown leaves durable reconciliation to the manager/helper; it
does not claim that closing a socket destroyed a station.

After restart, the adapter's Recoverer restores opaque handles for End/Destroy.
The r4 helper boundary persists boot_id/CLOCK_BOOTTIME before Create. Absence
after an uncertain attempt proves cleanup only when its status probe begins
after the saved boot-time fence (+6s), or a verified boot change invalidates the
request. Busy, clock failures and foreign bindings remain pending. Legacy r2
attempts without a stored fence still require this binding's destroyed record.
No wall-clock freshness fallback is used; real r4 helper acceptance is a host gate.

## Tools and evidence

From `experiments/rental-gateway`, use Go1.26.8:

```sh
GOTOOLCHAIN=go1.26.8 GOWORK=off go test -race ./...
GOTOOLCHAIN=go1.26.8 GOWORK=off go vet ./...
GOTOOLCHAIN=go1.26.8 GOWORK=off go build -trimpath -o .temp/gateway ./cmd/gateway
.temp/gateway validate -config /absolute/path/to/gateway.json
GOTOOLCHAIN=go1.26.8 GOWORK=off go run .scripts/gw1-guards.go -out .temp/gw1-guards
```

The guard runner copies mutable modules into a fresh `.temp/` tree, verifies
valid baselines, applies one plant at a time and requires the intended assertion
failure. A compile error, skip, crash or unapplied plant is not detection. It
records each test PID, source hashes and result in the requested evidence dir.

The genuine-Core test builds and runs the actual race-enabled CLI. It uses a
fresh isolated regtest wallet, real HTTP booking, signed consent, payment watcher,
real issuer and read-only public handoff, then reaches a local test station over
NIP-17 and stationlink. Foreign consent creates no package; spending the real
seal closes the cached grant without a second delivery. Linux host operations
are not executed by this test.

```sh
mkdir -p .temp
GW1_REGTEST=1 \
GW1_RUN_ROOT="$PWD/.temp/gw1-core-run" \
GW1_CORE_DAEMON=/absolute/path/to/namecoind \
GW1_CORE_CLI=/absolute/path/to/namecoin-cli \
GOTOOLCHAIN=go1.26.8 GOWORK=off go test -race -count=1 -v -timeout 5m -run '^TestCoreServe$' ./cmd/gateway
```

The run root must not exist and its parent must exist. The helper pins the Core
binaries by SHA256, binds only loopback, records owned daemon/gateway PIDs, and
stops those processes. Share only public issuance/presentation files, PID and
sanitized test results from the run root; never `private/`. Private gateway logs
are checked in place for credential leakage and race diagnostics. Add `-core`
to the guard command with the same `GW1_CORE_*` environment to exercise the
real-kernel replacement plant against this actual CLI path.
