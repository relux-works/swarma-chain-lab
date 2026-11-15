# Minimal per-slot model proxy

This module provides bounded Messages and function-tool Responses profiles for an approved rental
slot. It owns the upstream API key; the slot gets only a random, revocable
bearer through its private bootstrap. It is independent of the rental gateway,
Nostr, the station manager and the eventual rented-agent runtime.

This is an implementation and local fixture boundary, not a deployment. No
real API key or paid API request is used by the tests. The operator still chooses
the model, pinned limits/prices, TLS material, runtime and network policy.

## Authority and lifecycle

`Prepare(Binding)` persists one inactive 32-byte random bearer. Binding contains
booking/slot ID, grant ID, complete validity window (at most one hour) and caps.
Exact retries return the same credential; conflicting or terminal bindings
refuse. `Activate` enables use within that window. `Revoke` persists terminal
revocation and cancels in-flight work. It remains possible when the clock is
unavailable; a failed persistence operation poisons this process closed.

The optional `station-lifecycle/gatewaybind.ModelRegistrar` uses this sequence:
Prepare while freezing the bootstrap, Activate before manager Start, Revoke
independently of host Stop on End/Destroy. Either uncertain cleanup leaves the
closer operation retryable. The gateway may already mark the slot Ended and
remove its channel secret while that closer remains started.

Bootstrap v2 is canonical, ordered and closed:
`v`, `booking_id`, `station_name`, `channel_secret`, `model_bearer`,
`model_endpoint`, `model_cert_sha256`. The channel secret retains v1 encoding;
the model bearer is raw base64url. The endpoint is a canonical HTTPS origin.
The client calls `/slots/<booking_id>/v1/messages` using normal TLS trust plus
the exact server leaf DER SHA256 pin. V1 remains unchanged when the registrar
is absent. Existing broker profiles are not silently migrated to v2. The
payload/runtime consumer must support v2 before the operator enables it.

Public ingress accepts only POST on the bound slot route and exactly one Bearer
Authorization header. Unknown, other-route, prepared, expired, revoked and
clock-invalid credentials refuse before generation. A stolen bearer remains
transferable authority; a route check is not workload attestation.

The optional OpenAI Responses profile uses the same bootstrap origin and bearer
at `/slots/<booking_id>/v1/responses`. Its model ID must have an explicit
`model_profiles` entry. Models without one retain Messages, and neither route
can select a model assigned to the other profile. There is no models-discovery
GET route. See [RESPONSES-PROFILE.md](RESPONSES-PROFILE.md) for the accepted wire
subset, primary sources and the separate coding-harness qualification boundary.

## Reservation and accounting

Each allowed exact model ID requires a context window, integer nano-USD input
and output prices per token, and an operator source note. There are no built-in
production prices, guessed tokenizers or body-byte token estimates.

Before any generation I/O, the proxy durably charges one request plus a
reservation of the **entire model context window as input**, requested
`max_tokens` as output, and their pinned cost. It checks remaining total input,
output, request and cost caps, and the per-request output cap using checked
integer arithmetic. Equality is allowed; one unit beyond a cap refuses.
This deliberately rejects some short prompts despite unused actual quota.

A verified complete response replaces the reservation with actual usage.
Streaming usage updates are cumulative, not additive. Settlement is durable
before a complete JSON response or final SSE message_stop is released.
Disconnect, timeout, malformed/missing usage, truncated SSE, shutdown, failed
settlement and restart with a pending request retain the full unresolved
reservation. There is no generation retry or refund based on connection loss.
Status exposes charged exposure and observed usage separately; request counts
are never refunded. For Responses cancellation before upstream headers, the
current refusal is HTTP 502 with `{"error":"UPSTREAM"}`; it emits no
`response.completed`, reports no success and clears the in-flight marker while
retaining the entire reservation. Once a downstream SSE frame has been flushed,
revocation or expiry cuts that established stream with `proxy_stream` and no
`response.completed`. Neither path retries generation. Provider usage exceeding the reserved
bound freezes the slot; this cannot undo an upstream bill or prove a misbehaving provider obeyed
its contract.

The ledger is private, bounded and exclusively locked using `single-use/durable`:
0700 state root, 0600 files, fsync/rename/directory-sync, 64 lifetime records,
16 active/prepared slots, one in-flight request per slot and at most 16 globally.
A configuration fingerprint binds endpoint, upstream, model table, dialect and
daily cost ceiling.
Restart preserves credentials, revocation and exposure; it never replays work.
There is no automatic record GC. Resetting state would reset accounting and is
not an ordinary recovery step. A durable wall-clock high-water refuses rollback.
Expiry is checked again during requests every 25 ms; already accepted provider
work can continue after local cancellation, hence conservative retention.

## Proxy-wide daily cost ceiling

`daily_cost_ceiling_nano_usd` is an optional final top-level unsigned integer
in the canonical admin configuration, after `model_profiles` when present.
It uses the same integer nano-USD units and pinned model prices as booking caps.
Omission or zero disables generation; neither means unlimited. Provision a
positive operator-approved ceiling to enable generation. There is no built-in
production ceiling or price.

The installed loader admits this field only as part of the existing signed
static configuration set: the config bytes are hashed in the manifest, whose
signature and digest are pinned by the root-owned install anchor. The file is
root:exclusive-service-group0640 under protected0750 ancestry. See the
[install contract](../../deploy/INSTALL-CONFIG.md) for sealing and admission.
The daemon reads no environment override. Public Messages/Responses fields and
registrar operations cannot set the ceiling. Even a registrar that mints many
bindings with large booking caps cannot raise this proxy-wide limit. The
ceiling is copied at construction and included in the durable configuration
fingerprint; changing it requires a separately planned admin migration, not a
live update or deletion of state.

Admission reserves the full context/input and requested output cost against
both the booking and the current UTC day's ceiling. The process mutex covers
the check, addition and durable write; the exclusive state-directory lock
excludes another cooperating proxy. Both reservations are stored in the same
`registry.json` transaction using the existing atomic rename, file fsync and
directory fsync, before any provider call. Equality is admitted. If the new
exposure would exceed the ceiling by even one nano-unit, admission returns
HTTP403 `{"error":"DAILY_COST_CEILING"}` without a provider call or booking
charge. Integer overflow also refuses.

Today's committed spend is conservative charged exposure, including full
in-flight and uncertain reservations. Verified settlement replaces a reservation
with actual usage before releasing success. Interrupted calls and restart keep
the full unresolved cost. A reservation belongs to its UTC admission day:
forward midnight resets the current bucket durably on the next admission,
settlement or readback; a late settlement never refunds the new day. The existing
durable clock high-water refuses rollback. This bounds admitted cost under the
pinned provider billing contract, rather than proving a provider obeys it. A
hard limit on the provider key remains a separate operator action.

Provision accounting once, before the first normal startup, using the installed
binary with the same sealed inputs and service identity:

```sh
model-proxy -config SEALED_CONFIG -initialize-accounting
```

This command opens no listener and makes no provider call. It requires an
existing private0700 **empty** state directory and refuses any existing entry,
including a lock left by an attempted startup. It is not a recovery/reset
command. Normal startup never initializes missing accounting. Missing state
returns `DAILY_ACCOUNTING_MISSING`; invalid, incomplete or corrupted accounting
returns `DAILY_ACCOUNTING_CORRUPT`. Live admission/readback also checks the
persisted file and poisons the process closed on loss or modification; these
refusals use HTTP503. A checksum over the day and cost also detects accidental
accounting corruption at restart, including a zeroed spend. It does not attest
against an administrator rewriting state and its checksum. No refusal recreates
zero spend. Restore authoritative
state through an admin recovery plan, preserving spend and credentials. An
older ledger without the daily bucket is refused; this change provides no
automatic migration or reset of existing installations.

The pinned caller can read the peer-checked Unix admin endpoint. The install
plan can capture its JSON without loading or printing a provider key:

```sh
curl --silent --show-error --fail --unix-socket ADMIN_SOCKET http://local/v1/budget
```

The GET response contains only `utc_day` (YYYY-MM-DD), `ceiling_nano_usd`,
`committed_nano_usd` and `remaining_nano_usd` (ceiling minus charged exposure).
It is marked `Cache-Control: no-store`. Query parameters, a body, other methods
and unverified peers refuse; the public TLS generation listener has no budget
route. Readback advances and persists a pending UTC rollover before responding.

## Fixed Messages profile

The dialect interface separates request parsing, upstream headers, complete
usage and SSE validation from bearer, registry and cap enforcement.
The first profile pins API version `2026-10-21` and permits only `model`,
`max_tokens`, `stream`, text `messages` and optional text `system` from clients.
Duplicate keys, unknown fields, tools, images, documents, cache controls,
priority/fast settings and client-selected regions refuse.

The proxy itself inserts `service_tier=standard_only` and
`inference_geo=global`. It does not inherit priority capacity or regional
workspace defaults. Compatible usage must report standard/global dimensions
when present; cache/tool categories must be zero. Regional pricing, server
features and other dialects require a separately defined profile. Input and
rewritten body are limited to 64 KiB; responses to 8 MiB and each SSE frame to
64 KiB. Unknown events or invalid usage/order fail closed.

These choices follow the official [Messages reference](https://platform.claude.com/docs/en/api/http/messages/create),
[service tiers](https://platform.claude.com/docs/en/api/service-tiers),
[token counting](https://platform.claude.com/docs/en/build-with-claude/token-counting),
[streaming](https://platform.claude.com/docs/en/build-with-claude/streaming) and
[pricing](https://platform.claude.com/docs/en/about-claude/pricing), inspected
2026-11-09. They do not qualify a still-unselected agent runtime.

The proxy constructs fresh upstream headers with its configured key, fixed API
version and Content-Type. Client auth, beta/version overrides and other headers
are not forwarded. Only the configured HTTPS endpoint is used; redirects,
environment proxies and automatic generation retries are disabled. Network and
parse errors are translated into fixed codes. Audit records contain only a
validated slot ID, status, fixed code and integer usage. Bodies, headers, raw
URLs, API keys and bearer values never enter the audit sink. Private carriers
redact formatting, while JSON encoding is used only on explicit private paths.

## Linux administration and configuration

An optional final `model_profiles` field maps exact existing model IDs to
`{"profile":"openai-responses-functions-default-v1","upstream":"https://api.openai.com/v1/responses"}`.
Both fields are required; only this qualified profile is accepted. Each endpoint
is pinned HTTPS without user info, query or fragment, ending in /v1/responses.
The configured API credential must belong to every selected endpoint: use a
separate service/state/credential for another provider account. No client header
or request field can select that endpoint or credential.

The legacy top-level `upstream` field remains required. In an all-Responses
configuration it must be a Responses URL; generation selects the per-model
endpoint. If any model remains Messages, the deploy validator still requires
the Messages path for that top-level endpoint.

Prices/context bounds remain in the existing `models` table. Profile settings
are copied at construction and included in the durable configuration fingerprint.
An omitted profile map retains Messages selection. The daily ceiling extends
restart identity for every profile. Changing profiles after records exist is
refused as fingerprint drift; do not delete state to force an upgrade. A real migration needs a separate plan preserving
bearers and exposure. The Messages wire profile remains unchanged.

Responses accepts at most 2 MiB requests, 256 KiB SSE frames and 8 MiB total
replies. Text/refusal messages and declared function calls are validated against
their item/content lifecycles. Final success is withheld until clean EOF and
durable settlement; post-terminal frames, missing completion, unsupported
reasoning/hosted-tool events, incomplete responses and invalid usage retain the
full reservation. This profile injects store=false, background=false and
service_tier=default. Cached input is charged at the full pinned input price;
reasoning detail counters are included in output totals, not added twice.
Reported usage above the reservation freezes before terminal release. It cannot
prevent an upstream provider from violating its promised billing bounds.

`Client` implements Prepare/Activate/Revoke over a local Unix socket. The server
checks Linux SO_PEERCRED against one pinned caller UID; the client checks the
socket and connected proxy UID. Parent directory must be proxy-owned 0750,
socket 0660, with no symlink components. The operator supplies group membership
for access; the program installs no users, permissions or service definitions.
An existing socket is refused, never deleted to take over another listener.
Non-Linux administration fails with LINUX_ONLY and has no TCP fallback.

`LoadConfig` accepts a private owner-controlled 0600 canonical JSON file with
exact fields in this order: `state_dir`, `listen`, `endpoint`, `tls_cert`,
`tls_key`, `admin_socket`, `caller_uid`, `upstream`, `api_key_file`, `models`,
optionally followed by `model_profiles` and `daily_cost_ceiling_nano_usd`.
Endpoint has `url`, `cert_sha256`; each model has `context_tokens`,
`input_nano_usd`, `output_nano_usd`, `source`. Model keys are sorted by JSON
canonicalization. The listen address is an explicit IP and nonzero port matching
the endpoint port. The CLI serves TLS 1.3; configured cert must match the leaf
pin. TLS PEM files must be owner-controlled 0600 regular single-link files;
the API key must be an exact nonempty 0400 regular single-link file, at most
4096 bytes, printable ASCII without trailing newline. All path components must
be symlink-free. Only synthetic fixtures are read by automated tests.

## Tools and verification

From this module, with Go 1.26.10 and the sibling source modules present:

```sh
GOWORK=off go mod verify
GOWORK=off go vet ./...
GOWORK=off go test -race -count=1 ./...
GOWORK=off go build -o .temp/model-proxy ./cmd/model-proxy
GOWORK=off go run .scripts/guards.go -out .temp/guards
GOWORK=off go run .scripts/daily-ceiling-guards.go -out .temp/daily-guards
GOWORK=off go test -race -count=50 -run '^TestDailyParallelReservations$' .
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o .temp/model-proxy-linux ./cmd/model-proxy
```

The Linux executable takes `-config <private-config-path>`. Starting a real
proxy and providing deployment credentials are separate operator actions.
The CLI emits typed audit JSON and fixed startup failure codes only.

The phase-specific Responses closure checks can be repeated with
`GOWORK=off go test -race -count=200 -run '^TestResponses(InFlightClosure|PreHeaderClosure)$' .`.
Run once with a short, empty tmpfs `TMPDIR` and once with an empty disk-backed
`TMPDIR`; keep logs under `.temp/`. Established-stream cases wait for the first
complete downstream frame to be written and flushed. Pre-header cases hold all
headers until cancellation and verify booking exposure of 100 input tokens,
10 output tokens, one request and 230 nano-USD, with zero observed usage and
cleared in-flight state, including persisted state. This ledger version has no
daily aggregate counter; these tests do not claim daily-ceiling coverage.

Tests use a loopback TLS fake upstream. They cover reservation equality/overflow,
auth/header stripping, SSE accounting and interruption, actual child-process
crashes after reserve/settle, failed durable writes, restart and private file
controls. Linux-only `TestUnixPeerRoundTrip` exercises actual Unix credentials
and wrong-caller rejection. A macOS run or Linux crossbuild does not execute
that test. The injected admin-handler tests state this limitation explicitly.
Gateway binding tests exercise the actual proxy registry, broker and closer,
with injected registration transport and host. Real payload TLS and host effects
are separate qualification gates.

`.scripts/guards.go` copies only writable fixture modules under `.temp/`, runs
positive baselines, then MP1 and MP2 guard mutations. It records commands,
owned PIDs, source hashes, exits and exact assertion witnesses in its evidence
directory. Compile errors, unmatched mutations, panics and unrelated failures
do not count as detections. `.github/workflows/model-proxy.yml` defines Linux
CI, including the peer-credential tests; local evidence does not claim a hosted
CI pass. See [UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md) for remaining gates.

## Signed model limits

Binding.Caps retains the optional signed `default_max_output_tokens`. A positive value must not exceed MaxTokens; zero preserves old non-contract bindings. CC1 does not inject defaults: Responses still requires an explicit client limit. See [contract binding and upgrade boundary](../rental-booking/MODEL-CAPS.md).

## Installed static inputs (DK5)

Installed daemon configs/secrets now require root:exclusive-service-group0640,
root:same-group0750 parents and the signed manifest/root anchor in
[the install contract](../../deploy/INSTALL-CONFIG.md). Legacy owner0600/0400
examples below or in historical smoke fixtures are not installed-service inputs.
Mutable state, standalone tool/client keys and dynamic payload bootstrap retain
their separate contracts. No production mode fallback exists. Full signed
admission tests live in `single-use/configguard`; local ownership seams are
synthetic and do not qualify Linux deployment. See the deploy runbook for
same-binary preflight and the separate DK5b payload launch gate.

The daily-ceiling guard tool uses compiler overlays for three controls: removing
the ceiling check, admitting ceiling+1, and treating missing accounting as zero.
It records baseline and mutant command exits, owned PIDs, hashes and named test
assertions under `.temp/daily-guards`. Candidate source bytes remain unchanged.
`TestDailyParallelReservations` races sixteen bookings against three full-cost
admissions; the repeated command above checks fifty independent schedules. These
synthetic costs and local fakes do not exercise a paid provider.

CI also builds the CLI with local sibling replacements removed in a temporary
modfile. This verifies that the published `single-use` dependency includes the
sealed config field; a sibling source replacement alone cannot satisfy that
packaging boundary. The temporary modfile, sums and binary live under `.temp/`.
