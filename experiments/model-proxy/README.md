# Minimal per-slot model proxy

This module provides a bounded text-only Messages proxy for an approved rental
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
are never refunded. Provider usage exceeding the reserved bound freezes the
slot; this cannot undo an upstream bill or prove a misbehaving provider obeyed
its contract.

The ledger is private, bounded and exclusively locked using `single-use/durable`:
0700 state root, 0600 files, fsync/rename/directory-sync, 64 lifetime records,
16 active/prepared slots, one in-flight request per slot and at most 16 globally.
A configuration fingerprint binds endpoint, upstream, model table and dialect.
Restart preserves credentials, revocation and exposure; it never replays work.
There is no automatic record GC. Resetting state would reset accounting and is
not an ordinary recovery step. A durable wall-clock high-water refuses rollback.
Expiry is checked again during requests every 25 ms; already accepted provider
work can continue after local cancellation, hence conservative retention.

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

`Client` implements Prepare/Activate/Revoke over a local Unix socket. The server
checks Linux SO_PEERCRED against one pinned caller UID; the client checks the
socket and connected proxy UID. Parent directory must be proxy-owned 0750,
socket 0660, with no symlink components. The operator supplies group membership
for access; the program installs no users, permissions or service definitions.
An existing socket is refused, never deleted to take over another listener.
Non-Linux administration fails with LINUX_ONLY and has no TCP fallback.

`LoadConfig` accepts a private owner-controlled 0600 canonical JSON file with
exact fields in this order: `state_dir`, `listen`, `endpoint`, `tls_cert`,
`tls_key`, `admin_socket`, `caller_uid`, `upstream`, `api_key_file`, `models`.
Endpoint has `url`, `cert_sha256`; each model has `context_tokens`,
`input_nano_usd`, `output_nano_usd`, `source`. Model keys are sorted by JSON
canonicalization. The listen address is an explicit IP and nonzero port matching
the endpoint port. The CLI serves TLS 1.3; configured cert must match the leaf
pin. TLS PEM files must be owner-controlled 0600 regular single-link files;
the API key must be an exact nonempty 0400 regular single-link file, at most
4096 bytes, printable ASCII without trailing newline. All path components must
be symlink-free. Only synthetic fixtures are read by automated tests.

## Tools and verification

From this module, with Go 1.26.8 and the sibling source modules present:

```sh
GOWORK=off go mod verify
GOWORK=off go vet ./...
GOWORK=off go test -race -count=1 ./...
GOWORK=off go build -o .temp/model-proxy ./cmd/model-proxy
GOWORK=off go run .scripts/guards.go -out .temp/guards
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o .temp/model-proxy-linux ./cmd/model-proxy
```

The Linux executable takes `-config <private-config-path>`. Starting a real
proxy and providing deployment credentials are separate operator actions.
The CLI emits typed audit JSON and fixed startup failure text only.

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
positive baselines, then 17 representative guard mutations. It records commands,
owned PIDs, source hashes, exits and exact assertion witnesses in its evidence
directory. Compile errors, unmatched mutations, panics and unrelated failures
do not count as detections. `.github/workflows/model-proxy.yml` defines Linux
CI, including the peer-credential tests; local evidence does not claim a hosted
CI pass. See [UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md) for remaining gates.
