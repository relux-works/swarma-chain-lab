# Scripted station payload

This Go fixture consumes the existing canonical `gatewaybind.DecodeBootstrap`
v1/v2 document. It is a scripted station used for tests and composition rehearsals,
not a chosen rented-agent runtime or a deployment. Invalid versions, extra fields,
duplicates and noncanonical encoding refuse before network effects.

The station initiates gateway TLS with ordinary CA/hostname verification and the
operator's exact leaf DER SHA256, then performs stationlink's per-slot HMAC
challenge. V1 retains echo replies, `__extend__` refusal reporting and
`__end_early__`. V2 retains those scripted controls and uses the model proxy for
ordinary deliveries. The gateway local-test stub follows the same ID-bound wire protocol but remains a nondurable test fixture.

For v2, `model_endpoint` and `model_cert_sha256` come only from the validated
bootstrap. Messages requests go to `/slots/<booking_id>/v1/messages` with its model bearer.
Normal TLS verification and the leaf pin are both required. The operator supplies
an exact model ID and `max_tokens`; there are no inferred model or spending
defaults. Each delivery is one non-streaming, text-only user message with no
conversation history. Tools, arbitrary request objects and client headers cannot
be injected. Input text is bounded to 32 KiB, encoded requests to the proxy's
64 KiB profile, complete responses to 8 MiB and returned text to 32 KiB. The
reviewed Messages dialect validates complete response content and usage.

The operator can instead pin `responses`, which sends one string-valued `input`,
`model`, `stream=false` and `max_output_tokens` to `/slots/<booking_id>/v1/responses`.
There are no tools, instructions or conversation history. MP2's `Responses.Parse`
validates the outgoing request; `Responses.Complete` validates the matching
completed response and usage before text is released. Only assistant output text
is returned. Tool/unknown items and malformed usage/status refuse; a refusal
item returns fixed `MODEL_REFUSAL`, without provider text. Empty output refuses.
The text limits remain 32 KiB, responses 8 MiB; encoded Responses requests use
MP2's 2 MiB cap, permitting JSON escape expansion within the text limit. No SSE
is requested or consumed, so stream terminal handling is not part of this client.

## Durable delivery

The CLI requires `-journal-dir /absolute/private/slot-turns`; `Client.Run` requires
`Options.JournalDir`. Infra must provision an existing owner-only0700 directory
with canonical symlink-free, non-writable ancestry. There is no default. Input is
persisted before `received`; each `reply` carries its delivery ID. A durable
ready result is reused across restarts. A crash-left model call becomes the fixed
reply `uncertain`, with no second model call or charge. Before saving ready, the shared NIP-44/full-event relay-size policy replaces an
oversized reply with the fixed notice `reply exceeded deliverable size`.
The notice is immutable across retries and lets later deliveries proceed.
This covers JSON escaping and both encryption layers, without generating twice.
Corrupt/private-path/lock
failures refuse `PAYLOAD_JOURNAL` before a usable session.

The journal contains private input/replies and remains bound to the exact
bootstrap. Preserve it on restart; do not substitute an empty directory. Run
handles one connection and returns on channel failure; supervisor relaunch and
DK5b launch-path wiring remain separate. See the [DA1 wire and recovery
contract](../rental-gateway/DELIVERY.md) for outbox phases, limits and the
relay-accepted boundary. Renter display is not acknowledged by this protocol.

## Pinned startup and deployment

Deployment requires explicit `-dialect messages|responses` and `-model-config`
alongside the exact `-model` and positive `-max-tokens`. The config is an
operator-provisioned, canonical public copy of the model proxy configuration,
0600 with the same protected-path rules as the bootstrap. The loader reads only
this JSON, never paths named by `api_key_file`, `tls_key` or any other field.
Before network activity, `NewPinned` checks the selected model, its dialect,
output limit against context, and bootstrap origin/leaf pin against this copy.
Missing model, either direction of dialect mismatch, endpoint/pin mismatch or
an unknown dialect refuses `PAYLOAD_CONFIG`. Bootstrap v1/v2 bytes are unchanged;
pinned model mode requires v2.

The deploy validator requires a canonical payload pairing record plus the actual
public model configuration. The record mirrors operator argv and the expected
bootstrap origin/pin; Infra must pin those exact values when provisioning the
launch. The public copy and proxy config must be updated together. This checks
operator configuration, not remote live-state attestation or root-policy execution.
The existing global mainnet deployment refusal remains in force.

Omitted dialect (`New` and the old CLI argv) retains the Messages behavior solely
for legacy tests and is **unqualified for deployment**. Deploy admission rejects
missing pairing or an empty dialect. New fixtures and the Responses rehearsal
use pinned mode. This compatibility path does not perform a profile lookup.

The client has no generation retry, redirect following, environment proxy,
credential refresh or cap fallback. It disables connection reuse to avoid stale
connection replay. Only the proxy's exact CAP/AUTH refusals become terminal for
that client instance
(AUTH also covers expiry/revocation); later deliveries receive the same fixed
refusal without more HTTP requests. Local encoding/size failures, cancellation,
transport errors and other response failures refuse one delivery. A later caller
request uses the same credentials and remains subject to the proxy's unchanged
accounting, including retained reservations for uncertain upstream outcomes.
CAP maps to `MODEL_CAP`. Expired/revoked/prepared/invalid credentials intentionally
share `MODEL_AUTH`, matching the proxy's authority boundary. Other recognized
fixed proxy errors are prefixed `MODEL_`; unrecognized response bodies and
transport diagnostics become `MODEL_RESPONSE` or `MODEL_TRANSPORT`. A new client
does not reset proxy accounting or restore revoked credentials.

The CLI reads the canonical bootstrap from an owner-only 0600 regular single-link
file through the existing protected-file loader. All path components must be
symlink-free. The fixture CA file uses the same 0600 rule. It contains trust for
both gateway and proxy; no manager client certificate or upstream API key is
available to the payload. Public stderr contains only a fixed failure code.
Prompts, replies, bootstrap fields, bearer and arbitrary diagnostics are not logged.
Private input remains private on disk; this fixture does not claim secure erase.

## Tools and artifacts

Use Go1.26.8 with sibling modules present. Outputs belong under `.temp/`.

```sh
export GOTOOLCHAIN=local GOWORK=off
go mod verify
go vet ./...
go test -race -count=1 ./...
go run .scripts/guards.go -out .temp/guards
go build -trimpath -o .temp/station-payload ./cmd/station-payload
.temp/station-payload -bootstrap /absolute/private/bootstrap.json \
  -journal-dir /absolute/private/slot-turns \
  -ca /absolute/private/fixture-ca.pem -gateway 127.0.0.1:9444 \
  -gateway-pin <gateway-leaf-sha256> -model <operator-model-id> -max-tokens 10 \
  -dialect responses -model-config /absolute/private/public-model-config.json
```

For installed offline dependencies also use `GOPROXY=off GOSUMDB=off
GOFLAGS=-mod=readonly`. V1 does not require model flags. The Go API accepts a
separate CA pool for model requests and for the gateway channel; the CLI's shared
CA file is a fixture convenience, not authority to skip either leaf pin.

Tests exercise actual TLS payload → real MP1/MP2 Service → fake HTTPS upstream,
accounted usage and cap/expiry/revocation, chain and leaf-pin refusals, terminal
errors, text/response bounds, no redirect/replay, closed bootstrap and private CLI
input. Channel tests use real TLS/HMAC with scripted gateway frames; they do not
claim real grant admission. The guard runner mutates only copied source and
requires each intended assertion failure beside a passing baseline; compilation
errors, timeouts and panics are not detections. Direct child PIDs appear in logs.

Full Core/gateway/manager composition and the explicitly substituted macOS
registrar transport are separate rehearsal evidence. Linux production admin
continues to require peer credentials. See [UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md).

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

The authenticated gateway System frame must carry an explicit usable
`relay_max_event_bytes`. Before saving Ready, the shared delivery-size policy
checks complete gift-wrap JSON and both NIP44 layers; oversized model text becomes
the immutable notice `reply exceeded deliverable size`. At cap65536 a32768-byte
plain result also becomes the notice. Missing/invalid caps refuse before pulling
work. Keep the cap stable during pending turns; see the gateway DELIVERY.md.
