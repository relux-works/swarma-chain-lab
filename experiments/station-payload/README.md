# Scripted station payload

This Go fixture consumes the existing canonical `gatewaybind.DecodeBootstrap`
v1/v2 document. It is a scripted station used for tests and composition rehearsals,
not a chosen rented-agent runtime or a deployment. Invalid versions, extra fields,
duplicates and noncanonical encoding refuse before network effects.

The station initiates gateway TLS with ordinary CA/hostname verification and the
operator's exact leaf DER SHA256, then performs stationlink's per-slot HMAC
challenge. V1 retains echo replies, `__extend__` refusal reporting and
`__end_early__`. V2 retains those scripted controls and uses the model proxy for
ordinary deliveries. The original gateway local-test stub is unchanged.

For v2, `model_endpoint` and `model_cert_sha256` come only from the validated
bootstrap. Requests go to `/slots/<booking_id>/v1/messages` with its model bearer.
Normal TLS verification and the leaf pin are both required. The operator supplies
an exact model ID and `max_tokens`; there are no inferred model or spending
defaults. Each delivery is one non-streaming, text-only user message with no
conversation history. Tools, arbitrary request objects and client headers cannot
be injected. Input text is bounded to 32 KiB, encoded requests to the proxy's
64 KiB profile, complete responses to 8 MiB and returned text to 32 KiB. The
reviewed Messages dialect validates complete response content and usage.

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
  -ca /absolute/private/fixture-ca.pem -gateway 127.0.0.1:9444 \
  -gateway-pin <gateway-leaf-sha256> -model <operator-model-id> -max-tokens 10
```

For installed offline dependencies also use `GOPROXY=off GOSUMDB=off
GOFLAGS=-mod=readonly`. V1 does not require model flags. The Go API accepts a
separate CA pool for model requests and for the gateway channel; the CLI's shared
CA file is a fixture convenience, not authority to skip either leaf pin.

Tests exercise actual TLS payload → real MP1 Service → fake HTTPS upstream,
accounted usage and cap/expiry/revocation, chain and leaf-pin refusals, terminal
errors, text/response bounds, no redirect/replay, closed bootstrap and private CLI
input. Channel tests use real TLS/HMAC with scripted gateway frames; they do not
claim real grant admission. The guard runner mutates only copied source and
requires each intended assertion failure beside a passing baseline; compilation
errors, timeouts and panics are not detections. Direct child PIDs appear in logs.

Full Core/gateway/manager composition and the explicitly substituted macOS
registrar transport are separate rehearsal evidence. Linux production admin
continues to require peer credentials. See [UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md).
