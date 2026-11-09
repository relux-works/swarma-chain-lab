# MP2 Responses function profile

Design recorded before implementation, 2026-11-09, base `5a3e4a28`.
This unit qualifies OpenAI Responses only. A Meta variant and model discovery
remain deferred until its sanitized protocol evidence is available. No provider
credentials, paid requests or harness integration are part of this unit.

## Sources and accepted boundary

Official sources inspected: [create](https://developers.openai.com/api/reference/typescript/resources/responses/methods/create),
[stream events](https://developers.openai.com/api/reference/resources/responses/streaming-events),
[function calls](https://developers.openai.com/api/docs/guides/function-calling),
[Codex configuration](https://learn.chatgpt.com/docs/config-file/config-reference).
These define the wire shapes; the restrictions below are this proxy's policy.

Client top-level keys are exactly `model`, `input`, optional `instructions`,
optional `tools`, optional `stream`, and required positive `max_output_tokens`.
Input is a text string or a nonempty array of text messages, function calls,
and string-valued function call outputs. Messages use user/system/developer/
assistant roles and string or typed text content; no image, file, audio,
item reference, previous-response/conversation reference or hosted tool.
Function definitions have type=function, name, object-valued parameters,
optional description and strict boolean. Parameters are bounded JSON data;
the proxy does not fetch references or evaluate schemas. Function-call outputs
must match an earlier call_id in the supplied stateless history, once each.
Tool definitions and call names are bounded and unique where appropriate.

The proxy inserts `store=false`, `background=false`, `service_tier=default`.
Clients cannot provide those fields, tier/region, reasoning controls, provider
headers, tool-choice controls or arbitrary top-level settings. Upstream headers
are fresh JSON Content-Type and configured provider Bearer, never slot headers.
No OpenAI date-version header is invented; the named closed profile pins the
accepted protocol revision. No production model, context window or price is
assumed. The operator selects exact IDs, context bounds and conservative prices.

## SSE and accounting

Accepted events: response.created, response.in_progress, output_item.added/done,
content_part.added/done, output_text.delta/done, refusal.delta/done,
function_call_arguments.delta/done, response.completed (all response-prefixed).
Sequence numbers strictly increase; the response ID/model, item IDs/indexes,
content indexes, text/argument accumulation and final output must agree.
Multiple output items may interleave. Only text/refusal messages and calls to
declared function tools are supported. Reasoning/hosted-tool events, failed or
incomplete responses, duplicate terminals and unknown events fail closed. These
limits deliberately do not claim generic compatibility with every model/harness.

Both named SSE frames and data-only frames with a matching JSON type are
accepted. Final response.completed is held until clean EOF, then validated usage
is durably settled before terminal release. Any following frame, including an
unprofiled [DONE], refuses with full reservation retained. This OpenAI profile
does not implement Meta's post-completion subscription event or sentinel.
Request bodies are bounded at 2 MiB, frames at 256 KiB and total replies at 8 MiB;
the legacy Messages limits are unchanged. No automatic generation retry.
The existing service timeout remains 30 seconds by default (the Go API permits
up to one minute); the CLI uses that default. A longer-running coding harness
requires separate timeout qualification rather than an implicit unlimited stream.

Usage requires nonnegative integer input_tokens/output_tokens/total_tokens with
checked total equality. Cached input and reasoning detail counters, when present,
must fit their corresponding totals. Charge all input at the pinned full input
price and all output at the output price, without inferring cache discounts.
One call reserves the entire pinned context as input, requested output maximum,
one request, and worst-case cost through the existing registry. Every tool turn
is another call. Observed usage beyond reservation freezes the slot before a
terminal is released. Missing/invalid usage and interrupted transport retain
the reservation; no partial output is mistaken for successful settlement.

## Configuration and compatibility

To preserve Model's existing Go shape and canonical JSON, a new optional
`model_profiles` map associates an exact existing model ID with a closed profile
and pinned HTTPS generation endpoint. Omitted entries retain Messages. Profiles
participate in the fingerprint only when present, preserving the old registry
fingerprint and canonical configuration bytes for existing configurations.
No alias or dynamically supplied endpoint is allowed. One operator credential
is used per service; do not combine endpoints requiring different credentials.
An all-Responses configuration requires a Responses top-level upstream path;
when any model remains Messages, that legacy upstream keeps /v1/messages.
Routing is POST /slots/<booking_id>/v1/responses for configured Responses models;
Messages model IDs cannot be selected through that route or vice versa.
Bootstrap v2, bearer registry, reservation arithmetic and lifecycle are unchanged.

The documented Codex transport configuration is:

```toml
model = "<configured-model-id>"
model_provider = "slot"
[model_providers.slot]
name = "Slot proxy"
base_url = "https://proxy.example/slots/<booking-id>/v1"
env_key = "SLOT_MODEL_BEARER"
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
request_max_retries = 0
stream_max_retries = 0
```

Supply the ephemeral slot bearer through that environment variable, never the
provider key. Normal TLS trust and the bootstrap leaf-pin obligation still
apply; this configuration alone does not implement certificate pinning. The
separate harness unit must reconcile its emitted fields/tools/transport with
this closed profile, provide the pin enforcement, and test actual integration.
No documented Muse endpoint configuration is available to this unit, so none
is invented. No models GET route is implemented for the OpenAI-only profile.

## Verification obligations

Use loopback TLS fixtures, unchanged MP1 regression tests and isolated Go guard
plants. Positive controls include streaming text, function call then tool output,
nonstreaming completion, exact caps and an unchanged legacy registry reopen.
Negatives cover duplicate/unknown fields; hosted tool, image and tier; invalid
sequence/item/terminal; missing usage; oversized frame/body; usage overflow
freezing; auth expiry/revoke; wrong profile route; fingerprint drift; uncertain
reservation retention. Every control needs its intended assertion, not a crash
or unrelated build failure. No runtime qualification is inferred from fixtures.
