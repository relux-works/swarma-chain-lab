# Relay authentication and model registrar (GA1)

`gateway serve` supports optional relay authentication and model bootstrap v2.
These are local integration boundaries, not permission to deploy or spend funds.
The kernel still decides grant liveness; AUTH never replaces that decision.

## Relay configuration

`relay_auth` accepts `off`, `when_challenged`, or `required`. Omission preserves
`off`. The existing validated `agent_key_file` supplies the signing key; no new
key file or station credential is introduced.

- `off`: ignore challenges; an auth-required publication/subscription refuses.
- `when_challenged`: sign each challenge and await its positive OK before using
  that authentication. An initial unchallenged connection may operate normally.
- `required`: refuse without a key before dialing; gate REQ/EVENT on positive
  AUTH OK. No challenge or missing OK refuses within ten seconds (or the caller's
  earlier deadline). A negative AUTH OK fails the connection.

The implementation follows [NIP-42](https://github.com/nostr-protocol/nips/blob/master/42.md):
kind 22242, current timestamp, exact challenge and configured relay URL tags,
empty content, normal NIP-01 ID/BIP-340 signature, sent only as an AUTH frame.
An ACK for an obsolete challenge or ordinary publication cannot authorize the
current challenge. A new connection always starts unauthenticated.

After auth-required CLOSED/negative OK, a subscription/publication may retry once
following a newer accepted authentication. Restricted refusals do not retry.
Application errors contain closed `RELAY_*` codes, never relay reason text.
Writes have a ten-second deadline; frames are limited to 1 MiB, challenges to
4096 bytes and 32 signed challenges per connection. Excess challenges refuse.
Configuration is immutable after first use. The client reconnects only when its
caller invokes it again; `serve` retains its existing exit-on-transport-failure
behavior. No background reconnect loop or new relay server is included.

## Optional model_proxy configuration

When present, all fields are mandatory:

| Field | Meaning |
| --- | --- |
| `admin_socket` | Canonical absolute Unix socket path, at most 100 bytes |
| `server_uid` | Explicit unsigned proxy owner/peer UID; no inferred default |
| `origin` | Canonical HTTPS origin, no path, query, credentials or fragment |
| `cert_sha256` | Exact proxy leaf SHA256; repeated-byte placeholders refuse |
| `caps.input_tokens` | Positive total input-token cap |
| `caps.output_tokens` | Positive total output-token cap |
| `caps.requests` | Positive request cap |
| `caps.max_tokens` | Positive per-request output limit, at most output_tokens |
| `caps.cost_nano_usd` | Positive total integer nano-USD exposure cap |

Caps are operator decisions. Templates contain unresolved placeholders rather
than a spending allowance. The section requires the manager driver; `{}`, null,
partial fields, unknown fields, zero/invalid caps and implicit UID refuse.
Omission preserves the v1 bootstrap bytes exactly and constructs no registrar.

The production registrar is MP1's Unix `Client`, with socket owner and connected
peer UID verification. It requires Linux; there is no Darwin/TCP fallback. The
operator provisions its existing 0750 parent and 0660 socket under the proxy UID.
Gateway does not create service accounts, change ownership or read provider keys.

The wrapper pins the returned credential origin and leaf hash before gatewaybind
can write bootstrap v2. A mismatch returns no credential/bootstrap and never
activates the prepared bearer. Such a refusal may leave an inactive prepared
registry record; it is not evidence of a completed allocation. Successful Create
prepares a credential; StartSession activates it; End/Destroy revoke it, including
Reattach/Destroy after a gateway restart. The proxy independently enforces the
half-open booking window. Changing bootstrap profile/caps on existing broker state
remains subject to MP1's persisted profile checks; endpoint rotation/migration is
not provided here. A compatible payload must consume bootstrap v2 and enforce
its supplied TLS pin; payload implementation is a separate unit.

## Tools and evidence

From this module, with the pinned Go 1.26.8 toolchain and downloaded dependencies:

```sh
go test -race -count=1 ./gateway ./cmd/gateway
go run .scripts/ga1-guards.go -out .temp/ga1-guards
```

The guard runner copies task source into isolated temporary fixtures, runs valid
baselines, then requires each bounded guard-removal plant to reach its intended
assertion. It saves logs and original/mutant source hashes under the output path.
Original source is never modified by the runner.

Tests use real localhost websockets, signed AUTH, the real model registry and a
local HTTPS model fixture, durable gatewaybind and mTLS manager polling. They do
not run a host helper or a real model API. `linux-runtime` exercises the actual
serve constructor and Unix peer boundary on Linux; it explicitly skips elsewhere.
Linux cross-compilation alone is not execution evidence. Separate existing Core
and host qualification gates remain necessary for their respective claims.
