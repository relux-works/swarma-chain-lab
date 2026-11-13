# N1b credential output boundary inventory

This public-window gate covers the per-slot Track B token and the operator's
upstream model API key. It uses the same opaque storage defense as PR85:
`codec.Secret` owns credential bytes behind an unexported scalar string pointer.
Method-bypassing fmt diagnostics can inspect only an address. Generic JSON and
text encoders redact; explicit private wire and authentication operations reveal.
The approved bootstrap public projection is unchanged.

## Carriers and flows

| Class | Carrier or boundary | Representation / permitted operation |
|---|---|---|
| Track B | executor `TrackB.Mint` return and `TrackB.Claim` argument | `TrackBToken`, an alias of `codec.Secret[string]` |
| Track B | executor `trackBClaimRequest.Token` | Opaque; strict private DTO decoder preserves the former schema |
| Track B | executor mint response | `writeTrackBMintReply` reveals inside the private admin response encoder; original JSON bytes, headers and status retained |
| Track B | executor `TokenRecord`, `tokenState`, audit, windows and disk journal | Only SHA-256 commitments and bounded metadata; no raw token retained |
| Track B | station `TokenAdmin`, `TrackBAdminClient.Mint`, `MintToken` | Opaque API results, including local random minting and all refusal results |
| Track B | station `trackBMintReply.Token` | Opaque after the original strict schema is decoded inside a local private DTO |
| Track B | `Station.TrackBToken`, station copies, local/Linux drivers | Opaque; no string credential field survives in the driver handle |
| Track B | `FakeExec.Inputs` and Linux driver interface retention | Recorded private stdin is opaque too; explicit input accessor used only by tests |
| Track B | private station token file | Original hex token plus newline; exclusive 0600 write; destroy removes the home |
| Track B | gateway `startStation`, journal `Slot.TokenSHA256` | Reveal directly into SHA-256; journal and recovery retain only that commitment |
| Upstream key | model `Config.APIKey`, `Service.cfg`, copies and nested config values | `UpstreamKey`, alias of the same opaque holder |
| Upstream key | `Dialect.Headers`, Messages and Responses | Opaque argument; reveal only while constructing fresh upstream authentication headers |
| Upstream key | model CLI `ReadInstalledFile` -> `NewAPIKey` | Raw private file bytes are a temporary constructor input, never a retained configuration field |
| Upstream key | rehearsal registrar configuration | Opaque decoded field; private rehearsal input bytes and TLS credentials remain inside their explicit fixture boundaries |
| Upstream key | model registry, returned status and audit | Key is absent from the schema and configuration fingerprint; bearer records retain their previous distinct opaque credentials |
| Upstream key | deploy templates, service configuration and model profile | Contain only the private key-file path; deployment does not receive a raw API-key field |

The Track B flow is `executor mint -> private admin JSON -> station admin
client -> driver handle -> private file / gateway SHA-256`. Claims decode a
private request directly into an opaque request carrier, hash it, and compare
commitments in constant time. No token is added to journal/audit state.

The upstream flow is `installed private key file -> NewAPIKey -> Config ->
Service -> Dialect.Headers -> authenticated upstream request`. Neither the
Messages nor Responses dialect receives a plain string credential. Validation
reveals locally to enforce the unchanged ASCII/length bounds. No key is added
to a bootstrap, model registry, status or audit.

## Explicit reveals and raw-byte exceptions

The executable inventory lists every target reveal site, expression and count:
`go run .scripts/check-credential-output-boundaries.go`. It also records the
four pre-existing model-bearer reveals in `New`, because it checks that entire
validation function. Source changes adding a named credential carrier, changing
its type or changing this reveal inventory fail the guard and require re-audit.
Detector controls cover an added carrier, raw retained field and new reveal
site. This source-change guard is not an arbitrary-code taint proof.

Target reveals are limited to model `New` (three calls), Messages/Responses
`Headers` (one each), station local/Linux `Create` (one each), admin reply length
validation (one), gateway token commitment (one), executor `Mint` commitment
(one), `Claim` validation/commitment (two), and the private mint reply encoder
(one). There are **13 calls** for these two classes. Constructors copy their
inputs. Failed wrapper decodes and public mint refusals return no credential.

Local private decoder DTOs temporarily hold raw strings to preserve the existing
strict schema: the shared strict checker deliberately does not trust arbitrary
custom unmarshallers. These DTOs never escape the decoder. The private mint
encoder's transient map and authenticated HTTP headers intentionally contain
credentials; their bytes are private outputs, not logging projections. Private
file IO buffers and process stdin are likewise explicit private boundaries.
The audit excludes arbitrary caller code that deliberately logs a revealed
value or supplies an exfiltrating transport/driver implementation.

## Regression and compatibility evidence

`TestN1bUpstreamKeyOutput`, `TestN1bTrackBTokenOutput` and
`TestN1bMintedTokenOutput` adapt the rev232/rev234 probes: every standard fmt
verb, bad verbs, flag/width/precision variants, fmt/log/error sinks, direct and
nested JSON/text slog, and generic JSON. Their detectors check every eight-byte
substring of the synthetic credential and encoded forms, with positive and
negative controls. Live service/driver state, request/reply carriers and recorded
stdin are included. Generic JSON may safely refuse function-bearing configs;
that refusal is distinguished from a successful redaction.

The first probes fail on main `94791671`; the operator key reaches fmt's `%p`
bad-verb path despite its former String/Format methods. Fixed failure messages
do not quote credential bytes. Existing assertions, expected literals and golden
vectors are preserved through setup/access adapters, with executable AST and
literal comparison evidence attached to the producer report.

`TestN1bTrackBWireDifferential` and `TestN1bTokenFileAndReplyBytes` retain exact
private mint/claim and token-file bytes, strict rejection bounds, cleared refusal
state and destroy behavior. `TestN1bUpstreamKeyBoundaries` checks exact Messages
and Responses headers over 64 inputs, invalid-key refusals, registry exclusion
and decode/copy isolation. Earlier PR85 privacy and wire tests remain in place.

## Tools

Run from the repository root with Go 1.26.8:

```sh
go run .scripts/check-credential-output-boundaries.go > .temp/n1b-boundaries.json
go -C experiments/model-proxy test ./...
go -C experiments/rental-executor test ./...
go -C experiments/rental-gateway test ./...
```

The same module paths accept `go vet ./...`. The producer report lists every
additional consumer module tested, real exit codes, skips, mutant controls and
exact commands; task-scoped logs live outside the source checkout in the
keeper-authorized `.temp/n1b/` evidence directory. No deployment qualification
or keeper acceptance is inferred from these tests.
