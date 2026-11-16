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

The executable inventory uses a nested exact multiset:
`accessor name -> {path:owner:expression -> count}`. Run
`go run .scripts/check-credential-output-boundaries.go` from the repository root.
The independently listed [inventory fixture](../../.scripts/credential-output-inventory.json)
contains **18 carrier fields**, **53 direct Reveal sites / 67 calls**, and
four accessor keys: `Reveal` with those 53 entries, `RevealForBasicAuth` with
2 sites / 2 calls, `RevealForRequest` with 1 site / 1 call, and `RevealForOpen`
with the empty set `{}`. There are currently no inventoried method values.
The earlier plain-Reveal boundaries retain their operation counts; the journal
site now reveals in its private encoder instead of its DTO constructor.
The larger set also inventories bootstrap, channel-secret, model-bearer and
private lifecycle codec boundaries. The counts cover source expressions, not
runtime invocation frequency. Carrier fields include `Facts.Token`,
`Facts.Random` and the one-time `Result.Token`; the session token's explicit
opening accessor has no production call sites.

Every direct call whose selector starts with `Reveal` is counted on **any
receiver**, including plain `Reveal`. A selector outside the direct function
position of a call is also counted as a reveal site (for example,
`t.RevealForOpen` in `g := t.RevealForOpen; g()`). Direct calls are counted once;
method expressions are included. Every `Reveal*` method declaration on any type
in any scanned directory registers its accessor-name key, even without callers.
A new accessor requires an explicit expected set, empty unless reviewed call
sites exist. The existing generic `codec.Secret[T].Reveal` and lifecycle
`PrivateBytes.Reveal` remain unchanged; their actual call expressions are listed
under `Reveal`. Keys identify selector names, not type-resolved method identities.

The scanner traverses function bodies, named type declarations and package-level
`ValueSpec` initializers, including anonymous carrier structs and nested function
literals. Package-level initializers use owner `var`. It scans non-test `.go`
and `.go.txt` files across the tree, excluding dot directories and `vendor`.
Build tags do not exclude source from the syntax inventory. Exact carrier types,
accessor keys, site sets and multiplicities must match or the guard exits 1 with
`credential storage/reveal inventory changed; re-audit required` and the observed
inventory. Output consists of expression spellings and types, not revealed values.

This is a source-change guard, not an arbitrary-code taint proof. Explicit limits:
reflection by string, including `MethodByName("RevealForOpen")`, is not detected;
casts/conversions such as `[32]byte(t)` and slicing such as `t[:]` bypass name
matching; `_test.go` files are excluded. Alias/dataflow analysis, arbitrary
caller logging, dynamic behavior and receiver type resolution are outside scope.

Run the copied-tree controls with an absent fixture directory:
`python3 -I experiments/model-proxy/session/tools/guard_controls.py .temp/credential-controls .tmp/credential-controls`.
Use the pinned Go toolchain and task-owned absolute HOME, caches and TMPDIR.
The positive compares every field, accessor and expression against the listed
fixture. Every negative requires exit 1, the inventory diagnostic and its exact
whole-inventory delta, including package-level calls/function literals, method
values and an unused non-carrier accessor. Optional trailing legacy guard source
paths compare unchanged carrier and old Reveal multisets and rerun the old
rules' controls. Logs and PID/exit/witness records go in the first argument;
fixture and guard binaries stay under the second argument's parent. Controls
are local evidence; the hosted model-proxy workflow runs the guard and race
suite, not this Python runner.

Constructors copy their inputs. Failed wrapper decodes and public mint refusals
return no credential.

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
substring of the synthetic credential, with the same original-byte bound
after hex/base64 encoding, plus positive and negative controls. Typed map keys
and direct JSON/text encoding interfaces are checked separately. Live service/driver state, request/reply carriers and recorded
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

Run from the repository root with Go 1.26.10 and `GOTOOLCHAIN=local`:

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

## Exact-listed audit notes

The JSON fixture is the executable exact positive. The tables below annotate
every field, accessor key and source site; counts are source multiplicities.
Existing operations and their private boundaries are unchanged by this guard.

| Carrier key | Type | Audit note |
| --- | --- | --- |
| `experiments/single-use/node.go:Route.Password` | `RPCPassword` | Plain-string config decode; sole production accessor call installs the Basic Auth header. |
| `experiments/payment-chain/rpc.go:Route.Password` | `RPCPassword` | Module-local holder; watcher/issuer config and header bytes remain unchanged. |
| `experiments/rental-gateway/journal/private.go:slotPrivate.ChannelSecretHex` | `codec.Secret[string]` | Reuses the journal's existing holder; only EncodePrivateSlot emits private bytes. |
| `experiments/station-lifecycle/slotd/wire.go:Request.Bootstrap` | `*Bootstrap` | Optional base64 holder; sole production accessor call is the Unix request encoder. |
| `experiments/m5-rehearsal/fixtures/registrar.go.txt:rehearsalRegistrar.APIKey` | `proxy.UpstreamKey` | Rehearsal fixture retains the opaque proxy key. |
| `experiments/model-proxy/credential.go:FileSource.current` | `UpstreamKey` | Retained file-sourced key is an opaque holder. |
| `experiments/model-proxy/credential.go:UpstreamCredential.Value` | `UpstreamKey` | Private upstream credential remains opaque. |
| `experiments/model-proxy/credential.go:staticSource.value` | `UpstreamKey` | Retained static upstream key remains opaque. |
| `experiments/model-proxy/session/session.go:Facts.Random` | `Token` | Opening entropy draw; opaque token with redacting encoders. |
| `experiments/model-proxy/session/session.go:Facts.Token` | `Token` | Ephemeral use input; opaque token with redacting encoders. |
| `experiments/model-proxy/session/session.go:Result.Token` | `*Token` | One-time opening result; pointer retains token redaction. |
| `experiments/model-proxy/types.go:Config.APIKey` | `UpstreamKey` | Retained upstream key is an opaque holder. |
| `experiments/rental-executor/http.go:decodeTrackBClaim.Token` | `string` | Transient raw private decoder DTO; strict schema preserved, never retained. |
| `experiments/rental-executor/http.go:trackBClaimRequest.Token` | `TrackBToken` | Decoded private claim request retains an opaque token. |
| `experiments/rental-gateway/station/linuxuser.go:FakeExec.Inputs` | `[]codec.Secret[[]byte]` | Recorded private stdin is an opaque secret slice. |
| `experiments/rental-gateway/station/station.go:Station.TrackBToken` | `TrackBToken` | Station handle retains an opaque Track B token. |
| `experiments/rental-gateway/station/trackbadmin.go:decodeTrackBMintReply.Token` | `string` | Transient raw private response decoder DTO; never retained. |
| `experiments/rental-gateway/station/trackbadmin.go:trackBMintReply.Token` | `TrackBToken` | Decoded private mint reply retains an opaque token. |

| Accessor key | Registered declarations | Audit note |
| --- | --- | --- |
| `Reveal` | `codec.Secret[T].Reveal`; `lifecycle.PrivateBytes.Reveal` | Private consumer access and private bootstrap delegation, including the non-carrier lifecycle wrapper. All 53 sites / 67 calls are listed below; zero current method values. |
| `RevealForOpen` | `session.Token.RevealForOpen` | Opening-only token conversion; exact empty caller set, no production call. |
| `RevealForBasicAuth` | Module-local `RPCPassword.RevealForBasicAuth` | Exactly one call per password holder, in its Basic Auth header installer. |
| `RevealForRequest` | `slotd.Bootstrap.RevealForRequest` | Exactly one call in the private Unix request encoder. |

Keys are per selector name. A new method sharing an existing key does not
create a new type-resolved key; receiver identity is outside this syntax guard.

| Reveal site | Calls | Audit note |
| --- | --- | --- |
| `experiments/model-proxy/admin.go:Credential.Valid:c.Bearer.Reveal()` | 1 | Validates bearer encoding and endpoint/certificate constraints without publishing bearer bytes. |
| `experiments/model-proxy/credential.go:FileSource.read:f.current.Reveal()` | 1 | Compares private file bytes with the current key in constant time to update its version. |
| `experiments/model-proxy/credential.go:Service.issued:c.Value.Reveal()` | 1 | Registers issued private credential spellings with the bounded in-memory tripwire. |
| `experiments/model-proxy/credential.go:UpstreamCredential.valid:c.Value.Reveal()` | 1 | Checks upstream credential validity without returning raw key bytes. |
| `experiments/model-proxy/credential.go:authenticate:c.Value.Reveal()` | 1 | Constructs the private OAuth Authorization header after clearing stale authentication headers. |
| `experiments/model-proxy/messages.go:Messages.Headers:key.Reveal()` | 1 | Constructs the private upstream Messages authentication header. |
| `experiments/model-proxy/private.go:credentialPrivateValue:s.Bearer.Reveal()` | 1 | Copies bearer into the explicit private credential wire DTO; generic encoders still redact. |
| `experiments/model-proxy/private.go:recordPrivateValue:s.Bearer.Reveal()` | 1 | Copies bearer into the explicit private registry persistence DTO. |
| `experiments/model-proxy/registry.go:Service.authorize:r.Bearer.Reveal()` | 1 | Constant-time comparison against the presented bearer before phase/window admission. |
| `experiments/model-proxy/registry.go:newService:c.APIKey.Reveal()` | 3 | Checks static key presence/validity and registers it with the in-memory credential tripwire. |
| `experiments/model-proxy/registry.go:newService:r.Bearer.Reveal()` | 4 | Decodes and validates restored private bearer records and checks their uniqueness; no public output. |
| `experiments/model-proxy/responses.go:Responses.Headers:key.Reveal()` | 1 | Constructs the private upstream Responses Authorization header. |
| `experiments/model-proxy/tripwire.go:Service.foreignBearer:r.Bearer.Reveal()` | 1 | Compares a supplied credential against other private bearer records for the tripwire. |
| `experiments/model-proxy/tripwire.go:Service.foreignLeak:r.Bearer.Reveal()` | 1 | Compares the supplied bearer with other private records before applying the leak freeze. |
| `experiments/model-proxy/types.go:Credential.Equal:c.Bearer.Reveal()` | 1 | Constant-time comparison of the two credential values, returning only equality. |
| `experiments/model-proxy/types.go:Credential.Equal:other.Bearer.Reveal()` | 1 | Constant-time comparison of the two credential values, returning only equality. |
| `experiments/rental-executor/http.go:writeTrackBMintReply:token.Reveal()` | 1 | Encodes the token into the intentional private admin mint response. |
| `experiments/rental-executor/trackb.go:TrackB.Claim:token.Reveal()` | 2 | Validates and hashes the supplied claim token before commitment comparison. |
| `experiments/rental-executor/trackb.go:TrackB.Mint:token.Reveal()` | 1 | Hashes freshly minted token bytes; token store retains the commitment. |
| `experiments/rental-gateway/gateway/gateway.go:Gateway.startStation:st.TrackBToken.Reveal()` | 1 | Hashes the private station token; journal retains only its commitment. |
| `experiments/rental-gateway/gateway/inbound.go:Gateway.stationAuth:slot.ChannelSecretHex.Reveal()` | 2 | Checks credential presence and decodes it for private channel challenge verification. |
| `experiments/rental-gateway/gateway/inbound.go:Gateway.stationHello:slot.ChannelSecretHex.Reveal()` | 1 | Checks registered credential presence before starting the channel challenge. |
| `experiments/rental-gateway/journal/journal.go:Store.SetChannelCredential:credential.Reveal()` | 1 | Encodes the channel credential for the existing private journal setter. |
| `experiments/rental-gateway/journal/private.go:EncodePrivateSlot:value.ChannelSecretHex.Reveal()` | 1 | Serializes channel bytes only inside the explicit private journal encoder; its retained DTO remains opaque. |
| `experiments/rental-gateway/station/linuxuser.go:LinuxUserDriver.Create:token.Reveal()` | 1 | Supplies token bytes through private driver stdin for station creation. |
| `experiments/rental-gateway/station/localtest.go:LocalTestDriver.Create:token.Reveal()` | 1 | Writes the private station token file using the existing local driver boundary. |
| `experiments/rental-gateway/station/trackbadmin.go:TrackBAdminClient.Mint:out.Token.Reveal()` | 1 | Validates the private mint response before returning its opaque token. |
| `experiments/single-use/payloadbootstrap/codec/codec.go:Valid:b.ChannelSecret.Reveal()` | 1 | Checks channel-secret length and version-specific model-bearer validity; returns a boolean. |
| `experiments/single-use/payloadbootstrap/codec/codec.go:Valid:b.ModelBearer.Reveal()` | 2 | Checks channel-secret length and version-specific model-bearer validity; returns a boolean. |
| `experiments/single-use/payloadbootstrap/codec/codec.go:privateWire:b.ChannelSecret.Reveal()` | 1 | Extracts channel/model credentials for the intentional private bootstrap wire format. |
| `experiments/single-use/payloadbootstrap/codec/codec.go:privateWire:b.ModelBearer.Reveal()` | 1 | Extracts channel/model credentials for the intentional private bootstrap wire format. |
| `experiments/station-lifecycle/broker.go:Broker.Credential:r.Credential.Reveal()` | 2 | Checks length and returns a copied private credential to the authorized broker consumer. |
| `experiments/station-lifecycle/broker.go:NewBroker:r.Credential.Reveal()` | 2 | Validates persisted stopped/live private credential and bootstrap consistency. |
| `experiments/station-lifecycle/broker.go:NewBroker:v.Bootstrap.Reveal()` | 2 | Validates persisted stopped/live private credential and bootstrap consistency. |
| `experiments/station-lifecycle/gatewaybind/driver.go:Driver.Create:bootstrap.ChannelSecret.Reveal()` | 1 | Decodes private bootstrap and compares its channel credential before driver creation. |
| `experiments/station-lifecycle/gatewaybind/driver.go:Driver.Create:v.Bootstrap.Reveal()` | 1 | Decodes private bootstrap and compares its channel credential before driver creation. |
| `experiments/station-lifecycle/gatewaybind/driver.go:Driver.StartSession:bootstrap.ChannelSecret.Reveal()` | 1 | Decodes private bootstrap and compares channel credentials before starting a session. |
| `experiments/station-lifecycle/gatewaybind/driver.go:Driver.StartSession:st.ChannelSecret.Reveal()` | 1 | Decodes private bootstrap and compares channel credentials before starting a session. |
| `experiments/station-lifecycle/gatewaybind/driver.go:Driver.StartSession:v.Bootstrap.Reveal()` | 1 | Decodes private bootstrap and compares channel credentials before starting a session. |
| `experiments/station-lifecycle/gatewaybind/driver.go:New:credential.Bearer.Reveal()` | 1 | Copies the model bearer into an explicit private bootstrap during provisioning. |
| `experiments/station-lifecycle/manager.go:Manager.Apply:c.Slot.Bootstrap.Reveal()` | 1 | Hashes bootstrap bytes to check/create the persisted command binding. |
| `experiments/station-lifecycle/manager.go:Manager.Apply:s.Bootstrap.Reveal()` | 1 | Hashes bootstrap bytes to check/create the persisted command binding. |
| `experiments/station-lifecycle/manager.go:Manager.Start:s.Bootstrap.Reveal()` | 2 | Hashes bootstrap bytes for incoming binding and the starting record commitment. |
| `experiments/station-lifecycle/manager.go:New:v.Bootstrap.Reveal()` | 2 | Validates restored bootstrap presence/hash against persisted lifecycle state. |
| `experiments/station-lifecycle/private.go:brokerRecordPrivateValue:s.Credential.Reveal()` | 1 | Copies the broker credential into its explicit private persistence DTO. |
| `experiments/station-lifecycle/private.go:slotPrivateValue:s.Bootstrap.Reveal()` | 1 | Copies bootstrap bytes into the explicit private slot persistence DTO. |
| `experiments/station-lifecycle/private_bytes.go:PrivateBytes.Reveal:p.value.Reveal()` | 1 | Delegates the explicit reveal to the opaque generic holder, retaining nil/empty behavior. |
| `experiments/station-lifecycle/slotd/host.go:Host.Start:s.Bootstrap.Reveal()` | 1 | Base64-encodes bootstrap into the private slot-host creation request. |
| `experiments/station-lifecycle/slotd/host.go:bound:s.Bootstrap.Reveal()` | 1 | Hashes bootstrap to verify the private host response binding. |
| `experiments/station-lifecycle/types.go:Range.validateSlot:s.Bootstrap.Reveal()` | 2 | Checks only bootstrap length against the existing slot-policy bounds. |
| `experiments/station-payload/client.go:Client.generate:c.bootstrap.ModelBearer.Reveal()` | 1 | Constructs the authenticated private upstream Authorization header. |
| `experiments/station-payload/responses.go:Client.generateResponses:c.bootstrap.ModelBearer.Reveal()` | 1 | Constructs the authenticated private Responses Authorization header. |
| `experiments/station-payload/session.go:Client.Run:b.ChannelSecret.Reveal()` | 1 | Supplies channel credential to the private station-link handshake. |

### Retained plain-secret extension (PLAIN-SECRETS-2)

[The four-field audit](plain-secret-holders.md) explains the holder and consumer
changes. The existing carrier-name and Reveal-prefix detection rules are kept;
four exact audited field keys are additionally selected from the expected
inventory. Controls pin all 18 field types and all four accessor-name multisets,
including raw-field substitutions for each new row. This does not import the
separate tree-wide carrier-classification rule or change its policy.

The journal Reveal site moved from DTO construction to EncodePrivateSlot, with
its count unchanged. New production sites are:

| Site | Calls | Boundary |
| --- | --- | --- |
| `experiments/single-use/rpc_password.go:RPCPassword.SetBasicAuth:p.RevealForBasicAuth()` | 1 | Basic Auth header construction for existing route consumers. |
| `experiments/payment-chain/rpc_password.go:RPCPassword.SetBasicAuth:p.RevealForBasicAuth()` | 1 | Basic Auth header construction for payment routes. |
| `experiments/station-lifecycle/slotd/wire.go:encodePrivateRequest:bootstrap.RevealForRequest()` | 1 | Private Unix socket request serialization. |
