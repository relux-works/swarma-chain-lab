# Authority JSON input boundaries (SJ1)

The lexical rule is refusal: every object key must appear once, with an
unescaped UTF-8 spelling. A key containing any JSON escape is refused, including
an otherwise equivalent single `"gr\u0061nt"`. Duplicate checks are recursive,
including objects in arrays and `json.RawMessage`. String **values** retain their
normal JSON escapes. There is no Unicode normalization or rewriting of signed
input. Typed consumers additionally require their declared field names; opaque
JSON keys have no additional invented schema. Existing full-byte canonical
checks, signature domains, integer rules, size limits and unknown-field rules
remain in force unless explicitly described below.

Why re-encoding alone is insufficient: `encoding/json` re-emits the contents of
`RawMessage`. An outer canonical comparison can therefore preserve two nested
`version` fields. Independently encoded JSON in strings is checked when that
string is interpreted as an object; opaque ciphertext/base64 is checked only
after decryption/decoding by its designated consumer.

## Decoder inventory and decisions

Paths below are relative to `experiments/` unless prefixed `../`.

| Path / consumers | Previous boundary | SJ1 rule and coverage |
| --- | --- | --- |
| `sealwatch/json.go`, `watch.go`; Core observation and RPC projections | Recursive folded-duplicate guard; single escaped names accepted | `ValidateJSON` rejects escaped keys and invalid UTF-8 before decoding. `DecodeJSON` and `ProjectJSON` share it. Unknown Core extensions remain allowed; exact projections reject aliases of selected fields. |
| `single-use/policy.go:StrictInput` | Shared lexical guard, exact struct/slice fields; map values bypassed schema | Validate lexical keys, then exact schema recursively through maps, then populate destination. `RawMessage` is opaque to schema, never to lexical checks. |
| `rental/certificate.go`, `grant.go` | StrictInput plus exact canonical bytes | Retain stronger canonical/signature checks for v1/v2/v3 certificates, signed grants and presentations. Actual v3 fixtures cover duplicate orders and escaped single/duplicate keys. |
| `rental/agent_value.go`, `landlord_value.go`, `discovery/` | Canonical name values or StrictInput | Same refusal for K1/N1 bindings and nested social metadata. No change to the 520-byte bound or authority/social-key distinction. `TestCoreSJ1NameKeys` exercises the real resolver against plain and N1 landlord name updates in isolated Core, both pending and confirmed. |
| `rental/issuance.go`, `issuance_v2.go`, issuer/cache state | Request canonical parser; Event and Content separately StrictInput plus canonical bytes | Preserve both boundaries. Re-signed publication tests mutate request, publication, embedded package, contract and consent keys. Grant/presentation caches and issuer journals inherit recursive checks. |
| `rental/grant_kernel.go` version probe | Plain version-only decode followed by canonical v2/v3 parser | Probe never admits state: every selected branch canonical-validates the complete record, default refuses. No additional parser or authority rule. |
| `rental-booking/contract.go:Strict`, HTTP/service loaders | Shared StrictInput; typed contracts/consent/package inputs | Inherit shared refusal. HTTP regressions assert refusal before address allocation, then valid booking and consent. Hash/signature construction remains unchanged. |
| `agent-wallet/wire.go`, `service_wire.go`, `service_client.go`, `service_receipt.go`, state | StrictInput plus exact canonical bytes; Params/Effect can be RawMessage | Recursive lexical checks precede authentication and state admission. Actual signed action and re-signed ambiguous receipt effects are tested. Embedded legacy Event.Content has its own strict parser. |
| `agent-wallet/single_use.go:oneoffKind` | Plain map discriminator | Discriminator grants nothing: either selected oneoff parser or standing-grant kernel must validate the complete object. RPC scalars and display-only receipt rendering likewise grant no authority. |
| `signer-service/engine.go:observe` Core `gettxout` result | Plain `json.Unmarshal` into a fixed projection from the read-only Core observation | Retained as a trusted single-source RPC projection, not competing authority-object decoders. Amount/script/confirmation binding is checked against the independently decoded transaction before use; this unit does not claim lexical key enforcement at this projection. |
| `grantcheck/checker.go:load` durable clock state | Typed `Unmarshal`, then complete `json.Marshal(m)` byte equality | Retained: fixed Version/Binding/High fields with no `RawMessage`; duplicate, escaped, aliased and unknown keys cannot survive exact canonical equality. Binding/version/range checks precede state admission. |
| `signer-service/types.go:strict`, outbox/intents/state | Shared StrictInput; embedded request booking-ID probe was plain JSON | Probe now uses exact `ProjectJSON` before replay lookup or issuer inspection. Tests retain ledger/files and count issuer calls. Trusted encode/decode clones and string-array outbox indexes have no independent object ingress. |
| `rental-executor/event.go:Strict`, event/content/Track B state | Shared StrictInput plus existing null/cardinality checks | Shared refusal applies before execution. RPC failure diagnostics do not admit results; success projections use the shared guard. |
| `rental-gateway/kernel/presentation.go` | Decoder plus outer canonical comparison; opaque grant admitted duplicates | Shared typed guard precedes version probe and hash. Framing still does not validate grant authority; real kernel does. |
| `rental-gateway/nostr/event.go`, `relay`, Blossom auth | Top-level-only duplicate scan and case-insensitive typed decode | ParseEvent uses StrictInput for wrapper/seal/rumor, relay events and auth events. Each separately decrypted layer is parsed through it. Explicit null fields and field aliases now refuse; serializer remains unchanged. `TestNIP01KnownEvent` retains an independently published signed event, including a whitespace/value-escape variant. Relay config retains its null walker and uses StrictInput for typed decoding. |
| `rental-gateway/journal` | Plain Unmarshal of durable slot records | Shared lexical checks plus exact Slot/OpRecord key names precede admission. Historical null slices/omitted fields remain supported; unknown/alias fields refuse. Refusal returns no Store and does not rewrite files. |
| `rental-gateway/stationlink`, `station/trackbadmin.go` | Plain frame / unbounded mint-reply decode | StrictInput before frame/token return; mint replies bounded to 4096 bytes. A malformed reply prevents local credential admission, not rollback of a remote mint already performed. |
| `rental-gateway/exchange/store.go` | Typed metadata/client Unmarshal plus exact canonical bytes | Retained: these trees have no opaque RawMessage. Pending Event.Content is interpreted through its own strict parser. Relay array framing parses objects via ParseEvent. Test relay helpers are not production admission. |
| `model-proxy/messages.go`, `admin.go`, `files.go`, `registry.go` | Recursive exact duplicates; canonical binding/config/ledger; escaped single keys accepted in protocol maps | Local walker rejects escaped keys; registry also calls it before typed admission. Admin and restart tests retain exact ledger bytes on refusal. Responses/Messages protocol objects share the walker; provider string content remains opaque. |
| `station-lifecycle/types.go`, `slotd/wire.go`, `gatewaybind/bootstrap.go` | Typed decoder plus exact canonical byte equality | Retained. Payload bootstrap is encoded bytes, separately decoded canonically before HMAC/model credentials are used. Existing closed-schema and response framing tests remain applicable. |
| `grant-store/store.go`, replay, client descriptors | Typed canonical metadata/replay; client descriptors plain JSON | Stored blobs are opaque bytes addressed by their hash, not grant validation. Auth events use ParseEvent; consumers validate blob authority. Descriptor parsing alone cannot admit a grant. |
| `../deploy/policy.go:uniqueJSON`, `services.go:serviceDecode` | Duplicate walker plus typed canonical/normalized comparison | Reject escaped keys before normalization. Follow-on model/coin projections consume already-validated input. No deployment is performed by this validation. |
| `m5-host-smoke/config.go:Strict` | Duplicate/null walker plus decoder | Retain null walker; shared StrictInput adds lexical/exact typed names before destination population. These parser regressions do not require a host-runner or production operation. |

`station-payload` display parsing occurs after `model-proxy` protocol validation.
`payment-chain` remaining plain JSON decodes select scalar hashes, not object
keys. Internal marshal/unmarshal copies operate on owned typed values. These are
not independent authority-object parsers and are not rewritten mechanically.


### Typed-schema limits (RSJ1-01 Info)

`StrictInput` is scoped to the repository's plain wire structs. Struct-typed
fields with a scalar custom JSON representation (for example `time.Time`) are
not supported: they fail closed as `INPUT_OBJECT`. It is not a drop-in decoder
for arbitrary `json.Unmarshaler` types or embedded field promotion. The current
reflection allowlist also includes unexported fields; Go's JSON decoder then
ignores a matching key. Existing authority wire schemas use exported fields,
so that behavior grants no authority and does not admit a field alias. This
revision documents these pre-existing limits rather than broadening the parser
schema or changing unrelated wire behavior. New wire schemas must not rely on
custom scalar structs or unexported JSON fields.

## Executable evidence and limits

`TestSJ1*` cases sit beside each changed decoder. They include both duplicate
orders, escaped duplicate/single spellings, nested RawMessage/array cases,
valid neighbors, unchanged destinations and concrete no-admission/no-write
checks at journal, registry and signer seams. Existing product negative suites
remain enabled. A pure parser test does not establish OS custody, a live RPC
transaction, or remote rollback. Integration suites that require an explicitly
provisioned Core remain opt-in; ordinary test success is not Core execution. The separately enabled `TestCoreSJ1NameKeys` records eight pending refusals, eight confirmed refusals and eight repaired valid neighbors, with no resolver chain/mempool/state mutation. It tests landlord resolution, not every agent-pointer lifecycle.

`.scripts/sj1-guards.go` runs bounded Go overlays against unchanged source. Each
plant must match exactly once, its baseline must pass, and the mutant must fail
with the intended assertion rather than a build error, panic or timeout. It
covers duplicate and escape guard removal, a typed-map alias bypass, opaque
wallet effects, embedded signer requests, gateway framing/journal/Nostr/private
wire seams, and model/deploy walkers. Canonical typed paths have an independent
second refusal and are not expected to fail merely because a redundant lexical
guard is removed.

Run only from a task-owned physical checkout with absolute HOME, GOROOT, module
cache, build cache, config and temp directories inside the same scratch root:

```sh
go test -race -count=1 ./...  # run in each affected Go module
go run .scripts/sj1-guards.go -out /absolute/new-task-scratch/sj1-controls
```

The overlay command runs at repository root. Its output directory contains
baseline/mutant logs, overlays, source/mutant hashes, direct child PIDs, exits and
`results.json`. The launcher records the source commit/diff and environment.
This chain-lab unit is separate from the subsequent a2a-transport-nostr envelope
and extensions unit; it makes no claim that the latter has already changed.

RSJ1-01 requires the existing module guard instruments as well as the root SJ1
controls. Run every `experiments/*/.scripts/*guards.go`,
`experiments/grant-store/.scripts/guard-controls.go` and
`deploy/.scripts/dk2-guards.go` from its module directory with a fresh `-out`
path. The relay duplicate control targets `strictShape` directly, so its
second shared guard cannot hide a missed mutation. Core-specific controls
remain separately opt-in and must never be reported as executed by a default
non-Core run.
