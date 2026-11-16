# Retained plain-secret holders

PLAIN-SECRETS-2 implements the existing [credential output boundary](credential-output-n1b.md)
for four additional retained fields. Private wire/config schemas are unchanged;
generic formatting and automatic JSON/text projections redact.

| Retained field | Holder | Sole production Reveal* call | Tests |
| --- | --- | --- | --- |
| single-use `Route.Password` | module-local `RPCPassword` | `RPCPassword.SetBasicAuth`, at header construction | `TestRPCPasswordHolderRedaction`, `TestRPCPasswordConfigCompatibility`, `TestRPCPasswordStrictConfigNegative` |
| payment-chain `Route.Password` | module-local `RPCPassword` | `RPCPassword.SetBasicAuth`, at header construction | same names in the payment-chain module |
| journal `Slot.ChannelSecretHex` | existing `codec.Secret[string]` | existing explicit private consumers (see full carrier inventory) | existing journal/channel suites; retained field now also inventoried |
| journal `slotPrivate.ChannelSecretHex` | existing `codec.Secret[string]` | `EncodePrivateSlot` | `TestSlotPrivateHolderRedaction`, `TestJournalPrivateWireCompatibility`, `TestSlotPrivateWireGoldenVariants` |
| slotd `Request.Bootstrap` | module-local `*Bootstrap` | `encodePrivateRequest` | `TestBootstrapHolderRedaction`, `TestBootstrapPrivateWireGolden`, `TestBootstrapPrivateEncodingVariants`, `TestBootstrapInvalidNeverDials` |

RPC/base64 admission predicates and operation-specific accessors require the
small local holders; the journal reuses its existing generic holder.

The scalar-pointer storage prevents unsupported-verb diagnostics from walking
credential bytes through unexported containing fields. Holder/real-container
matrices cover standard fmt verbs, bad verbs, flags, width and precision, JSON
and encoding.TextMarshaler, plus slog text/JSON, beside populated non-secret
controls. Hidden pointer containers include %s/%q/%t and %+p/%#p. The detector
checks every eight-byte synthetic substring in plain, compact/space-flag hex
and decimal encodings; this is bounded regression evidence, not an arbitrary-code noninterference proof.

Each password holder accepts plain JSON strings. `JSONInputString` declares that
unchanged scalar schema to `singleuse.StrictInput`: lexical duplicate/escaped-key
checks still run first, exact field spelling still applies, and only JSON
strings pass the schema boundary. Arbitrary custom unmarshallers do not bypass
object traversal. Direct invalid-type holder decodes clear their old value;
encoding/json can reject malformed syntax before invoking a holder method.
A zero password still marshals as the legacy empty string so credential-free
wallet binding hashes retain their bytes. Populated generic encodings redact.
The existing CLI and installed gateway/wallet/signer config fixtures continue to
exercise their real loaders, in addition to frozen plain-string route vectors.

The single-use Route has additional consumers in agent-wallet, signer-service
and rental-executor. Their existing transports delegate header construction to
the holder, preserving the sole RevealForBasicAuth call site. Length predicates
retain
16..256 bounds, or the broadcaster's existing stricter 32..256 bounds. No new
cross-module dependency or replacement was added. The guard inventories the
sole `RevealForBasicAuth` call per password holder and sole `RevealForRequest`
call for Bootstrap; same-package field access is outside that source rule.
The holders remain in their existing packages.

The r2 consumer inventory is **12 go.mod files**, not two disjoint sets:
agent-wallet, signer-service, rental-executor, rental-gateway,
rental-gateway/kernelbind, grantcheck, grant-store, relay, m5-rehearsal,
m5-host-smoke, station-lifecycle/gatewaybind and station-payload. Each requires
single-use `v0.3.1-0.20261116084028-6fb17070638c`.
The r3 minimum additionally raises payment-chain, rental, rental-booking and
model-proxy to that version. Payment-chain's scalar password adapter needs
that StrictInput walker even when a consumer requires only payment-chain.
The other raised roots now state the same holder baseline explicitly.

Adapted tests also include rental-booking/regtest_test.go (private operator
observer configs), rental-gateway/kernelbind/core_e2e_test.go (opaque route
construction), and relay/delivery_size_test.go (explicit channel handoff).
The r3 rental-executor/process_core_test.go now projects both private routes;
its non-gated TestPrivateProcessConfigFixture checks Strict decoding and exact
password bytes, and demonstrates the old encoder's placeholder/refusal.

## Encoder audit

The tree audit covered every Route/slotPrivate/Request construction and each
`json.Marshal`, `json.MarshalIndent`, `json.NewEncoder` and local encoder helper
in the affected modules and consumers.

- Production Route JSON occurs inside generic config projections/bindings and
  now redacts. Credential-independent bindings clear the holder first and keep
  their previous empty-string encoding. Config input retains `json:"password"`.
- Private Route config writers are test fixtures. They now explicitly project
  into a frozen test-only legacy schema, including nested wallet config routes,
  rather than using the generic redacted Route. Core fixture setup still writes
  original credential bytes. Fixture-only accessor calls are excluded from the
  production source inventory, as before.
- `slotPrivateValue` copies the holder without revealing it. `EncodePrivateSlot`
  encodes the redacted DTO and substitutes only its known credential scalar at
  the original field position. The key cannot appear unescaped in a JSON string;
  its expected redacted value is checked before replacement. Empty credentials
  remain omitted. The frozen pre-existing legacy schema verifies exact disk
  bytes, reload, clearing, order and escaping.
- The sole production request writer is `Client.Call`. Its private encoder
  serializes public fields and appends the optional final bootstrap scalar,
  preserving v1 order, presence/omission, escaping and newline. A net.Pipe test
  compares the real outgoing stream with a pre-change golden, without a node or
  external helper. Fake helper test adapters compare private request bytes;
  ordinary `json.Marshal(Request)` remains redacted.

Transient Track B decoder DTOs, designated private proxy/lifecycle outputs,
notary and deploy are unchanged.

## Validation and controls

Run `gofmt`, `go vet ./...` and `go test -race -count=1 ./...` in each affected
module, using Go 1.26.10, GOTOOLCHAIN=local, task-owned absolute HOME/caches and
short owned TMPDIR paths. Genuine Core integration is separately gated and is
not exercised by the offline suite.

From an isolated task checkout run:

```sh
python3 -I .scripts/check-plain-secret-holders.py .temp/plain-secret-controls .tmp/plain-secret-overlays
go run .scripts/check-credential-output-boundaries.go
python3 -I experiments/model-proxy/session/tools/guard_controls.py .temp/credential-controls .tmp/credential-controls
python3 -B .scripts/check-module-graph.py
python3 -B .scripts/check-strict-module-snapshots.py
python3 -B .github/scripts/check-public-hygiene.py
```

The new control runner writes command/PID/exit/source-hash evidence to its first
argument and Go overlays to the new second directory. Each holder has a
JSON-redaction removal mutant and an inline-storage revert
mutant that retains the redacting methods. A kill requires exit 1, the named
output test, and its specific JSON or fmt disclosure assertion; compilation/setup
failures do not count. The inline controls calibrate method-bypassing fmt
reflection through real holders/containers. They do not independently calibrate
every verb or logging handler.

The credential guard retains its existing rules and adds five exact audited
field keys, including the already-opaque retained Slot.ChannelSecretHex. Its
controls require the complete expected inventory delta, including
raw substitutions for those fields. Graph/snapshot checks validate unchanged
module metadata; hygiene checks publication content. Producer evidence records
actual commands, exits and skips, and does not imply hosted CI or review acceptance.

The detached-v2 consumer manifest re-audits the strict-parser file hash after
its scalar-schema extension; its identifier behavior and guard rule are unchanged.
`TestPrivateWalletRouteFixtureBytes` additionally freezes nested private wallet
config routes beside a redacted public Config control, covering Core fixture
writers without making a local node call.
