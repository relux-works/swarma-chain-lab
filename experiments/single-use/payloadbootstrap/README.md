# Public bootstrap metadata

`DecodeBootstrap(b []byte) (Bootstrap, error)` validates the existing canonical
v1/v2 station bootstrap and returns `V`, `BookingID`, `StationName`, optional
`ModelEndpoint`/`ModelCertSHA256`, and `SHA256` of every original byte. It returns
no channel secret or model bearer, and a zero result on `PAYLOAD_BOOTSTRAP`.
The wire format, 4096-byte bound and no-whitespace/no-newline canonical form are
unchanged. Input bytes are not modified. Slot and deadline are absent from this
wire format; bind them separately through checked payloadlaunch manifest/receipt
inputs. A matching digest alone proves no trusted file custody or authority.

`codec` is the explicitly credential-bearing compatibility package, not the root
consumer result. Its single generic wire schema holds credentials in
`codec.Secret[T]`, with an unexported pointer to scalar string storage. This also
protects invalid fmt verbs: bad-verb diagnostics bypass `String`/`GoString`, and
can dereference a nested pointer to a slice, but print a scalar pointer's address.
`codec.NewSecret(value)` copies input bytes; `Reveal()` returns the original
credential type with a fresh slice for channel consumers. Retain the wrapper in
struct fields and reveal only for an explicit credential operation. JSON encoding
is deliberately private and preserves the original v1/v2 bytes and field order.
The codec does not import lifecycle or proxy.
Gatewaybind aliases that schema and delegates encoding/decoding. Proxy credential
validation delegates to the same credential predicate. The public wrapper parses
through this codec, discards credentials and computes the digest. Neither package
reads files, environment or time, nor opens a network connection.

Compatibility callers construct fields with `gatewaybind.NewChannelSecret` and
`gatewaybind.NewModelBearer`, and read them through `Reveal()`. The downstream
`station.Station.ChannelSecret` handle likewise uses opaque storage constructed
by `station.NewChannelSecret`. The six-field public projection is unchanged.

Run `go test -race ./payloadbootstrap/...` from the single-use module inside
owned scratch. Shared literal golden vectors in `testdata/golden.json` include
valid v1/v2 neighbours and explicit refusal codes. Existing gatewaybind tests use
the same file and assert byte-exact re-encoding; public tests additionally assert
nonmutation, digest/projection and the fixed public field set. The source import
gate is calibrated by an isolated forbidden-import fixture. Run the repository's
`.scripts/dk5b-api-guards.go` for executable predicate/delegation controls.
