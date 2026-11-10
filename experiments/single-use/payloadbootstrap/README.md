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
consumer result. Its single generic wire schema preserves the existing secret
types and redacting bootstrap formatting without importing lifecycle or proxy.
Gatewaybind aliases that schema and delegates encoding/decoding. Proxy credential
validation delegates to the same credential predicate. The public wrapper parses
through this codec, discards credentials and computes the digest. Neither package
reads files, environment or time, nor opens a network connection.

Run `go test -race ./payloadbootstrap/...` from the single-use module inside
owned scratch. Shared literal golden vectors in `testdata/golden.json` include
valid v1/v2 neighbours and explicit refusal codes. Existing gatewaybind tests use
the same file and assert byte-exact re-encoding; public tests additionally assert
nonmutation, digest/projection and the fixed public field set. The source import
gate is calibrated by an isolated forbidden-import fixture. Run the repository's
`.scripts/dk5b-api-guards.go` for executable predicate/delegation controls.
