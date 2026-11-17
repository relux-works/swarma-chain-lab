# Broker framing provenance

`canonical.go` and `frame.go` are unmodified copies of
`relux-works/swarma-credential-broker` commit
`698d9e40f57058addd80a82d56c356009239dea6` (see the full resolved pin in
`../../../../../docs/gateway-service.md`), paths `internal/wire/canonical.go` and
`internal/wire/frame.go`. They retain the upstream Apache-2.0 license here.
The protocol uses four-byte big-endian lengths and CCJ-1 objects, not JSON lines.
No other broker implementation or provider lifecycle code is copied.


The upstream attribution is retained in `NOTICE`. Source SHA-256 values:

| File | SHA-256 |
| --- | --- |
| `canonical.go` | `11ef191c1ea85cafd7a95a3d37b0923284c3e6ca31b110136de70321baf02592` |
| `frame.go` | `c7d735b79534d9d1965fcab22fd3444f61d6d1c541bd537a1dfe848aa2c06d47` |

`TestPinnedCodecHashes` enforces these digests. `wire_test.go` adapts the
upstream canonical rejection, frame-bound, closed-schema, alias and failed-read
erasure tests, with a local request-schema fixture. The upstream refusal-code
test is omitted because its error types are outside the copied codec; the
service client tests exercise the local closed diagnostic seam instead.
