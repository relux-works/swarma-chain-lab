# Broker framing provenance

`canonical.go` and `frame.go` are unmodified copies of
`relux-works/swarma-credential-broker` commit
`698d9e40f57058addd80a82d56c356009239dea6` (see the full resolved pin in
`../../../../../docs/gateway-service.md`), paths `internal/wire/canonical.go` and
`internal/wire/frame.go`. They retain the upstream Apache-2.0 license here.
The protocol uses four-byte big-endian lengths and CCJ-1 objects, not JSON lines.
No other broker implementation or provider lifecycle code is copied.
