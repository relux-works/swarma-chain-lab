# Broker framing provenance

`canonical.go`, `frame.go` and `types.go` are unmodified copies of
`relux-works/swarma-credential-broker` commit
`698d9e40f57058addd80a82d56c356009239dea6` (see the full resolved pin in
`../../../../../docs/gateway-service.md`), paths `internal/wire/canonical.go` and
`internal/wire/frame.go` and `internal/wire/types.go`. They retain the upstream
Apache-2.0 license here.
The protocol uses four-byte big-endian lengths and CCJ-1 objects, not JSON lines.
No other broker implementation or provider lifecycle code is copied.


The upstream attribution is retained in `NOTICE`. Source SHA-256 values:

| File | SHA-256 |
| --- | --- |
| `canonical.go` | `11ef191c1ea85cafd7a95a3d37b0923284c3e6ca31b110136de70321baf02592` |
| `frame.go` | `c7d735b79534d9d1965fcab22fd3444f61d6d1c541bd537a1dfe848aa2c06d47` |
| `types.go` | `4d211115f8610df31c05bfc967c1fe6615ec8f6810bb256fe276d6b4b3c6a3cf` |

`TestPinnedCodecHashes` enforces these digests. `wire_test.go` adapts the
upstream canonical rejection, frame-bound, closed-schema, alias and failed-read
erasure tests, with a local request-schema fixture. The client uses the pinned
`Refuse` closed code set directly, without a second partial allow-list.
`TestBrokerRefusalTable` independently enumerates all 60 codes, compares that
table with every `Refuse` switch arm using Go's parser, and exercises each code
on all five lifecycle methods. Adding or dropping a wire code without updating
the reviewed table fails the test; changing a copied source also fails its pin.
Unknown codes are protocol failures, not members of a broker refusal bucket.
