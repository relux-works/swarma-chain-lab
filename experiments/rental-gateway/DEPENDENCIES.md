# Dependencies (rental-gateway)

Direct requirements (everything else in `go list -m all` is a
transitive test/tooling entry of these; see `go.sum` for the full
graph). Sums verified with `go mod download -json` on 2026-11-08.

| Module | Version | Sum | License | Used for |
| --- | --- | --- | --- | --- |
| `github.com/btcsuite/btcd/btcec/v2` | v2.3.5 | `h1:dpAlnAwmT1yIBm3exhT1/8iUSD98RDJM5vqJVQDQLiU=` | ISC | BIP-340 schnorr sign/verify, ECDH |
| `github.com/decred/dcrd/dcrec/secp256k1/v4` | v4.4.0 | `h1:NMZiJj8QnKe1LgsbDayM4UoHwbvwDRwnI3hwNaAHRnc=` | ISC | secp256k1 field/scalar ops via btcec/v2 |
| `golang.org/x/crypto` | v0.55.0 | `h1:+KWHjbgOaAQ66dh/YlkZKHlz9ZUlq61AFirAR9ntP8M=` | BSD-3-Clause | ChaCha20 + HKDF for NIP-44 v2 |
| `github.com/gorilla/websocket` | v1.5.3 | `h1:saDtZ6Pbx/0u+bgYQ3q96pZgCzfhKXGPqt7kZ72aNNg=` | BSD-2-Clause | relay client + in-process test relay |

Not a dependency: `github.com/nbd-wtf/go-nostr` (surveyed at
v0.52.3, `h1:Xd87pXfJEJRXHpM+fLjQQln8dBNNaoPA10V7BbyP4KI=`). Used
only as a scratch interop oracle during development; kept out of
`go.mod` because the shipped strict unwrap must refuse what its
`GiftUnwrap` silently rewrites (rumor pubkey := seal pubkey), and
because its single module pulls a 102-module graph.

Test-vector provenance: BIP-340 vector 0 (bitcoin/bips), official
NIP-44 v2 valid/invalid vectors (noble/nostr test vectors as carried
in multiple implementations), one published NIP-01 event
(id `dc90c95f…`) for id/signature recomputation.

The nested `kernelbind/` module additionally depends only on
in-tree siblings (`experiments/rental`, `experiments/single-use`,
`experiments/sealwatch` via replaces) and this module; see its
`go.mod`. The adapter targets the landed K1 v3 API; no external or
bench-local module replacement is needed.

E1 adds the in-tree `single-use/durable` package to the root module for private,
locked, fsynced state. The nested binding adds in-tree `rental-booking` and its
already-pinned `btcd v0.24.2` / `btcutil v1.1.5` dependencies; its selected
`chainhash` becomes v1.1.0, matching booking. The root gateway retains chainhash
v1.0.1. HD derivation imports in binding tests use public regtest fixtures only.
No external module replacement or new wallet/signing capability is exposed by
`exchange` or `bookingbind`.
