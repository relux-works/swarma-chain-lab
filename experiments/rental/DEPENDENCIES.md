# M1 dependency pins and verified checksums

Go proxy downloads verified through `sum.golang.org` on 2026-11-08. These are pinned dependencies, not a statement that the versions are latest or independently audited. No Nostr framework is added. Runtime dependencies use permissive ISC (btcec, chainhash, Decred) or BSD-3-Clause (x/crypto) licenses; the delivery packet includes their exact license files.

| Module | Version | Module checksum | go.mod checksum |
| --- | --- | --- | --- |
| github.com/btcsuite/btcd/btcec/v2 | v2.3.5 | h1:dpAlnAwmT1yIBm3exhT1/8iUSD98RDJM5vqJVQDQLiU= | h1:m22FrOAiuxl/tht9wIqAoGHcbnCCaPWyauO8y2LGGtQ= |
| github.com/btcsuite/btcd/chaincfg/chainhash | v1.0.1 | h1:q0rUy8C/TYNBQS1+CGKw68tLOFYSNEs0TFnxxnS9+4U= | h1:7SFka0XMvUgj3hfZtydOrQY2mwhPclbT2snogU7SQQc= |
| github.com/decred/dcrd/crypto/blake256 | v1.1.0 | h1:zPMNGQCm0g4QTY27fOCorQW7EryeQ/U0x++OzVrdms8= | h1:2OfgNZ5wDpcsFmHmCK5gZTPcCXqlm2ArzUIkw9czNJo= |

Existing W3 dependencies remain Decred secp256k1/v4 v4.4.0 and x/crypto v0.55.0. btcec uses the former through minimum-version selection. chainhash supplies BIP-340 tagged hashing; blake256 is linked through the Decred error/nonce implementation imported by btcec (not used as the certificate hash). An initial blake256 v1.0.1 cache download was superseded by secp256k1 v4.4.0's requirement v1.1.0; it is not selected. Exact build dependency graph, licenses and test-only modules will be recorded in the final packet.

btcec source commit 253c36dd2729fc75e043259fec32c17472a31b54, tag btcec/v2.3.5. `go.sum` contains full checksums for new and reused modules. `go list -deps -json ./cmd/...` records actual binary dependencies; `go list -m -json all` also lists graph-only modules, not necessarily linked runtime code.

Compatibility finding: btcec v2.3.5 accepts only 32-byte Schnorr messages. It
rejects official vectors 15-18 added for variable-length BIP-340 messages.
Rental signatures and NIP-01 event signatures always sign a 32-byte SHA256
digest, so that extension is outside this profile. Tests exercise vectors
0-14 against their official verdicts and explicitly record rejection of
15-18; do not describe this as support for every current BIP-340 message size.
Official vectors: `https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv`. Checked-in CSV SHA256: `34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d`.

Dependency test-only module fetched by `go mod tidy`: github.com/davecgh/go-spew
v1.1.1, module h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=,
go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=.
