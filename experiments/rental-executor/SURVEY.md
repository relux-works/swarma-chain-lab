# M4a executor survey

2026-11-08; producer request M4a-01. Base/current fetched main:
`2a4410e2e06bbd1de40da5a5096f060bc5ef5af6`. No task board or local skill
was found in this checkout. Tracking: `.temp/tasks.md`.

## Reuse and layout

- New Go module `experiments/rental-executor`; no edits to M1/M2/M3.
- W3 `single-use/journal.go` supplies the private-state, flock, fsync/rename
  and terminal reservation pattern. Generalize it to per-slot nonces and
  conservative cumulative budget accounting. Persist reserved inputs with
  the nonce before any effect; uncertain outcomes never release or retry.
- Use W3's `singleuse.Node` and loopback observer RPC for fresh M1
  `rental.Check` on every new effect. No node, clock, policy or certificate
  is accepted from the station request. Only verdict `live` admits.
- M1 certificate has no booking ID: trusted slot configuration pins booking ID,
  envelope and policy; the renter event must match that slot and the
  authenticated certificate's contract hash and grantee.
- Implement a small NIP-01 printable-ASCII request subset over btcec Schnorr;
  no go-nostr or gateway dependency. Preserve independent id recomputation,
  strict JSON duplicate/unknown/null rejection and exact tag cardinality.
- Separate executor and Track B admin Unix sockets, each 0600 in a 0700
  directory. Claim endpoint is separate and intentionally lacks a grant check.
  The station driver holds admin access; the station gets only its token.
- Pay: explicit pinned slot-budget outpoints, local P2PKH construction/signing,
  fixed bounded fee and pinned change address. Never wallet auto-selection.
  Prize A outpoint/address excluded at configuration and input construction.
  Spent or reserved budget inputs cannot fall back to prize or general wallet
  funds. Prize watcher reports the independent outpoint state.
- Deliver: bounded bytes bound to the signed SHA-256 target, private local
  per-request storage, local link and seven-day retention metadata.
  Publish/repository.push: explicitly harmless local-record implementations.
  secret.release: unconditional refusal.
- Track B: random per-slot bearer tokens, durable hash-only token storage,
  mint/revoke/list interface, sanitized audit committed before response/key
  release. Slot binding and revocation survive restart; unknown/revoked and
  cross-slot tokens refuse. Throwaway regtest prize material only.

## Dependencies and evidence

Go 1.26.8, modules declare Go 1.26.0. Same cryptographic pins as M1/M2:
`github.com/btcsuite/btcd/btcec/v2 v2.3.5`,
`github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0`.
Payment serialization/address handling additionally uses btcd v0.24.2 and
btcutil v1.1.5 (same as M3), avoiding hand-written Bitcoin transaction crypto.
Full resolved versions/checksums will be captured after M1 dependency pinning.
M1 immutable dependency is now 63087f31b62da50a6566250ef96af969e313e51b,
verified signed and independently accepted on 2026-11-08. Build against that
exact dependency until it is integrated into the default branch.

Primary protocol references consulted:
[NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) defines the
six-item event-id preimage; [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
defines x-only keys and Schnorr verification. Our accepted request subset is
narrower than a general Nostr client, with no prose interpretation.

Core 28 binaries remain read-only under `<core-bin>/`; SHA256 pins:
- namecoind: `86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f`
- namecoin-cli: `5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d`

All validation uses own isolated regtest datadirs under a task-specific test root,
listen=0/networkactive=0, recorded process PIDs, and no live wallet access.
Tests cover the requested negative contracts with nearby valid controls and
intended guard-removal assertion failures. Pending review and dependency
integration are never represented as completed validation.
