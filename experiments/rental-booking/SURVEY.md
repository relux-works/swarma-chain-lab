# M3-01 survey (before implementation)

2026-11-08. Producer: ivmbp_swarma-grants_dev2, Codex gpt-6-astra / high.
Base: `2a4410e2e06bbd1de40da5a5096f060bc5ef5af6`, freshly fetched origin/main.
Scope: a bounded local regtest experiment, not a public deployment. No real
wallets, renter keys, relays, spending, or custody changes. M1's
`experiments/rental/` remains untouched.

## Reuse and layout

New Go module `relux.works/swarma-chain-lab/experiments/rental-booking`,
Go 1.26.8, with local module replacements for `single-use` and `sealwatch`.
Use `singleuse.NewRPC`/`NewOperatorRPC` for the read-only node capability and
`sealwatch.ProjectJSON` for exact field spelling/duplicate rejection. Do not
reuse the strict legacy seal-spend decoder for generic payment discovery.
Inspect transaction outputs only; never decode unrelated inputs/witnesses.
Reuse the journal durability pattern: private directory, no-follow files,
exclusive flock, temporary write + file fsync + rename + directory fsync.

Files: `contract.go`, `nostr.go`, `address.go`, `store.go`, `watcher.go`,
`http.go`, `relay.go`; entry points `cmd/rental-booking` and a loopback-only
`cmd/rental-relay`; Go unit tests and an opt-in genuine Core regtest harness.
No frontend framework. The inline browser code only obtains the renter key,
submits booking input, displays server-derived terms, calls NIP-07 signEvent,
and posts the result. HTML template escaping, request bounds, exact origin,
loopback binding, and server-side validation apply to every browser input.

Payment reads use only `getblockchaininfo`, `getblockhash`, `getblockheader`,
`getblock`, `getrawtransaction`, `getrawmempool`, and optional `name_show`.
These are in the existing verifier whitelist; no wallet RPC in the service.
The isolated test harness alone creates/funds its disposable regtest wallet.
Check regtest chain/genesis and coherent tip before committing any observation.
An incomplete scan or RPC failure must not commit a partial payment verdict.
Scan from a pinned booking checkpoint; retain receipt block identities for reorg
checks. Bound reads explicitly and refuse observation on exhausted bounds.

Payment is an individual output meeting the quoted amount, not accumulation
of arbitrary dust. Addresses are BIP32 direct non-hardened children of a pinned
public extended branch; monotonically persisted child indices are never reused.
Use legacy P2PKH (regtest version 111); reject private extended keys and pin
mismatches before serving. No HD private material enters the service.

## Proposed lifecycle

A booking atomically reserves one configured station interval of at most one
hour; intervals are half-open. Configurable hold 1200..1800 seconds. Expiration
releases an unpaid/unissued slot. Matching payments first observed too late are
recorded for operator refund review, never silently reassigned to another hold.
Additional payments also require refund review; no second issuance or slot.
A paid booking retains its slot beyond the hold. A reorg returns confirmed
payment to pending; if already handed to the issuer, append a revoke trigger.

New scope from the orchestrator on 2026-11-08 (owner-source verification
requested): stable `agent_pubkey` instead of station key; optional renter name;
USD-denominated quotes; explicit `advance` and `start_now` payment policy.
For `start_now`, a qualifying mempool payment can enable issuance; replacement
or disappearance creates a durable revoke trigger and must never silently
retarget an already issued booking to a replacement. Core full-RBF means
non-signalling is not a safety guarantee. Issuance and revocation are outbox
records for M1; M3 never broadcasts chain transactions.

Proposed quote: integer `price_usd_cents`, integer `usd_micros_per_nmc`,
`rate_as_of`, and configured `max_rate_age_seconds`; compute NMC atoms as
ceil(price_usd_cents * 10^12 / usd_micros_per_nmc) with checked arithmetic.
Reject stale/future/nonpositive rates. Freeze the quote in the contract at hold
creation, so subsequent rate changes cannot change the amount owed.

## Dependencies

The application will use btcsuite's BIP-340 and BIP32 implementations instead
of implementing elliptic-curve signatures or HD derivation. Gorilla supplies
only the WebSocket transport for local Nostr EVENT/OK publication. No full
Nostr SDK is needed for the two event kinds. These explicit compatible pins
are selected for this experiment, not claimed to be the newest releases.

| Module | Pin | Go module content checksum |
| --- | --- | --- |
| github.com/btcsuite/btcd/btcec/v2 | v2.3.5 | h1:dpAlnAwmT1yIBm3exhT1/8iUSD98RDJM5vqJVQDQLiU= |
| github.com/btcsuite/btcd/btcutil | v1.1.5 | h1:+wER79R5670vs/ZusMTF1yTcRYE5GUsFbdjdisflzM8= |
| github.com/gorilla/websocket | v1.5.3 | h1:saDtZ6Pbx/0u+bgYQ3q96pZgCzfhKXGPqt7kZ72aNNg= |
| github.com/decred/dcrd/dcrec/secp256k1/v4 | v4.4.0 | h1:NMZiJj8QnKe1LgsbDayM4UoHwbvwDRwnI3hwNaAHRnc= |
| golang.org/x/crypto | v0.55.0 | h1:+KWHjbgOaAQ66dh/YlkZKHlz9ZUlq61AFirAR9ntP8M= |

`btcd/chaincfg` and transitive module checksums will be recorded in go.sum and
a complete dependency manifest before delivery. Download evidence is retained
in the bench's `.temp/m3-survey/`. Run go mod verify and upstream vector tests
for the used BIP32/BIP340 packages; preserve licenses for redistributed source.

## Verification and evidence

At least 20 negative controls paired with valid neighbours, plus durable-state,
concurrency/restart, exact-schema, rate freshness, and local HTTP/relay checks.
Payment below price, wrong address, late payment, duplicate payment, mempool
pending (advance), reorg, replacement/drop (start_now), and unrelated witness,
many-input and large-mempool traffic must run on genuine Core 28 regtest.
Contract/consent controls cover wrong key/hash/id/time/booking, byte tampering,
wrong profile, missing privacy consent, and scope limits. Check actual refusal
codes and post-failure state, not just an error. Targeted mutation plants in
isolated copies must demonstrate that the relevant tests catch missing guards;
base lacks the new API, so compile failures on base do not count as controls.

Core binaries are read-only from `/Users/iv/Werkstatt/grants-dev/w7/core-bin/`:
`namecoind` SHA-256 `86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f`,
`namecoin-cli` SHA-256 `5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d`.
Both verified on this bench. New node directories stay under this bench's
`m3/`; listen=0, networkactive=0, no peers. Record and terminate only own PIDs.
Public evidence must exclude credentials, private keys, and private node state.

## Primary references

- [NIP-01 event encoding and relay protocol](https://github.com/nostr-protocol/nips/blob/master/01.md)
- [NIP-07 browser signing API](https://github.com/nostr-protocol/nips/blob/master/07.md)
- [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [btcsuite hdkeychain](https://pkg.go.dev/github.com/btcsuite/btcd/btcutil/hdkeychain)
- [btcsuite BIP-340](https://pkg.go.dev/github.com/btcsuite/btcd/btcec/v2/schnorr)

Read on 2026-11-08. The protocol subset will use ASCII-only fields/content
for its canonical contract and consent event, avoiding JSON Unicode escaping
ambiguity between browser signers and Go. NIP-07 supplies key access/signing;
the server still recomputes the NIP-01 event id and verifies BIP-340 itself.

## Findings during implementation

Genuine Core 28 after invalidate/reconsider reported `blocks=111, headers=110`
with IBD false. A header-progress equality/ordering assumption incorrectly
refused the restored active chain. The watcher now checks nonnegative header
metadata, regtest genesis, IBD false, contiguous active block links through the
pinned tip, and unchanged final tip/mempool; it does not infer chain validity
from relative header and block counters. Regression evidence:
`m3/regtest-reorg-05/public/restored-chaininfo.json` (failing predecessor) and
`m3/regtest-06/public/reorg.json` (corrected matrix) in the producer bench.

The orchestrator accepted conservative first admission before hold expiry for
both payment modes. Signed package hold bounds were added; block time is never
used as an observation timestamp. Default hold is 1800 seconds. An unissued
booking at expiry goes to refund/operator review, even if relay recovery occurs
later. M1 independently accepted the frozen wire fixture and expiry boundaries
(event $Md0UHoaCiIAMr2IVIHKNYq8rfsIsjaCVMhE9Ypl4s4o). Station grammar is bounded
lowercase `id/<identifier>`; deployment prefixes are not a trust rule.
