# Finite seal observation

This Go package observes one operation against an externally pinned, fully
validating own node. It has no CLI, transport, credential loader, signer,
transaction builder, broadcaster or command executor. It uses only the Go
standard library and does not change certificate, enrollment or request formats.

The wrapper supplies an `RPC` capability and a `Binding`. The capability returns
the JSON RPC **result**, not the envelope. It must independently enforce this
read-only allowlist at the node:

```
getblockchaininfo getblockhash getrawtransaction
getrawmempool gettxout getblock
```

`Call` and its response stream must honor context cancellation, including blocked
reads. The broker must pin its own-node destination and prevent redirects and
wallet/signing access. An in-process Go interface cannot confine a malicious
implementation; run the real broker across the existing isolation boundary.
No real broker or node is supplied or qualified here.

The binding contains the exact seal outpoint and script from the verified
certificate; the exact anchor txid, active-chain height and hash; and the
certificate's existing canonical 32-byte commitment. The existing short
`6a20<commitment>` OP_RETURN is checked in the anchor transaction. The wrapper
must verify that all these values came from the **same** verified certificate
and enrollment/request. Computing that commitment, checking the certificate's
signature and scope, and checking current identity state remain with existing
code. This package neither parses a new certificate format nor treats a digest
alone as a valid certificate.

`StartTip`, `Deadline`, `ProofValidUntil` and `LastBlockAt` must come from the
wrapper's immutable operation/proof clocks. `LastBlockAt` is the time a genuine
new active block was last observed, not a fresh timestamp on a repeated tip.
The wrapper must not reset these fields on retry or restart. A newly observed
active-chain successor advances `last_block_at`; peer heights and block header
timestamps do not. Thirty minutes without a new block stops before further RPC.

```go
observer := sealwatch.New(readOnlyBroker)
verdict := observer.Watch(ctx, binding, sealwatch.DefaultLimits())
// Encode verdict with encoding/json for the integration boundary.
// Only verdict.SealChainOK can contribute to the wrapper's combined decision.
// Always also check the wrapper's own immutable deadline and proof freshness.
```

The module import path is
`github.com/relux-works/swarma-chain-lab/experiments/sealwatch`; integration may use a local
Go module replacement to this directory. There are no downloaded dependencies
or new wire versions. The thin prototype retains the existing KeyVault owner,
fixed target and actions; no repository operation is executed.

| State | Meaning |
| --- | --- |
| `UNSPENT` | Both local UTXO views bind the seal at a stable validated tip; no inspected actual input spends it. |
| `SUSPEND` | An actual mempool input spends the seal, or an earlier observed spend still needs reconciliation. |
| `FINALREVOKED` | An actual spending input is in an active-chain successor block, from its first confirmation. |
| `UNKNOWN` | Reorg, unavailable, ambiguous, malformed or over-budget observation; refuse. |
| `STOP` | Original deadline/cancellation, expired proof, no new block for 30 minutes, or six-successor limit; refuse. |

`privileged_commands_allowed` is always false. Even an `UNSPENT` result only
contributes a seal/chain check; admission requires all separate KeyVault,
identity, chain and seal checks. It is valid for at most one second, further
clipped by the original proof and operation cutoffs. A command must not be
admitted after the result expires. No outgoing inv, peer-height observation,
local mempool absence or successful send establishes latest global state.

Pass the returned suspension/final verdict as `Binding.Prior` on a subsequent
observation of the same binding and retain it durably in the wrapper. Missing
mempool transactions never resume a suspended seal. Reorg of a prior observation
refuses. A reorg does not make the experimental one-block finality irreversible.
There is no automatic reconciliation/resume path. After an unknown result the
wrapper must preserve any earlier suspension separately and must not clear it.

Active blocks are scanned from the immutable operation start tip through its
sixth successor, using decoded **actual inputs**. A skipped poll does not move
that baseline. At successor six an observed spend in that window is revoked;
without such evidence the operation stops. Spending in successor seven cannot
widen the operation window. A seal spent before this bounded window, without an
available spend observation, produces `UNKNOWN` through the UTXO check. This
adapter is not a historical spender index. Block/mempool scans that exceed the
explicit count/byte/call budget refuse rather than truncate and admit.

Default bounds are six polls, one second between polls, ten seconds total,
two seconds per RPC, 256 RPC calls, 8 MiB per response, 64 MiB total response
bytes, 128 mempool transactions and 10,000 transactions per block. Reads use a
limit-plus-one sentinel; the measured bytes may exceed a configured byte cap
by exactly one before refusal. Input limits may tighten these values. Hard
ceilings are 64 polls, 30-second poll interval, 1500-second operation duration,
10-second RPC timeout, 4096 calls, the same byte ceilings, 1024 mempool
transactions and 100,000 transactions per block. Context, proof and original
operation deadlines always stop earlier. Concurrent calls on one watcher are
refused. There is no goroutine spawned for uninterruptible transports and no
infinite watch/retry loop.

Checks are causal offline fixtures: actual inputs drive derived UTXO truth.
They cover unspent, exact mempool spend, unrelated input, first-block spend,
dropped spend, prior/spend reorg, tip race, unknown/malformed replies, proof and
clock expiry, six-successor boundary, byte/call/count budgets, cancellation
and concurrent operation refusal. They do not establish live-node, mainnet,
runtime, wallet, policy or whole-prototype review qualification.

## Exact Core field projection

All structured node replies use official case-sensitive Core field names,
including nested transaction inputs and outputs. Alias-only fields, aliases
beside official members, and exact or Unicode case-fold-equal duplicates yield
`UNKNOWN/RPC_UNAVAILABLE_OR_MALFORMED`. Unknown non-conflicting Core extensions
remain compatible. Context-dependent optional transaction fields retain the
existing schema checks; an absent field cannot supply a seal or spend proof.
Block hashes remain strings and mempool replies remain bounded lists of unique
canonical transaction IDs. A null UTXO keeps its existing spent/unknown meaning.

Run `GOTOOLCHAIN=local GOFLAGS=-mod=readonly go test -race ./...` in this module.
`TestW7WatchExactProjection` pairs official UNSPENT/SUSPEND/FINALREVOKED controls
with alias/conflict/duplicate replies. `TestW7FoldDuplicates` includes Unicode
fold classes not merged by lowercasing. Keep test logs under `.temp/`.
The production watcher and projection tests match the Keyvault `lab/sealwatch`
copy byte-for-byte; import paths are the only module-level distinction.
