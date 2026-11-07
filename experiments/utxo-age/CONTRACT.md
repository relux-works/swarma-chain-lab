# Independent review and real-data admission contract

Status: **SOURCE_AND_SYNTHETIC_FIXTURES_ONLY; REAL_MEASUREMENTS_NOT_RUN**.
This repository composition requires fresh independent review. The candidate
must not be connected to a persistent node merely because fixture checks pass.

## Exact remaining gap

The dump format is confirmed from the pinned Namecoin source and its native
serializer is exercised offline. The remaining missing component is an
independently reviewed **validated-chain evidence adapter**: an immutable
genesis-to-base ancestor table from a fully locally validated Namecoin chain,
bound to the exact block-validation run, validation settings and UTXO dump.
The fixture header reader checks only 80-byte pure-header hashes, links and
timestamps. It deliberately refuses nonfixture use. It does not validate PoW,
AuxPoW, difficulty, chainwork, transaction scripts, name consensus, checkpoints
or local node custody. A trusted-looking JSON flag is not proof of validation.

The [pinned pure-header definition](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/primitives/pureheader.h)
and [its GetHash implementation](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/primitives/pureheader.cpp)
define the 80 bytes and hash. AuxPoW is additional validation data. Merely
hash-linking those pure headers does not replace native validation.

Real analysis must stay unavailable until the adapter and this exact candidate
pass fresh independent review and a separately authorized snapshot run. The
current CLI has no real-data mode or production approval switch.

## Immutable snapshot binding required later

The custodian, under separate execution authorization, must provide:

1. Exact Core source/binary version and digests, mainnet/genesis, full native
   validation settings and a receipt establishing a locally validated chain.
2. Dump RPC `base_hash`, `base_height`, `coins_written`, `txoutset_hash`, dump
   byte count, immutable SHA-256 and generation interval.
3. Accepted tip hash/height and chainstate best-block hash before and after
   export, native statistics, and ancestor-table collection. Every hash and
   height must agree with the dump base. A changed tip, reorganization,
   incomplete validation, lost receipt, unknown height or mismatch refuses
   the combined result. Do not silently choose another comparison block.
4. The existing native `gettxoutsetinfo("none")` result at exactly that same
   block: `txouts`, `transactions` and Namecoin's `amount.coins`, `.names`,
   `.total`. Do not duplicate an already arranged native scan. If it is at
   another block, retain that mismatch; the present authorization supplies
   no permission to rerun anything.
5. Exact decimal-to-atom conversion evidence for original RPC JSON. Preserve
   number lexemes or use exact decimal parsing; reject binary floats,
   sub-atom fractions, negative/overflow amounts and duplicate JSON fields.
   The fixture schema takes atom integers; a real RPC conversion adapter is
   not implemented here. Compare all native totals and counts exactly, plus
   the independently recomputed dump `txoutset_hash`.
6. The immutable validated ancestor-table digest and tip binding, coverage of
   every referenced creation height, per-height timestamp/hash provenance,
   collection interval, and the independently reviewed adapter's exact code
   hash. A peer/explorer timestamp list is insufficient.

The current fixture binding schema checks dump/header digests, exact count,
transaction count, all three native amount totals, serialized UTXO hash and
same-hash `tip_before`, `tip_after`, `chainstate_before`, `chainstate_after`,
`native_bestblock`, plus `native_height`. It is a test contract only; it does
not implement the custody, node validation or interval evidence above.

A native coherent dump may be valid at an old base while the live tip advances.
It can eventually support an explicitly historical measurement with separate
authorization and matching evidence. It cannot support optimistic global or
current-tip statistics by combining different blocks. Local currency also
does not independently establish network-wide agreement about the latest tip.

## Age and report policy

Height determines ancestry and locates each creation header. **Dates do not
determine chain order.** The pinned [header validation](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/validation.cpp#L4303)
uses previous median time, not strictly increasing successive timestamps.
Historical header timestamps can regress. Never binary-search a height/date
table assuming monotonic dates or substitute a nominal block interval.

Reference time is the bound base header's timestamp, not wall-clock now.
Elapsed age is reference timestamp minus the actual creation header timestamp.
Preserve and count timestamp regressions. If any referenced creation date is
later than reference time, refuse the entire age result: no negative ages,
clamping, date sorting, deleting outliers or silently switching to median time.
This can refuse a consensus-valid chain; it is an explicit conservative report
policy. A different policy requires its own review and labeled results.

A year is exactly 365*86400 seconds. Bands are [0,1y), [1y,2y), [2y,5y),
[5y,10y), [10y,infinity). Requested dormant summaries are **at least** 5y
and at least 10y, inclusive at the threshold. They describe UTXO creation-age
only. No owner inactivity, original coin age, inaccessibility or loss follows.
The reference header itself is not a certificate of accurate civil time.

Age/value-band and largest-output scope is all native UTXOs, including name
outputs, zero-value outputs and immature coinbases. Totals also separate
ordinary coins, all native-recognized name outputs, and each name operation.
Native `amount.names` includes NAME_NEW and is **not** a count or value of
active registered names. No name DB membership or ownership is inferred.
Value bands are zero, (0,1 NMC), [1,10), [10,100), [100,1000), [1000,infinity).
All share denominators are all-UTXO count or exact all-UTXO value respectively.
Largest outputs are individual outputs, bounded to at most 100; ties use
internal outpoint order for deterministic selection. Published fixture results
expose only value, creation height and category, not scripts, addresses or
outpoints. There is no address/holder grouping or claim about spendability.

## Destroyed amounts and historical rules

This measures value still represented by native UTXOs, not issued supply,
circulating supply, an emission schedule, cumulative fees or coins destroyed.
Absent coins cannot be recovered from a dump alone. Native omission of genesis
coinbase and provably unspendable scripts, unclaimed rewards, overwritten
outputs where applicable, and expired name deposits must not be added back.
Do not infer a coins-destroyed total from the gap to a theoretical supply.

Pinned primary details are in [coins.cpp::AddCoin](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/coins.cpp#L100),
[validation.cpp's genesis/expiry handling](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/validation.cpp#L2563),
and [names/main.cpp](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/names/main.cpp#L298).
Name expiry removes the update output permanently from the UTXO set; it is
not a refund. The native connection path expires at next-block height.
Historical ignored name operations and the special name-stealing/expiry
exceptions are described in [doc/NamecoinBugs.txt](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/doc/NamecoinBugs.txt).
Some historical name UTXO/name-DB relationships are exceptional. Do not
reimplement another chain's BIP30 or name policy or count raw historical
transactions to reconstruct this snapshot. Preserve exactly what the pinned
fully validated native view contains, then reconcile its own amount schema.

## Bounds and refusal behavior

Default decoder ceilings: 64 MiB input, 1,000,000 coins, 100,000 outputs per
group, 4 MiB serialized group payload, 10,000 bytes per script, 30 seconds.
The group sort has O(group) bounded storage; the rest of UTXO aggregation is
streaming. At most 100 largest outputs are retained. Header tables are bounded
to 2,000,000 entries / 160,000,000 bytes; fixtures contain only six. Python
object overhead exceeds serialized payload size; the sandbox's process
address-space limit, not the payload ceiling, bounds total allocation.

The supplied execution recipe adds an outer 180-second timeout with five-second
kill grace, 1.5 GiB address-space ceiling, 128 descriptors, no core dumps and
64 MiB output-file ceiling. File EOF detection may probe one byte beyond the
accepted input budget solely to refuse trailing data. No input is silently
truncated and no partial aggregate is successful. Decoder iteration yields
untrusted interim records; only a completely exhausted, reconciled analysis
may return a result. Larger budgets need measured resources and separate
execution authorization; fixture performance predicts no full-chain runtime.

Review should bind the exact candidate head/tree and source archive hash,
name reviewer model/effort, and inspect primary-source parity, adversarial
refusals, native reference independence, snapshot custody, date policy,
integer precision, public-output limits and the explicit real-data gate.
