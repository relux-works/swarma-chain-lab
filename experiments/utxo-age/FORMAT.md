# Exact source and serialization contract

Pinned release: `nc28.0`, commit
`a08218ef2d44b81c53d25c399898e59271f4b642` of **namecoin/namecoin-core**.
The release tag is annotated (`c267cca30cb54ad130ed38a1ba07441ff2cd7f1d`).
The official `namecoin-28.0.tar.gz` must have SHA-256
`389b676e7aa74f6b96f235c77dacdf0dcca6a6ab2e32bd7c823efeb252ab8bd8`.
This contract is specific to that source, not inferred from another chain.
Changing the release, format, network or serializer requires a new review.

Primary definitions at that commit:

| Definition | Primary source |
|---|---|
| Snapshot header, version 2 | [node/utxo_snapshot.h](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/node/utxo_snapshot.h#L33) |
| Grouped dump and coherent LevelDB cursor | [rpc/blockchain.cpp, CreateUTXOSnapshot](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/rpc/blockchain.cpp#L2807) |
| Coin height/coinbase and compressed CTxOut | [coins.h](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/coins.h#L33) |
| Amount/script formatter | [compressor.h](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/compressor.h#L64), [compressor.cpp](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/compressor.cpp#L57) |
| CompactSize and subtract-one VARINT | [serialize.h](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/serialize.h#L307) |
| Database key order | [txdb.cpp, CoinEntry](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/txdb.cpp#L48) |
| Native names/coins and UTXO commitment | [kernel/coinstats.cpp](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/kernel/coinstats.cpp#L50) |
| Native name-prefix recognizer | [script/names.cpp](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/script/names.cpp#L10) |
| Network magic and genesis | [kernel/chainparams.cpp](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/kernel/chainparams.cpp#L159) |

## Container

There are exactly 51 metadata bytes:

| Offset | Size | Encoding |
|---|---:|---|
| 0 | 5 | ASCII `utxo` followed by `ff` |
| 5 | 2 | little-endian unsigned version: `02 00` |
| 7 | 4 | mainnet magic: `f9 be b4 fe` |
| 11 | 32 | base block hash in internal byte order, reverse of display hex |
| 43 | 8 | little-endian unsigned number of coins |

Height, timestamp, genesis, validation status, file digest and a UTXO commitment
are **not stored in this header**. They need separate bound evidence. The
network genesis is
`000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770`.

After metadata, each transaction group contains a raw 32-byte transaction ID,
canonical CompactSize coin count greater than zero, then that many pairs of
CompactSize vout and serialized `Coin`. Group counts must exhaust the exact
metadata count; the next byte must be EOF. Native writer output has strictly
increasing raw transaction-ID bytes. Vouts follow the lexicographic order of
their **database VARINT bytes**, not universally numeric order. For example,
16512 (`80 80 00`) precedes 16511 (`ff 7f`). Enforcing these writer orders
refuses duplicates with bounded memory. Arbitrarily reordered snapshots are
outside this strict canonical-writer contract even if a loader accepts them.

## Coin

`Coin` contains VARINT uint32 `(creation_height << 1) | coinbase`, VARINT
uint64 compressed amount, then VARINT uint32 compressed-script code and payload.
The height is at most 31 bits and may not exceed the independently bound base
height. It is the height of this output's last creation, not the earliest
coinbase ancestor. No time estimate is derived from height differences.

CompactSize has tags fd/fe/ff with little-endian 16/32/64-bit payloads and
must use the shortest form. Native reading ordinarily limits values to
`0x02000000`; the candidate retains that ceiling and additional budgets.
VARINT is the native big-endian subtract-one base-128 encoding, **not**
CompactSize, LEB128, protobuf varint or a signed integer. Bounds are checked
before every shift and increment.

Amounts follow `CompressAmount` and `DecompressAmount` exactly. The decoder
uses arbitrary-precision intermediate arithmetic, then refuses results
outside native `MoneyRange` (0 through 2,100,000,000,000,000 atoms) or signed
int64. Aggregate totals are separately bounded by signed int64, as native
coinstats uses checked sums. One NMC is 100,000,000 atoms. There are no floats,
rounded NMC values or approximate percentages; shares are exact numerator /
denominator pairs, null when the denominator is zero. JSON consumers must
retain integer precision rather than coercing large integers to binary64.

Script codes 0/1 carry 20-byte P2PKH/P2SH payloads. Codes 2/3 carry the x
coordinate of structurally compressed P2PK scripts. Codes 4/5 reconstruct an
uncompressed P2PK point with the encoded parity; invalid curve points are
refused. Code >=6 is the native raw-script length plus six, not an unknown
format fallback. Raw scripts over 10,000 bytes and raw spellings of a script
that the native writer would compress are refused. OP_RETURN raw outputs
are also refused because native AddCoin omits provably unspendable outputs.
Other native raw scripts retain their bytes internally without executing
them or inventing a destination/address or proof of spendability.

Native name operations are raw scripts, not extra snapshot compression tags.
The coin/name split reproduces `CNameScript::isNameOp`, including recognized
NAME_NEW, FIRSTUPDATE and UPDATE, accepted nonminimal data pushes, and the
native treatment of malformed prefixes as ordinary coins. The recognizer
does not establish transaction validity or name-database membership.

## Serialized UTXO commitment

The pinned native `hash_serialized_3` / dump `txoutset_hash` is double-SHA256
of concatenated uncompressed records: internal txid, uint32-LE vout,
uint32-LE height/coinbase code, signed-int64-LE amount, CompactSize script
length and full script. Within a txid group these records are hashed in
**numeric vout order** (`std::map` in native coinstats). The candidate buffers
one bounded group for this sort. Its displayed hash reverses digest bytes
like native uint256 display. This is distinct from the SHA-256 of dump bytes.

`CreateUTXOSnapshot` locks `cs_main` across flush, UTXO statistics and cursor
creation; the LevelDB cursor then iterates a snapshot despite later writes.
That guarantees an internal dump snapshot, not that a concurrently running
node's before/after tip or an unrelated RPC measurement is the same snapshot.
