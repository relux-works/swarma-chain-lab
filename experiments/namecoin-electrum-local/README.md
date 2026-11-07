# Offline preparation for a local Electrum-NMC server

**Source correction prepared; activation awaits independent review.** The pinned
server plus an explicit local patch builds offline, passes 228 header boundary
cases and the existing 32 synthetic checks. The unmodified upstream source still
fails its checkpoint-covered variable-length header reproducer. No server, node, network
listener, RPC connection or chain indexing was started by this experiment.
The configuration is an inspection template, not an admitted deployment.

## Implementation and exact baseline

Use **spesmilo/ElectrumX 2.0.1**, official tag commit
`39d477f31727ff95ce99694f6d8cb4a4cd7bd633`, as the evaluated baseline. This is
a server, separate from the Electrum-NMC client. The
[Namecoin project's name-script description](https://www.namecoin.org/2018/07/15/electrumx-name-scripts.html)
and [protocol 1.4.3 announcement](https://www.namecoin.org/2022/10/28/name-show-in-electrum-nmc-protocol-v1.4.3.html)
identify ElectrumX and its Namecoin extensions; the
[maintained implementation](https://github.com/spesmilo/electrumx/tree/39d477f31727ff95ce99694f6d8cb4a4cd7bd633)
contains those features explicitly. This selection does not assume a generic
Bitcoin server supports names.

The tag signature verifies under SomberNight's public key published through
[the Electrum project's key links](https://electrum.org/). Primary fingerprint:
`4AD64339DFA05E20B3F6AD51E7B748CDAF5E5ED9`; signing subkey:
`6D7A2116DA909E00AC21108BB33B5F232C6271E9`. GnuPG ownertrust is undefined.
The PyPI `e-x==2.0.1` sdist matches the independently fetched Git source for all
34 Python source and relevant build/license files. Exact archive digests and
source commits are in [sources.json](sources.json).

This is a new dependency baseline, with no existing server lock upgraded.
[dependencies.json](dependencies.json) pins every fetched distribution's exact
version, filename, size, canonical PyPI SHA256 and URL. The two requirements
locks cover Python build tools and runtime wheels. There are no Go modules;
canonical Go `h1` is **not applicable**. A Python wheel SHA256 is not a Go h1.
No unresolved language dependencies are fetched during a build.

The native backend is **plyvel 1.5.1** plus **Google LevelDB 1.23**, commit
`99b3c03b3284f5886f9ef9a4ef703d57373e61be`. No compatible prebuilt plyvel wheel
was available for the evaluated CPython 3.14 ABI, so its exact source is built.
The supplied generated C++ is used without Cython regeneration. LevelDB's
RTTI setting requires `-fno-rtti` for plyvel as well. Snappy and external CRC32C
are deliberately disabled; this changes compression/performance expectations,
not the pin. LevelDB's archive has an acquisition SHA256 and official repository
ref binding, without an independently verified release signature.

## Namecoin-specific behavior

The pinned [coin definitions](https://github.com/spesmilo/electrumx/blob/39d477f31727ff95ce99694f6d8cb4a4cd7bd633/src/electrumx/lib/coins.py)
select `Namecoin(NameIndexAuxPoWMixin, Coin)`, the mainnet genesis hash,
`DeserializerAuxPowSegWit`, `NameIndexBlockProcessor`, a 36,000-block name
expiration constant and `NameIndexAuxPoWElectrumX` sessions.

* Address indexing strips the name prefix and hashes the ownership script.
* Name history indexing normalizes firstupdate/update to
  `OP_NAME_UPDATE <name> OP_0 OP_2DROP OP_DROP OP_RETURN`, then hashes that
  script. The wire scripthash is SHA256 in reversed-byte hexadecimal form;
  the database uses a shortened internal hashX.
* The [block processor](https://github.com/spesmilo/electrumx/blob/39d477f31727ff95ce99694f6d8cb4a4cd7bd633/src/electrumx/server/block_processor.py)
  adds that secondary name history in addition to address/output processing.
* Variable-length AuxPoW headers are parsed; the Namecoin header hash covers
  the base 80 bytes. Parsing is not consensus validation or a work check.
* Protocol 1.4.1 provides legacy history/transaction/Merkle/header calls.
  Protocol 1.4.3 additionally registers `blockchain.name.get_value_proof`.
  That endpoint bundles reverse history, transaction bytes, transaction Merkle
  branches and checkpoint header proofs, stopping at a checkpoint or a name
  expiration gap. Electrum-NMC's `name_show` is a client command, not a native
  ElectrumX wire RPC named `name_show`.

The earlier evaluated Electrum-NMC 4.0.6 client negotiated 1.4.1. Its public
server refused further work with error -101 before any name lookup completed.
That refusal remains a failure, not an absent name or a reason to change client
identity. A local server is a future alternative after qualification.

## Node RPC compatibility: source-checked, not runtime-qualified

The intended node baseline is **Namecoin Core 28.0 / nc28.0**, commit
`a08218ef2d44b81c53d25c399898e59271f4b642`. The supplied handoff did not establish
a synchronized current tip. No current node state or private authentication
material was accessed here. A validated full node remains a prerequisite.

| ElectrumX requirement | What the exact node source provides | Remaining condition |
| --- | --- | --- |
| `getblockcount`, `getblockhash`, `getblock(hash,false)` | Chain height/hash and raw blocks; the Boolean verbosity compatibility path exists in [blockchain.cpp](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/rpc/blockchain.cpp). | Locally validated current tip; retained historical blocks; no pruning. |
| `getrawtransaction(txid,0/1)` | Raw/verbose transactions in [rawtransaction.cpp](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/rpc/rawtransaction.cpp). ElectrumX passes no block hash. | For arbitrary old confirmed transactions, a synchronized `txindex=1` is needed. The handoff config omits it, and its source default is false. Enabling/building it needs separate node-change and capacity review. |
| `getrawmempool`, `getmempoolinfo` | Mempool enumeration and the expected minimum/incremental fee fields in [mempool.cpp](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/rpc/mempool.cpp). | The supplied block-only node is not a qualified source of comprehensive unconfirmed name history. |
| `getnetworkinfo`, `estimatesmartfee` | Relay-fee information in [net.cpp](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/rpc/net.cpp) and fee estimation in [fees.cpp](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/rpc/fees.cpp). | Fee estimation can be unavailable; it does not qualify name state. |
| `name_show`, `name_scan`, optional `name_history` | Native name-state RPCs in [names.cpp](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/rpc/names.cpp); `name_history` requires `-namehistory`. | ElectrumX does not use these to replace its own script/name history index. These are full-node answers, not automatically portable SPV proofs. |

Namecoin inherits the generic daemon adapter, not the Bitcoin class's Core 31
version/index requirements. The upstream default protocol maximum is 1.7;
that does **not** establish Namecoin 28 support for every newer Bitcoin RPC
such as spender-index queries. Future qualification must restrict/evaluate the
actual 1.4.1/1.4.3 client path. Do not advertise the full newer protocol surface
as verified on this node.

Authentication remains unresolved for deployment. The pinned adapter takes a
credential-bearing `DAEMON_URL`; it does not natively select a Core cookie file.
No cookie bridge, password, wallet or key is supplied. A separately reviewed,
least-privilege mechanism must avoid credential output and argument logging.
Upstream exposes transaction broadcast methods even on a private service;
loopback alone does not make it read-only. A future lookup service needs a
reviewed method allowlist and daemon privilege policy before activation.

## Upstream defect and explicit local correction

[reproduce_header_boundary.py](tools/reproduce_header_boundary.py) calls the
installed upstream `phandle_block_headers(100,2,101)` using synthetic dynamic
header offsets and headers of 160 and 240 bytes. The checkpoint-covered reply
must contain two truncated 80-byte headers, A then B. It instead returns **400
bytes**, with five 80-byte markers A,A,B,B,B while its count field remains two.
The reproducer exits **1** on that correctness assertion against the unmodified
source; its original failure is retained separately from the patched result.

In [session.py](https://github.com/spesmilo/electrumx/blob/39d477f31727ff95ce99694f6d8cb4a4cd7bd633/src/electrumx/server/session.py),
`block_headers_array` starts its local height at zero and uses absolute
`header_offset(height+1)` values to slice a buffer starting at another height.
The Namecoin checkpoint-truncation path reuses that method. This establishes an
offline variable-header boundary defect, not a real-chain exploit or consensus
finding. The separately pinned [local patch](local-patch.json) corrects this
helper without changing version or dependencies. It translates file offsets
relative to the requested starting height, uses the returned count, and rejects
inconsistent byte boundaries. The same reproducer then returns 160 bytes and
exits zero. See [the correction and protocol analysis](HEADER_CORRECTION.md)
and the [bounded regtest proposal](PART_A_PLAN.md). Independent exact-head review
is required before activation; these synthetic results do not qualify a service.

## Reproduction and evidence scope

The sealed evidence packet includes the exact source archives, dependency
wheels, licenses, native library and built wheels. The tools assume read-only
mounts `candidate -> /src`, `artifacts -> /artifacts`, and one private writable
scratch directory at `/scratch`. These are sandbox paths, not deployment paths.
Use bubblewrap `--unshare-all --clearenv`, a new session, no inherited sockets,
read-only system tools, a new proc/dev view, no host home, and absolute 0700
HOME/TMP/cache directories inside scratch. Network acquisitions occur separately
and are limited to public source/artifact retrieval.

Inside that sandbox, run `tools/build_offline.sh` from this experiment. It
checks every input, builds and installs from local files only, checks transitive
requirements, applies the exact local patch and runs the fixtures. Use
`PYTHONPATH=/scratch/runtime` and `LD_LIBRARY_PATH=/scratch/prefix/lib` when
running the regression reproducer separately. It fails on the unpatched pinned
version and passes on the explicit patched candidate. The narrower
`tools/build_header_candidate.sh` reuses the sealed native build, builds only the
changed Python wheel and tests the installed candidate; it does not rebuild the
unchanged LevelDB/plyvel artifacts.

Two clean builds with the recorded toolchain and fixed `SOURCE_DATE_EPOCH`
produced byte-identical ElectrumX and plyvel wheels and the LevelDB shared
library. This is same-toolchain reproducibility, not a cross-platform binary
reproducibility claim. The private receipts bind the tool versions, hashes,
actual times and exits. The native library still needs the recorded C/C++
system ABI; the plyvel wheel is not a standalone manylinux distribution.

The 32 passing fixture checks cover normalization/address/name hashes,
AuxPoW structural parsing and base hashing, protocol gates, synthetic proof
bundle shape/cutoffs, config parsing, and a tiny database reopen. Its mocked
transaction/proof providers deliberately return invalid synthetic bytes.
It does not verify a real transaction, signature chain, chainwork, difficulty,
consensus, real Merkle proof, full index or current name value.

## Resource proposal and admission boundary

**All following chain/index sizes and memory values are planning estimates,
not measurements or allocations.** The native tiny fixture size is not an
estimate of chain storage.

| Resource | Conservative planning range or proposed limit |
| --- | --- |
| Additional ElectrumX index | Estimate 4–16 GiB retained; plan 8–32 GiB with compaction/temporary headroom, especially without Snappy. Actual workload unknown. |
| Additional Core transaction index | Estimate 1–4 GiB, separate from block files and chainstate; must be measured under an admitted cap. |
| Indexer memory | Estimate 1–2 GiB RSS with `CACHE_MB=128`; propose 2 GiB hard limit, no swap, subject to a reviewed clean-stop test. Cache size is not an RSS bound. |
| CPU and descriptors | Propose one CPU and at most two local client sessions; review roughly 1024 descriptors for indexing. Build uses at most two compiler jobs. |
| Time and logs | No current-chain indexing duration measured. Require a finite maintenance window, bounded logs, stop threshold and flush headroom; do not infer a duration from historical benchmarks. |

The existing **12 GiB node cap applies to the node alone**. It grants no extra
index database allocation and does not guarantee room for a transaction index.
There is no admitted index capacity in this candidate. Before indexing, obtain
source-capacity admission for separate bounded storage and enforce an aggregate
quota or reviewed stop guard with compaction and shutdown headroom. Preserve
the node's existing cap; do not silently combine these estimates into it.

Any prospective service is private to an unprivileged lab account and
**IPv4 loopback only**, with discovery/announcement and external services off.
A later admitted client listener could explicitly bind `tcp://127.0.0.1:50001`;
this template keeps `SERVICES` empty, and no listener was opened here. No unit
file or activation command is supplied. An empty service list still permits
indexing if someone starts upstream, so it is not an execution safety gate.

## Remaining qualification tests

1. Independent exact-source review of this candidate and the header defect;
   review any correction with a separate exact diff and immutable source pin.
2. Verify a fully validated, stable node tip and retained raw-block availability.
   Separately review any `txindex` change and measure its capped resource use.
3. Admit authentication and a read-only method policy without exposing cookies
   or adding wallet/broadcast privileges; confirm same-user loopback isolation.
4. Under separate storage/CPU/RAM admission, perform bounded indexing, graceful
   cap/flush/stop/restart, corruption recovery and reorg tests. Reconcile index
   height/hash against the validating node before serving requests.
5. Test the signed Electrum-NMC 4.0.6 client at protocol 1.4.1 and an independently
   pinned 1.4.3 client. Verify real AuxPoW/difficulty/header chains and checkpoint
   proofs, transaction inclusion, name normalization, expiration, re-registration,
   optional signature chains, stale/omitted history and malformed proofs.
6. Compare selected current name values/outpoints with full-node `name_show`
   and `gettxout`; test failure on resource refusal, missing history, lag and
   conflicting tips. Empty history is not an authenticated NXDOMAIN proof.

SPV inclusion and checkpoint proofs do not establish latest/unspent name state,
general nonexistence, complete history or immunity to server omission/eclipsing.
The full node validates consensus; the indexer supplies searchable derived data;
the client verifies only the proofs and freshness rules it implements. A local
indexer backed by one's own validating node reduces reliance on a public
operator but is not independent second-operator evidence or production approval.

The included `tools/offline_sandbox.sh` accepts absolute source, artifact and
already-created private 0700 scratch directories followed by the sandbox
command. It applies a 180-second wall timeout, 120-second per-process CPU limit,
2 GiB per-process address-space limit and 32 MiB per-file limit for these small
offline build/fixture operations. These are build bounds, not a service/index
storage admission or aggregate filesystem quota.
