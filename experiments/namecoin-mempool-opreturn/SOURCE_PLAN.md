# Mempool revocation and OP_RETURN: bounded source and experiment plan

Status: source findings and an executable offline case generator only. No new
node, indexer, wallet, key, transaction broadcast, block, or mainnet read was run.
Independent exact-head review is required. Existing lab fixes and composition
take precedence. This plan neither qualifies a chain-only authorization profile
nor changes source custody or landing authority.

## Inputs and evidence boundary

The base candidate is `db20885a5d4eb4ec6e907b7fd200dd79d4a21f73`, tree
`f5986dfbec41ab1a3a79f8bd6ef1e7b9deda294a`. It fixes the checkpoint-height
domain of the existing Part A verifier. The earlier actual runtime used
`e5f75e3f0f643aeb47736cac5d22103eb8e32170`, tree
`ee897d3a4d2c5963203029475a2b958e026a4c58`; the corrected verifier was replayed
offline, not used in a new node run. The ongoing current-main composition must
retain the correction before a later experiment uses it. Do not read or modify
an active composition workbench; the custodian supplies a sealed candidate.

Reuse these exact inputs without an upgrade:

| Input | Pin |
| --- | --- |
| Namecoin Core 28.0 (`nc28.0`) | `a08218ef2d44b81c53d25c399898e59271f4b642` |
| Core release archive SHA256 | `6f12031926f0999b8507e073648cc2b4488d452531301a2244a562a92f2f7860` |
| Executed daemon SHA256 | `dc7430676e445af3992430e036f7c1a17bea44f757e9cf25b69205e39625f2f7` |
| ElectrumX 2.0.1 | `39d477f31727ff95ce99694f6d8cb4a4cd7bd633` |
| Accepted header-offset patch SHA256 | `bb504c218edc2179ecee22facac4da96d28ee92bd4d30c6fc6ef2556948ed6ed` |
| Patched source archive SHA256 | `90171af850977878c74c2b16f26fd4339394933019b0fbf8af6ff9adebbf10e8` |
| Executed patched wheel SHA256 | `d888ac1ba35333f7fecd1f18b7d5fac69fc92a4aa030389ef768e28e295871ab` |

The existing runtime receipt covers 2026-11-07T05:10:47.783993Z through
05:12:45.129711Z, 117.345724 seconds, exit 0; its outer receipt is
05:10:47.284247691Z through 05:12:45.198658898Z, exit 0. It records ten
**confirmed** notifications, 143 protocol requests and 89,339 received bytes.
Mining dispatch to confirmed notification median was 4432.856 ms; this is **not**
a mempool latency measurement. It did not independently validate spend signatures.
Its single-server omission and stale-value negatives were undetectable using
inclusion alone; controlled disagreeing views were not independent operators.
It used a designated ordinary P2PKH seal, not a complete grant/action binding.

Preserve the actual failed first attempt (05:08:20.303482884Z through
05:09:51.310042704Z, exit 1, fee rejection `10000 < 19100`) and the failed
offline aggregation checker. Only the fixture fee was corrected in the run;
do not hide this with a success-only summary. Prior runtime bounds were aggregate
3 GiB RAM, zero swap, CPU 200%, 64 tasks, private tmpfs 1536 MiB, 1500 seconds
plus a 1600-second supervisor backstop. New results get new timestamps and exits.

The inherited dependency manifest and lock files remain unchanged. No dependency
is installed for this plan. Python standard library suffices for case generation.
Canonical Go `h1` verification is inapplicable: no external Go module is used.
Any later native signature-verifier addition needs a separately pinned, reviewed
input; a new dependency cannot be smuggled in as part of a runtime replay.

## Public source findings

All Core links below bind the exact pinned commit. Acquired files are checked
against their canonical Git-tree blob IDs, and their SHA256s are in the sealed
evidence. ElectrumX citations bind upstream plus the explicitly pinned local
header patch; the relevant name/mempool methods are outside that patch.

1. [Core policy constants](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/policy/policy.h#L66)
   set data-carrier support true and its maximum **script size** to 83 bytes.
   A conventional single push of 80 data bytes has one OP_RETURN byte, two
   PUSHDATA1 framing bytes, and 80 data bytes. The payload size is not itself
   the tested limit. Two 40-byte pushes also occupy 83 bytes; pushes of 76 and
   4 bytes occupy 84 bytes despite the same 80-byte total payload.
2. [IsStandard and IsStandardTx](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/policy/policy.cpp#L70)
   check the whole NULL_DATA script, at most one such output, and whole
   transaction weight <=400,000. [Solver](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/script/solver.cpp#L184)
   requires OP_RETURN followed by push-only operations for NULL_DATA classification.
   Non-push instructions, truncated pushes, two data outputs, and transaction
   weight overflow are distinct negatives, not all an 80-byte data rejection.
3. [Mempool defaults](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/kernel/mempool_options.h#L29)
   set `DEFAULT_ACCEPT_NON_STD_TXN=false`;
   [argument application](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/node/mempool_args.cpp#L82)
   makes standardness required unless explicitly overridden. Do not assume
   this Namecoin regtest defaults to accepting nonstandard transactions.
   Record the actual arguments and queried effective state in the future run.
4. OP_RETURN bytes reside in the non-witness output script. Their weight is four
   units per serialized byte; witness input discounts do not discount this data.
   Include CompactSize script-length prefixes, output value bytes, all inputs,
   change, marker/flag and witness in the actual transaction's stripped size,
   total size, weight and vsize. The default 83-byte policy is not a consensus
   payload cap. [Consensus bounds](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/consensus/consensus.h#L11)
   impose 4,000,000 block weight and serialization constraints;
   [CheckTransaction](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/consensus/tx_check.cpp#L19)
   bounds stripped transaction size. Large output scripts are unspendable by
   [CScript::IsUnspendable](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/script/script.h#L570).
   The 520-byte stack element and 10,000-byte executed-script rules are not a
   blanket maximum size for creating an unspent OP_RETURN output. This does
   not mean consensus permits unbounded data; inputs, money, weight and block
   validity still apply.
5. [Default block assembly](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/node/miner.cpp#L371)
   selects from the mempool with block weight/fee/package constraints; the
   default block weight target is 3,996,000. [generateblock](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/rpc/mining.cpp#L304)
   can take raw transactions and test block validity directly. That forced
   inclusion is a separate consensus control, not evidence of default relay
   or default template selection. `testmempoolaccept` is local admission only,
   and `sendrawtransaction` success alone is not observed peer-to-peer relay.
6. [ElectrumX mempool](https://github.com/spesmilo/electrumx/blob/39d477f31727ff95ce99694f6d8cb4a4cd7bd633/src/electrumx/server/mempool.py#L470)
   computes output hashXs with `coin.hashX_from_script` and derives input
   hashXs from prevouts. [NameIndexMixin](https://github.com/spesmilo/electrumx/blob/39d477f31727ff95ce99694f6d8cb4a4cd7bd633/src/electrumx/lib/coins.py#L632)
   strips the name prefix to get the owner script for that method. Its distinct
   synthetic name hashX is added in
   [block processing](https://github.com/spesmilo/electrumx/blob/39d477f31727ff95ce99694f6d8cb4a4cd7bd633/src/electrumx/server/block_processor.py#L919).
   **Source inference:** this mempool path exposes a name_update through the
   owner-script history, not through the synthetic name index before a block.
   The [name value-proof handler](https://github.com/spesmilo/electrumx/blob/39d477f31727ff95ce99694f6d8cb4a4cd7bd633/src/electrumx/server/session.py#L2771)
   requests transaction Merkle proofs; it is not an unconfirmed value API.
   Do not promise unconfirmed name-index notifications or a new pending value
   there. Probe and report exact unchanged/absent/error responses in the run.
7. Core's [name_pending](https://github.com/namecoin/namecoin-core/blob/a08218ef2d44b81c53d25c399898e59271f4b642/src/rpc/names.cpp#L805)
   explicitly enumerates unconfirmed name updates; `name_show` reads the chain
   name state. This is an oracle observable, not an extra Electrum capability.
   When the known organization name outpoint/owner script is watched, fetch its
   unconfirmed raw spend via ordinary history and parse the name/value output.
   Visibility, exact bytes, signature ancestry and latest-state completeness
   must be reported separately.

No admitted source/binary for the short current revision `f58a3f9c` is present
in these input packets. Its alleged ~100,000-byte setting is an unverified
request premise here. Do not fetch/build a new node, resolve it to an arbitrary
moving branch, or infer relay capacity from a script-size constant equal to the
whole transaction's nominal weight allowance. An already supplied current binary
would require a full commit, archive/binary hashes and source-policy check first.

## Revocation protocol and independent validation

Use a new disposable regtest fixture inside the existing bounded namespace,
never the old deleted wallet. Pin a confirmed funding transaction, its exact
txid/vout/value/script, and an independently trusted laboratory checkpoint.
Authenticate the prevout before any mempool test. Reuse the corrected in-range
checkpoint verifier; no new full-SPV claim follows. For the first runtime unit,
support only one legacy compressed-key P2PKH seal input using strict DER,
low-S, SIGHASH_ALL and an exact standard P2PKH locking script. Unsupported
scripts, extra sighash forms, duplicate inputs and ambiguous parsing fail closed.

The thin client must own its parser, sighash construction and secp256k1 ECDSA
verification, without oracle RPC, wallet/cookie, chain mount, or producer private
key. A reviewed, reference-only standard-library implementation can restrict
itself to this fixture; it is not production cryptography. Authenticate the
pubkey hash against the pinned locking script, reconstruct the legacy SIGHASH_ALL
preimage with that script, and verify the signature against the exact candidate
bytes and watched input. Node acceptance, a reported txid, script text mentioning
an outpoint, and signature-shape checks cannot substitute for verification.
The existing thin driver has no such verifier: **implement and independently
review it before the next runtime**, with known valid signatures and mutations
of signature, pubkey, input txid/vout, output, locktime and sighash byte. Compare
against Core as a test oracle only, not as a capability held by the client.
Place this client in its own nested `bwrap --unshare-all --clearenv` namespace
with no node binary, chain, wallet, cookie, runtime cache or oracle socket mount.
Give it only a read-only public prevout/checkpoint file and a framed protocol
pipe connected to the read-only gateway. The parent may forward allowed Electrum
requests through that pipe; it never forwards a Core RPC request. The client has
no shared loopback path to Core or its read-only RPC proxy. Process separation
and withholding the cookie alone would not establish this capability boundary.
Use at most two instances of this same client: a primary honest-view instance
and a hidden-only instance. Initialize each from the same authenticated prevout,
but never feed primary notifications, candidate txids or state into the hidden
instance. Only after its hiding window expires may it query the second honest
view. This prevents a shared state machine from concealing the omission result.

Track state per watched outpoint and candidate txid, with an append-only public
reason/timestamp journal: ACTIVE -> SUSPENDED only after exact outpoint and
signature validation; SUSPENDED -> FINAL at one validated inclusion. One block
is the requested research threshold, not irreversible finality. A reorg or
invalidation returns FINAL to SUSPENDED pending explicit reconciliation.

Subscribe before broadcast, save the initial status, and wait for subscription
acknowledgment. Use `blockchain.scripthash.subscribe`, `get_history`,
`get_mempool`, and `blockchain.transaction.get`. Heights 0 (confirmed inputs)
and -1 (unconfirmed parents) mean unconfirmed; neither is a block height.
Fetch exact raw bytes after status change, recompute the legacy txid, and match
history entries to inputs. A notification/status alone never suspends.

Record monotonic_ns and UTC for broadcast dispatch and return, server mempool
observation, protocol notification receipt, raw-byte receipt, validation start/
finish, SUSPENDED journal append, mining dispatch and return, confirmed
notification, inclusion completion and FINAL append. Report broadcast-to-notify
and broadcast-to-suspend against both dispatch and return, then mine-to-final
and broadcast-to-final. Do not label sampled index times as exact ingestion.
Keep signature-only CPU time separate from network/wait time. One primary valid
spend is a sample, not a latency percentile. Preserve misses/timeouts as censored
observations with their windows. No mining until the primary suspend check and
all pre-mining negatives finish; a mining-barrier assertion must enforce this.

| Case | Procedure and required observable |
| --- | --- |
| Valid spend | Broadcast via fixture producer only; client sees height 0/-1, verifies independently, enters SUSPENDED before any mining. Mine one block after barrier, verify inclusion/checkpoint, then FINAL. |
| Bad signature, correct outpoint | Mutate signed bytes and recompute txid. Core rejection alone does not test the client: a controlled protocol adapter also advertises/injects the invalid raw candidate. Client validation fails and state remains ACTIVE. Preserve RPC rejection separately. |
| Wrong outpoint | Use a valid signed spend of another owned fixture output; route it through the watched-script stream (or controlled injection). Exact txid/vout check rejects it; ACTIVE remains. |
| Hiding server | Replay genuine pre-spend status/history/unspent replies and suppress the notification. Single-server client remains unaware within the 20-second window; report UNDETECTED, not proof of no spend. |
| Second honest view | After the hidden window enable a second controlled protocol endpoint/session serving the real mempool. It reveals the spend, and independent validation suspends. Endpoints can share an indexer; explicitly no independent-operator claim. |
| Dropped candidate | After a valid candidate suspended its own seal, remove it from the owned regtest mempool through controlled no-persist restart; observe absence for 20 seconds. Keep SUSPENDED. Never interpret missing history/UTXO disagreement as permission to resume. No host process restart. |
| Replacement | A separate fixture seal has a valid replaceable spend, then higher-fee conflicting replacement. Record both txids, signatures and Core results. Keep SUSPENDED through disappearance/replacement; one validated spend at one block finalizes revocation of that outpoint. If policy rejects replacement, report rejection and stop that case; no policy change/retry loop. |
| Reconciliation | Resume only through explicit recorded policy decision with trusted validated-chain reconciliation of the outpoint and all known conflicts; this unit does not implement automatic resume. Restart/reorg uncertainty remains SUSPENDED. |
| Organization name | Pin existing name and prior name outpoint. Before mining compare synthetic-name subscription/history/value-proof, owner-script subscription/history/raw transaction, Core name_show/name_pending. Parse name_update, exact name/value and predecessor. Signature validation of the name-prefixed predecessor requires an additional reviewed verifier path; until then label value as observed bytes, not independently validated organization authority. After mining repeat the same queries. |

Do not change ElectrumX to invent the absent unconfirmed name API. No free-form
transaction supplied by an external server reaches the producer broadcast RPC.

## OP_RETURN matrix and separate result columns

`design.py` generates deterministic public output scripts and an executable
machine-readable schedule. It never constructs a signed transaction or contacts
a service. `design.json` is the finite experiment specification. Generated
`standard_script_size_candidate` is a source predicate only, not a measured
policy/admission/relay/mining result.

Include single pushes of 0, 1, 75, 76, 79, 80, 81, 82, 83, 255, 256,
520, 521, 9999, 10000, 65535, 65536, 99990, 100000, 100001,
999000 and 1000000 data bytes. Boundaries cross push prefixes, CompactSize,
execution-rule misconceptions, standard weight and block weight. Add two
40-byte pushes, a 76+4 split, two NULL_DATA outputs, OP_RETURN+nonpush, and a
truncated PUSHDATA1. The large cases are metadata/serialized-output fixtures,
not claims that a transaction of that size fits in a block.

Later sign each selected case using separate mature fixture inputs and a fixed
conservative fee computed from actual signed vsize (at least twice the queried
effective minimum, with an explicit finite regtest fee ceiling). The earlier
fixed-fee rejection is why signed vsize must be used. Record Core rejection
codes/text verbatim and distinguish fee, weight, shape and datacarrier causes.
Never modify default relay or mining policy to obtain a success.

Each row records data bytes summed over pushes, script bytes, push framing,
output serialization, stripped tx bytes, total bytes, witness bytes, weight,
vsize, fee/rate, exact arguments, local testmempoolaccept, local admission,
peer relay, default template membership, default generated-block inclusion,
and explicit raw-transaction forced-block validity as **separate** columns.
Unperformed columns are NOT_RUN, never inferred from another column.

The existing topology has one Core and P2P disabled. It can measure local
admission and default template/mining, **not P2P relay**. Do not add a second
node under this plan. After a separate bounded topology admission, a receiver
can observe P2P receipt under unchanged defaults in private loopback; without
that admission the relay column remains NOT_RUN. Two Electrum endpoints do
not prove Core-to-Core relay.

For a default rejection, a subsequent `generateblock` raw-transaction control
may test consensus-valid inclusion on a disposable branch, explicitly labelled
forced selection. A separate branch is required to avoid contaminating default
mining tests with a forced block. It is not part of the immediate revocation
runtime below. If a bound stops the search, report only the largest tested
success and smallest tested failure, with exact construction and tested domain;
do not claim the global largest relayed/mined or unbounded consensus capacity.

## Part B: later, read-only, held

Prerequisites: the managed mainnet node custodian supplies a validated tip receipt with height,
hash, chain=main, headers/blocks agreement, initialblockdownload=false,
verificationprogress and chainwork, explicit assumevalid/validation policy,
pruning and block-data availability, and txindex state where required. A header
tip alone is insufficient. No live node RPC or filesystem access occurs here.
No new index, txindex, rescan or capacity is implicitly admitted.

Use a separately authorized read-only RPC allowlist (`getblockchaininfo`,
`getblockhash`, `getblock` verbosity 2, `getpeerinfo` once), with custodian-held
credentials never exported. Freeze stop height/hash. Scan bounded ranges with
one request in flight, <=2 requests/second, <=5000 blocks or 10 minutes per
chunk, <=64 MiB response bytes and <=24 MiB exported evidence; checkpoint cursor
and abort on tip/hash mismatch or missing/pruned data. A chunk is partial until
all ranges at the frozen snapshot are accounted for. Do not invent zero counts
for unscanned years or start an unbounded whole-chain scan.

Define year by the containing block's UTC header timestamp (not wall arrival or
MTP); explain timestamp irregularity. Count outputs whose script starts with
OP_RETURN, separately counting push-only parseable NULL_DATA, malformed/nonpush,
zero-data and multiple-data-output transactions. Decode push lengths, sum raw
data bytes without treating script/prefix bytes as payload, retain script-size
distribution separately, and report a declared treatment of small-integer
opcodes. Publish per-year output count and histogram, count with payload >80,
largest payload and script with txid/vout/height/blockhash, and scan coverage/
errors. Block outputs can be decoded without historical txindex; do not require
a new txindex merely for this survey. Witness is recorded separately if present.

One cheap getpeerinfo snapshot may supply sanitized user-agent (`subver`)
counts, bounded strings and peer count. Do not export peer IPs/addresses/node
IDs or present self-reported user agents as authenticated software identity,
miner identity, network population or policy support. No discovery/connect,
broadcast, wallet, keys or coins. A later source-checked parser must precede
the scan; no scan was performed for this plan.

## Exact next bounded runtime unit and cleanup contract

Next proposed unit: **revocation-mempool-regtest-v1**, only after the corrected
composition and new independent signature-verifier/driver review are sealed.
It does not inherit runtime authorization from this source plan. The lab operator
supplies a separate acceptance clock and the exact reviewed head/tree, input
hashes, fixture-only operation allowlist and launcher receipt. The independently
reviewed driver must implement the schedule in `design.json`; the generator is
not that driver. Do not run the old Part A mining harness as if it measured
unconfirmed suspension.

Finite scope: one Core 28, one unchanged patched ElectrumX, two controlled
read-only protocol endpoints, at most two capability-separated instances of the
same thin client, <=6 mature
fixture funding outputs, <=12 signed candidate spends, <=224 total blocks from
genesis, one name_firstupdate and one pending name_update, <=2 owned Core
restarts for the drop/reconciliation controls, <=512 protocol requests,
<=64 MiB protocol traffic, <=1 MiB per frame. No new full node or public peer.
Stop if maturity/name setup consumes the block allowance. Limit each awaited
notification to 20 seconds and each RPC to 10 seconds; preserve the default
ElectrumX 5-second mempool refresh and cost limits. Wall cap 1500 seconds,
supervisor backstop 1600 seconds, total acceptance budget 35 minutes with the
last 120 seconds reserved for export and cleanup. Do not retry after exhaustion.
OP_RETURN runtime and all Part B work are subsequent separate bounded units.

Launcher checklist, fail closed before fixture creation:

- Aggregate cgroup MemoryMax=3 GiB, MemorySwapMax=0, CPUQuota=200%, TasksMax=64;
  two-CPU affinity; CPU budget <=1200 seconds/process; no paid reserve or bypass.
- bwrap `--unshare-all --clearenv --new-session --die-with-parent --cap-drop ALL`;
  source/tools/public verified runtime read-only. Empty /etc and /home; no host
  home, keys, foreign caches, agent/session sockets, host /run or credentials.
- Private task-owned namespace tmpfs capped at 1536 MiB, stop at 80%; task
  retained allocation <=2 GiB. Absolute 0700 HOME/TMPDIR/XDG_CACHE_HOME and
  umask 077. No host-network fallback; only namespace loopback.
- Core regtest, assumevalid=0, txindex only in disposable fixture, P2P disabled,
  no discovery/seeds/connect; confirm chain, genesis, zero peers and initial
  empty listening table. Keep fixture cookie/keys/wallet out of logs/artifacts.
- Producer alone may sign and broadcast fixture transactions and mine after
  the explicit barrier. Indexer gets read-only RPC proxy; client gets protocol
  only. Client process has no cookie, key, wallet or oracle RPC capability.
  Adversarial adapters can return public invalid bytes but cannot broadcast.
- Sample cgroup current/peak memory, CPU, tasks and tmpfs usage at startup,
  prebroadcast, presuspend, premine and shutdown. Stop on headroom threshold,
  unsupported signature/path, wrong-chain mismatch, or missing containment.
- Trap exit/signals: stop indexer and Core, drain/reap children, inspect namespace
  listeners and exact owned unit MainPID/state, discard private tmpfs, retain
  only public transaction/proof/status bytes and sanitized timing receipts.
- Export actual attempts, limits, start/end/exits including timeout/OOM/rejection;
  no success relabelling. Seal report/result/source/diff/receipts/checks and
  SHA256SUMS <=24 MiB before deadline. Cleanup is disposal, not secure erasure.

No real phones, Namecoin fork, production profile, or real Muse session belongs
to these experiments. No messages, push, PR, merge or landing is performed here.
