# Part A: bounded offline regtest proposal

This is the next-step plan, not a server activation or another implementation.
First obtain fresh independent review of the exact candidate head/tree, patch,
artifact hashes and tests. Then admit the resource bounds and the separately
pinned regtest node/client inputs. Do not infer a permission to run from these
documents or from the upstream configuration template.

## Reuse and isolation

Reuse the pinned server with this reviewed patch. Its exact coin definitions
include `NamecoinRegtest`, inheriting the Namecoin dynamic-header/name-index
behavior with `NET=regtest` and a distinct genesis. Use Namecoin Core 28.0 at
its recorded commit, with its binary/source verification admitted separately.
Use one thin protocol driver for requests, timestamping and fault injection;
reuse an independently pinned existing Namecoin SPV/proof verifier for consensus
and name validation. Do not reimplement those validators or duplicate the
completed name/seal experiments. Their admitted public interfaces are inputs to
the next phase, not results claimed by this packet.

Run all processes in one fresh unprivileged bubblewrap network namespace with
`--unshare-all --clearenv`, read-only public tools/source, private absolute 0700
HOME/TMP/cache, no host home, keys, sockets or caches. Bring up only private
loopback. Mount no persistent node data, cookies or wallets. Use a fresh regtest
datadir and index; do not bind host ports or enable public peers, discovery,
announcement, DNS seeds, UPnP, NAT traversal or external listeners.

Proposed private endpoints are Core RPC `127.0.0.1:18443`, Electrum
`127.0.0.1:50001` and two fault adapters `127.0.0.1:50002/50003`, all exclusively
inside that namespace. They are proposals, not opened listeners. Core must bind
RPC only to private loopback, listen to no P2P peers, and use only the new private
regtest state. Assert the exact genesis, `regtest` chain identifier and initial
index/header hash before any fixture is accepted. Set `COIN=Namecoin`,
`NET=regtest`, `PEER_DISCOVERY=off`, `PEER_ANNOUNCE=false` and empty report
services; never reuse the mainnet preparation template unchanged.

Core regtest txindex may be enabled only in this new disposable datadir under
this plan's admission. It does not alter or qualify any persistent mainnet
index. The server's daemon adapter needs a reviewed private cookie-to-RPC
mechanism because it takes an authenticated URL rather than a cookie path.
No credential in argv, logs, artifacts or errors. Restrict client methods to
read-only proof/history/header/subscription requests; the fixture's local Core
transaction producer is a separate narrow capability. If the existing runtime
cannot enforce the reviewed auth/method policy, stop and report that blocker.

## Proposed limits, measurements and stop conditions

These are proposed ceilings, not measured requirements or current allocations:

| Resource | Whole lab proposal |
| --- | --- |
| Wall time | 90 minutes total: 10 preflight, 20 chain/name fixtures, 20 proofs/subscriptions, 20 adversarial cases, 10 restart/reconciliation, 10 export/cleanup. Stop earlier on a failed prerequisite. |
| CPU | Aggregate 2 CPU equivalents, at most 2 producer threads. Record per-process CPU and total elapsed time. |
| Memory | Aggregate 3 GiB, no swap: Core target 768 MiB, server 1536 MiB, adapters/driver target 256 MiB, remaining supervisor/flush headroom. Targets are not hard memory enforcement. |
| Disk | Hard aggregate 2 GiB private volume: proposed node 512 MiB, index 768 MiB, logs 16 MiB, final receipts 32 MiB, remaining compaction/flush headroom. Count all temporary files, DB WAL and both indexes. |
| Workload | Initially at most 512 blocks and 128 fixture transactions; at most 32 concurrent scripthash subscriptions per session, 2 sessions, 256 total protocol requests plus bounded subscription notifications. |
| Responses/timeouts | 10 MiB wire-frame ceiling inherited for AuxPoW; additionally bound client total received bytes to 64 MiB, individual request wall time 5 s and scenario deadline 120 s. Preserve actual refused requests. |

Use an available reviewed cgroup/quota mechanism for aggregate CPU/memory/disk
bounds; bubblewrap and per-file `ulimit` alone do not provide these limits. If
no unprivileged mechanism is available, stop for infrastructure admission; do
not call a sampled size check a hard aggregate quota. Warn/stop new work at
70% disk, request graceful shutdown at 80%, reserve the remainder for flush,
record peak byte/inode usage and test the shutdown path before the workload.
Record monotonic and UTC timestamps, executable/source hashes, exact config
without secrets, CPU/RSS, filesystem/index sizes, tip height/hash and every
command exit. No arbitrary increase beyond an admitted ceiling.

## Real positive cases

1. Verify new datadir provenance and regtest genesis, full local validation,
   synchronized regtest txindex, and server indexed tip equals Core's hash.
   Construct real regtest transactions using only ephemeral regtest material;
   mine enough maturity/commitment confirmations under the pinned consensus
   rules. Keep ephemeral key/seed/cookie bytes out of the export. Record public
   raw transactions, txids, heights, block headers and expected scripts.
2. Register one name through real `name_new` and `name_firstupdate`, then perform
   at least two real `name_update` transitions with distinguishable values.
   Prove transaction inclusion and ownership transitions with the existing
   verifier. At 1.4.1 fetch history/transactions/Merkle/header proofs explicitly;
   at 1.4.3 also test `blockchain.name.get_value_proof`. A bundle or RPC success
   alone is not a verified result. Crosscheck final name/value/outpoint against
   the local validating node's name state and unspent-output query.
3. Exercise the corrected header path at nonzero heights with no checkpoint,
   checkpoint exactly covering the last returned header and a later checkpoint;
   check array/hex shapes and limits against individual headers. Regtest may not
   naturally produce representative mainnet AuxPoW extensions: report that
   gap and retain the synthetic dynamic-header controls. Do not call ordinary
   regtest PoW an AuxPoW consensus validation test.
4. Subscribe using `blockchain.scripthash.subscribe` to the actual notification
   script, name-index script where appropriate, and seal output script. Receive
   the initial status before mining each trigger. Exercise creation, name value
   change and seal spend; fetch the resulting history/proof after notification.
   Verify that the script truly changes for each expected notification.
5. For at least 10 bounded trigger observations, record monotonic timestamp at
   mining RPC dispatch and return, indexed-tip observation, notification receipt
   and completed proof verification. Report dispatch-to-notification,
   return-to-notification (possibly negative), index-to-notification and
   notification-to-verified-state. Report min/median/p95/max and censor any
   timeout at its actual bound; no latency promise is inferred in advance.
   Mining RPC return is not the exact consensus-acceptance instant. An exact
   acceptance latency requires a reviewed timestamped local hook; otherwise
   present the dispatch/return interval and its limitation explicitly.

## Adversarial and causal controls

Use two tiny deterministic response adapters over the one real indexed server;
they alter protocol responses, not chain data or the verifier. This avoids a
duplicate index while testing disagreeing views. It is not evidence of two
independent server operators. Log fault rule IDs and public response hashes.
Pair each fault with the same unfaulted successful request and an expected
reject, unknown or freshness failure outcome.

* Stale: replay the earlier valid name proof/value at the newer known tip;
  withhold header/tip updates and bound the freshness timer. Reject a detected
  contradiction or mark the answer stale/unknown instead of claiming latest.
* Omission: hide a known update, omit a known seal spend, return empty name
  history, or suppress the subscription notification. The real local node and
  the unfaulted view provide the test oracle, so record which omissions that
  oracle detects. Timeout is not a proof of absence or an unspent output.
* Disagreement: one adapter reports the update/spend, the other the old value
  or outpoint. Preserve both responses, tip heights/hashes and proof failures;
  do not choose whichever server yields a convenient answer.
* Wrong chain: inject a Bitcoin/different-regtest genesis or a foreign header
  prefix into a Namecoin response. The pinned verifier must reject the chain
  binding before accepting a name/seal value. Pair with modified Merkle branch,
  tx bytes, checkpoint root and a nonzero-start boundary regression control.
* Protocol/resource failures: checkpoint below the last returned header,
  count/array/byte mismatch, truncated AuxPoW, chunk limit, error -101,
  malformed/oversized reply, disconnect and notification loss. Treat refusal
  as failure/unknown, not missing name or authorization to evade server costs.
* Reconcile after a small local regtest reorg and graceful restart under the
  same cap; ensure old status and proofs are invalidated before a new claim.

**A single server can omit a relevant transaction or history consistently
without SPV inclusion proofs exposing the omission.** If no independent oracle
or previously known conflicting fact is available, the omitted update/spend may
remain undetectable, including a hidden seal spend. Record that control as
`UNDETECTABLE_WITH_SINGLE_SERVER_EVIDENCE`, never as a successful completeness,
latest-value, nonexistence or unspent-state proof. Subscription delivery and a
seal do not remove this limitation. The local full node oracle tests detection;
it does not turn a thin remote client into a full validator.

## Exit packet and Part B hold

Seal public fixtures, exact source/config/artifact pins, protocol transcripts,
request and notification timestamps, proof outcomes, failure bounds, resource
measurements and cleanup receipt. Include all failed attempts. Delete only the
new private lab state after stopping its processes; export no private keys,
cookies or wallet files. A reviewer decides which bounded claims the evidence
supports; the producer does not certify operational qualification.

Part B remains **blocked**. The older sealed height-zero observation is stale
and proves no current tip. No persistent-node RPC, cookie, datadir, txindex,
index configuration or capacity is accessed or changed here. Require a validated
current tip and separate reviewed node/index capacity and configuration plan
before estimating or measuring mainnet indexing. No mainnet transaction,
wallet, token, coin, funding or broadcast belongs to this plan.
