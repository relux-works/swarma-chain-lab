# T1b relay evidence with blocks-only operation

This is source qualification, with no RPC, connection, node/config change or
transaction execution. It supplies no runtime admission. The fixed fee is
200 sat/vB; an unavailable estimator grants neither an inclusion prediction nor
a reason to wait for an estimate.

The assessed Core is release `nc28.0`, commit
`a08218ef2d44b81c53d25c399898e59271f4b642`. Its source establishes:

- `src/init.cpp`: `-blocksonly` rejects ordinary incoming peer transactions;
  RPC-submitted transactions are unaffected. Fee estimation is not initialized
  when incoming transaction relay is ignored.
- `src/net_processing.cpp`, `RejectIncomingTxs`: blocks-only connections reject
  transactions; in blocks-only mode a peer requires the relay permission for
  incoming transactions. Existing permissions must be evidenced, never assumed.
- `src/node/transaction.cpp`, `BroadcastTransaction`: local RPC submissions can
  enter the mempool and request outgoing relay. This does not prove any peer
  accepted them. Core also tracks local unbroadcast transactions; this collector
  supplies no retry or resend API, and runtime qualification must account for
  Core's own background relay behavior without claiming one network announcement.

The preserved configuration snapshot pins `blocksonly=1`, `persistmempool=0`,
`listen=0`, two configured connections, and no peer relay-permission exception.
Its configuration SHA256 is
`5f71154ee38196502814c622851c2ff0501593aaf65aa0c204058142cb2ccf2f`.
The later funding launcher pins the same configuration and overrides only
network activity and wallet availability relevant here; it does not override
blocks-only mode. This assessment uses exported configuration/start records,
not a new read of any node directory or credential. No current node state is
asserted.

| Fact | What blocks-only mode permits us to conclude | Missing qualification |
|---|---|---|
| Own `testmempoolaccept` | Local policy only | No peer acceptance or inclusion promise |
| Own `getrawmempool` | Can observe an RPC-submitted own transaction | Not a representative view of other peers' unconfirmed transactions; absence is not universal non-relay |
| Successful local send / outgoing inventory | Local submission / announcement only | No independently authenticated remote acceptance |
| Remote mempool receipt | Potential pre-inclusion relay evidence | Separately admitted observer, actual transport/destination, exact txid/raw hash, authenticated UTC receipt after broadcast, permission and mempool capability |
| Remote block receipt | Inclusion at that observer | Does not demonstrate pre-inclusion mempool relay |
| Local block and exact raw bytes | Active-chain inclusion at observation | No authenticated miner identity, peer policy maximum, or finality guarantee |

The collector already requires an own-loopback observer, local mempool presence
and a separate authenticated peer receipt. This delta narrows the peer receipt
to `remote_mempool`; `remote_block` now stops with `PEER_EVIDENCE_KIND`. Missing,
refused or late peer evidence remains terminal. It neither synthesizes an
observer nor replaces remote evidence with a local check. The preserved node
and funding records do not demonstrate such an independent observer exists or
is admitted, so T1b relay readiness remains unqualified.

No change from `blocksonly=1` is necessary merely to submit and inspect one's
own RPC transaction. If the experiment needs a general own-node view of incoming
peer transactions, the proposed parameter is explicit `blocksonly=0` on the
separately admitted experimental node, with its memory/traffic limits and
background wallet/relay behavior qualified first. This is a proposal only;
no parameter, permission, connection or node is changed. Enabling it would
still not replace the independently authenticated remote mempool receipt.

Each exact raw transaction still needs Meta GO; only Ivan funds it; the total
cap remains 1 NMC. The six-block window and all earlier time, call and byte
bounds apply independently of whether relay evidence is available. Earlier
bounds can stop a stalled chain before it produces six blocks. Reorgs stop;
they do not refresh the broadcast baseline or permit another send.
