# Destination-bound observations and preparation capacity

Read-only RPC observations to the admitted own T1 node at literal `127.0.0.1`
are capped at ten serial dispatches per second in **every phase**: initialization,
verifier broker, preparation, local mempool, peer checks, inclusion, maturity
and expiry. The own observer capability has an explicit destination binding;
the launcher must enforce it on the actual transport, without DNS substitution,
redirects or proxies, and attest it in capability custody. A matching read
method on any other capability does not earn this exception. This metadata is
not itself a transport sandbox or proof of ownership.

The scheduler retains one shared last-observation clock. An own-node read waits
at least 0.1 seconds after the preceding observation. Every other observation,
including each public/remote-peer poll and a public-server RPC with the identical
read method, retains its ten-second wait after the preceding observation.
Neighboring loopback reads therefore cannot accelerate public requests. All
retained anchors consume separate actual RPC slots. No caching, batching,
omission, concurrent burst or phase-specific exemption is introduced.
Construction, wallet signing and broadcast do not acquire a read-only exception.
The in-flight lock, response/transport bounds, bytes and global **2100 total
calls** (including construction/sign/send and remote calls) remain separate.
Waiting may sample more slowly. Local loopback traffic retains the node's
existing 100% CPU, 2 GiB and 64-task caps; this source changes none of them.

## Full-path calculation

An established-tip `network()` makes `4+a` RPCs with `a` retained anchors:
blockchain info, genesis, previous tip, each anchor and current tip. The actual
source has **three** complete network passes: entry before policy,
the shared builder (or exact-input branch), and the final pass after exact-raw
admission. For a funded single-input transaction it also makes nine observation
RPCs: two fee-policy reads; helper decode/prevout/policy; inspect
decode/prevout/UTXO; and final acceptance. Thus it needs `3*(4+a)+9` calls.
For an exact-input operation the corresponding minimum is `3*(4+a)+6`;
additional funded inputs add three reads each. These counts omit transport,
construction/signing, durable-journal and exact-raw admission latency.
The capacity guard conservatively retains one reserved policy-read slot,
using the earlier `+10` and `+7` allowances. No estimator RPC is dispatched.

| Retained anchors | Single-input read calls | Best possible dispatch span | Actual zero-latency control preparation | Peer after symbolic send |
|---:|---:|---:|---:|---:|
| 0 | 21 | 2 s | 2.1 s | 10.6 s |
| 10, T1b entry | 51 | 5 s | 5.1 s | 11.6 s |
| 12 | 57 | 5.6 s | 5.7 s | 11.8 s |
| 13 | 60 | 5.9 s | 6 s | 11.9 s |
| 16, last T1b step | 69 | 6.8 s | 6.9 s | 12.2 s |

The control begins immediately after a prior observation, hence one additional
initial wait. It executes the actual full collector path with only synthetic
transport/capability/gate doubles: **no scheduling or feasibility bypass** for
successful rows. Its peer path includes local pool, all network/anchor reads
and the unchanged ten-second public wait. This proves scheduling feasibility
under the stated zero-latency assumptions, not a successful chain experiment or
a guarantee that real RPC/Meta latency fits the remaining margin.

Preparation now has an exclusive 180-second limit. The capacity guard uses
`(minimum_calls-1)*0.1` and still refuses impossible mandatory observation
counts before construction, signing, exact-raw admission or send. The actual
seven-size synthetic series, starting with ten retained anchors, completes
80/100/200/520/1000/4000/10000 in 154.7 seconds, uses 892 total calls including
initialization, and consumes seven separate exact-raw admissions. It retains
all seventeen resulting anchors and never resets the series or shared clocks.

The peer minimum after symbolic send is `10+(6+a)*0.1` seconds, including the
local pool, network and immutable broadcast-baseline reads and the ten-second
public wait. At ten anchors this is 11.6 seconds, so the existing 120-second peer bound is retained; no
300-second extension is needed by this formula. Real transport/journal/gate
latency can still exceed the limit and must stop safely. The peer deadline is
the earlier of preparation-start plus 180+120 and broadcast-start plus 120;
it never extends the 1500-second step or either immutable shared clock.

Historical causal controls explicitly restore the prior 1/s and 60-second
parameters in tests only. They retain the prior thirteen-anchor guard refusal,
guard-only-bypass deadline failure without send, and fourth-size series stop.
The new controls separately allow a 100-second exact-raw gate delay and refuse
a 180-second delay before send. These are synthetic controls, not live node,
funding, signing or broadcast evidence.

Destination neighbor controls execute identical read methods on the own
observer, a public capability and a foreign capability labeled loopback. Only
the admitted own observer receives 10/s. They cover every phase and preserve
public spacing. Actual peer-pending and inclusion-pending paths hit their
unchanged deadlines and stop without retry or advancing. The verifier still
executes in its separately isolated sibling process with the restricted public
stdio broker; no signer or broadcaster capability crosses that boundary.

Preparation <180 s; peer <120 s, inclusion <1320 s, step <1500 s, series <10500 s
and the original shared <=21600 s remain fixed. Before any T1b gate/preparation,
the collector reserves all 10500 seconds against both immutable shared clocks.
Just below that amount, or at/after either expiry, it refuses without T1b I/O.
Reentry resets neither start nor deadline. Higher observation throughput can
reach the unchanged global 2100-call ceiling sooner; it does not authorize a
counter reset or a separate per-phase/series allowance.

The funding cash-flow revision, Ivan-only funding, maximum 1 NMC cap, and
source-bound exact-raw GO before every broadcast remain intact. This source
neither authorizes runtime nor supplies a live launcher. Independent review
and a new exact marker are required for this changed source.
