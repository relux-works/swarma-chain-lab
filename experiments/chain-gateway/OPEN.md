# Questions and answer events

Answers are attributed to the supplied events, not independent host verification.
Source answered contract head `3f50b9b257fcc9e337a440146d1330b6f08ef6c7`.
A changed head still requires Source's delta acceptance and the review of record.

## Answer events

- **S-r1**: Source, consumer answers r1, 2026-11-16, `source-answers-r1.md`.
  SHA256: `9d2a214105b603664c222f704e8ecf33719a3e077fcb11fbe0a662a9375a0ad9`.
  Source read the contract, not the fixture corpus; adapter fixture binding and
  D29 parser adoption are separate evidence obligations.
- **I-Q367**: Infra's Q3/Q6/Q7 reply on that same head,
  `infra-answers-q3-q6-q7.txt`.
  SHA256: `e51a5e222292fd7a676e16e7d2b708f0c5492d0e00f4df748be5d6958c4b5ee5`.
  Host facts are attributed; install proposals require S8 owner GO.

## Answered questions

| ID | Answer event and disposition |
| --- | --- |
| Q1 | S-r1 Q1: accepted for v1 with four connections per command, shared-UID 8/s bucket, Linux listener and SH5 approximation. For this delta, darwin/ivmbp is snapshot-only v1; active-chain membership is a v2 candidate. Normative §4. |
| Q2 | S-r1 Q2: accepted not_in_utxo_set. Absence refuses each command; permanent closure only after this reader journaled unspent, never-seen absence is per-command. Closures never lift, gateway errors create none. Consumer mapping closed; policy-owner spec clarification remains Q8. Normative §3. |
| Q4 | S-r1 Q4: part (B) final, accepted for the helper build now; D29 retargets its parser and later identifies its adoption head. No claim of installed adoption. Normative §5. |
| Q5 | S-r1 Q5: 30-second heartbeat/60-second observe labels accepted. Requested block-header Tip.time added to all successes and snapshot. Default lag 7200 s is consumer policy, not gateway policy; (b)-only has no independent live tip and never labels fresh. Normative §§3–5; changed-head acceptance pending. |
| Q6 | I-Q367 Q6: install settings proposed in INSTALL PROFILE, with S8 accounts list/GO and socket-parent provisioning decision still required. Answer closed as proposal, not install approval. |
| Q7 | I-Q367 Q7: root oneshot, flock, fresh cookie each run, tmp/fsync/rename, explicitly allow-listed root after gateway install accepted by Infra. Normative §5; paths/custody in INSTALL PROFILE remain an S8 proposal. |
| Q9 | S-r1 Q9: confirmed SH3/4/5/6 and O3.4–O3.6; deep-reorg false refusal approximation and Draft/co-author status preserved. Normative §4. |

## Open gates

| ID | Decision/input needed | Owner | Gate |
| --- | --- | --- | --- |
| Q3 | Qualify an exact node/read adapter that witnesses all tip transitions, including hidden A→B→A and same-height reorgs, coherent name binding and mempool-inclusive gettxout. Infra proposes Core 28.0, dedicated node, rpcwhitelist and ZMQ sequence; no feasibility evidence yet. Settle ancillary reads for header time and network/IBD validation. Ordinary RPC bracketing is insufficient for §4 gateway (a) and any enforcement. The accepted §5 amendment permits bracketed OBSERVE ONLY snapshots without a witness. | Gateway implementer and node owner | Gateway (a) and enforcement consistency; live qualification |
| Q8 | Assign book PR for new service/wire/snapshot profile and spec PR for coherent observations and accepted UTXO-absence mapping; obtain policy-owner approval for permanent closure rule. | Lead and documentation/spec owners | Production adoption |
| Q10 | S-r1 Q10 states D29 is observe-only and per-command polling is insufficient. Separate host-owned watcher/journal writer and consumer reader must be accepted and qualified, including SH5 state, missing-journal refusal and durable closures outside agent authority. §4 records these enforcement preconditions; this contract implements none. | Lead, Source and host-side implementer | Enforcement remains off |

Enforcing over snapshot (b) remains prohibited without a new owner decision.
The INSTALL PROFILE is an attributed proposal under S8 GO, never installed code.

## Accepted HELPER-B r3 amendment

Source acceptance event `$Omp4AzWq`, backed by the lead in the supplied brief,
authorizes §5 ordinary RPC bracketing for OBSERVE ONLY. Complete Tip equality,
three attempts with 100/200 ms backoff, untouched previous file and exit 12 on
exhaustion, and required closed `consistency:bracketed` are normative. V1
rejects `witnessed` as invalid; it cannot be self-asserted. Bracketed closures
belong only to an observe journal, never enforcement state. Q3 remains in full
for (a) and enforcement; Q10 and installation/adoption remain separate gates.
The helper build blocker from r2 is resolved by this explicit amendment.
