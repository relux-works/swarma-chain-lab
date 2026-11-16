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

- **R147-FIX1**: Opus review of record 5920320803 on `3f50b9b2`;
  owner accepted ALL twelve findings for the current-head fix round. F1/F2
  require kernel endpoint-owner authentication before credentials and verifier
  users; only a same-host root helper may select the cookie install exception.
  Reviewer proposed vectors/observations and omission-analysis aid are credited
  in CONTRACT.md and incorporated with the new schema fields.
- **S-F5**: Source's binding F5 decision, `source-F5-decision.txt`:
  confirmed AND not mempool-spent, separate transient states, exact script and
  confirmations, no transient permanent closure. This supersedes S-r1 Q2's
  ambiguous “absent” wording. The new exact head needs Source's delta acceptance.
- **CGW-NW**: The non-witness clarification supersedes F5/Q2's permanent-reader-
  closure wording. A gateway-backed reader refuses anything but `unspent` and
  creates NO enforcement closure. Prior journaled `unspent` followed by
  confirmed-set absence creates only an OBSERVE-GRADE closure, never imported
  into enforcement: no spender was validated, and a reorg can remove funding.
  Enforcement closures come ONLY from CGW-J1 (Q10), with spending transaction
  bytes validated against the seal script, conflict completeness and one named
  tip. The four states and closed v1 method set are unchanged.

## Answered questions

| ID | Answer event and disposition |
| --- | --- |
| Q1 | S-r1 Q1: accepted for v1 with four connections per command, shared-UID 8/s bucket, Linux listener and SH5 approximation. For this delta, darwin/ivmbp is snapshot-only v1; active-chain membership is a v2 candidate. Normative §4. |
| Q2 | S-F5's two fixed gettxout views (false/true) and four states stay: unspent is confirmed >=1 AND not mempool-spent. CGW-NW makes the gateway-backed reader a NON-WITNESS for mempool-first closures: refuse anything but unspent; create NO enforcement closure. Prior journaled unspent followed by confirmed-set absence yields only an OBSERVE-GRADE closure, never imported into enforcement; absence can be a funding-removal reorg, not a validated spender. Transient states and errors create no closure; observe-grade labels never become enforcement state. Enforcement closures come only from Q10's CGW-J1. Q8 policy-owner approval remains separate. Normative §§3–4. |
| Q4 | S-r1 accepted part (B) for helper build; HELPER-B r3 accepted bracketed observe-only amendment. Fix 1 adds seal metadata/states and exact byte/binding rules, needing Source's new-head acceptance. Missing confirmed names prevent whole-file publication (exit 11, old file ages); file alone cannot distinguish vanished name/helper failure. Static watch set requires root reconfiguration after a list adds seals; incomplete sets label invalid. D29 adoption needs its own head. |
| Q5 | S-r1 Q5: 30-second heartbeat/60-second observe labels accepted. Requested block-header Tip.time added to all successes and snapshot. Default lag 7200 s is consumer policy, not gateway policy; (b)-only has no independent live tip and never labels fresh. Normative §§3–5; changed-head acceptance pending. |
| Q6 | I-Q367 Q6: install settings proposed in INSTALL PROFILE, with S8 accounts list/GO and socket-parent provisioning decision still required. Answer closed as proposal, not install approval. |
| Q7 | Owner F1/F2 supersedes gateway-cookie proposal: gateway verifier user only, enumerated five-method rpcwhitelist; ivmbp verifier user only. Helper normally uses its own verifier user. Only explicitly configured same-host Linux root helper may read the fresh node-owned cookie, or an independently admitted restart-synchronized root copy under §2 custody; no gateway/agent access or fallback. Root oneshot/flock/atomic publication remain. Cookie exception is broader authority, not a least-privilege claim; rotation/copy qualification and S8 GO remain required. |
| Q9 | S-r1 Q9: confirmed SH3/4/5/6 and O3.4–O3.6; deep-reorg false refusal approximation and Draft/co-author status preserved. Normative §4. |

## Open gates

| ID | Decision/input needed | Owner | Gate |
| --- | --- | --- | --- |
| Q3 | Qualify exact node/read adapter for ALL tip transitions including hidden A→B→A, name_show (no complete tip/hash witness), and negative gettxout (null has no bestblock). Positive gettxout has bestblock but the fixed false/true pair also needs coherent mempool state. Require name/value hex round trip, header-time/network/IBD ancillary reads using EXACTLY getblockchaininfo,getblockhash,getblockheader,name_show,gettxout; qualify expired-record retrieval and signed vout range. Infra proposes Core 28.0/ZMQ sequence, with no feasibility evidence yet. Freeze is interface-only; “enforcement-ready” requires this qualification. Ordinary brackets remain insufficient for (a); §5 is observe-only. | Gateway implementer and node owner | Gateway (a) and enforcement; unqualified reads unavailable |
| Q8 | Book PR for new service/wire/snapshot/profile/resource reservations; spec PR for coherent observations, confirmed-only unspent and CGW-NW's non-witness/OBSERVE-GRADE clarification of F5/Q2. Pinned LIP-0029 §3.1 field 6 defines only outpoint; §8.3 O8.8 and following paragraph leave seal script open. The gateway claims no seal-script validation; Q10 requires an accepted script binding before the watcher can qualify validated spending bytes. Define that expected script in an accepted clause/list extension before claiming it. | Lead and documentation/spec owners | Production adoption and any script-check claim |
| Q10 | CGW-J1: separately admitted chain-lab host-owned watcher/journal next to the node, and Source journal reader. This is the ONLY source of enforcement closures: spending transaction bytes validated against the seal script, conflict completeness and one named tip are required. Reference sealwatch, with dedicated node-enforced getblockchaininfo,getblockhash,getrawtransaction,getrawmempool,gettxout,getblock credential for actual spending inputs. No new v1 gateway method. Qualify durable closures, SH5 state and missing-journal refusal outside agent authority. Per-command (a) is a NON-WITNESS and creates no enforcement closure, even with a coherent-read witness; owner scope is 1 LU for watcher/journal, with consumer work and owner approval separate. | Lead, Source and host-side implementer | Enforcement remains off |
| Q5 qualification | Maximal configured snapshot must fit 65536 bytes and finish within the 20-second total collection budget before the 30-second heartbeat. Root gets reserved 512-token burst/128 tokens per second and 16 active slots; agent traffic cannot spend them. A slow/moving node may legitimately leave an old file stale. (b)-only has no independent live tip: never fresh. | Helper implementer, Infra and Source | Cadence/fresh-label qualification |
| Q6 qualification | Verify kernel-owned listener AND connected reverse-tuple node UID before ANY credential bytes, with genuine-node positive and wrong-UID listener/no-Authorization negative. Same network/initial user namespace, no PrivateUsers, reserved agent IDs rejected (root helper explicit exception), no socket activation, connect-time fd delegation documented, owned restart cleanup only. Qualify per-UID reservations/fair progress under competing traffic. | Infra and gateway implementer | S8 install/host qualification |

Enforcing over snapshot (b) remains prohibited without a new owner decision.
The INSTALL PROFILE is an attributed proposal under S8 GO, never installed code.

## Accepted HELPER-B r3 amendment

Source acceptance event `$Omp4AzWq`, backed by the lead in the supplied brief,
authorizes §5 ordinary RPC bracketing for OBSERVE ONLY. Complete Tip equality,
three attempts with 100/200 ms backoff, untouched previous file and exit 12 on
exhaustion, and required closed `consistency:bracketed` are normative. V1
rejects `witnessed` as invalid; it cannot be self-asserted. Bracketed closures
belong only to an observe journal, never enforcement state. Neither a bracketed
snapshot nor a witnessed gateway read creates an enforcement closure; only
Q10's CGW-J1 watcher journal can do that. Q3 remains in full for (a)'s coherent
reads; Q10 and installation/adoption remain separate gates.
The helper build blocker from r2 is resolved by this explicit amendment.

## Fix 1 current-head finding assessment

Compared against `b435906cc0528ceda3c1b527d133bb6f48e6325c`, not only the
review's older head. F1–F10 remain open at that base; F11 is partly superseded
by the accepted bracketed amendment and (b)-only unknown labels, but still lacks
exact LF/read bound, missing-name/static-watch-set, directory and crash-temp
rules. F12 already has a dedicated Go 1.26.10 test/vet workflow, so its CI/toolchain
subitems are closed at base; expiry/range/error/profile/reflection ambiguities
remain open. Fix 1 addresses the open contract/schema/fixture items; these are
not live qualification results or Source acceptance of the new head.

## Stacked helper adoption required (PR #149)

Do not treat the helper at `414c1294` as conforming to this new contract head.
It must adopt the seal schema/two-view projection and fixtures, node UID/profile
configuration and authenticated pre-write dial, exact verifier whitelist plus
safe forbidden-method probe, dump hardening and cookie rotation custody,
name/value hex, bounded concurrent collection and the 20-second budget, and
owned crash-temp cleanup. Its schema extraction must preserve the new controls
and label/config oracles. Review its current substring reflection matcher against
the exact full-credential rule. New fake-RPC/kernel/custody/negative tests and
exact-head CI are required there. Fix 1 does not edit or rebase #149.
