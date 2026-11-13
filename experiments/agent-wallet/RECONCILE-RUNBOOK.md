# PX1 reconciliation runbook — blocked draft

**Not executable: no operator reconcile command exists at the inspected base
`32dd1d18a2d1302661d73ae51e3f5306c2eaf2e0`.** F6 and its private-regtest
rehearsal remain blocked. The frozen contract describes an operator CLI;
the implementation provides the record verifier and journal gates, but no
CLI creates the release. Do not edit journal JSON or substitute a test helper.

## Roles and custody

The primary human operator investigates and authorizes a release; a designated
backup covers absence. The deployment keeper confirms the assignment, monitored
alert channel, target host and approved executable before a public window.
Those concrete assignments belong in private deployment records.

The future reconcile CLI must run from the operator shell **as the service
UID**, using the service's existing receipt key. Separation means operator
shell only, no wire action reaching reconciliation, and a separate agent UID
that reads neither the journal nor the receipt key (T18). There is no separate
operator signing key in PX1. A local unit test cannot establish host custody.

## Recognize and retain uncertainty

The wallet journal kinds are `reserve`, `complete`, `uncertain`,
`refuse-retained`, `track`, and `reconcile`; the service journal kinds are
`admit`, `service-reserve`, and `terminal`.

After reservation, a broadcast error or a returned txid different from the
planned txid attempts to append `uncertain` and returns `BROADCAST_UNCERTAIN`.
A service-reservation failure or a failed completion append can also return an
uncertain receipt while leaving only a reservation. A crash can leave the same
open reservation without a receipt. Preserve both journals and original
receipts. Never retry under a new nonce, delete state or restore an older copy.

`FoldLedgerV2` retains `reserved_sat` minus signed releases. Both a reservation
without an outcome and an uncertain record count toward the sats **and count**
of every UTC day until closed. A partial release leaves the remainder open;
only a full release ends its future-day carry and frees the inputs. The original
reservation day's transfer count is never returned. A tracker confirmation,
conflict or UTC midnight never releases a debit.

## Actual alert path and delivery gap

`px1Runtime.scanUncertain` raises `ALERT_UNCERTAIN_VERDICT` for each newly
scanned wallet `uncertain` record and each service terminal uncertain receipt.
One request can therefore alert once per layer; startup scans existing records
again. A bare reservation without either outcome is not covered by that scan.

The default `NewLogAlertSink` writes to stderr:

```text
PX1_ALERT code=ALERT_UNCERTAIN_VERDICT at=<unix> detail=<txid-or-reason>
```

The systemd deployment captures stderr in journald. An authorized operator
with journal access can inspect the supplied unit's logs:

```sh
journalctl --unit=swarma-wallet.service --since='1 hour ago' --no-pager
```

The operator status projection also retains the last 64 alerts. The code and
deploy kit do **not** forward these to a human notification channel or prove
delivery. Configuring and measuring that delivery is an open launch gate.
Do not treat the absence of a notification as proof that no debit is uncertain.

## Collect evidence on the service's own node

Preserve the reserve sequence, grant ID, wallet nonce, plan txid, inputs,
retained amount, journal binding and receipt public key. Keep private journals,
RPC credentials and key material out of the public operator note.

For the blocked private-regtest rehearsal, the operator would explicitly pin
the fresh node's datadir and RPC port on every call:

```sh
namecoin-cli -regtest -datadir="$REHEARSAL_DATADIR" -rpcport="$REHEARSAL_RPC_PORT" getblockchaininfo
namecoin-cli -regtest -datadir="$REHEARSAL_DATADIR" -rpcport="$REHEARSAL_RPC_PORT" getblockhash "$HEIGHT"
namecoin-cli -regtest -datadir="$REHEARSAL_DATADIR" -rpcport="$REHEARSAL_RPC_PORT" getblockheader "$BLOCK_HASH"
namecoin-cli -regtest -datadir="$REHEARSAL_DATADIR" -rpcport="$REHEARSAL_RPC_PORT" getrawtransaction "$PLAN_TXID" true
namecoin-cli -regtest -datadir="$REHEARSAL_DATADIR" -rpcport="$REHEARSAL_RPC_PORT" getrawmempool
namecoin-cli -regtest -datadir="$REHEARSAL_DATADIR" -rpcport="$REHEARSAL_RPC_PORT" gettxout "$INPUT_TXID" "$VOUT" true
```

Confirm `chain=regtest` and the configured genesis before the rehearsal.
Use the service's node, never a different node to settle its accounting.
Repeat the tip read after collecting evidence and discard inconsistent
snapshots. The public note must explain the evidence, observation time and
proposed release, with SHA-256 matching `note_sha256`.

The record accepts `absent` (no conflict txid), or `conflict` (a distinct
spender txid). For a conflict, also retrieve that transaction, inspect its
inputs against the reserved outpoints and check its active-chain block and
confirmations. `gettxout` returning null does not identify a spender.
A failed RPC, unavailable transaction index, missing transaction or mempool
absence alone is not proof that a payment never happened or cannot appear
later. The journal checks evidence shape, not chain truth; the CLI's evidence
policy needs QA approval before any release or rehearsal.

These commands are collection examples, not an implemented release procedure
or authorization to access a deployed node.

## Host command and files: missing implementation

There is **no current reconcile binary, subcommand, flag set or executable
operator invocation**. `agent-walletd` serves requests and runs startup checks;
`agent-wallet` signs socket requests; `agent-wallet-legacy` has no reconcile
subcommand. The deploy kit provides no wrapper for one.

The existing G2 layout identifies the future command's inputs, not evidence
that it runs: service config `/etc/swarma/wallet/service.json`, wallet config
`/etc/swarma/wallet/wallet.json`, receipt key
`/etc/swarma/wallet/receipt.key`, wallet state
`/var/lib/swarma-wallet/wallet`, and separate service state
`/var/lib/swarma-wallet/service`. Wallet journal v2 uses `journal-v2.lock`
and `journal-v2-*.json` segments. No existing operator command reads or writes
these for a release. Lock acquisition, service downtime and recovery must be
specified by the approved design; do not bypass a running daemon's locks.

## Signed record and hourly gate

`ReconcileRecordV2` carries `target_seq`, `evidence`, `height`, `block_hash`,
`conflict_txid`, `released_sat`, `note_sha256` and `signature`. Its enclosing
record preserves the reservation identity and plan; its phase is `released`.
The amount must be positive and at most the retained debit.

The receipt key signs BIP-340 over `ReconcileDigestV2`: SHA-256 of
`swarma-wallet-reconcile-v2` followed by canonical JSON containing the journal
binding, grant ID, nonce, next sequence and payload with an empty signature.
`VerifyReconcileV2` verifies at append, reopen/replay and ledger fold.
Authorization failures return `RECONCILE_AUTHORIZATION`; invalid evidence
shape returns `RECONCILE_EVIDENCE`; malformed targets/amounts return
`JOURNAL_RECORD`. Replay can fail as `JOURNAL_SEGMENT` during open.

`ReconcileMinIntervalSeconds` is 3600. The journal requires a release's
`last_time` to be at least 3600 seconds after the previous release in that
wallet journal, across requests. An otherwise valid newly signed record inside
that interval returns `RECONCILE_RATE_LIMITED` without being appended. Reusing
an old signature at a new sequence fails authorization first. These are library
refusals; no CLI exit-code contract exists yet. The future CLI must use the
real executor clock, with no operator-supplied timestamp override.

## Startup check and forbidden outcomes

`NewStartupReconciler` compares wallet `listtransactions` sends with txids
present in wallet-layer records. It pages 1000 rows at a time, up to 100
pages. An unknown send or exhausted page bound returns
`STATE_RECONCILE_REQUIRED`; malformed history and RPC errors also fail closed.
The daemon runs this before serving; that reconciliation refusal poisons the
runtime. It is an integrity check, produces no release and does not repair
missing history. Preserve state and investigate; do not invent a reservation
to make an unknown send pass startup. Provision a new hot wallet without sends
and fund it externally, as the existing deployment contract requires.

No action on either socket may produce a reconcile record. The action parser
accepts only `spend`, `balance`, `receive`, `history` and `budget`; an action
named `reconcile` returns `ACTION_UNSUPPORTED`. The status socket accepts only
`status` and makes no journal write. The matrix-row-20 executable negative
must establish journal invariance across wire attempts, with valid action
controls; source inspection alone does not qualify that row. T18 must separately
show the agent UID cannot read the journal or receipt key on the actual host.

## Remaining acceptance evidence

The operator command, evidence policy, confirmed human/channel/host assignment,
measured alert delivery, private-regtest end-to-end release, signature
verification, second-run hourly refusal and row-20 negative are outstanding.
Existing unit coverage of the journal gates is not the requested rehearsal.
See [unresolved questions](UNRESOLVED_QUESTIONS.md) and
[journal format](FORMAT-JOURNAL-V2.md) for the current contracts.
