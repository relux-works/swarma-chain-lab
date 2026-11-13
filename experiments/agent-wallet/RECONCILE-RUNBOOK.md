# PX1 operator reconciliation

Reconciliation releases a retained wallet debit only after an operator checks a
conflicting transaction. The CLI runs in the operator shell **as the service
UID** and signs with the existing receipt key. It opens no listener and never
broadcasts. No wire or frozen PX1 contract is changed.

## Roles and preparation

The primary human operator owns each incident. The infrastructure backup may
execute on the station only on that operator's explicit per-incident instruction.
The keeper confirms the private assignment, host, installed revision, numerical
service UID, operator alert room and owner DM before the public window. Names,
room identifiers and host assignments stay in private deployment records.

Only the service UID may read the journals and receipt key; the agent UID must
read neither (T18). Service and agent UIDs are different. The reconciler's
service-UID access is an existing operator entitlement, not a capability given
to the agent. Never supply a raw key, RPC URL/password, alternative state root,
clock override or unsigned release to the CLI.

Build from the repository root:

```sh
go -C experiments/agent-wallet build -trimpath -o ../../.temp/agent-wallet-reconcile ./cmd/agent-wallet-reconcile
go -C experiments/agent-wallet build -trimpath -o ../../.temp/agent-wallet-alert-forwarder ./cmd/agent-wallet-alert-forwarder
```

Install through the owner's signed release/config process. The reconciler uses
the same DK5 signed installed-config admission as the daemon; standalone private
files cannot substitute for it. `--check-installed` provides the same admission
preflight. There is no test, staging or unsigned mode in the production binary.

## Recognize uncertainty and retain the charge

The service journal kinds are `admit`, `service-reserve`, `terminal`; the wallet
kinds are `reserve`, `complete`, `uncertain`, `refuse-retained`, `track`,
`reconcile`. A broadcast error or mismatched returned txid attempts an
`uncertain` append and returns `BROADCAST_UNCERTAIN`. A failure after wallet
reservation, a failed completion append or a crash may leave only a reservation
and/or an uncertain service receipt. Preserve the original state and receipts.

`FoldLedgerV2` charges reserved-without-outcome and uncertain records on **every
UTC day**, including transfer count, until they close. A partial release leaves
the retained remainder open; a full release ends future-day carry and frees the
inputs. The reservation day's transfer count is never returned. Tracker
confirmation, conflict, elapsed time and midnight never release a debit.
Never delete, roll back or edit a journal, invent a reservation, change roots,
rebroadcast the plan, or retry the payment under a new nonce to recover allowance.

## Alert delivery

The runtime scans both journals and raises `ALERT_UNCERTAIN_VERDICT` for each
new wallet `uncertain` record and each terminal uncertain service receipt. One
request can alert once per layer. Startup scans old records again. A bare
reservation without either outcome is not covered by this alert scan; investigate
retained status entries after crashes as well.

The default sink writes:

```text
PX1_ALERT code=ALERT_UNCERTAIN_VERDICT at=<unix> detail=<txid-or-bounded-reason>
```

The daemon's stderr reaches journald. An authorized operator can inspect it:

```sh
journalctl --unit=swarma-wallet.service --since='1 hour ago' --no-pager
```

The separate `agent-wallet-alert-forwarder` unit follows that journal and sends
only sanitized typed alerts through the supported a2a CLI to **both** configured
operator-room and owner-DM topic roots. It uses a separately provisioned
infrastructure identity, with no wallet credentials or receipt-key access.
The separate [unit template](operator/swarma-wallet-alert-forwarder.service.in)
and [non-secret config example](operator/forwarder.example.json) require
operator substitution and provisioning; they are not automatically deployed.
Use the Curator-admitted a2a command and this unit's own identity/config root.
Do not reuse another session's credentials, join/create rooms or bind an owner DM
from this service. The operator preprovisions and verifies both audiences.

Its config is a single-link owner-only `0600` regular file. State is an
owner-only `0700` directory. Pin the two exact room IDs and existing topic event
IDs, the identity, absolute installed commands, a2a config root and explicit
RFC3339 initial `start_since`. Neither tokens nor passwords belong in this
config, command lines, source or logs. a2a credentials stay in its private store.

```sh
agent-wallet-alert-forwarder --config /etc/swarma/wallet-alerts/forwarder.json
```

Cursor progress requires successful, matching ACKs from both destinations.
Before a send, a durable in-flight reservation fences crashes/lost ACKs. An
unknown result returns `FORWARDER_DELIVERY_UNKNOWN` and stops; the unit does not
automatically restart/repost. Preserve its state and resolve the actual a2a
publication outcome with the keeper before recovery. Do not delete the fence
to retry. The second audience may be pending after the first ACK; no two-room
atomicity or automatic recovery is claimed. A cursor write failure can also
leave the outcome uncertain. Monitor the forwarder's own unit failures.

The operator status projection contains the last 64 alerts. Status and logs
alone do not establish watched-client delivery. Before opening the public
window, execute the authorized delivery drill below and record its measurement.

## Collect conflict evidence on the service's node

Use the configured own node and matching network/genesis. Collect the reserve
sequence, grant, nonce, plan txid, reserved inputs and retained amount from the
private journal. Keep private config, journal files and keys out of public notes.
Only `conflict` is approved: **another** transaction must spend at least one
reserved input in an active-chain block with **at least six confirmations**.
The tracker threshold of two is for alerts only. `absent` is always refused;
missing txids, a null `gettxout`, mempool absence or an RPC failure authorize no
release.

For the private rehearsal, pin its fresh datadir and RPC port on every call:

```sh
namecoin-cli -regtest -datadir="$REHEARSAL_DATADIR" -rpcport="$REHEARSAL_RPC_PORT" getblockchaininfo
namecoin-cli -regtest -datadir="$REHEARSAL_DATADIR" -rpcport="$REHEARSAL_RPC_PORT" getblockhash 0
namecoin-cli -regtest -datadir="$REHEARSAL_DATADIR" -rpcport="$REHEARSAL_RPC_PORT" getrawtransaction "$CONFLICT_TXID" true
namecoin-cli -regtest -datadir="$REHEARSAL_DATADIR" -rpcport="$REHEARSAL_RPC_PORT" getblockheader "$CONFLICT_BLOCK"
namecoin-cli -regtest -datadir="$REHEARSAL_DATADIR" -rpcport="$REHEARSAL_RPC_PORT" getblockhash "$CONFLICT_HEIGHT"
namecoin-cli -regtest -datadir="$REHEARSAL_DATADIR" -rpcport="$REHEARSAL_RPC_PORT" getblock "$CONFLICT_BLOCK" 1
```

Check chain/genesis, decode the raw transaction and its txid, compare its inputs
with the reservation, confirm active-block membership and k>=6, then recheck the
tip. The CLI repeats these checks with the existing payment-observation code;
it refuses a changed tip, mismatched raw data or block, k<6, the plan's own txid,
a non-spender, invalid amount, absent evidence and node errors. The six-block
bound limits reorg risk; it cannot make future reorgs impossible.

Write a bounded, owner-only public operator note explaining the incident,
conflicting spender, evidence tip, amount and decision. The CLI hashes its exact
bytes into `note_sha256`. Keep it available for later audit.

## Exact host invocation

The operator first stops the wallet daemon using the existing authorized host
procedure. It must be inactive; the CLI never stops another process itself.
Enter the operator shell as the configured service UID and verify it:

```sh
test "$(id -u)" = "$SERVICE_UID"
agent-wallet-reconcile --config /etc/swarma/wallet/service.json \
  --target-seq "$RESERVE_SEQ" --released-sat "$RELEASE_SAT" \
  --evidence conflict --conflict-txid "$CONFLICT_TXID" \
  --note /var/lib/swarma-wallet/operator/reconcile-note.txt
```

`SERVICE_UID` is the keeper-confirmed numerical service UID. Binary resolution
must point to the admitted release. The service config references the existing
wallet config, receipt key and state roots; the CLI cannot override those pins.
The current layout is `/etc/swarma/wallet/{service.json,wallet.json,receipt.key}`,
wallet state `/var/lib/swarma-wallet/wallet`, and separate service state
`/var/lib/swarma-wallet/service`. Wallet journal v2 uses `journal-v2.lock` and
`journal-v2-*.json`; service and wallet lifetime locks are also held. A running
holder returns `STATE_BUSY`; missing journal state is never initialized as repair.

Inspect JSON and exit status together:

| Exit | Meaning | Operator action |
| --- | --- | --- |
| 0 | Signed record durably appended and verified/folded | Preserve the record/note/evidence; independently verify on reopen. |
| 2 | Refused before a known possible write | Read `reason`; correct authority/evidence or wait, preserving state. |
| 4 | A write may have happened, or the output could not be reported | Do not retry; inspect the journal and resolve persistence first. |

`ReconcileRecordV2` carries the target reserve seq, `conflict`, evidence tip
height/hash, conflicting txid, positive released amount, note hash and signature.
The enclosing record preserves the reservation identity and plan. The receipt
key signs BIP-340 over `ReconcileDigestV2`: the v2 domain plus canonical binding,
grant, nonce, next seq and payload with empty signature. `VerifyReconcileV2`
checks it before append, on replay and during ledger fold. A signature lifted
to another journal/request/sequence refuses `RECONCILE_AUTHORIZATION`.

`ReconcileMinIntervalSeconds` is 3600, globally for the wallet journal. The CLI
uses the real executor clock and rejects rollback. A repeated invocation or
another target inside the hour returns `RECONCILE_RATE_LIMITED` without a new
record; its append timestamp is sampled after evidence collection, and `--now`
is not supported. After the interval, a previously fully released
target still cannot be released again. Do not wait an hour to retry an exit-4
outcome without first resolving its journal state.

## Startup integrity and wire prohibition

Startup reconciliation pages wallet `listtransactions` (1000 rows/page, at most
100 pages). A send whose txid is absent from the wallet record `txid` fields, or
an exhausted history bound, returns `STATE_RECONCILE_REQUIRED` before serving;
that refusal poisons the runtime. RPC/malformed-history failures also fail closed.
It produces no release and repairs no missing history.

A conflicting out-of-band hot-wallet send can therefore still block restart
after its debit release: the current startup check does not count
`reconcile.conflict_txid` as a known send. Preserve state and escalate that
startup hold to the keeper/QA; never invent a record or reset state to pass it.
The reconcile command does not grant a startup bypass.

No action on either socket may produce a reconcile record. The action socket
supports only spend/balance/receive/history/budget; `reconcile` is
`ACTION_UNSUPPORTED`. The status socket supports only status and never writes
the journal. Row-20 tests inspect both journals across real-socket attempts and
valid action controls. They do not substitute for actual-host T18 custody.

## Authorized alert-delivery drill (procedure only)

The deployment owner executes this after installation; the producer does not
send to a real room. Confirm the separate forwarder identity and two exact
preprovisioned topic roots. Record the installed binary/config digests (never
credential contents), clock synchronization, current cursor and unit state.
On an isolated, authorized station regtest fixture, drive a real spend to an
uncertain outcome through the wallet service; do not spend a canary or perturb
a live wallet. Record the resulting typed alert's executor timestamp/txid.

Observe that same alert in the keeper's watched operator-room client and the
owner's watched DM client. Record each Matrix event ID, server timestamp and
human observation/acknowledgement time privately. Compute both delays from the
source alert time; the end-to-end value is the later acknowledged arrival.
Check that both ACKs preceded cursor advancement and no credential/path appeared
in either body or service logs. A missing audience or unknown send is a failed
drill, not delivery. Archive sanitized commands, actual exit codes, source and
both arrival observations with SHA-256; keeper confirms the private assignment
and measurement before the public window.

## Qualification limits

A local fixture under one UID cannot qualify T18. A test-only synthetic installed
reader cannot qualify the built CLI's DK5 installed path. The private rehearsal
must report its actual binary exit and any such limit; primitive/function tests
are separate evidence. Fresh independent review, installed station readback,
measured real-room/owner-DM delivery and keeper-confirmed assignments remain
explicit deployment gates. See [unresolved questions](UNRESOLVED_QUESTIONS.md).
