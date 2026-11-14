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

Obtain all three tools from the owner's signed deploy-kit release, not a
separate local build. After verifying the `SHA256SUMS.sig` release signature
as described in [deploy/SMOKE.md](../../deploy/SMOKE.md#2-infra-verify-the-unopened-release-before-installation):

```sh
(cd "$RELEASE_DIR" && sha256sum -c SHA256SUMS)
RECONCILE="$RELEASE_DIR/bin/agent-wallet-reconcile"
CLIENT="$RELEASE_DIR/bin/agent-wallet"
FORWARDER="$RELEASE_DIR/bin/agent-wallet-alert-forwarder"
```

All three appear in `manifest.json`'s `tools` inventory and `SHA256SUMS`.
The reconciler is an owner-run one-shot, with no unit or separate drop-in.
Configguard reads the daemon's existing root-owned
`/etc/systemd/system/swarma-wallet.service.d/10-install.conf` directly under
the wallet service identity; process environment cannot substitute its pins.

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
The release ships the [unit template](../../deploy/templates/systemd/swarma-wallet-alert-forwarder.service.in),
matching the [F6 source template](operator/swarma-wallet-alert-forwarder.service.in).
Substitute `@VERSION@` with the verified installed release version and refuse
remaining placeholders. It needs no wallet DK5 drop-in. The
[non-secret config example](operator/forwarder.example.json) requires
operator substitution and provisioning; the unit is not automatically deployed.
Use the Curator-admitted a2a command and this unit's own identity/config root.
Do not reuse another session's credentials, join/create rooms or bind an owner DM
from this service. The operator preprovisions and verifies both audiences.

Its config is a single-link owner-only `0600` regular file. State is an
owner-only `0700` directory. Pin the two exact room IDs and existing topic event
IDs, the identity, absolute installed journal/a2a commands, a2a config root and explicit
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
100 pages). A send is known only when its txid is in a wallet spend record, or
is the **exact** conflicting txid named by a conflict-release record in the
opened hash-chained journal. The latter must pass existing receipt-key,
binding, sequence and fold verification, then own-node raw transaction/input,
active membership, signed evidence-tip and k>=6 checks. The observer uses the
installed network/genesis pins and its existing read-only credential route.

A verified release naming X permits startup with X; it does not whitelist an
unrelated or later Y. A rollback lacking the release still refuses
`STATE_RECONCILE_REQUIRED`. Tampered signatures or broken segment links refuse
`JOURNAL_SEGMENT` at journal open; false/orphaned/insufficient-depth evidence
refuses `RECONCILE_EVIDENCE` before serving. A lifted release cannot authorize a
later conflict. History bounds and RPC failures remain fail-closed. Startup
never writes a release or repairs history; debit accounting comes only from
verified journal records. The generic frozen journal does not query the node;
the operator's append boundary checks k>=6 before calling it.

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

## Infra installed rehearsal

Infra runs this inside the draft-6 installation rehearsal on its assigned
station, with the installed **signed** configuration and distinct service and
agent UIDs. This is a procedure, not a claim that the producer ran the native
rehearsal. The owner separately authorizes the watched-channel delivery drill.

### Fixture admission and capture

Use a fresh private **regtest** fixture only. The install manifest supplies the
absolute installed binaries `NAMECOIND`, `NMC`, `RECONCILE`, `CLIENT`, the fresh
`PRIVATE_DATADIR`, its `NODE_CONF`, free `RPC_PORT`/`P2P_PORT` above 28000,
`SERVICE_CONFIG`, `CLIENT_CONFIG`, `WALLET_STATE`, `SERVICE_STATE`, dedicated
`WALLET_UNIT`, action `SOCKET`, numerical `SERVICE_UID`/`AGENT_UID`, hot-wallet
name `HOT_WALLET`, funded/mined `MINER_ADDRESS`, allow-listed `RECIPIENT`,
standing `GRANT_ID`, operator `STATUS_SOCKET` and public `GRANTEE`.
`RECONCILE` and `CLIENT` must resolve to the verified release
`bin/agent-wallet-reconcile` and `bin/agent-wallet` above, with hashes in
`manifest.json` and `SHA256SUMS`. Paths and ports must match the signed
installed config. Do not repoint an existing installation or use shared nodes.
Record manifest/release hashes and public pins; never print a config, cookie,
key or wallet file. The fixture needs one confirmed spendable input, fresh
journals and allowance for 20000 sat plus a fee limit of 30000 sat. If those
terms are unsuitable, Infra provisions an approved fixture before proceeding.

Each actor runs in its own already-authorized shell. `CAP` is an absolute,
actor-owned `0700` evidence directory; use separate directories for node,
service and agent actors. Transfer only the explicitly public evidence files
between actors through the installation evidence collector. The agent never
reads the service evidence directory, journals or receipt key. Use this Bash
capture function in each shell. Require the saved exit to be 0 after each
capture unless a different expected exit is stated below; stop on any mismatch.
Expected refusals are checked explicitly. Capture the surrounding generation,
extraction and assertion commands in the private operator transcript as well:

```bash
umask 077
mkdir -p "$CAP"
chmod 0700 "$CAP"
cap() {
  local label=$1 rc
  shift
  printf '%q ' "$@" >"$CAP/$label.command"
  printf '\n' >>"$CAP/$label.command"
  "$@" >"$CAP/$label.stdout" 2>"$CAP/$label.stderr" &
  local child=$!
  printf '%s\n' "$child" >"$CAP/$label.pid"
  if wait "$child"; then rc=0; else rc=$?; fi
  printf '%s\n' "$rc" >"$CAP/$label.exit"
}
```

In the service-UID shell:

```bash
test "$(id -u)" = "$SERVICE_UID"
cap admission "$RECONCILE" --check-installed
test "$(cat "$CAP/admission.exit")" = 0
```

Expect `reason=INSTALLED_OK`. `DK5_SERVICE_GROUP`, any other DK5 refusal, or
inability to enter the real service UID stops qualification. Fix the signed
installation through its normal owner process; do not stub admission. Infra
also records separate-UID T18 denied-read checks against the installed journal
and receipt-key **paths**, without printing their contents. If unavailable,
record `T18_NOT_QUALIFIED` and the missing environment capability.

### Produce an uncertain spend through the installed service

The node operator starts only its own fresh fixture node, before the dedicated
wallet unit. The existing draft-6 node config contains the observer, wallet and
broadcast credential routes. Use explicit public method sets for all three routes, plus the broadcast
intersection. Repeating the normal sets is deliberate: it preserves them even
when command-line settings take precedence over the config file. These match
`deploy/g2_pay.go`; Infra checks them against the admitted fixture manifest:

```bash
FAULT=(
  -rpcwhitelist=w3-observer:getblockchaininfo,getblockhash,getblockheader,getrawtransaction,gettxout,name_show,getrawmempool,getblock
  -rpcwhitelist=w1-wallet:getbalances,getnewaddress,listtransactions,fundrawtransaction,signrawtransactionwithwallet
  -rpcwhitelist=w1-broadcast:sendrawtransaction
  -rpcwhitelist=w1-broadcast:getblockchaininfo
)
printf '%q ' "$NAMECOIND" -regtest -datadir="$PRIVATE_DATADIR" -conf="$NODE_CONF" \
  -port="$P2P_PORT" -rpcport="$RPC_PORT" -listen=0 -networkactive=0 \
  "${FAULT[@]}" >"$CAP/node.command"
"$NAMECOIND" -regtest -datadir="$PRIVATE_DATADIR" -conf="$NODE_CONF" \
  -port="$P2P_PORT" -rpcport="$RPC_PORT" -listen=0 -networkactive=0 \
  "${FAULT[@]}" >"$CAP/node.log" 2>&1 &
NODE_PID=$!
printf '%s\n' "$NODE_PID" >"$CAP/node.pid"
RPC=(-regtest -datadir="$PRIVATE_DATADIR" -conf="$NODE_CONF" -rpcport="$RPC_PORT")
cap chain "$NMC" "${RPC[@]}" -rpcwait getblockchaininfo
cap genesis "$NMC" "${RPC[@]}" getblockhash 0
```

Require `chain=regtest` and the installed regtest genesis. Core intersects
multiple whitelists for one user: this removes `sendrawtransaction` from
`w1-broadcast` while leaving planning/signing/observer routes unchanged. Keep
the fixture's `rpcwhitelistdefault=0` so its own cookie administrator can mine
and construct the conflict. No RPC credential is passed on a command line.
Record the node PID and exact argv; stop that PID at the end. Infra's normal
fixture setup funds/matures the input on this node and starts only the dedicated
installed wallet unit. Do not touch another unit or daemon.

In the agent-UID shell, create the canonical public request (environment values
are public; the client loads its existing private key itself):

```bash
test "$(id -u)" = "$AGENT_UID"
export CAP RECIPIENT GRANT_ID GRANTEE
python3 - <<'PYREQ'
import json, os, secrets, time
r = dict(v=1, service="wallet.nmc", action="spend",
         params=dict(to=os.environ["RECIPIENT"], amount_sat=20000, fee_limit_sat=30000),
         grant=dict(kind="standing", id=os.environ["GRANT_ID"]),
         nonce=secrets.token_hex(16), created_at=int(time.time()), grantee=os.environ["GRANTEE"])
open(os.environ["CAP"]+"/spend.json", "w").write(json.dumps(r, separators=(",", ":")))
PYREQ
cap uncertain "$CLIENT" --config "$CLIENT_CONFIG" --request "$CAP/spend.json"
test "$(cat "$CAP/uncertain.exit")" = 4
```

Require the signed receipt's `receipt.verdict=uncertain`,
`receipt.reason=BROADCAST_UNCERTAIN` and `receipt.effect.txid=PLAN_TXID`.
Capture the typed journald alert and timestamp in the service/operator shell.
Do not resend this nonce or create a replacement payment. Infra stops the
**dedicated fixture unit** using its authorized install controller, e.g.
`cap stop-wallet systemctl stop "$WALLET_UNIT"`, before journal inspection or
reconciliation. A running holder must refuse `STATE_BUSY`.

In the service-UID shell, extract only the reserve metadata. Set `PLAN_TXID`
from the public receipt; the fixture must have exactly one reserved input. Define a public metadata snapshot helper in that
same shell and capture both journal layers around every refusal/socket probe:

```bash
export WALLET_STATE SERVICE_STATE
cat >"$CAP/snapshot.py" <<'PYSNAP'
import glob, json, os
out = {}
for label, root in [("wallet", os.environ["WALLET_STATE"]), ("service", os.environ["SERVICE_STATE"])]:
    rows = []
    for p in sorted(glob.glob(root+"/journal-v2-*.json")):
        rows.extend(json.load(open(p))["records"])
    out[label] = dict(last_seq=max([r["seq"] for r in rows], default=0),
                      reconciles=sum(r["kind"] == "reconcile" for r in rows))
print(json.dumps(out, sort_keys=True))
PYSNAP
cap before-k5 python3 "$CAP/snapshot.py"
```

Extract the reserve:

```bash
export CAP WALLET_STATE PLAN_TXID
python3 - <<'PYRES'
import glob, json, os
rows = []
for p in sorted(glob.glob(os.environ["WALLET_STATE"]+"/journal-v2-*.json")):
    rows.extend(json.load(open(p))["records"])
r, = [r for r in rows if r["kind"] == "reserve" and r["txid"] == os.environ["PLAN_TXID"]]
assert len(r["inputs"]) == 1
out = dict(target_seq=r["seq"], released_sat=r["reserved_sat"], input=r["inputs"][0],
           plan_txid=r["txid"], original_day=r["day"], grant_id=r["grant_id"])
open(os.environ["CAP"]+"/reserve.json", "w").write(json.dumps(out))
open(os.environ["CAP"]+"/before.json", "w").write(json.dumps(dict(
    last_seq=max(r["seq"] for r in rows), reconciles=sum(r["kind"]=="reconcile" for r in rows))))
PYRES
```

The collector gives only `reserve.json` to the node operator. Assign
`INPUT_TXID`, `INPUT_VOUT`, `RESERVE_SEQ`, `RELEASE_SAT` from its exact fields;
never copy a wallet file, key, cookie or private config. Retained debit must
still include the full `reserved_sat`, with the original-day transfer count.

### Mine the conflicting spend and collect evidence

In the node shell, use its own cookie administrator and fixture hot wallet:

```bash
INPUT_TXID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["input"]["txid"])' "$CAP/reserve.json")
INPUT_VOUT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["input"]["vout"])' "$CAP/reserve.json")
cap input "$NMC" "${RPC[@]}" gettxout "$INPUT_TXID" "$INPUT_VOUT" true
export CAP MINER_ADDRESS
python3 - <<'PYTX'
from decimal import Decimal
import json, os
root = os.environ["CAP"]
r = json.load(open(root+"/reserve.json"))
i = json.load(open(root+"/input.stdout"), parse_float=Decimal)
assert i is not None and i["confirmations"] > 0
value = i["value"] - Decimal("0.00100000")
assert value > Decimal("0.00100000")
open(root+"/inputs.json", "w").write(json.dumps([r["input"]], separators=(",", ":")))
# Decimal is emitted as a JSON number, without binary floating point rounding.
open(root+"/outputs.json", "w").write("{"+json.dumps(os.environ["MINER_ADDRESS"])+":"+format(value, ".8f")+"}")
PYTX
INPUTS_JSON=$(cat "$CAP/inputs.json")
OUTPUTS_JSON=$(cat "$CAP/outputs.json")
```

The 100000 sat fixture conflict fee is independent of the agent's payment fee.
All transaction inputs/outputs below are public data.

```bash
cap raw "$NMC" "${RPC[@]}" createrawtransaction "$INPUTS_JSON" "$OUTPUTS_JSON"
RAW=$(cat "$CAP/raw.stdout")
cap signed "$NMC" "${RPC[@]}" -rpcwallet="$HOT_WALLET" signrawtransactionwithwallet "$RAW"
```

Require `complete=true`. Extract the public transaction hex:

```bash
SIGNED_CONFLICT=$(python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); assert r["complete"]; print(r["hex"])' "$CAP/signed.stdout")
```

Then:

```bash
cap broadcast-conflict "$NMC" "${RPC[@]}" sendrawtransaction "$SIGNED_CONFLICT"
CONFLICT_TXID=$(cat "$CAP/broadcast-conflict.stdout")
test "$CONFLICT_TXID" != "$PLAN_TXID"
cap mine-five "$NMC" "${RPC[@]}" generatetoaddress 5 "$MINER_ADDRESS"
cap depth-five "$NMC" "${RPC[@]}" getrawtransaction "$CONFLICT_TXID" true
```

In the service shell, derive the exact target and amount from its reserve
metadata. Set `NOTE` to a service-owned operator-note path; transfer only public
conflict txid/evidence through the collector:

```bash
RESERVE_SEQ=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["target_seq"])' "$CAP/reserve.json")
RELEASE_SAT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["released_sat"])' "$CAP/reserve.json")
printf 'Private regtest incident; reserve=%s; conflict=%s; release_sat=%s; confirmed conflict only.\n' \
  "$RESERVE_SEQ" "$CONFLICT_TXID" "$RELEASE_SAT" >"$NOTE"
chmod 0600 "$NOTE"
cap note-hash sha256sum "$NOTE"
```

Run the **built installed binary**:

```bash
ARGS=(--config "$SERVICE_CONFIG" --target-seq "$RESERVE_SEQ" \
  --released-sat "$RELEASE_SAT" --evidence conflict \
  --conflict-txid "$CONFLICT_TXID" --note "$NOTE")
cap k5 "$RECONCILE" "${ARGS[@]}"
test "$(cat "$CAP/k5.exit")" = 2
cap after-k5 python3 "$CAP/snapshot.py"
cap k5-no-write cmp "$CAP/before-k5.stdout" "$CAP/after-k5.stdout"
test "$(cat "$CAP/k5-no-write.exit")" = 0
```

Require `reason=RECONCILE_EVIDENCE`, `may_have_written=false`, no new journal
record and unchanged debit. Node operator mines one more block, then collects:

```bash
cap mine-six "$NMC" "${RPC[@]}" generatetoaddress 1 "$MINER_ADDRESS"
cap tip-before "$NMC" "${RPC[@]}" getblockchaininfo
cap conflict "$NMC" "${RPC[@]}" getrawtransaction "$CONFLICT_TXID" true
CONFLICT_BLOCK=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["blockhash"])' "$CAP/conflict.stdout")
cap header "$NMC" "${RPC[@]}" getblockheader "$CONFLICT_BLOCK"
CONFLICT_HEIGHT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["height"])' "$CAP/header.stdout")
cap membership "$NMC" "${RPC[@]}" getblock "$CONFLICT_BLOCK" 1
cap active-height "$NMC" "${RPC[@]}" getblockhash "$CONFLICT_HEIGHT"
cap tip-after "$NMC" "${RPC[@]}" getblockchaininfo
```

Require raw txid/input binding, active block membership, matching
height hash, confirmations>=6 and unchanged before/after tip. CLI hash outputs
are plain hex lines; do not decode them as JSON strings. Save this evidence and
the note SHA-256 before the service shell continues:

```bash
cap release "$RECONCILE" "${ARGS[@]}"
test "$(cat "$CAP/release.exit")" = 0
cap before-hourly python3 "$CAP/snapshot.py"
cap hourly "$RECONCILE" "${ARGS[@]}"
test "$(cat "$CAP/hourly.exit")" = 2
cap after-hourly python3 "$CAP/snapshot.py"
cap hourly-no-write cmp "$CAP/before-hourly.stdout" "$CAP/after-hourly.stdout"
test "$(cat "$CAP/hourly-no-write.exit")" = 0
```

Require `release.reason=RECONCILED`, `verified=true`, `may_have_written=true`;
the signed record must match reserve, amount, conflict, evidence tip and note
hash. Require `hourly.reason=RECONCILE_RATE_LIMITED`, no possible write and no
new record. Do not change clocks or wait out the hour. Preserve a filtered
journal header and signed release for `VerifyReconcileV2` audit; the CLI's fold
and subsequent daemon reopen independently reverify its receipt-key binding.

### Startup, row 20 and capture closeout

Infra starts only the dedicated installed wallet unit through its install
controller. Capture unit status and bounded journald output: startup must open
and verify the journal, recognize **only X**, and serve a valid signed balance
request. It must not stay at `STATE_RECONCILE_REQUIRED`. Operator status must
show `reserved_sat=0`, `uncertain_sat=0`, `released_sat=RELEASE_SAT` for
`GRANT_ID`; original-day transfer count is unchanged. Run the framed read in an
operator shell entitled to the status socket (not in the agent shell):

```bash
export STATUS_SOCKET GRANT_ID
cat >"$CAP/status.py" <<'PYSTATUS'
import json, os, socket, struct
b = b'{"v":1,"action":"status"}'
def readn(s, n):
    out = b""
    while len(out) < n:
        part = s.recv(n-len(out))
        if not part: raise RuntimeError("short status frame")
        out += part
    return out
with socket.socket(socket.AF_UNIX) as s:
    s.settimeout(10); s.connect(os.environ["STATUS_SOCKET"])
    s.sendall(struct.pack(">I", len(b))+b)
    size, = struct.unpack(">I", readn(s, 4)); assert size <= 1048576
    p = json.loads(readn(s, size)); print(json.dumps(p))
    assert not p["poisoned"]
    g, = [g for g in p["grants"] if g["grant_id"] == os.environ["GRANT_ID"]]
    assert g["reserved_sat"] == 0 and g["uncertain_sat"] == 0
PYSTATUS
cap startup-status python3 "$CAP/status.py"
test "$(cat "$CAP/startup-status.exit")" = 0
```

The ledger's input-release invariant is covered by `TestF6StartupNamedConflict`;
status does not expose an input-reservation field. In the service shell, take
`cap before-row20 python3 "$CAP/snapshot.py"` after startup completes and before
the following agent requests. Do not mine or introduce another spend during
these probes. The six startup-policy test groups cover unknown Y, rollback,
tampering, depth and replay; never tamper with installed fixture journals to
simulate those unit cases.

For row 20, in the agent shell use the real installed action socket. Export
`SOCKET`, `GRANTEE` and `CAP`; this deliberately unsupported action must reach
the socket (the signing client would reject it locally):

```bash
python3 - <<'PYWIRE' >"$CAP/row20.stdout" 2>"$CAP/row20.stderr"
import json, os, secrets, socket, struct, time
r = dict(v=1, service="wallet.nmc", action="reconcile", params={},
         grant=dict(kind="none"), nonce=secrets.token_hex(16),
         created_at=int(time.time()), grantee=os.environ["GRANTEE"])
b = json.dumps(dict(request=r, signature="0"*128), separators=(",", ":")).encode()
def readn(s, n):
    out = b""
    while len(out) < n:
        part = s.recv(n-len(out))
        if not part: raise RuntimeError("short frame")
        out += part
    return out
with socket.socket(socket.AF_UNIX) as s:
    s.settimeout(10); s.connect(os.environ["SOCKET"])
    s.sendall(struct.pack(">I", len(b))+b)
    size, = struct.unpack(">I", readn(s, 4)); assert size <= 65536
    reply = json.loads(readn(s, size)); print(json.dumps(reply))
    assert reply["receipt"]["reason"] == "ACTION_UNSUPPORTED"
PYWIRE
printf '%s\n' "$?" >"$CAP/row20.exit"
```

Require exit 0 and the named refusal, rather than timeout or authentication
failure. The placeholder signature bounds this probe to dispatch refusal;
`TestF6Row20Socket` also covers valid signed unsupported requests, payload
injection and valid read controls over the real socket. Create and execute the
valid neighbor in the agent shell:

```bash
python3 - <<'PYBAL'
import json, os, secrets, time
r = dict(v=1, service="wallet.nmc", action="balance", params={}, grant=dict(kind="none"),
         nonce=secrets.token_hex(16), created_at=int(time.time()), grantee=os.environ["GRANTEE"])
open(os.environ["CAP"]+"/balance.json", "w").write(json.dumps(r, separators=(",", ":")))
PYBAL
cap balance "$CLIENT" --config "$CLIENT_CONFIG" --request "$CAP/balance.json"
test "$(cat "$CAP/balance.exit")" = 0
```

Require `receipt.verdict=executed`. Service UID compares both journals'
last sequence and reconcile count before/after these socket probes: unchanged,
exactly the one operator release, no wire-produced reconcile:

```bash
cap after-row20 python3 "$CAP/snapshot.py"
cap row20-no-write cmp "$CAP/before-row20.stdout" "$CAP/after-row20.stdout"
test "$(cat "$CAP/row20-no-write.exit")" = 0
```

Stop the dedicated fixture wallet unit, then `kill -TERM "$NODE_PID"` and
`wait "$NODE_PID"`, recording both real statuses and the final node log. Kill
only the recorded node started above; never use pattern kills. Discard the
runtime whitelist fault with this node shutdown; no installed config was
changed. If another run is needed, provision a new fixture through draft 6.

Infra's `REHEARSAL.md` includes every executed command (including generation,
field extraction, unit control and checks), actor UID, PID, exact exit and
bounded output, installed head/signature, signed-config admission, private node
pins, uncertain signed receipt/alert, reserve metadata, k5 refusal/no-change,
k6 evidence, verified signed record, hourly refusal/no-change, startup balance,
row-20 no-write snapshots and cleanup. Hash an **explicit allow-list** of these
public evidence files with SHA-256; never recursively walk a datadir or hash/copy
wallets, cookies, private keys or credential configs. Record any missed step as
unqualified. Add the separately authorized measured alert drill and T18 results
before public-window acceptance; procedure availability is not qualification.

## Qualification limits

A local fixture under one UID cannot qualify T18. A test-only synthetic installed
reader cannot qualify the built CLI's DK5 installed path. Infra performs the
native F6 rehearsal inside the draft-6 signed installation fixture using the procedure above.
The producer does not run a local native-CLI
rehearsal; historical DK5 refusals remain correct, not a reason to add a bypass.
Primitive/function tests are separate evidence. Fresh independent review,
installed station readback, measured real-room/owner-DM delivery and keeper-confirmed assignments remain
explicit deployment gates. See [unresolved questions](UNRESOLVED_QUESTIONS.md).
