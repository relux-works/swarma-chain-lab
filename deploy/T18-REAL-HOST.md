# G2 real-host qualification: T18 and setpriv

This is the operator procedure for the T18 half of the G2 real-host
qualification report. T18 is the different-UID custody check of
[SMOKE-G2.md](SMOKE-G2.md) §4 (PX1 stream S5, `PX1-INTERFACES.md` row T18). The
T19 half, the slot manager's own real-host run, is a separate harness and is
not part of this document.

The run is done by Infra, an operator with root, on a provisioned station.
It produces one report file with one line per T18 item. Nothing here changes a
product file, funds a wallet, spends, or sends a wallet request. The tool is
`deploy/t18-real-host-report.sh`. It runs the existing tools
(`deploy-kit g2-render`, `g2-host-flow`, `g2-agent-groups`, `g2-custody-probe`,
`g2-custody-verify` and `deploy/g2-custody-check.sh`) and reads their output.

There are two kinds of station:

- **The live-wallet station** runs `agent-walletd` with a funded hot wallet.
  For the wallet, only the handshake is allowed: the socket accepts a
  connection, and the peer is identified. Nothing more.
- **The stand-in station** has no wallet service. Infra creates root-owned
  placeholder files at the production paths of `denied_reads`, with the
  production modes, holding no secret (empty or random bytes), and a listener
  planted by root (`root:swarma-wallet-peer`, mode 0660) answers at the wallet
  socket path. The report runs there with the stand-in flag (see §3, step 6).
  Every placeholder-backed item (each `denied-read`, `status-dir` and
  `allowed-socket`) is then `STAND_IN`, never `PASS`, and the OVERALL line ends
  in `run=stand-in valid-only-as-a-stand-in-run`: such a report is valid only
  as a stand-in run, never as the live-wallet qualification.

**The positive path is not proven here.** The real-wallet POSITIVE path (an
authorized request that executes) is proven by the separate owner-authorized,
bounded mainnet smoke gate, not by T18. On a host the wallet client sends
nothing. The item `positive-request` is `COVERED_BY_HOSTED`, pinned to
`TestPX1CoreServiceG2FailClosed` in run 43360330369, and it turns FAIL if the
host evidence shows that any frame was sent (a receipt other than the
no-request marker, another exit than 3, or any client error output). The
report carries this statement as a `# positive-path:` line, and `check`
refuses a report without it.

## 1. Operator parameters

These are the station's values, written into the station's `parameters.json`
(SMOKE-G2.md §1). They are not constants of any code: the runner reads every
number from the parameters and from the `sysusers.conf` rendered from them.

The owners confirmed this agent account. Infra created it in this order:

| Parameter | Value |
| --- | --- |
| agent group | `g2-agent`, GID 210001, created first |
| agent user (`agent_user`, `agent_uid`) | `g2-agent`, UID 210001, primary group `g2-agent` (GID 210001) |
| socket group (`agent_socket_gid`) | `swarma-wallet-peer`, GID 210101, the account's only other group |
| agent key (`agent_key_file`) | `/etc/swarma-g2-agent/agent.key`, `g2-agent:g2-agent`, mode 0600, one link (nlink 1). Its parents are root-owned and mode 0755. The slot binds it read-only. |
| `service_uid`, `operator_gid`, `node_datadir`, `node_rpc_port`, `hot_wallet_name`, `grantee`, `receipt_pubkey` | the station's values |

The agent's credential set is therefore {210001, 210101}. Its primary GID
equals its UID, which is what the declaration `u g2-agent 210001` renders.
Before the run, check the account:

```sh
id g2-agent   # uid=210001(g2-agent) gid=210001(g2-agent) groups=210001(g2-agent),210101(swarma-wallet-peer)
```

Check the key file's metadata with `stat` only. Do not read its contents. The
slot manager enforces the key chain on the T19 side, so these lines are a
precondition for this run, not a report item:

```sh
stat -c '%U:%G %a %h %F' /etc/swarma-g2-agent/agent.key   # g2-agent:g2-agent 600 1 regular file
stat -c '%U %a %F' /etc/swarma-g2-agent /etc /             # root 755 directory, three times
```

## 2. Preconditions

1. **Node: `txindex=1`, with the index synced.** The payment tracker needs
   this (SMOKE-G2.md, "Node prerequisite"). The node's operator saves the
   node's answer to a file. This is a node call, not a wallet call.

   ```sh
   namecoin-cli -datadir="$NODE_DATADIR" getindexinfo txindex > getindexinfo.json
   ```

   It must read `{"txindex": {"synced": true, "best_block_height": N}}`. Any
   other answer, an empty answer, or no file makes the item `node-txindex`
   FAIL.

   This answer is also the node-liveness evidence of the `denied-rpc` items
   (r9): a `denied-rpc` item is PASS only when `node-txindex` is PASS in the
   same report. Save it in this run, right before step 3, with the node
   running; the node must keep running through step 5. A stopped node makes
   the RPC port refuse the probe's connection, and that is FAIL (see the item
   table).
2. **The account exists as in §1**, created by Infra. This procedure never
   creates or changes an account. It never runs `systemd-sysusers`.
3. **Every `denied_reads` path exists.** On the live-wallet station each
   path is the production object with its production owner and mode. This
   includes the node cookie and `wallet.dat` from `custody-spec.json`. On the
   stand-in station Infra creates each missing path as a root-owned
   placeholder with the production mode and no secret (empty or random
   bytes); those items are `STAND_IN`, never `PASS`. A missing path under a
   parent the agent can search reads `ENOENT`, and its item FAILs on either
   station (a missing file proves nothing); under a parent the agent cannot
   search it reads `EACCES` (see §7). Step 2 of §3 lists missing paths before the run.
4. **Tools.**
   - `deploy-kit` is built from the reviewed head. Put it, with
     `t18-real-host-report.sh` and `g2-custody-check.sh` side by side, in a
     root-owned mode 0755 directory, so the agent can run them.
   - `perl` with its core `Socket` module, for the peer identity. The agent
     phase records the first version line of `perl -v` (for example
     `This is perl 5, version 34, subversion 0 (v5.34.0) ...`) as the evidence
     of this precondition: item `peer-precondition`.
   - GNU `stat` and `sha256sum`, `setpriv` (util-linux), and `awk`, `sed`,
     `cmp`.
5. **Wallet mode, the stand-in flag.** Use `real` on the live-wallet station
   and `stand-in` on the stand-in station. `stand-in` is the explicit stand-in
   flag: it is the only way a report may contain `STAND_IN`, and with it no
   placeholder-backed item can be `PASS`.

## 3. Commands, in order

Set the variables once. `$RUN` is a new directory; the evidence never
overwrites earlier evidence.

```sh
KIT=/opt/t18/deploy-kit                # built from the reviewed head
T18=/opt/t18                           # holds t18-real-host-report.sh and g2-custody-check.sh
PARAMS=/root/g2/parameters.json        # the station's parameters (no secret)
TXINDEX=/root/g2/getindexinfo.json     # the node's answer saved in §2
RENDERED=/root/g2/rendered-$(date -u +%Y%m%dT%H%M%SZ)
RUN=/var/lib/t18/run-$(date -u +%Y%m%dT%H%M%SZ)
AGENT_USER=g2-agent
GRANTEE_XONLY=...                      # the parameters' "grantee"
WALLET_MODE=real                       # or stand-in: the stand-in flag
mkdir -p -m 0755 /var/lib/t18 && mkdir -m 0755 "$RUN"
```

The agent must be able to search `$RUN` and every parent of it, so they are
root-owned and mode 0755. `$RENDERED` stays private: the agent gets copies in
step 4.

**Step 1. Render.** Render the station's parameters:

```sh
"$KIT" g2-render -params "$PARAMS" -out "$RENDERED"
```

This writes the six frozen files. `custody-spec.json` is the T18 input in the
launch layout. `sysusers.conf` holds the agent's numeric declaration, and
`client.json` holds the client pins.

**Step 2. Root preflight of the spec paths** (SMOKE-G2.md §4). The output must
be empty:

```sh
grep -o '"/[^"]*"' "$RENDERED/custody-spec.json" | tr -d '"' | while read -r p; do test -e "$p" || echo "MISSING $p"; done
```

**Step 3. Operator phase: re-render, account check and txindex.** This step
needs no root. The account is pre-created by Infra, so the apply is a no-op;
the report prints the literal line `apply no-op: account pre-created by
Infra` above the `account` item.

```sh
DEPLOY_KIT="$KIT" sh "$T18/t18-real-host-report.sh" operator "$RUN/operator" "$PARAMS" "$RENDERED" "$TXINDEX"
```

It does three things:

- It re-renders `$PARAMS` and compares the result byte for byte with
  `$RENDERED`.
- It runs `deploy-kit g2-host-flow -params "$PARAMS" -sysusers true -- true`.
  That is the account check against the account Infra created, in the frozen
  `RunG2HostFlow` order:
  1. the preflight `ValidateG2PayIdentity` (an existing `agent_user` only at
     exactly `agent_uid`);
  2. the frozen post-apply `VerifyG2AgentAccount` (`agent_user` at
     `agent_uid`, in `agent_socket_gid`, not in `operator_gid`);
  3. the exact group set: the account's groups are exactly {own GID == UID,
     `agent_socket_gid`}.

  The apply and the activation are `true`, because the account is adopted.
  Nothing is applied and nothing is started. `G2_HOST_FLOW_ACTIVATED` in the
  output therefore means only that all three checks passed. The phase records
  this mode (`host-flow-mode.txt`).
- It reads the exact set {own GID == UID, `agent_socket_gid`} once more from
  the REAL account: `id -u`, `id -g` and `id -G` of `g2-agent` from this
  host's account database, given to `deploy-kit g2-agent-groups`. This runs in
  every operator phase, and the `account` item needs it: `account` is PASS
  only when the host flow passed, the no-op mode is recorded, the real
  account's UID is `agent_uid`, its primary GID equals that UID, and
  `g2-agent-groups` printed `G2_AGENT_GROUPS_OK` for its group list. So the
  no-op apply cannot skip the exact-set check.
- It saves `id g2-agent` and the flattened `getindexinfo.json`.

**Step 4. The agent's numbers and inputs** (root). Both numbers come from
the agent's `u` line of the rendered `sysusers.conf`, with the two lines of
SMOKE-G2.md §4 (210001 and 210001 here). The rendered directory is mode 0700,
so the agent gets read-only copies of its three inputs. They hold no secret.

```sh
cd "$RENDERED"
AGENT_UID=$(awk -v u="$AGENT_USER" '$1 == "u" && $2 == u { split($3, id, ":"); print id[1] }' sysusers.conf)
AGENT_GID=$(awk -v u="$AGENT_USER" '$1 == "u" && $2 == u { n = split($3, id, ":"); print id[n] }' sysusers.conf)
install -d -o "$AGENT_UID" -g "$AGENT_GID" -m 0700 "$RUN/agent"
install -o "$AGENT_UID" -g "$AGENT_GID" -m 0400 "$RENDERED/custody-spec.json" "$RUN/agent/custody-spec.json"
install -o "$AGENT_UID" -g "$AGENT_GID" -m 0400 "$RENDERED/client.json" "$RUN/agent/client.json"
install -o "$AGENT_UID" -g "$AGENT_GID" -m 0400 "$PARAMS" "$RUN/agent/parameters.json"
```

The report checks that the agent ran with byte-identical copies
(`agent-inputs`).

**Step 5. Launch T18 with the slot's credentials**, exactly as in SMOKE-G2.md
§4:

```sh
setpriv --reuid="$AGENT_UID" --regid="$AGENT_GID" --init-groups -- \
  env DEPLOY_KIT="$KIT" \
  sh "$T18/t18-real-host-report.sh" agent "$RUN/agent/evidence" \
    "$RUN/agent/custody-spec.json" "$RUN/agent/client.json" "$GRANTEE_XONLY" "$RUN/agent/parameters.json"
```

`--reuid` is the agent's UID. `--regid` is the numeric primary GID. Never give
it a group name: a name can resolve to another GID, and the swapped run has the
same two-GID set. `--init-groups` adds the account's group list, as the slot
does. Do not drop to a reduced group set.

As the agent, the agent phase does four things:

1. It records its own `Uid`, `Gid`, `Groups` and capability lines from
   `/proc/<pid>/status` (`launch.txt`).
2. It records the SHA-256 of its three inputs.
3. It runs the unchanged `g2-custody-check.sh`:
   - the readback (`id -g`, `id -G`, `deploy-kit g2-agent-groups`);
   - `deploy-kit g2-custody-probe`;
   - `deploy-kit g2-custody-verify`.

   Here `AGENT_WALLET` is the runner itself in no-request mode. It prints
   `T18_REAL_HOST_REQUEST_NOT_SENT`, exits 3 and sends nothing. The custody
   script's own verdict therefore always reads `T18_FAIL` here, because its
   `T18_PASS` needs the positive request. The report does not use that
   verdict; it reads each step's evidence.
4. It records the first version line of `perl -v` (`perl-version.txt`),
   connects to the wallet socket once more, reads the peer's kernel
   credentials (`SO_PEERCRED`) without sending a byte, and records the
   socket's type, owner, group and mode (`stat`).

**Step 6. Report** (root, because the agent's evidence is mode 0600; this step
only reads files). The last argument is the stand-in flag: `real` or
`stand-in`. The report records the SHA-256 of `$RENDERED/custody-spec.json`,
the exact spec file it was composed from, and that file is copied next to the
report so `check` can be given it.

```sh
DEPLOY_KIT="$KIT" sh "$T18/t18-real-host-report.sh" report "$RUN/operator" "$RUN/agent/evidence" "$RENDERED" "$PARAMS" "$WALLET_MODE" > "$RUN/T18-REPORT.txt"
echo "report exit $?"
cp "$RENDERED/custody-spec.json" "$RUN/custody-spec.json"
```

**Step 7. Check** (anyone). This recomputes the OVERALL line from the stored
report. The second argument, the custody spec the run used, is required:
without it `check` does not run (usage error, exit 64).

```sh
DEPLOY_KIT="$KIT" sh "$T18/t18-real-host-report.sh" check "$RUN/T18-REPORT.txt" "$RUN/custody-spec.json"
echo "check exit $?"
```

Exit 0 means OVERALL PASS. Exit 1 means OVERALL FAIL, followed by a
`# reasons:` line.

`check` binds the report to the spec it is given. The report's one
`custody_spec_sha256 <hex>` line must be the SHA-256 of that file: a report
without the line, with it twice, or checked against another spec is refused
(`custody-spec-sha256:missing`, `:duplicate`, `:differs`). No spec hash in
the report is a free field: the `render` line's `custody_spec_file_sha256`
must be the SHA-256 of that file too (`render-custody-spec-file-sha256:differs`),
and the header's `spec_sha256` must be the canonical hash of that file
(`header-spec-sha256:differs`). The runner never computes that hash itself:
`report` and `check` take it only from the product, `$DEPLOY_KIT
g2-custody-hash -spec SPEC`, which reads the spec with the reader of
`g2-custody-probe` and `g2-custody-verify` and prints exactly one line
`T18_CUSTODY_SPEC_SHA256 <64 lowercase hex>` (the `CustodySpecSHA256` a probe
report carries and verify checks). If that command cannot be run, exits
non-zero, refuses the spec or prints anything else, `check` refuses with
`canonical-hash-unavailable`, and `report` composes nothing and exits 1
(`REFUSED canonical-hash-unavailable`). There is no fallback. The hash
names the spec's CONTENT only: `g2-custody-hash` applies probe's reader and
not verify's `-launch` layout check. The launch layout is a property of the
run, checked per run by `g2-custody-verify -launch=true` in the agent phase
and reported as its own item, `launch-layout` (r7). Every
`denied_reads` and `denied_rpc` entry of the spec must have exactly one
`denied-read:<path>` or `denied-rpc:<target>` row, whatever its verdict: a
deleted row is `missing:denied-read:<path>` even when the OVERALL counts were
edited to match, a repeated row is `duplicate:<row>`, and a denied row for
anything the spec does not list is `extra-row:<row>`. The report does not
copy the spec's path list; the hash identifies the file.

`check` parses the stored report once and refuses instead of choosing. Every
line is the header, the `custody_spec_sha256` line, the literal no-op apply
line, the literal positive-path statement, an item line or the final OVERALL
line, single-space separated and newline-terminated. In an item line each
field key stands once: a second `host=`, `run=` or `real_account=` is refused
(`duplicate-field:<item>:<key>`) even when both copies agree. A `PASS`, `STAND_IN` or `COVERED_BY_HOSTED` line
carries exactly the fields of its item, in order, each with the one value its
verdict needs (from the header or the pin table), so a field that contradicts
its verdict, the header or another item is refused (for example a launch form
with a saved UID 0, a socket that is not mode 660, `host=not-run` beside a
credentials `PASS`). Any other line (a blank or comment line, a line after
OVERALL, an unterminated last line) is refused too, and the stated OVERALL
line must be the recomputed line byte for byte. The no-request receipt is read
the same way in the report step: it must be exactly the marker line, and any
client error output fails `positive-request` in both covered branches.

**r8: identities, raw bytes, group order.** The header's identities are bound
to the supplied spec the product accepted: `agent_uid` and `primary_gid` must
equal the spec's `agent_uid` (`header-agent-uid-not-spec`,
`header-primary-gid-not-spec`), `service_uid` the spec's `service_uid`
(`header-service-uid-not-spec`), and none of the four header IDs may be a
reserved ID (0, 65534, 65535, 4294967295: `header-reserved-id:<key>`). The
values come from the spec file, read only after `g2-custody-hash` accepted
it; a spec whose identities cannot be read is `spec-identity-unavailable`.
Every item is compared with the header, so the account, launch UIDs and GIDs,
credentials, custody-verify UID, peer UID and socket owner are bound to the
spec through it. The spec carries no socket GID: `socket_gid` is bound to the
items only, and must not be reserved or the primary GID. The product's
`g2-custody-hash` output and the verifier outputs (`launch-layout-on.txt`,
`launch-layout-off.txt`, `custody/custody-verify.txt`) are judged on their
raw bytes: the file must be exactly the one expected line and one newline
(compared with `cmp`), so a NUL byte, a CR, an extra or missing newline or
binary garbage is refused (`canonical-hash-unavailable` for the hash;
`launch-layout FAIL` or `custody-verify FAIL` for the verifier outputs);
nothing is compared after a command substitution normalized it. The exit
status is checked on its own, with or without errexit. A group list (the
real account's `id -G` list in `account`, and the `launch-form` and
`credentials` lists) is the exact set {primary GID, `agent_socket_gid`} in
either order, as `CheckG2AgentGroups` defines it; a third, missing or
repeated GID is refused. This is deliberately stricter than
`CheckG2AgentGroups` for a repeated GID, which `id -G` does not print.

**Dry run.** Anywhere, with no root and no station, with `go` on `PATH`:

```sh
sh deploy/t18-real-host-report.sh self-test
```

It builds the real `deploy-kit` from this checkout (a `DEPLOY_KIT` in the
environment is not used), composes synthetic evidence through the same report
code and prints `SELF_TEST PASS`. Its valid samples are a real run (with the no-op apply line)
and a stand-in run (placeholders `STAND_IN`, OVERALL valid only as a stand-in
run). Its known-bad samples (a placeholder reported `PASS` on a stand-in run, a
refused real-account group set, an ENOENT, a stand-in declared real, a sent
request, `STAND_IN` on a real wallet) must FAIL with their named lines. The
valid real report must pass `check` with its spec, `check` without a spec must
be a usage error, and eight plants must fail `check` with their named reason: a
deleted required row with the OVERALL count edited to match, another spec, a
missing and a duplicated `custody_spec_sha256` line, each of the three spec
hashes (the `custody_spec_sha256` line, the header's `spec_sha256`, the
`render` line's `custody_spec_file_sha256`) changed alone, and an extra denied
row. The canonical hash comes only from the product: with no `deploy-kit`, or
one that prints nothing, garbage or exits non-zero, `check` refuses with
`canonical-hash-unavailable`; one that prints another well-formed hash gives
`header-spec-sha256:differs`; and the valid report checked against its spec
with a leading space (file hashes moved along) passes, because the product
reads it as the same spec. r9: a refused RPC connection is FAIL
`node-not-listening` on a real run and `STAND_IN` on a stand-in run, `check`
refuses that `STAND_IN` relabeled `PASS` (`rpc-pass-node-not-listening`), and
an HTTP 401 without a `getindexinfo` answer is FAIL `node-liveness-unproven`.

## 4. The report

The first line is the header: `T18-REAL-HOST v1 wallet=<mode> commit=<pinned
commit> spec_sha256=<canonical spec> agent_uid=... primary_gid=...
socket_gid=... service_uid=...`. The second line is `custody_spec_sha256
<hex>`, the SHA-256 of the exact `custody-spec.json` file the report was
composed from (step 7 checks the report against that file, and checks the
header's canonical `spec_sha256` and the `render` line's
`custody_spec_file_sha256` against it too). Then comes one
line per item, in this form:

```
<item-id> PASS|FAIL|STAND_IN|COVERED_BY_HOSTED <evidence>
```

Two more lines are literal: `apply no-op: account pre-created by Infra`
right before `account`, and the `# positive-path:` statement right before
`positive-request`.

The last line is `OVERALL PASS|FAIL pass=.. stand_in=.. covered=.. fail=..
invalid=.. missing=.. run=real`. On a stand-in run it ends in
`run=stand-in valid-only-as-a-stand-in-run`: even an OVERALL PASS there is
valid only as a stand-in run.

**Verdicts:**

- `PASS`: the host showed the property, with the evidence on the line.
- `FAIL`: it did not, or there is no evidence.
- `STAND_IN`: only the placeholder-backed items (`denied-read:<path>`,
  `status-dir`, `allowed-socket`), and only with the stand-in flag (header
  `wallet=stand-in`): a denial (`EACCES` or `EPERM`) of a placeholder, or a
  successful connect to the planted listener. It is never a PASS, and `check`
  refuses any of these items as `PASS` on a stand-in report. r9: a
  `denied-rpc` item is `STAND_IN` too, but only on a stand-in run and only for
  a refused connection (`observed=REFUSED`): the stand-in station may run no
  node. Nothing is planted at the RPC port, so `denied-rpc` is not
  placeholder-backed: an explicit `HTTP_401` or `HTTP_403` there is a real
  refusal and is PASS under the same liveness rule as on the live-wallet
  station.
- `COVERED_BY_HOSTED`: the property cannot be shown on a correctly provisioned
  host without a destructive or privileged fixture. The line must carry
  exactly the pin of its row below: `pin=<test>`, `commit=<commit>`,
  `run=<hosted run id>` and `job=<job>`. A covered line with any other value,
  or without one of them, is invalid.

**OVERALL is PASS only when all of these hold:**

- every required item is present exactly once;
- no item is FAIL;
- each line agrees with its own evidence:
  - a `denied-read` or `status-dir` PASS shows `EACCES` or `EPERM`;
  - a `denied-rpc` PASS shows `HTTP_401` or `HTTP_403`, never `REFUSED`
    (`rpc-pass-node-not-listening:<item>`; another observation is
    `rpc-pass-without-refusal:<item>`), and `node-txindex` is PASS in the same
    report (`rpc-pass-without-live-node`); a `denied-rpc` `STAND_IN` shows
    `REFUSED` (`rpc-stand-in-without-refused:<item>`) on a stand-in run
    (`stand-in-misplaced:<item>` otherwise);
  - a socket PASS shows `CONNECTED` and a peer UID equal to the header's
    `service_uid`;
- every covered item carries exactly its pin;
- `STAND_IN` appears only for placeholder-backed items of a stand-in run, and
  none of those is `PASS` there;
- an `account` PASS stands under the literal no-op apply line and carries the
  real account's exact-set evidence;
- the `# positive-path:` statement is present once.

**Host items:**

| Item | Run in | PASS when |
| --- | --- | --- |
| `node-txindex` | step 3 | `getindexinfo txindex` reads exactly `{"txindex":{"synced":true,"best_block_height":N}}` |
| `render` | step 3 | `g2-render` exits 0 and its six files are byte-identical to `$RENDERED` |
| `account` | step 3 | the no-op mode is recorded (the report prints `apply no-op: account pre-created by Infra`); `g2-host-flow` prints `G2_HOST_FLOW_ACTIVATED`: the preflight, `VerifyG2AgentAccount` and the exact set {own GID == UID, `agent_socket_gid`} passed on this host's account database; and the REAL account read back has UID `agent_uid`, primary GID == UID, a group list `g2-agent-groups` accepts (`G2_AGENT_GROUPS_OK`), and that list, as `id -G` printed it, is exactly {primary, `agent_socket_gid`} in either order (r8). The apply and activation were no-ops. |
| `agent-inputs` | steps 4, 5 | the agent's spec, client and parameters have the SHA-256 of `$RENDERED/custody-spec.json`, `$RENDERED/client.json` and `$PARAMS` |
| `launch-form` | step 5 | `/proc` shows the setpriv launch form: real, effective, saved and filesystem UID all `agent_uid`; all four GIDs the declared primary GID; `Groups` exactly {primary, `agent_socket_gid`}; `CapPrm`, `CapEff` and `CapAmb` each present exactly once and all zero |
| `credentials` | step 5 | `g2-agent-groups` accepted the readback: observed `id -g` == declared primary GID, `id -G` == exactly {primary, socket} (`G2_AGENT_GROUPS_OK`) |
| `denied-read:<path>` | step 5 | one item per `denied_reads` path, in spec order; the probe observed `EACCES` or `EPERM` (and traversal was denied too). `ENOENT`, `READ_OK`, or no probe result is FAIL. With the stand-in flag a denial is `STAND_IN`, never PASS. |
| `status-dir` | step 5 | `/run/swarma-wallet-status` is in `denied_reads` and its probe is `EACCES` or `EPERM` (freeze amendment 1, A8). With the stand-in flag a denial is `STAND_IN`, never PASS. |
| `denied-rpc:<target>` | step 5 | r9: denied RPC needs a live node. PASS only when both hold: the credential-less JSON-RPC call got an explicit authorization refusal, HTTP 401 or HTTP 403 (`observed=HTTP_401` or `HTTP_403`: a listener at the target answered at probe time and refused it), and `node-txindex` is PASS in the same report (node liveness in this run). A refusal without that liveness is FAIL `reason=node-liveness-unproven`. A refused connection (`observed=REFUSED`: nothing listens at the port, no node or a stopped node) proves nothing: FAIL `reason=node-not-listening` on a `real` run, `STAND_IN` on a `stand-in` run, never PASS. A timeout or any other transport error aborts the probe, so there is no observation: FAIL `observed=none`. `HTTP_OK` (not refused) is FAIL. |
| `peer-precondition` | step 5 | the first version line of `perl -v`, as the agent ran it, reads `This is perl 5, version N, subversion M ...`; the line is on the item (`perl_v=`) |
| `allowed-socket` | step 5 | `real`: the probe connected (`CONNECTED`, no frame), and the peer is identified: `SO_PEERCRED` UID == `service_uid`, socket owner == `service_uid`, group == `agent_socket_gid`, mode 0660. These are the checks the agent client makes before its first frame. `stand-in`: `STAND_IN` after a successful connect, otherwise FAIL. |
| `custody-verify` | step 5 | probe exit 0, verify exit 0, and `T18_CUSTODY_VERIFIED <sha>` binds the canonical spec of the header |
| `launch-layout` | step 5 | the agent phase ran `g2-custody-verify -launch=true` on the custody report: it exited 0 (one `launch_true_exit` line) and printed exactly `T18_CUSTODY_VERIFIED <sha>` of the header. Otherwise FAIL, with `layout=refused` when the same report passed verify with `-launch=false` (the launch layout check alone refused it) and `layout=unknown` otherwise. |
| `positive-request` | step 5 | never sent here: `COVERED_BY_HOSTED` with `host=not-sent` (the receipt is the no-request marker, the exit is 3 and the client wrote no error output), or `host=not-run` (a refused readback stopped the script), and `positive_path=mainnet-smoke-gate`. Any other evidence, such as a real receipt, is FAIL. The real-wallet positive path is the owner-authorized mainnet smoke gate's, not T18's. |

**Covered items.** Every row but one pins a test at commit
`ca5edc6809ae71f5365c142a0010ba95c43b27be` and a push run on main at that
commit. Deploy kit checks is run 43360330648 (job `checks`). Agent wallet
checks is run 43360330369 (jobs `px1-core-gate` and `w2-core`). Both
succeeded. The exception is `cov-core-node-policy`:
`TestPX1T18CoreNodePolicy` needs `W1_REGTEST=1`, which the Deploy kit job does
not set, so it skipped in run 43360330648 and is not pinned to it. The
`px1-core-gate` job of Agent wallet checks, which fetches and verifies the
pinned Namecoin Core 28.0, now runs it with `W1_REGTEST=1` and fails unless the
`go test -json` stream shows it ran and passed with no skip. It is pinned to
the first such run: commit `dcad699da8cbc7e03436b00b85f667a5b2093b04`, run
43404324238 (`workflow_dispatch`), job `px1-core-gate`.

| Item | Pinned test | Run, job | What it shows | Why not on the host |
| --- | --- | --- | --- | --- |
| `positive-request` | `TestPX1CoreServiceG2FailClosed` | 43360330369, px1-core-gate | under the G2 profile, the service executes a valid own-agent request on genuine Namecoin Core 28 regtest | on the live-wallet station it is a wallet RPC beyond the handshake, which is forbidden; on the stand-in station there is no service |
| `cov-positive-request-client` | `TestCoreActionClient` | 43360330369, w2-core | the real agent-wallet CLI signs and exchanges a request with the socket service | same as above |
| `cov-wallet-foreign-peer` | `TestPX1T5ServiceRefusals` | 43360330369, px1-core-gate | under G2, a foreign peer UID is refused with `SERVICE_PEER` and another grantee with `GRANTEE_MISMATCH`, before admission | it needs a frame from a foreign UID to the live wallet |
| `cov-enoent-not-denied` | `TestPX1T18DeniedReadMustBeEACCES` | 43360330648, checks | a missing (`ENOENT`) or readable denied path fails its probe and the report | it needs a private file removed or opened up |
| `cov-searchable-dir` | `TestPX1T18SearchableDirectory` | 43360330648, checks | a directory that can be searched but not listed fails (`READ_OK`) | it needs a private directory's mode changed |
| `cov-rpc-not-refused` | `TestPX1T18RPCClassification` | 43360330648, checks | an RPC answer other than 401 or 403 (`HTTP_OK`) fails | it needs a node that answers without credentials |
| `cov-probe-uid-gate` | `TestPX1T18ProbeUIDGate` | 43360330648, checks | the probe refuses to run unless real and effective UID == `agent_uid` != `service_uid` | it needs a privileged run as the service UID, which could read wallet files |
| `cov-verify-refusals` | `TestPX1T18VerifyRefusals` | 43360330648, checks | verify refuses a report from another UID, a stale spec hash, a reordered, missing or extra probe, or a contradicting pass bit | it needs forged reports; the host shows only the genuine one |
| `cov-host-flow-tripwire` | `TestPX1S5HostFlowTripwire` | 43360330648, checks | a substituted UID, a UID collision, a third group, an own group at another GID or an outage stops the flow before activation | it needs a misprovisioned account |
| `cov-readback-refusals` | `TestPX1T18CustodyScript` | 43360330648, checks | a role-swapped, reduced or extra-group readback is refused before the probe and the request | it needs a wrong launch of the agent |
| `cov-core-node-policy` | `TestPX1T18CoreNodePolicy` | 43404324238, px1-core-gate (commit `dcad699d`) | on genuine Namecoin Core 28 regtest: a credential-less RPC call is HTTP 401; the rendered route whitelists allow and refuse as rendered; the rendered cookie and `wallet.dat` paths exist; a same-UID probe reads them, and verify refuses that report | it needs node calls with route credentials and a same-UID read of node secrets |

A covered item is never pinned to a run in which its test skipped.

## 5. Never do this on the live-wallet station

- **No spend** and no funding transaction, of any amount.
- **No wallet request beyond the handshake.**
  - No `agent-wallet` request of any action, `balance` included.
  - No `agent-walletd` or operator CLI call against the live service.
  - No query of the status socket.
  - Do not run `g2-custody-check.sh` on its own: it sends a `balance` request.
    Run it only through the agent phase (step 5), which replaces the request
    with the no-request mode.
  - The only contacts with the wallet socket are the probe's connect and the
    peer check's connect. Neither sends a frame.
- **No node wallet RPC.** The only node call is `getindexinfo txindex`.
- **Nothing reads wallet files.** Nobody, root included, reads, copies, backs
  up or opens `wallet.json`, `receipt.key`, `wallet.dat`, the journal or
  anything under `/etc/swarma/wallet` or `/var/lib/swarma-wallet`. The probe
  only attempts a read as the agent, and the kernel refuses it. Never run the
  probe, the custody script or the agent phase as root or as the service UID.
- **Do not weaken the check.**
  - Do not use `g2-custody-verify -launch=false` as evidence. The agent
    phase runs it once, only to name the cause of a `launch-layout` FAIL
    (`layout=refused`); no item passes on it.
  - Do not edit `custody-spec.json` or a report line.
  - Do not create a file to turn an `ENOENT` into a denial. (Placeholders
    belong only to the stand-in station, are created by Infra before the run,
    and are reported `STAND_IN`, never `PASS`.)
  - Do not run the live-wallet station with the stand-in flag, or the
    stand-in station without it.
  - Do not give `--regid` a name.
  - Do not relabel `STAND_IN` as `PASS`.

## 6. Collect the report

```sh
tar -C "$RUN" -czf "$RUN.tar.gz" operator agent/evidence T18-REPORT.txt custody-spec.json
sha256sum "$RUN.tar.gz" "$RUN/custody-spec.json"
```

Hand over: `T18-REPORT.txt`, the `custody-spec.json` the run used and its
SHA-256 (`check` needs the file; it is also in the tarball), the tarball and
its SHA-256, and the `deploy-kit` commit the run was built from. The receiver
checks the spec's SHA-256 before running `check` (step 7), with the hash
handed over in place of `<spec sha256>`:

```sh
echo "<spec sha256>  custody-spec.json" | sha256sum -c -
```

The evidence holds no credential:

- the public parameters' renders and their comparison, and the custody spec
  the run used (public paths and IDs);
- the `g2-host-flow` output and `id g2-agent`;
- the `getindexinfo` answer;
- the `/proc` credential lines;
- the custody script's evidence (the readback, the probe report, the verify
  output, the request it did not send, and the marker);
- the peer and socket lines.

## 7. What this report does not prove

- **The slot's own launch.** The report shows that a setpriv launch with
  these credentials holds what the slot should hold. The slot's systemd
  confinement and its key binding are the T19 half.
- **The positive own-agent request on the host.** The real-wallet positive
  path (an authorized request that executes) is proven by the separate
  owner-authorized, bounded mainnet smoke gate, not by T18. Here the request
  is pinned to the hosted Core tests and never sent.
- **The wallet layout on the stand-in station.** Its placeholder-backed items
  are `STAND_IN`; a stand-in report is valid only as a stand-in run.
- **Cross-UID denial for unknown children of a directory.** Only the
  directories themselves are probed. The rule that a searchable directory
  fails is the covered `cov-searchable-dir` item.
- **The node's own access policy** beyond one credential-less call. The route
  whitelists are shown by the Core test in SMOKE-G2.md §5.
- **That the node answered at the probe's moment and port** (r9). The
  liveness evidence of `denied-rpc` is the `getindexinfo` answer, an
  authenticated node call saved by the operator before step 3, so before the
  probe of step 5. The report cannot see when it was saved, and `namecoin-cli`
  reaches the node through the datadir's own settings, not through the
  probed `denied_rpc` target. What is shown at probe time is that a listener
  at the target answered the credential-less call with 401 or 403. To bind
  both to the same node at the probe's moment, a second `getindexinfo` answer
  is needed, saved after step 5 against the `denied_rpc` target
  (`-rpcconnect`/`-rpcport`), with both save times recorded; this runner does
  not collect it. That is a node call, not a wallet call; no wallet RPC is
  ever added.
- **That a denied path exists, when its parent is closed.** A missing path
  whose parent directory the agent cannot search (for example the node cookie
  of a stopped node, under a mode 0700 datadir) reads `EACCES`, not `ENOENT`:
  the denial comes from the parent and holds for any object later created at
  that path, but the report does not prove the object exists. The root
  preflight of step 2 (`MISSING` lines) is that evidence; the runner does not
  collect it.
- **That `custody-verify` and `launch-layout` saw an RPC denial.** They state
  the product verifier's verdict, and the product counts a refused
  connection as a denial. On a live run with a stopped node they can be PASS
  while the `denied-rpc` item is FAIL `node-not-listening`, so OVERALL is
  FAIL; only the `denied-rpc` items judge the RPC denial.
