# G2 pay deploy and T18 custody check (PX1 S5)

This is the operator procedure for the G2 pay executor's deploy inputs and for
T18, the different-UID custody check. It sits on the frozen PX1 contract in
`g2_pay_api.go` (see `experiments/agent-wallet/PX1-INTERFACES.md`).

Nothing here funds a wallet or spends coins. Users are created and services
started only by the owner, as root, through the target-host flow in §3. The
mainnet-safe smoke (G2-PAYMENT-EXECUTOR §3.8) runs only after Ivan approves
and funds it, and nothing in this document authorizes it.

Placement (Q9): `agent-walletd` and the rented agent run on the same host under
separate UIDs. The agent reaches only `/run/swarma-wallet/wallet.sock`; that
directory holds only `wallet.sock` and is the only one bound into a slot. The
operator status socket lives in its own directory, `/run/swarma-wallet-status`
(freeze amendment 1, A8), which is never bound into a slot. The executor host
runs its own Namecoin node (txindex, listen=0) with the dedicated hot wallet.

## 1. Parameters

Copy `templates/g2-pay/parameters.json` and replace every `PLACEHOLDER` with an
operator-owned public value. Numeric placeholders become JSON numbers. Keep the
canonical member order and compact form, because the parser accepts only exact
`json.Marshal` bytes.

| Member | Meaning | Rule |
| --- | --- | --- |
| `network`, `genesis` | chain pin | `main` with the main genesis. `regtest` with the regtest genesis is accepted for rehearsals only. |
| `agent_uid` | the rented agent's UID (service `peer_uid`) | not 0, 65534, 65535 or 2^32-1 |
| `agent_socket_gid` | per-agent socket group `swarma-wallet-peer` (service `socket_gid`) | not 0, 65534, 65535 or 2^32-1; differs from `operator_gid` |
| `operator_gid` | operator status group `swarma-wallet-status` | not 0, 65534, 65535 or 2^32-1 |
| `service_uid` | UID of `swarma-wallet` (sysusers `u` line, `client.json`, custody spec) | not 0, 65534, 65535 or 2^32-1; differs from `agent_uid` |
| `agent_user` | the agent's account name on the target host | strict sysusers name (`[A-Za-z_][A-Za-z0-9_-]*`, at most 31 bytes); not `root`, `nobody` or a `swarma-wallet*` name |
| `agent_key_file` | the agent's action key file (`client.json`) | absolute, clean path; not the node datadir |
| `node_datadir` | the own node's datadir (cookie and `wallet.dat` in the custody spec) | absolute, clean path, at most 1024 bytes; not under `/var/lib/swarma-wallet`, `/etc/swarma` or `/run` |
| `grantee` | the agent's x-only action key (pay-grant grantee) | valid BIP-340 key |
| `receipt_pubkey` | x-only receipt key (terms `executor_key`) | valid BIP-340 key; never equal to `grantee` |
| `fee_rate_sat_vb` | fee rate for the private `wallet.json` | 100..1000. The template uses 110 (co-lead review: relay floor 100, never 200). |
| `hot_wallet_name` | Core wallet on the own node | lowercase label; never the unnamed default wallet |
| `node_rpc_port` | loopback RPC port of the own node | 1..65535 |
| `g2` | the operator block, mirror of agent-wallet `G2OperatorConfig` | see below |

`ValidateG2PayParameters` first runs the frozen pure
`ValidateG2PayIdentityDomain` (the four IDs, `service_uid != agent_uid`, the
name rule and the two paths); its refusal wins over every other error. It reads
no account database: whether `agent_user` exists, and at which UID, is checked
on the target host in §3. The two group IDs and both UIDs are written into
`sysusers.conf`. systemd-sysusers cannot parse ID 65535 (the 16-bit
`(uid_t)-1`), so it is refused for all four before anything is rendered. 65533
and 65536 are valid.

The `g2` block in the template carries the §3.8 smoke values, which are pinned
byte-for-byte by the frozen golden (`max_transfer_sat` 100000, `max_day_sat`
300000, `max_day_count` 10, `max_fee_sat` 100000, `max_float_sat` 2000000,
`low_float_sat` 500000, canary 10000, k=2, N=6, 60 reads/hour, capacity 2048).
Public values are Ivan's. The deploy pre-check is deliberately stricter than
the daemon for launch. It refuses `allow_single_use: true` (Q7) and
`allow_any_recipients: true` (Q2, phase 1). It also requires
`max_transfer_sat ≤ max_day_sat ≤ max_float_sat`, `1 ≤ k ≤ 6`, `k ≤ N ≤ 144`,
a canary of at least 546 atoms, and
`journal_spend_capacity ≥ max_day_count + 64`. The agent-wallet startup
validator stays authoritative.

## 2. Render

From `deploy/`:

```sh
go run ./cmd/deploy-kit g2-render -params "$PARAMS" -out "$NEW_ABSOLUTE_DIR"
```

This writes exactly the six frozen files (mode 0600) into a new directory and
never overwrites an existing one:

| File | Content | Installed as |
| --- | --- | --- |
| `service.json` | W2 public pins plus the `g2` block | `/etc/swarma/wallet/service.json`, root:swarma-wallet 0640 |
| `client.json` | the agent's client pins (socket, `service_uid`, receipt key, `agent_key_file`) | the agent's own config; no RPC, no coin key |
| `sysusers.conf` | `u swarma-wallet <service_uid>`, `swarma-wallet-peer` and `swarma-wallet-status` (GIDs pinned), the service in both groups, then `G2AgentSysusers` verbatim: `u <agent_user> <agent_uid>` and `m <agent_user> swarma-wallet-peer` | applied by root only through §3 |
| `tmpfiles.conf` | `/etc/swarma/wallet` 0750, the state root and its four subdirectories 0700, and `d /run/swarma-wallet-status 0750 swarma-wallet swarma-wallet-status -` | applied by root |
| `namecoin-rpc.conf` | chain section; `listen=0`, `txindex=1`, loopback RPC; `rpcwhitelistdefault=0`; the three route whitelists; `wallet=` | merged into the node config by root |
| `custody-spec.json` | the T18 input (`CustodySpecV1`): `service_uid`, the private paths, `/run/swarma-wallet-status`, `<node_datadir>` cookie and `wallet.dat` | read by the probe |

No rendered file carries a credential or a placeholder. The operator adds one
`rpcauth` line per route (`w3-observer`, `w1-wallet`, `w1-broadcast`) to the
node config. The route passwords go only into the private `wallet.json`.

Each rendered file was given to its own consumer:

| File | Consumer | Evidence |
| --- | --- | --- |
| `custody-spec.json` | `deploy-kit g2-custody-probe` and `g2-custody-verify` (`ParseCustodySpec`, `ValidateG2CustodyLaunchSpec`) | `TestPX1S5RenderFileSet`, `TestPX1S5HostFlowArtifacts` |
| `client.json` | the agent-wallet CLI, whose first step is `LoadActionClientConfig` | `TestPX1S5ClientConsumerResolved` builds the CLI from `experiments/agent-wallet` as a subprocess and runs it on the rendered bytes: the loader accepts them. The same file with a quoted UID, a relative key path or a placeholder key path is refused with `CLIENT_CONFIG`. |
| `sysusers.conf` | `systemd-sysusers` | `TestPX1S5SysusersResolvedConsumer` runs the real consumer with `--dry-run --root=<fixture>`: on a first install it would create the agent at exactly `agent_uid` and the service at `service_uid`; an existing agent is kept. On a UID collision it still exits 0 but would create the agent at another UID, which is why §3 has the preflight and the post-apply check. |

The node paths in the spec are `<node_datadir>/.cookie` and
`<node_datadir>/wallets/<hot_wallet_name>/wallet.dat` on main. On regtest they
sit under `<node_datadir>/regtest/`. A Core-initialized datadir has a
`wallets/` directory. The Core test checks this layout on Namecoin Core 28.

### Validate

```sh
go run ./cmd/deploy-kit validate -config "$PUBLIC_DIR/wallet/deploy.json" -public "$RENDERED/service.json"
```

The wallet validator accepts the `g2` member only with an explicit chain pin and
a launch-valid operator block. A W2 `service.json` without `g2` validates
exactly as before.

## 3. Target-host flow (root, on the target host only)

The account binding is checked on the TARGET host, the host that applies
`sysusers.conf` and runs the slot, never on the rendering machine. The order is
fixed (freeze amendment 1, A3) and implemented once, in `RunG2HostFlow`:

1. **Render** (pure, as in §2).
2. **Preflight** `ValidateG2PayIdentity(p, G2HostAccounts{})`: an existing
   `agent_user` is admitted only at exactly `agent_uid`; an absent
   `agent_user` only when no other name owns `agent_uid`. A lookup outage
   refuses; it is never absence.
3. **Apply**: `systemd-sysusers -` on the `sysusers.conf` rendered from the same
   parameters. Its exit status authorizes nothing: sysusers substitutes a free
   UID on a collision and keeps an existing name at its UID, both with exit 0.
4. **Post-apply check** (required) `VerifyG2AgentAccount(p, G2HostAccounts{})`:
   `agent_user` at exactly `agent_uid`, a member of `agent_socket_gid` and not
   of `operator_gid`.
5. **Activation**, and T18 after it (§4), only after step 4 passed.

A failed step stops the flow before the next one. Run it with the
`deploy-kit` binary built from the reviewed head:

```sh
deploy-kit g2-host-flow -params "$PARAMS" -- systemctl start swarma-wallet.service
```

The command after `--` is the activation; it runs only after the post-apply
check. The command prints `G2_HOST_FLOW_ACTIVATED` only after a successful
activation. Do not run `systemd-sysusers` on the rendered file by hand, and do
not start a G2 service before this command has printed that line.

**Groups (A8).** The service account `swarma-wallet` is in
`swarma-wallet-peer` (it owns `wallet.sock`) and in `swarma-wallet-status` (it
gives `status.sock` that group); its unit keeps the operator group as a
supplementary group (S3's G2 unit section). The agent's only G2 group is
`swarma-wallet-peer`. The operator user's only G2 group is
`swarma-wallet-status`, and the operator is never put into
`swarma-wallet-peer`. `sysusers.conf` renders no operator account; the owner
adds the operator user to `swarma-wallet-status` only. Nothing rendered here
binds `/run/swarma-wallet-status` into a slot.

## 4. T18: different-UID custody check

T18 runs on the executor host after §3 printed `G2_HOST_FLOW_ACTIVATED`.
Neither the probe nor the script needs root.

**Root preflight (owner).** The probe runs as the agent and often sees `EACCES`
on a parent directory, so the probe cannot tell that a file exists. Before T18,
root confirms that every path in the resolved spec exists:

```sh
grep -o '"/[^"]*"' custody-spec.json | tr -d '"' | while read -r p; do test -e "$p" || echo "MISSING $p"; done
```

**Agent run.** With the agent's slot credentials. The slot runs its payload
with `User=` and `Group=` set to the agent account, and systemd adds the
account's group list through initgroups. The agent therefore runs with UID
`agent_uid`, its own primary group (the group `systemd-sysusers` creates for
`u <agent_user> <agent_uid>`, at GID `agent_uid`) and `swarma-wallet-peer`
(`agent_socket_gid`), and with nothing else. Root launches T18 with the same
credentials: `--reuid` and `--regid` name the agent account and its own group
the way `User=` and `Group=` do, and `--init-groups` applies initgroups for the
account. This equals what the slot applies (`User=` plus `Group=` plus
initgroups) for an account whose own group is its primary group, which is what
`systemd-sysusers` creates from the declaration. Run the script with binaries
built from the reviewed head, and give it the `parameters.json` the files were
rendered from (it holds no secret):

```sh
setpriv --reuid="$AGENT_USER" --regid="$AGENT_USER" --init-groups -- \
  env DEPLOY_KIT=/path/to/deploy-kit AGENT_WALLET=/path/to/agent-wallet \
  deploy/g2-custody-check.sh custody-spec.json client.json "$GRANTEE_XONLY" \
    parameters.json "$NEW_EVIDENCE_DIR"
```

`AGENT_USER` is `agent_user` of the parameters. Do not drop to a reduced group
set (the socket GID alone, or a hand-made group list): such a run tests
credentials the slot never has.

The script first reads back `id -G` and records it in `credentials.txt`. It
hands the readback to `deploy-kit g2-agent-groups -params parameters.json`,
which derives the expected set from the parameters: the agent's own primary
GID from its sysusers declaration (`G2AgentSysusers`), and `agent_socket_gid`.
The readback must be exactly that set: both GIDs present, in any order, nothing
else, and never the operator GID. A repeated GID is not an extra group. The
result goes to `credentials-check.txt`. On a refused readback the script prints
`T18_FAIL` and runs nothing else. An account whose own group sits at another
GID (an existing account, or a GID collision during the apply), or that has any
other group, fails here. Fix the account; do not change the check.

It then prints `T18_PASS` and exits 0 only when all three of these hold:

1. **`deploy-kit g2-custody-probe`** runs only as `agent_uid` (real and effective
   UID), never as the service UID. Every denied read must be `EACCES` or
   `EPERM`, and the agent must also be unable to traverse into the target
   (resolving `<target>/.` must be refused, or fail with `ENOTDIR` for a file).
   A denied directory listing alone proves nothing about the files below it: a
   directory that the agent may search but not list (`x` without `r`, as in
   mode 0711) still hands out every child whose name is known, such as a
   journal. Such a target is recorded as `READ_OK` and fails, even when the
   known children are private, because they cannot all be checked one by one.
   `ENOENT` (missing) and `READ_OK` both fail. Every credential-less
   JSON-RPC call to the node port must be HTTP 401, HTTP 403 or a refused
   connection. Any other HTTP status is recorded as `HTTP_OK` and fails.
   Finally the probe connects to the wallet socket without sending a frame
   (`CONNECTED`), so the service admits nothing.
2. **One own-agent `balance` request** goes through `agent-wallet`, with a fresh
   nonce and the current time, and must return an `executed` receipt. Under
   the G2 profile this needs S1-S3 to have landed.
3. **`deploy-kit g2-custody-verify`** accepts the stored report. The spec must
   have the rendered launch layout. The report must have run as `agent_uid`,
   bind the SHA-256 of the canonical spec, and list exactly one probe per
   target in spec order. Every probe must pass under the recomputed rule; a
   reported pass bit is never trusted.

The denied reads include `/run/swarma-wallet-status`: the agent is not in the
operator group, so it must get `EACCES` there.

The evidence directory keeps `credentials.txt`, `credentials-check.txt`, `custody-report.json`, the
positive request and receipt, the verify output, and `exits.txt`. Keep it with
the launch packet.

## 5. What the tests prove and what they do not

- Unit tests run as the test UID. A mode-0000 file and directory give a genuine
  `EACCES`. A missing path gives `ENOENT`, which fails. A readable path gives
  `READ_OK`, which fails. A closed loopback port gives `REFUSED`, and a live
  unix socket gives `CONNECTED`.
- `TestPX1T18SearchableDirectory` models a directory the agent may search but
  not list (mode 0111) with a readable `journal.jsonl` inside. The probe records
  `READ_OK` and the report fails verification. A mode-0000 or mode-0200
  directory, a file behind a mode-0000 parent, and a private file probed
  directly are the passing neighbours. Same-UID modes stand in for the agent's
  view of another user's mode-0711 or mode-0700 directory.
- `TestPX1S5HostFlowTripwire` drives `RunG2HostFlow` over a fixture account
  database. A refused preflight (existing name at another UID, UID owned by
  another name, outage, no database) stops before the apply. A post-apply
  mismatch (substituted UID, missing peer membership, operator-group
  membership, nothing created, outage, failed apply) stops before activation.
  The clean first-install and existing-account paths reach activation once,
  after the post-apply check. `TestPX1S5HostFlowArtifacts` checks the rendered
  numeric declaration, that only the service and the agent are in
  `swarma-wallet-peer`, the status directory in `tmpfiles.conf` and its denial
  in `custody-spec.json`, and that no rendered file has a placeholder.
  `TestG2HostFlowCommand` runs `deploy-kit g2-host-flow` on the real account
  database of the test host, with recording fakes for `systemd-sysusers` and
  the activation command.
- `TestPX1S5AgentSlotGIDs` derives the primary GID from the agent's own
  declaration and refuses parameters whose derived primary GID is the socket
  or operator GID. `TestPX1S5AgentGroupsReadback` accepts exactly the
  two-group set (any order, repeats allowed) and refuses a third group, the
  operator GID, a missing socket GID, a missing primary GID (the old
  socket-GID-only set) and an empty readback. `TestG2AgentGroupsCommand` runs
  the same cases through `deploy-kit g2-agent-groups`.
  `TestPX1T18CustodyScript` runs the script with the real `deploy-kit
  g2-agent-groups` and a fake `id`, and shows that a refused readback runs
  neither the probe nor the request. `TestPX1S5T18LaunchCredentials` checks
  that the documented launch is the `--init-groups` form and that no S5 T18
  text keeps the reduced form. The tripwire's `t18-readback` part shows that
  an existing account with an extra group of its own passes the frozen
  post-apply check and is activated, but is refused by the readback.
- `TestPX1S5SysusersResolvedConsumer` and `TestPX1S5SysusersGIDDomain` give
  the rendered `sysusers.conf` to the real `systemd-sysusers`, only with
  `--dry-run` and a new fixture root, and check that the fixture `passwd` and
  `group` are unchanged afterwards. On a first install the consumer would give
  the agent its own group at the derived primary GID. The rendered file is accepted with GIDs
  1301/1401, 65533 and 65536, and a hand-edited GID 65535 line is refused by
  the consumer itself. The consumer
  part skips, and says so, where `systemd-sysusers` is not installed or has no
  `--dry-run` option. systemd 249 on the hosted ubuntu-22.04 runner refuses the
  option and does nothing, so there it skips. It never runs without
  `--dry-run`.
- The Core test (`W1_REGTEST=1`) starts Namecoin Core 28 on regtest from the
  rendered `namecoin-rpc.conf`. A credential-less call gets HTTP 401. Each route
  can call only its README method set, and HTTP 403 refuses everything else,
  including `dumpprivkey`, `dumpwallet`, `sendtoaddress` and `stop`. The hot
  wallet loads from the rendered `wallet=` line, and the cookie and `wallet.dat`
  sit at the spec paths. The probe, run as the node's own UID, reads both
  (`READ_OK`) and the report is refused. This shows that same-UID custody fails
  T18.
- **Not proven here:** a real apply and post-apply check on a target host, a
  cross-UID denial on a provisioned host, systemd enforcement, slot
  confinement, and the positive own-agent request under G2. Those are the §3
  and T18 host runs themselves.
