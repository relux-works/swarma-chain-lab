# G2 pay deploy and T18 custody check (PX1 S5)

This is the operator procedure for the G2 pay executor's deploy inputs and for
T18, the different-UID custody check. It sits on the frozen PX1 contract in
`g2_pay_api.go` (see `experiments/agent-wallet/PX1-INTERFACES.md`).

Nothing here funds a wallet, starts a service, creates users or spends coins.
The mainnet-safe smoke (G2-PAYMENT-EXECUTOR §3.8) runs only after Ivan approves
and funds it, and nothing in this document authorizes it.

Placement (Q9): `agent-walletd` and the rented agent run on the same host under
separate UIDs. The agent reaches only `/run/swarma-wallet/wallet.sock`. The
executor host runs its own Namecoin node (txindex, listen=0) with the dedicated
hot wallet.

## 1. Parameters

Copy `templates/g2-pay/parameters.json` and replace every `PLACEHOLDER` with an
operator-owned public value. Numeric placeholders become JSON numbers. Keep the
canonical member order and compact form, because the parser accepts only exact
`json.Marshal` bytes.

| Member | Meaning | Rule |
| --- | --- | --- |
| `network`, `genesis` | chain pin | `main` with the main genesis. `regtest` with the regtest genesis is accepted for rehearsals only. |
| `agent_uid` | the rented agent's UID (service `peer_uid`) | not 0, 65534 or 2^32-1 |
| `agent_socket_gid` | per-agent socket group (service `socket_gid`) | not reserved; differs from `operator_gid` |
| `operator_gid` | operator status group | not reserved |
| `grantee` | the agent's x-only action key (pay-grant grantee) | valid BIP-340 key |
| `receipt_pubkey` | x-only receipt key (terms `executor_key`) | valid BIP-340 key; never equal to `grantee` |
| `fee_rate_sat_vb` | fee rate for the private `wallet.json` | 100..1000. The template uses 110 (co-lead review: relay floor 100, never 200). |
| `hot_wallet_name` | Core wallet on the own node | lowercase label; never the unnamed default wallet |
| `node_rpc_port` | loopback RPC port of the own node | 1..65535 |
| `g2` | the operator block, mirror of agent-wallet `G2OperatorConfig` | see below |

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
| `client.json` | the agent's client pins (socket, service UID, receipt key, key file) | the agent's own config; no RPC, no coin key |
| `sysusers.conf` | `swarma-wallet`, `swarma-wallet-peer` (GID pinned), `swarma-wallet-status` (GID pinned) | applied by root |
| `tmpfiles.conf` | `/etc/swarma/wallet` 0750, the state root and its four subdirectories 0700 | applied by root |
| `namecoin-rpc.conf` | chain section; `listen=0`, `txindex=1`, loopback RPC; `rpcwhitelistdefault=0`; the three route whitelists; `wallet=` | merged into the node config by root |
| `custody-spec.json` | the T18 input (`CustodySpecV1`) | read by the probe |

No rendered file carries a credential. The operator adds one `rpcauth` line per
route (`w3-observer`, `w1-wallet`, `w1-broadcast`) to the node config. The
route passwords go only into the private `wallet.json`.

### Placeholders the parameters cannot fill

The frozen `G2PayParameters` has no service UID, no agent key path, no node
datadir and no agent user name. A freeze amendment is proposed to add them.
Until it lands, the render leaves these placeholders, and every consumer refuses
them (`ErrPlaceholder`, or a decode error for the UID):

| Placeholder | Where | Resolve with |
| --- | --- | --- |
| `"PLACEHOLDER_WALLET_UID_INTEGER"` (quoted) | `client.json`, `custody-spec.json` | the numeric UID of `swarma-wallet` after provisioning, unquoted |
| `PLACEHOLDER_AGENT_SIGNING_KEY_ABSOLUTE_PATH` | `client.json` | the agent's action key file |
| `PLACEHOLDER_NODE_DATADIR` | `custody-spec.json` | the own node's datadir, without a trailing slash |
| `PLACEHOLDER_AGENT_USER` | `sysusers.conf` | the user name whose UID is `agent_uid` |

The node paths in the spec are `<datadir>/.cookie` and
`<datadir>/wallets/<hot_wallet_name>/wallet.dat` on main. On regtest they sit
under `<datadir>/regtest/`. A Core-initialized datadir has a `wallets/`
directory. The Core test checks this layout on Namecoin Core 28. Keep the
resolved spec in canonical form: replace the values in place and add no
whitespace.

### Validate

```sh
go run ./cmd/deploy-kit validate -config "$PUBLIC_DIR/wallet/deploy.json" -public "$RENDERED/service.json"
```

The wallet validator accepts the `g2` member only with an explicit chain pin and
a launch-valid operator block. A W2 `service.json` without `g2` validates
exactly as before.

## 3. Status socket (open item)

S3 owns the status socket `/run/swarma-wallet/status.sock` (mode 0660, operator
group). Its directory `/run/swarma-wallet` is 0750 with group
`swarma-wallet-peer`, and the daemon requires exactly that. An operator user
outside `swarma-wallet-peer` therefore cannot reach the status socket. The
rendered `sysusers.conf` creates `swarma-wallet-status` with `operator_gid` and
adds the service user to it, so the daemon can set the socket group. It adds no
operator user. The choice between putting the operator user in the peer group
and moving the status socket to its own runtime directory is open with S3.

## 4. T18: different-UID custody check

T18 runs on an agents1-class host whose users the owner has provisioned. Neither
the probe nor the script needs root.

**Root preflight (owner).** The probe runs as the agent and often sees `EACCES`
on a parent directory, so the probe cannot tell that a file exists. Before T18,
root confirms that every path in the resolved spec exists:

```sh
grep -o '"/[^"]*"' custody-spec.json | tr -d '"' | while read -r p; do test -e "$p" || echo "MISSING $p"; done
```

**Agent run.** As the agent user, with binaries built from the reviewed head:

```sh
DEPLOY_KIT=/path/to/deploy-kit AGENT_WALLET=/path/to/agent-wallet \
  deploy/g2-custody-check.sh custody-spec.json client.json "$GRANTEE_XONLY" "$NEW_EVIDENCE_DIR"
```

The script prints `T18_PASS` and exits 0 only when all three of these hold:

1. **`deploy-kit g2-custody-probe`** runs only as `agent_uid` (real and effective
   UID), never as the service UID. Every denied read must be `EACCES` or
   `EPERM`. `ENOENT` (missing) and `READ_OK` both fail. Every credential-less
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

The evidence directory keeps `custody-report.json`, the positive request and
receipt, the verify output, and `exits.txt`. Keep it with the launch packet.

## 5. What the tests prove and what they do not

- Unit tests run as the test UID. A mode-0000 file and directory give a genuine
  `EACCES`. A missing path gives `ENOENT`, which fails. A readable path gives
  `READ_OK`, which fails. A closed loopback port gives `REFUSED`, and a live
  unix socket gives `CONNECTED`.
- The Core test (`W1_REGTEST=1`) starts Namecoin Core 28 on regtest from the
  rendered `namecoin-rpc.conf`. A credential-less call gets HTTP 401. Each route
  can call only its README method set, and HTTP 403 refuses everything else,
  including `dumpprivkey`, `dumpwallet`, `sendtoaddress` and `stop`. The hot
  wallet loads from the rendered `wallet=` line, and the cookie and `wallet.dat`
  sit at the spec paths. The probe, run as the node's own UID, reads both
  (`READ_OK`) and the report is refused. This shows that same-UID custody fails
  T18.
- **Not proven here:** a cross-UID denial on a provisioned host, systemd
  enforcement, and the positive own-agent request under G2. Those are the T18
  host run itself.
