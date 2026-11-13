# W2 wallet service: LIP-0006 v1 profile

Experimental, with explicit NMC-main or regtest network/genesis pins. `agent-walletd` owns the RPC configuration, public
grant mirror, journals and receipt key under a dedicated non-root OS user.
`agent-wallet` is now a signing Unix-socket client. It holds only the grantee
action key, service UID/key pins and socket path. `agent-wallet-legacy` preserves
W1's same-user CLI for regression and explicit legacy deployments; it does not
provide custody separation. Never give its private configuration to a W2 agent.

## Transport and exact bytes

One request and one response per Unix connection, each prefixed by a four-byte
unsigned big-endian body length, 1..65536 bytes. No newline is part of the wire
body. The service checks kernel peer credentials before reading a frame, records
UID/GID, and applies a 1..60 second connection deadline. There is one configured
grantee and peer UID per instance. Linux uses SO_PEERCRED; Darwin uses LOCAL_PEERCRED.
The client checks the socket owner/mode, actual peer UID and pinned receipt key.
The socket is 0660 in a canonical service-owned 0750 directory, with a dedicated
per-agent group. An existing socket refuses startup; investigate it manually
after establishing that its owner process exited. Do not add automatic unlink.

All wire objects have exactly the field order below, compact JSON, no unknown,
duplicate, omitted required, null, case-aliased or trailing fields/bytes. Integers
use their canonical decimal form. Hex is lowercase. The request structure is:

```json
{"v":1,"service":"wallet.nmc","action":"balance","params":{},"grant":{"kind":"none"},"nonce":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","created_at":500,"grantee":"c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"}
```

This is public test data, not a current request or authorization. `nonce` is
16 random bytes encoded as 32 hex characters; `created_at` is positive Unix
seconds. `grantee` is a BIP-340 x-only public key. `request_hash` is SHA256 of
these exact unsigned request bytes. Sign BIP-340 over
`SHA256(UTF8("swarma-action-v1") || binary32(request_hash))`. The digest does
not use the ASCII hex hash and is not an 8184 event ID.

Transport wraps this as `{"request":REQUEST,"signature":"128_HEX"}`. A
single-use spend may append `,"proof":{"use_txid":"64_HEX"}` before the
wrapper's closing brace. This locator is unsigned and outside request_hash;
the service independently verifies its chain proof. It is forbidden for other
actions/grant kinds. W3's OP_RETURN commitment is SHA256 of the unsigned request
bytes. Never fabricate a Nostr event or commit the wrapper instead.

| Action | Params, exact field order | Grant |
| --- | --- | --- |
| `spend` | `{"to":"NETWORK_P2PKH","amount_sat":INTEGER,"fee_limit_sat":INTEGER}` | `{"kind":"standing","id":"64_HEX"}` or `single-use` |
| `balance`, `history`, `receive` | `{}` | `{"kind":"none"}` |
| `budget` | `{}` | `standing` or `single-use`, with stable ID |

Amounts are positive atoms; amount plus fee must fit MaxMoney. Fee is 1..MaxFee.
Standing spend maps to W1 `pay`; all existing grant scope, recipient, window,
fee-inclusive cumulative budget, plan and signature checks apply. Single-use
requires the exact signed grant amount/recipient and no larger fee limit.
Name registration and updates are rejected. Registration's separate reveal
continuation is deferred to W2b; no duplicate-receipt workaround implements it.

## Admission, authority and effects

Validate peer, canonical schema/service, signature and pinned grantee first.
Check the durable per-grantee nonce journal next. A different request hash under
the same nonce refuses. A terminal duplicate returns the original signed receipt
byte-for-byte, even outside skew or after authority expires. It never retries an
effect. A pending duplicate re-observes the chain. Only first admission checks
the configured 1..300 second skew, then persists admission telemetry before
resolving the grant. Skew never replaces the grant's own validity window.

Grant IDs resolve only in the service-controlled object directory; request paths
and arbitrary RPCs are not accepted. Malformed or mismatching public objects
return OBJECT_HASH rather than a direct W1 parser error. Grant grantee/kind and
contract terms bind before the shared W1 executor. Each read verifies the configured
network/genesis. Signed no-grant reads do not imply spending authority. `budget`
reports live=false when authority is not live; a successful query is not a grant.
`receive` allocates an address and therefore reserves durably before calling RPC.

Spending uses the original W1 checks, then reserves both the wallet plan/budget
and service action before broadcast. After reservation it checks authority,
single-use proof where applicable, and all input coins again. These observations
are not atomic with broadcast; later chain changes remain possible. A final
refusal retains the reservation. RPC timeouts and ambiguous outcomes do not
authorize a retry. A missing single-use proof is terminal USE_PROOF_REQUIRED;
USE_PENDING is pending and can advance with the same request after confirmation.

The service nonce maps into W1's 32-byte nonce as SHA256 of UTF8
`"swarma-action-nonce-v1" + grantee_hex + nonce_hex`; exact unsigned request bytes
remain the W1 journal commitment. This does not change the legacy event codec.

## Signed receipts and recovery

Receipt field order: `v,service,grantee,request_hash,verdict,reason,effect,
journal_seq,observed_height,peer`; peer fields are `uid,gid`. The wrapper contains
`receipt,signature`. BIP-340 signs SHA256 of UTF8 `swarma-action-receipt-v1`
followed by the canonical receipt bytes. The service key is distinct from the
grantee key. Clients must pin it independently; no response supplies its own key.

Verdicts: executed, pending, refused, uncertain. Reasons reuse W1/K1 codes with
bounded ACTION_/SERVICE_ transport codes; no raw error, input or credential is
echoed. Sequence is one-based admission order, or zero for pre-admission refusal.
Observed height is a sampled regtest tip, not an atomic authorization snapshot;
zero means unavailable/not observed. Spend effect contains txid when available,
reserved_sat and phase; receive contains address; reads use their W1 projections.
Malformed requests receive a refusal bound to SHA256(raw frame body), since no
authenticated canonical request hash exists. Peer/framing failures close silently.

The service journal has a lifetime lock, 0600 single-link files in a 0700 root,
at most 32 entries and 65536 bytes, with 16384-byte receipt headroom. Oversize
receipts become uncertain. Admission may stop before 32 entries when byte
headroom runs out. No pruning or automatic reset restores consumed authority.
Corruption/configuration/receipt-key changes refuse reopening. Write uncertainty
poisons the live service. Crash after reservation returns durable uncertainty;
the wallet-reserved/service-pending gap is also never rebroadcast. Receive
reservations likewise never allocate twice. Preserve state and reconcile with
the operator; do not change nonce, roots, keys or journal contents to retry.

## Configuration and commands

Build all three commands from this module; outputs are scratch artifacts:

```sh
go build -trimpath -o ../../.temp/agent-wallet ./cmd/agent-wallet
go build -trimpath -o ../../.temp/agent-walletd ./cmd/agent-walletd
go build -trimpath -o ../../.temp/agent-wallet-legacy ./cmd/agent-wallet-legacy
agent-walletd --config SERVICE_CONFIG
agent-wallet --config CLIENT_CONFIG --request UNSIGNED_CANONICAL_REQUEST
agent-wallet --config CLIENT_CONFIG --request UNSIGNED_CANONICAL_REQUEST --use-txid TXID
```

Daemon config fields, in order: version,service,socket,socket_gid,peer_uid,
grantee,skew_seconds,timeout_seconds,state_dir,wallet_config,receipt_key_file.
`LoadServiceConfig` requires a private owner0600 single-link regular file. Native
startup refuses root, the service's own UID as peer, group zero, noncanonical
paths, wrong socket-directory ownership/group/mode and grantee/receipt-key reuse.
The private wallet_config retains the W1 schema and separate RPC principals.
The grant mirror is service-owned and not group/world writable. Operator-provision
all parents without symlinks and without agent write access; private-file loaders
reject final symlinks, but do not claim universal ancestor/rename-race protection.

Client config fields: version,service,socket,service_uid,receipt_key,key_file.
It is a closed public schema; RPC fields refuse. Receipt and grantee key files
contain exactly 64 lowercase hexadecimal scalar characters, with no newline,
owner0600, single link, no final symlink. Let the client read its own action key;
never copy the daemon key or wallet credentials to the client. Exit codes are
0 executed, 2 refused/client error, 3 pending, 4 uncertain. The printed verified
receipt has a display newline; its wire body does not.

See [deploy wallet templates](../../deploy/templates/wallet/) and the
[deploy credential table](../../deploy/README.md). They prepare one service/agent
instance. Provision separate users/groups/roots/ports for additional agents;
these templates do not implement a multi-tenant wallet.

## G2 operations (PX1)

A service config with a `g2` block selects the G2 pay-limits profile. For
that profile, `agent-walletd` takes three extra flags:

- `-status-socket PATH`: the operator status socket. The only accepted PATH
  is the frozen `StatusSocketPath`, `/run/swarma-wallet-status/status.sock`
  (freeze amendment 1, A8); any other path refuses `STATUS_SOCKET_CONFIG`
  before the startup pass. Leave it empty to run without one.
- `-status-gid GID`: the operator group of that socket and of its directory.
  It is required with `-status-socket` and must differ from `socket_gid`. The
  agent account (`peer_uid`) must not be a member of it: startup refuses
  `STATUS_SOCKET_AGENT` otherwise, or when the agent's groups cannot be read.
- `-tick-seconds N`: the observation interval, 1 to 3600, default 30.

Without a `g2` block, the W2 behaviour is unchanged, and the two status flags
are refused with `SERVICE_ARGUMENTS`.

Before serving, a G2 service runs one observation pass, which covers the
canary, startup reconciliation, the tracker, the float and the seals. If that
pass fails, the service exits with status 2 and the bounded code. Two causes
need the operator:

- `STATE_RECONCILE_REQUIRED`: a hot-wallet send that no journal record
  carries.
- A spent canary: it poisons the service.

The hot wallet must start without sends: fund the float and the canary from
outside it. Alerts are single `PX1_ALERT` lines on stderr. See `STATUS.md`
for the pass, the tracker rules, the status projection and the socket.

### Status socket access (G2)

The status socket has its own runtime directory (freeze amendment 1, A8).
The agent-facing `/run/swarma-wallet` holds only `wallet.sock` and is the
only directory bound into an agent slot; the status directory is never bound.

| Directory | Mode | Owner | Group | Holds |
| --- | --- | --- | --- | --- |
| `/run/swarma-wallet` | 0750 | `swarma-wallet` | `swarma-wallet-peer` (`socket_gid`) | `wallet.sock` (0660) only |
| `/run/swarma-wallet-status` | 0750 | `swarma-wallet` | `swarma-wallet-status` (operator) | `status.sock` (0660) only |

Access is granted by group membership:

| Account | `swarma-wallet-peer` (`socket_gid`) | `swarma-wallet-status` (operator) | Reaches |
| --- | --- | --- | --- |
| service `swarma-wallet` | primary group | supplementary (unit) | owns both sockets |
| agent (`peer_uid`) | member | never | `wallet.sock` only |
| operator user | never | member | `status.sock` only |

The operator is never a member of `swarma-wallet-peer`: its only G2 group is
`swarma-wallet-status`. Deploy renders the groups and the directory; for
reference, the operator's lines and the status directory are:

```text
# sysusers.d
g swarma-wallet-status @OPERATOR_GID@
m @OPERATOR_USER@ swarma-wallet-status
# tmpfiles.d
d /run/swarma-wallet-status 0750 swarma-wallet swarma-wallet-status -
```

The agent's sysusers lines are `G2AgentSysusers` in `deploy`:
`u <agent_user> <agent_uid>` and `m <agent_user> swarma-wallet-peer`. No line
puts the agent into `swarma-wallet-status`.

The daemon keeps the operator group as a supplementary group, so that it can
give `status.sock` that group, and needs write access to the status
directory, because the W2 unit runs with `ProtectSystem=strict`. The source of
truth is the committed [G2 status drop-in template](../../deploy/templates/systemd/swarma-wallet-g2-status.conf.in),
shipped verbatim as `templates/systemd/swarma-wallet-g2-status.conf.in` in the
release and covered by its signed `SHA256SUMS`. After verifying the release,
substitute `@VERSION@` with the installed release version (the same value as
in `swarma-wallet.service.in`) and `@OPERATOR_GID@` with the numeric operator
GID. Refuse any remaining `@` placeholder. Install the resolved drop-in next
to the W2 unit as `swarma-wallet.service.d/g2-status.conf`; keep the empty
`ExecStart=` reset before the replacement command. The template bytes are:

```ini
[Service]
SupplementaryGroups=swarma-wallet swarma-wallet-status
ReadWritePaths=/run/swarma-wallet-status
ExecStart=
ExecStart=/opt/swarma/wallet/@VERSION@/bin/agent-walletd --config /etc/swarma/wallet/service.json -status-socket /run/swarma-wallet-status/status.sock -status-gid @OPERATOR_GID@
```

`@OPERATOR_GID@` is the numeric GID of `swarma-wallet-status`. Startup checks,
in order, before the socket is bound:

- `STATUS_SOCKET_CONFIG`: a path other than `StatusSocketPath`, the operator
  group equal to `socket_gid`, or an operator group of 0.
- `STATUS_SOCKET_AGENT`: the agent account is a member of the operator group,
  or its groups cannot be read.
- `STATUS_SOCKET_DIR`: the status directory is not a real directory reached
  without a symlink, mode 0750, owned by the service UID, with the operator
  group; or it is, contains, or lies inside the directory of `wallet.sock`.
  The daemon never creates or repairs it.
- `STATUS_SOCKET_EXISTS`: a file already exists at the socket path.
- `STATUS_SOCKET_MODE`: the socket cannot be given the operator group and
  mode 0660; without the supplementary group the chown fails.

The status listener also closes, without a reply, any connection whose
`SO_PEERCRED` UID is `peer_uid`. The agent is shut out by the directory's
group first; the agent-group refusal and the peer-UID refusal stay as
defence in depth.

`/run/swarma-wallet-status` comes from tmpfiles, so it is not removed when the
service stops. A clean stop unlinks `status.sock`; after a crash the stale
socket refuses the next start (`STATUS_SOCKET_EXISTS`). As for `wallet.sock`,
establish that the old process exited, then remove it by hand.

**Runbook: restart after a crash (G2).** The W2 rule holds for the status
socket: nothing unlinks a socket automatically, so the stale
`/run/swarma-wallet-status/status.sock` blocks every restart until the
operator removes it. As root on the executor host:

1. Confirm that the service has no live process: `systemctl status
   swarma-wallet.service` shows it inactive or failed, and
   `systemctl show -p MainPID --value swarma-wallet.service` prints `0`.
2. Confirm that the path is a socket owned by `swarma-wallet` with the
   operator group: `stat -c '%F %U %G %a' /run/swarma-wallet-status/status.sock`
   prints `socket swarma-wallet swarma-wallet-status 660`. Remove nothing else.
3. Remove it: `rm /run/swarma-wallet-status/status.sock`. (`wallet.sock`
   lives in the unit's `RuntimeDirectory=`, which systemd removes when the
   unit stops; if startup still refuses `SERVICE_SOCKET_EXISTS`, apply the
   same three checks to `/run/swarma-wallet/wallet.sock`.)
4. Start the service: `systemctl start swarma-wallet.service`. It runs its
   startup reconciliation and one observation pass before it serves; a spend
   before a successful pass refuses `SERVICE_STATE_UNAVAILABLE`.

PX2 candidate, not implemented: an `ExecStopPost=` line in the G2 drop-in that
removes `status.sock` after the main process has exited would make the restart
automatic. It changes the W2 "no automatic unlink" rule for this socket, so it
needs its own decision.

## Evidence boundaries and checks

Unit/race/vet checks use the README commands. Genuine Core socket suites are
TestCoreActionStanding, Oneoff, Refusals, OneoffBindings, Crash, FinalCheck,
Transport, Client, State, StateLimits, SealFunding, Rotation, Startup and
WireRefusals (each name has
the TestCoreAction prefix). Run each separately with a fresh W1_RUN_ROOT and
the README's exact Core pins. They exercise actual sockets and kernel credentials
under one UID using an unexported test constructor, not production startup.
There is no production same-UID/test-clock escape flag. They do not establish
that a different OS user cannot read files. Linux cross-compilation and unit
template checks are not OS custody or systemd enforcement evidence. Infra must
test actual denied reads of credential/journal/other-agent socket and a positive
own-agent request under separate UIDs before deployment. No users or services
are created by these tests.

The existing 25 W1 plants plus service-mutations.json exercise selected guards.
The runner copies all five sibling dependencies and requires the intended
compiled assertion failure; setup errors, skips, timeouts and crashes do not
count. Redundant lower-level private-file defenses are covered by direct tests,
not falsely claimed as killed by removal of only one of their checks. W1 names
remain legacy regression coverage; all name actions are unsupported over W2.
