# notary1 accounts and filesystem contract

Infra assigns numeric UIDs/GIDs from its **S8 accounts list** before executing
this pack. Do not guess numbers, reuse a login account, or use root for either
daemon. Check `getent passwd NAME`, `getent group NAME`, and `id NAME` against
S8; abort on a collision or unexpected supplementary membership.

| Account/group | Required contract |
| --- | --- |
| `namecoin-node` user and private primary group | System account, locked password, `/usr/sbin/nologin`, home field `/var/lib/namecoind-regtest`; no created home beyond that state directory. |
| `notary-service` user and private primary group | System account, locked password, `/usr/sbin/nologin`, home field `/var/lib/notary-service`; no created home beyond that state directory. |
| `namecoin-cookie` group | Only the node and service users. Node unit runs with this effective group; service unit adds it as a supplementary group. It grants cookie read access, not write access or node-state access. |

Infra's account tool must create the accounts with the S8 numeric assignments,
without a login home, shell access, extra groups, or user services. Verify the
password is locked using the account tool's status query; never read a hash.

| Path | Owner:group | Mode | Purpose |
| --- | --- | --- | --- |
| `/opt/notary-service`, `/opt/notary-service/v0.1.1` | `root:root` | 0755 | Root-controlled release directory chain. |
| `/opt/notary-service/v0.1.1/notary-service` | `root:root` | 0755 | Verified release executable. |
| `/opt/namecoin`, `/opt/namecoin/28.0`, `/opt/namecoin/28.0/bin` | `root:root` | 0755 | Infra's pinned Guix Core release. |
| `/opt/namecoin/28.0/bin/namecoind`, `/opt/namecoin/28.0/bin/namecoin-cli` | `root:root` | 0755 | Independently verified Core executables. |
| `/etc/namecoin`, `/etc/notary-service` | `root:root` | 0755 | Read-only configuration directories. |
| `/etc/namecoin/notary1-regtest.conf` | `root:root` | 0644 | Empty configuration; all node options are in the unit. |
| `/etc/notary-service/service.json`, `/etc/notary-service/deployment-policy.json` | `root:root` | 0644 | Public configuration and strict D8 laboratory policy. |
| `/var/lib/namecoind-regtest` | `namecoin-node:namecoin-node` | 0700 | Node state only; never grant cookie-group traversal. |
| `/var/lib/notary-service`, `/var/lib/notary-service/private` | `notary-service:notary-service` | 0700 | Service state and exclusive key generation directory. |
| `/var/lib/notary-service/private/attestation.key` | `notary-service:notary-service` | 0600 | Created only by service-user keygen on this VM. |
| `/run/namecoind-regtest` | `namecoin-node:namecoin-cookie` | 0750 | systemd-created node runtime directory. |
| `/run/namecoind-regtest/.cookie` | `namecoin-node:namecoin-cookie` | 0640 | Core-created cookie (`-rpccookieperms=group`). |
| `/run/notary-service` | `notary-service:notary-service` | 0700 | systemd-created service runtime directory. |
| `/run/notary-service/rpc.cookie` | `notary-service:notary-service` | 0600 | Private copy made at each service start. |
| `/etc/systemd/system/namecoind-regtest.service`, `/etc/systemd/system/notary-service.service` | `root:root` | 0644 | Reviewed units, no local drop-ins. |
| `/var/lib/notary1-install` | `root:root` | 0700 | Local receipt and checks; never publish. |
| `/var/lib/notary1-install/receipt.md` | `root:root` | 0600 | The **only operator record** of the public key; the authorized private-regtest name value necessarily carries it too. |
| `/etc/systemd/system/namecoind-regtest.service.d` | `root:root` | 0755 | Temporary commissioning override directory; no unknown drop-ins. |
| `/etc/systemd/system/namecoind-regtest.service.d/commissioning.conf` | `root:root` | 0644 | Exact reviewed wallet-enabled command, removed before enablement and on execution rollback. |
| `/var/lib/notary1-install/smoke-policy.json`, `smoke-request.json`, `smoke-address.json`, `certify.started` | `root:root` | 0600 | Protected smoke artifacts and one-shot marker; no service key, response or cookie bytes. |

All parent components must be real directories without symlink redirection or
non-root write access, except the explicitly service-owned state/runtime leaves.
Inspect `namei -l`, `stat`, and effective ACLs (`getfacl -p`) before use. Abort
on unexpected ACL write/read authority, old files, or ownership/mode drift.

The service loader demands a regular credential owned by its UID with mode
**exactly 0600**. Neither a group-readable node cookie nor systemd's read-only
0400 credential directly satisfies that contract. `ExecStartPre=install`
copies the Core cookie as the service UID into its private runtime directory;
no privileged pre-start helper, credentials in argv, or relaxed loader is used.
The group holds full node RPC authority: it is a trusted service group, not a
read-only RPC capability. Restart the notary after any cookie rotation; the
units propagate an explicit node restart with `PartOf=`. No automatic restart
is configured. Confirm the actual cookie owner/mode on the pinned target.

The target-only smoke temporarily creates wallet `notary1-smoke` within the
node's private state using the reviewed commissioning override. Mining/name
control keys are generated by Core on the target, never supplied by this pack,
printed, copied to receipts, or exported. Disable RPC/debug/console logging
during commissioning so name-value RPCs are not extra public-key records.
The absent-binding control writes `{}` only to this VM's private regtest name;
the helper restores the correct binding without another certification. The
public key may not be recorded in separate files, responses, logs or evidence.
Default KEEP rollback preserves the wallet, both historical name values and
the retained signing key; deletion requires the separately authorized scope.

No separate persistent journal/state-path config field exists in v0.1.1.
The only persistent notary state here is its private key. Durable admission,
anti-equivocation and gateway integration remain outside this pack.
