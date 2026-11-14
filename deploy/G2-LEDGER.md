# G2 attempt ledger

`deploy-kit g2-ledger` is a Linux attempt journal and conservative rollback
engine. Use the binary from the verified signed release. The install shell
orchestrates steps and stops on any nonzero result; it does not fingerprint
objects after unrelated creators or implement its own rollback deletion lists.

## Interface

All paths must be absolute, clean and free of symlinks in every component.
The installation runs as root. The library also permits an effective user's
private fixture directory, allowing real filesystem tests without root.
Account and systemd mutations in `RealSystem` require root.

```text
deploy-kit g2-ledger init -dir D -manifest M -baseline S0
deploy-kit g2-ledger verify -dir D
deploy-kit g2-ledger create-dir -dir D -path P -owner U -group G -mode 0755 -ret R
deploy-kit g2-ledger create-file -dir D -path P -src S -owner U -group G -mode 0640 -ret R [-secret]
deploy-kit g2-ledger exec-create -dir D -kind secret -ret R -path P -- TOOL ARGS
deploy-kit g2-ledger modify-file -dir D -path P -backup B -new N
deploy-kit g2-ledger create-group -dir D -name NAME -gid GID -ret R
deploy-kit g2-ledger create-user -dir D -name NAME -uid UID -gid GID -ret R
deploy-kit g2-ledger add-member -dir D -user USER -group GROUP
deploy-kit g2-ledger enable -dir D -unit NAME.service
deploy-kit g2-ledger replay -dir D -mode station|station-remove|rehearsal
```

`U` and `G` are account names or decimal IDs. `R` is exactly `d6`, `state` or
`remove`. Accounts require explicit numeric IDs. Users are created without a
home, private group or login shell (`/usr/sbin/nologin`). Membership creation
executes `usermod -aG` itself. Unit enablement requires an initially disabled
unit and executes `systemctl enable` itself. Existing objects, accounts,
memberships and enables are refused; there is no post-hoc `add`, `adopt` or
`rehash` operation. An S0 absence observation grants no creation authority.

Before `init`, the caller verifies the release signature and checksums.
`init` additionally calls the existing `deploy.ValidateManifest` inventory
validator. It takes no H12 or release-digest override: the full commit and its
first twelve characters come from the manifest, and both `manifest_sha256`
and `release_sha` are SHA-256 of the exact supplied manifest bytes. It records
the S0 directory and a sorted digest of its directory metadata and regular-file
metadata/content digests. S0 must contain a nonempty `taken-at.txt` and an empty
`errors.txt`; symlinks and special files refuse initialization. The S0 digest
is a creation-time binding, not a promise to rehash the entire baseline on
subsequent verification. Each restore independently checks its backup digest.

`init` exclusively creates D with mode 0700. An existing D, including an
incomplete attempt, refuses. `LOCK`, `records.jsonl` and `HEAD` are private
0600 owner files. Never recreate or edit these to make a failed attempt pass.
The journal and baseline cannot themselves be mutation targets.

### Exclusive external creators

A process exiting zero does not establish that it created a particular file.
This implementation admits only the **same deploy-kit executable** running its
audited `g2-keygen` or `g2-rpcauth` subcommand. Both write secrets, so `-kind
secret` is required. Their exact output flag must name the sole declared path:

```sh
"$KIT" g2-ledger exec-create -dir "$LEDGER" -kind secret -ret d6 -path "$KEY" \
  -- "$KIT" g2-keygen -out "$KEY"

"$KIT" g2-ledger exec-create -dir "$LEDGER" -kind secret -ret d6 -path "$CONFIG" \
  -- "$KIT" g2-rpcauth -params "$PARAMS" -wallet-public "$PUBLIC" \
  -wallet-config-out "$CONFIG"
```

`g2-keygen -out` and `g2-rpcauth -wallet-config-out` both reach
`g2NewSecretFile` in `cmd/deploy-kit/g2_keygen.go`, which opens with
`O_CREAT|O_EXCL|O_NOFOLLOW`. The RPC command has no `-out` alias.
The wrapper snapshots the declared output parent, persists intent, invokes the
exclusive creator, and checks the exact declared output and the parent inventory
before committing its observed identity. Missing outputs, new or changed
undeclared siblings, and tool failures are named preserved orphans (exit 3).
Only committed public stdout is forwarded; no child stderr is echoed.

The parser accepts repeated `-path` arguments and the schema supports multiple
identities. The two admitted tools each have one output, so multiple paths,
`-kind file`, arbitrary executables, no-op wrappers and installer scripts are
currently refused **before execution**. A future external publisher needs an
audited exclusive creation contract or per-object creator receipts before it
can be added. No whole-filesystem inventory or arbitrary-process provenance
claim is made. This is a deliberate boundary of the current `exec-create` slice.

## Record schema and durability

The version-1 wire format is newline-delimited canonical Go JSON. Each record:

```text
{seq, prev, body, hash}
hash = SHA256(canonical JSON of {seq, prev, body})
```

Sequence starts at zero. Genesis uses a 64-zero `prev`; later records name the
previous record hash. The body is a discriminated union:

| `op` | Exact payload | Meaning |
| --- | --- | --- |
| `genesis` | `genesis` | Version, random 128-bit attempt ID, manifest/release SHA-256, full commit, H12, S0 path and digest |
| `intent` | `action` | Kind, retention, targets, requested IDs/mode, and applicable before identities and backup/new hashes |
| `commit` | `result` | Intent sequence and the exact ordered observed identities |
| `abort` | `result` | Intent sequence and `exclusive-refused`; the exclusive call proved it did not create the object |

Exactly one intent may be outstanding. A commit or abort must resolve that
intent; a standalone result, duplicate completed `(path, kind)` creation,
renumbered duplicate or reordered result is invalid. Unknown ops, kinds,
retentions and fields are errors. There are no wildcard identities.
`DisallowUnknownFields` plus canonical byte comparison rejects duplicate keys,
case aliases, omitted required zero fields, null payloads and trailing values.
Only the exact expected fields may appear in each action and identity variant.

| Kind | Required identity |
| --- | --- |
| `dir` | Path, device, inode, type, permission mode, uid, gid; zero size/time fields |
| `file`, `modify` | Path, device, inode, regular-file type, mode, uid, gid, size, nanosecond mtime, SHA-256 |
| `secret` | Same filesystem metadata, without a content digest; identity reads never read secret content |
| `user` | Name, uid **and primary gid**, nologin shell |
| `group` | Name, gid; explicit uid=0 and shell="" are structural fields, not a user identity |
| `membership` | Full user and group identities plus membership state |
| `unit` | Unit name and enablement state |

UID/GID `4294967295` is rejected as a syscall wildcard; UID/GID zero remains
an explicit valid root identity. Hardlinked regular files, special file types
and setuid/setgid files refuse. Directories use descriptor operations and their
mutable size/mtime are excluded from identity.

Every append checks the actual write count (a short or zero write fails), fsyncs
the record file, and fsyncs its directory when first creating it. Then it writes
`HEAD = {count, hash}` through an `O_EXCL` temporary file, fsyncs, renames it and
fsyncs the directory. `HEAD` must match the count and last record hash, including
for a valid-prefix truncation. An exclusive nonblocking flock spans validation,
the creator and commit, or the entire replay. Verification opens the existing
lock read-only and creates nothing.

No mutation syscall/tool runs before its intent and HEAD are durable. File
creation uses exclusive no-follow open; directory creation uses `mkdirat`.
Ownership and mode changes use the open descriptor. Files and parent directories
are synced before commit. A failed or interrupted commit never grants rollback
authority; it reports the affected path/account as an orphan. A partial record
or a record/HEAD crash window fails verification and requires inspection.
There is no automatic truncation, orphan adoption or guessed cleanup.

The envelope separates operation kinds from phases. A later `create-tree` kind
can add typed action/identity fields within version 1; older engines refuse the
unknown kind. This PR implements no tree traversal/deletion authority.

## Replay and retention

Replay validates the **whole** journal and HEAD before any effect. It then visits
committed operations newest first. Every lookup distinguishes matching presence,
absence and error. The first error or mismatch stops immediately, preserving all
older operations. Already completed newer reversals are not rolled back again
as a transaction. Missing created objects are harmless; operational lookup
failures never mean absence. Retained objects must still match their identity.

| Retention | `station` | `station-remove` | `rehearsal` |
| --- | --- | --- | --- |
| `d6` | Keep | Keep | Keep |
| `state`, newly created filesystem/accounts | Keep | Keep | Keep |
| `remove` | Remove matching objects | Remove matching objects | Remove matching objects |
| Modified file / unit state | Restore | Restore | Restore |

This implements the explicit “d6 never deleted” requirement. It intentionally
does not inherit the retired shell plan's deletion of d6 objects in
`station-remove` or `rehearsal`. There is no key/wallet-data deletion confirmation
string and no secure-erasure claim. Do not use these modes as authority to
destroy retained data. Changing this retention policy needs a separately
reviewed contract.

Directories are removed only by `unlinkat(..., AT_REMOVEDIR)` when empty. A
foreign child stops replay. Regular files are unlinked only after the full
identity matches. Parent traversal uses `openat` with `O_NOFOLLOW`; removal and
rename use the held directory descriptor. Symlinks are never followed.

`modify-file` requires live content to equal the S0 backup, then installs staged
bytes through an exclusive temp and rename, preserving original uid/gid/mode.
Replay restores only a fully matching committed new identity and new hash, from
a still-matching backup. A retry accepts already-restored old content with exact
old metadata without writing. Foreign edits or replacements stop.

Unit lookups accept only `enabled`/status 0 and `disabled`/status 1 from
`systemctl is-enabled`. Empty output, unexpected statuses (including 73/127),
masked, runtime, static, missing and all other states stop. An enable operation
undoes only its own disabled-to-enabled transition. Membership reversal requires
both user and group identities to match before `gpasswd -d`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Successful operation or fully validated replay |
| 1 | Refused or stopped, with a named stderr reason; invalid journal touches no replay targets |
| 2 | Usage or internal failure |
| 3 | Named unresolved intent/orphan; keep the object for inspection |

`verify` also returns 3 for a structurally valid unresolved intent. It reports
parse/chain/HEAD errors as 1. A tool-created orphan outside the declared parent
inventory is not automatically discoverable; admitted creators have no such
outputs. Secret contents, tool arguments and child stderr are never included in
journal records or diagnostics.

## Install call sites

| Plan stage | Thin-shell engine call |
| --- | --- |
| B, after verified release and S0 | `init -manifest ... -baseline ...` |
| S1 | Four `create-dir` calls and `create-file` for the probe |
| S2 | One `exec-create ... -- "$KIT" g2-keygen ...` for each key |
| S4.3 | `modify-file -path ... -backup ... -new ...` |
| S5 | `exec-create ... -- "$KIT" g2-rpcauth ... -wallet-config-out ...` |
| S7 | `create-file` for tmpfiles config, service config, manifest, signature, install drop-in, binary, unit and status drop-in; `create-dir` for drop-in and executable directories |
| Accounts and private runtime directories | `create-group`, `create-user`, `add-member`, `create-dir`; no post-hoc registration of sysusers/tmpfiles outputs |
| S8 | `enable -unit ...` |
| S9 | `create-user` with explicit IDs; `create-dir` / `create-file` for helper and staging paths; external installer publication still requires a creator-receipt integration |
| Rollback | `replay -mode ...`; stop the shell on the first nonzero result |

`g2-host-flow -ledger`, `create-tree`, and ephemeral install signing are separate
integrations. Existing subcommands retain their interfaces and behavior.
Service stopping, process inspection, node readiness, native ownership and
installed adoption remain external orchestration/qualification responsibilities.
No failed inspection licenses continued shell cleanup.

## Threat model and validation

The production boundary is a root-owned 0700 directory and 0600 files. Hash chain
and independently updated HEAD detect accidental edits, foreign unprivileged
writers, ordering errors, crashes and truncation. **A root writer can rewrite
both the records and HEAD.** This is not protection from malicious root, a
hostile same-owner writer or arbitrary concurrent privileged namespace/account
mutation. Descriptor anchoring prevents symlink traversal; it does not make a
pathname compare-and-unlink or NSS compare-and-delete a kernel transaction.
Keep privileged mutation serialized, use protected parents, and inspect failures.
No hardware power-loss test or native root/systemd qualification is claimed.

Tests use real temporary files and separate real competing processes. `System`
fakes only privileged command results and chown behavior, with real EEXIST,
missing-account, ID-collision, live-user and primary-group refusal semantics.
The command contracts come from [useradd(8)](https://man7.org/linux/man-pages/man8/useradd.8.html),
[groupadd(8)](https://man7.org/linux/man-pages/man8/groupadd.8.html),
[usermod(8)](https://man7.org/linux/man-pages/man8/usermod.8.html),
[getent(1)](https://man7.org/linux/man-pages/man1/getent.1.html),
[userdel(8)](https://man7.org/linux/man-pages/man8/userdel.8.html),
[groupdel(8)](https://man7.org/linux/man-pages/man8/groupdel.8.html),
[gpasswd(1)](https://man7.org/linux/man-pages/man1/gpasswd.1.html), and
[systemctl(1)](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).
In particular useradd/groupadd refuse ID-in-use (4) and name-in-use (9); only
getent exit 2 with empty output is absence. Other failures stop or leave an
orphan. Fakes never invoke real account/systemd mutations.

```sh
cd deploy
go test -race ./g2ledger ./cmd/deploy-kit -run '^TestLedger' -count=1
go vet ./...
go test -race ./...
go build -trimpath -o /tmp/deploy-kit ./cmd/deploy-kit
```

`testdata/release-manifest.json` is a public schema fixture with synthetic hashes,
not a signed or deployable release. The tests' one-line claim comments specify
the scope and limits of the cross-check witnesses and positive neighbours.
