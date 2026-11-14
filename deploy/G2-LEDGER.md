# G2 attempt ledger

`deploy-kit g2-ledger` is a Linux attempt journal and conservative rollback
engine. Use the binary from the verified signed release. The install shell
orchestrates steps and stops on any nonzero result; it does not fingerprint
objects after unrelated creators or implement its own rollback deletion lists.

## Interface

All paths must be absolute, clean and free of symlinks in every component.
The installation runs as root. The library also permits an effective user's
private fixture directory, allowing real filesystem tests without root.
Account and systemd mutations in `RealSystem` require root. Local tests use a
fake account/systemd boundary and never invoke those real mutations.

```text
deploy-kit g2-ledger init -dir D -manifest M -baseline S0 -purpose station|rehearsal -scope SCOPE.json
deploy-kit g2-ledger verify -dir D
deploy-kit g2-ledger create-tree -dir D -path P -owner NAME -mode 0700 -ret R [-socket RELATIVE_PATH ...]
deploy-kit g2-ledger create-dir -dir D -path P -owner U -group G -mode 0755 -ret R
deploy-kit g2-ledger create-file -dir D -path P -src S -owner U -group G -mode 0640 -ret R [-secret]
deploy-kit g2-ledger exec-create -dir D -kind secret -ret R -path P -- TOOL ARGS
deploy-kit g2-ledger modify-file -dir D -path P -backup B -new N
deploy-kit g2-ledger create-group -dir D -name NAME -gid GID -ret R
deploy-kit g2-ledger create-user -role ROLE -dir D -name NAME -uid UID -gid GID -home H -gecos G -shell /usr/sbin/nologin -ret R
deploy-kit g2-ledger add-member -dir D -user USER -group GROUP
deploy-kit g2-ledger enable -dir D -unit NAME.service
deploy-kit g2-ledger replay -dir D -mode station|rehearsal
```

`U` and `G` are account names or decimal IDs. `R` is exactly `d6`, `state`, `remove` or
`rehearsal`. Accounts require explicit numeric IDs. Users are created without a
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
`errors.txt`; symlinks and special files refuse initialization. The S0 evidence
directory digest is a creation-time binding, not a promise to rehash that evidence directory on
subsequent verification. Each restore independently checks its backup digest.
Separately, `init` snapshots the declared live comparison scopes into genesis,
so final comparison never reconstructs S0 from later observations.

`-purpose` defaults to `station`; pass `-purpose rehearsal` for a rehearsal
attempt. Genesis binds this purpose. `replay -mode rehearsal` refuses a station
ledger, and either station mode refuses a rehearsal ledger, with exit 1 and
`MODE_PURPOSE_MISMATCH` before target lookup or effects. Retention `rehearsal`
is refused at creation time on a station ledger with
`REHEARSAL_RETENTION_REQUIRES_REHEARSAL_PURPOSE`; journal validation enforces the
same constraint before replay. These fields and S0 scopes are required in newly
written genesis records. Earlier ledgers lacking them fail closed; there is no
in-place upgrade or inferred purpose.

### Declare S0 comparison scopes

`-scope` is a required absolute path to a JSON object, for example:

```json
{
  "paths": [
    {"path":"/var/lib/swarma-rehearsal/regtest","kind":"dir"},
    {"path":"/var/lib/swarma-rehearsal/regtest/probe","kind":"file"},
    {"path":"/var/lib/swarma-rehearsal/key","kind":"secret"},
    {"path":"/etc/systemd/system/swarma-rehearsal.service","kind":"file"}
  ],
  "users": ["swarma_rehearsal"],
  "groups": ["swarma_rehearsal"],
  "units": ["swarma-rehearsal.service"]
}
```

Declare every intended mutation path with its kind (`dir`, `tree`, `file`, `secret`),
every created account, both subjects of every membership, and every enabled
unit **before init**. Config modification requires a `file` scope. Missing
objects and missing parents are captured as absent. Present objects are
observed without adoption; their S0 presence never permits creation over them.
Initialization reads these objects but makes no account or unit changes.
The strict JSON decoder refuses duplicate, escaped, aliased and unknown keys;
duplicate scope targets also refuse. Unknown kinds, unsupported identities,
symlinks in target/parent traversal and operational lookup failures refuse init.
Mutation targets outside the declared scope refuse with
`TARGET_OUTSIDE_INIT_SCOPE` before durable intent or effects. Declaring a
ordinary `dir` grants no authority over unnamed children. A `tree` scope is
the explicit exception described below; it cannot overlap any declared child
target or another tree.

Scopes include immediate parents, with directory mode (including sticky bits),
uid, gid, device and inode, and a **shallow** inventory of child names and types.
Public `file` targets include metadata and content digests; `secret` targets
include metadata only, never content or digests. Account identities include
name, uid, primary gid, shell, home and GECOS; groups include their full explicit member
lists. Unit scope includes enablement state, including a proven
`not-found`/status 4 absence at init. Ledger and S0 evidence directory paths are
excluded from parent inventories by exact pathname; neither may be a mutation
target. The JSON scope input is recorded as typed data in genesis and need not
be reopened at replay.

`init` exclusively creates D with mode 0700. An existing D, including an
incomplete attempt, refuses. `LOCK`, `records.jsonl`, `HEAD` and the temporary `UNSEALED` guard are private
0600 owner files. Never recreate or edit these to make a failed attempt pass.
The journal and baseline cannot themselves be mutation targets.

### Volatile runtime objects belong to tmpfiles

`/run`, every `/run/...` target, `/var/run` and its descendants, and any path
resolving under `/run` are forbidden in `init -scope` and every filesystem
`create-*` call (including `create-tree` and `exec-create`). The named refusal
is `VOLATILE_RUNTIME_OBJECT_TMPFILES`: this is a volatile runtime object owned
by tmpfiles. Existing symlink aliases and dangling links into `/run` also
refuse before intent or creation. Protected parents and serialized privileged
writers remain required to prevent namespace races.

Record the persistent tmpfiles configuration **file** with `create-file`, then
let tmpfiles own creation/lifetime of the runtime directories and sockets.
Persistent `/var/lib/...` targets remain eligible. Account `-home` is passwd
metadata only and creates no directory. No runtime socket/directory is adopted
into the ledger. Baseline parent inventories exclude runtime paths and aliases;
the baseline comparison summary explicitly lists `"excluded_volatile":["/run"]`
and stderr includes `excluded_volatile=/run`. This exclusion is not a claim to
compare volatile contents or whole-host equivalence.

### Exclusive external creators

A process exiting zero does not establish that it created a particular file.
This implementation admits only the **same deploy-kit executable** running its
audited `g2-keygen` or `g2-rpcauth` subcommand. Both write secrets, so `-kind
secret` is required. Their exact output flag must name the sole declared path:

```sh
"$KIT" g2-ledger exec-create -dir "$LEDGER" -kind secret -ret d6 -path "$KEY" \
  -- "$KIT" g2-keygen -out "$KEY" -owner "$OWNER" -group "$GROUP"

"$KIT" g2-ledger exec-create -dir "$LEDGER" -kind secret -ret d6 -path "$CONFIG" \
  -- "$KIT" g2-rpcauth -params "$PARAMS" -wallet-public "$PUBLIC" \
  -wallet-config-out "$CONFIG" -owner "$OWNER" -group "$GROUP"
```

`g2-keygen -out` and `g2-rpcauth -wallet-config-out` both reach
`g2NewOwnedSecretFile` in `cmd/deploy-kit/g2_keygen.go`, which opens with
`O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC` at mode `0600`. Optional `-owner U`
and `-group G` accept names or canonical decimal IDs (no sign/leading zeroes
except `0`, no all-ones syscall sentinel). Both specified fields must resolve
before the open; unknown names and lookup errors refuse without output. On the
created descriptor, `fchown` precedes `fchmod` to the final mode, then the
count-checked content write and file/parent sync. Failed metadata calls remove
only the observed original inode before any secret content is written. Absent
ownership flags preserve creation ownership. The key mode is `0600` by default
or `0640` with `-mode`; wallet configuration mode stays `0640`. The RPC command
has neither an `-out` alias nor a `-mode` option.

The creator audit accepts exactly these two additional ownership flags with
validated values, including `-flag=value` and `--flag` forms; duplicate flags,
unknown flags, and invalid owner/group values are refused before intent. The
intent records resolved uid/gid and final mode; the commit checks and records
the actual produced identity, and replay compares that identity. **No chown
after exec-create**: later ownership changes invalidate its committed identity.
Generate directly into the final path, never into a plaintext staging copy.
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
| `genesis` | `genesis` | Version, purpose, declared scope, typed live S0 snapshot, random 128-bit attempt ID, manifest/release SHA-256, full commit, H12, S0 evidence path and digest |
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
| `dir`, `tree` | Path, device, inode, type, permission mode, uid, gid; zero size/time fields |
| `file`, `modify` | Path, device, inode, regular-file type, mode, uid, gid, size, nanosecond mtime, SHA-256 |
| `secret` | Same filesystem metadata, without a content digest; identity reads never read secret content |
| `user` | Name, uid **and primary gid**, nologin shell, home and GECOS description |
| `group` | Name, gid; explicit uid=0 and shell="" are structural fields, not a user identity |
| `membership` | Full user and group identities plus membership state |
| `unit` | Unit name, enablement state and exact created symlink path/target/dev/ino/uid/gid/mode set |

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

The envelope separates operation kinds from phases. `tree` adds a dedicated
owner identity and an optional sorted list of named socket paths to its intent.
The loader requires a matching earlier committed user creation in this same
ledger. Older engines refuse the new kind.

## Replay and retention

Replay validates the **whole** journal and HEAD before any effect. It then visits
committed operations newest first. Every lookup distinguishes matching presence,
absence and error. The first error or mismatch stops immediately, preserving all
older operations. Already completed newer reversals are not rolled back again
as a transaction. Missing created objects are harmless; operational lookup
failures never mean absence. Retained objects must still match their identity.

The following is the single CONFIRMED v1 policy table, approved by the plan
owner. The only replay modes are `station` and `rehearsal`. Any other mode is
rejected with `USAGE_REPLAY` (exit 2) before opening or reading the ledger.
Implementation rules live in
`g2ledger/policy.go` (`retentionPolicy`). Every removal still requires exact
identity, including both uid and primary gid for users and gid for groups.

| Object / retention | `station` | `rehearsal` |
| --- | --- | --- |
| Any `d6` creation, including keys/wallet data | Keep (`retain-d6`) | Keep (`retain-d6`) |
| `state` user/group/secret/tree creation (including exec-create outputs) | Keep (`retain-station-protected`) | Remove (`remove-rehearsal-state`) |
| `state` ordinary files/dirs | Keep (`retain-station-state`) | Remove (`remove-rehearsal-state`) |
| `remove` user/group/secret/tree creation (including exec-create outputs) | Refuse at creation and journal load (`STATION_PROTECTED_RETENTION`, exit 1, named target) | Remove (`remove-exact-identity`) |
| `remove` ordinary file/dir creation | Remove (`remove-exact-identity`) | Remove (`remove-exact-identity`) |
| Explicit `rehearsal` creation | Refused at creation and journal validation | Remove (`remove-explicit-rehearsal-object`) |
| Config modification, own membership addition, own unit enable | Restore (`restore-attempt-transition`) | Restore (`restore-attempt-transition`) |

Station protected kinds are precisely `user`, `group`, `secret`, and `tree`. All
exec-create outputs must be `secret`, so they share key protection. Station
never deletes these created accounts or keys, regardless of retention labels.
An incompatible `remove` request refuses before any effect or intent; a forged
or legacy journal containing it stops validation/replay before any undo.
Membership is a modification rather than account creation: replay removes only
the attempt-added membership after checking both subjects, preserving both
accounts. Ordinary state directories remain; exact `remove` files/dirs undo.
Journal and S0 evidence are never deletion targets. A rehearsal-only key or wallet artifact
must be explicitly created with `-ret rehearsal`; d6 never becomes deletable
because of mode. There is no engine mode for deleting d6 data or station keys.
Removal after an install requires a separate reviewed procedure. There is no
secure-erasure claim.

Rehearsal first checks **all** present committed identities before any removal;
a changed gid or replaced directory preserves both older and newer entries.
Already reversed absence/config/unit/membership states allow retry. It also
refuses foreign explicit members before deleting a created group. Reverse order
removes recorded memberships before the created accounts they depend on, and
removes only the recorded enable symlinks before removing its recorded unit files.
Unit files are ordinary `create-file` records, so they need `state`, `remove`
or `rehearsal` retention to be removed in rehearsal. Regtest and fixture process-written output uses the explicit `create-tree`
contract below; ordinary directories/files require individual
`create-dir`/`create-file` records. A directory still containing anything after recorded child reversals
stops with `DIRECTORY_NOT_EMPTY <child-path>`; nothing is recursively deleted.
Use d6 for a directory that must remain to hold retained d6 children.

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
undoes only its own disabled-to-enabled transition. A replay retry accepts a
missing unit only when init proved it absent; an existing S0 unit still requires
the strict enabled/disabled lookup contract. Membership reversal requires
both user and group identities to match before `gpasswd -d`.

### Final baseline comparison

Every replay that reaches the end of reversal compares live state with init's
S0. It examines every target declared in genesis, the immediate parent of each
declared filesystem target, and the complete explicit member lists of declared
groups. This includes unused declared targets and exclusive creation refusals.
No late scope expansion or post-hoc S0 capture is permitted.

The compared properties are precisely the identities and shallow directory
inventories described above. Each identity difference, child-name/type delta,
and explicit group-member delta is a separate JSON line on stdout. A difference
is accepted only with a real committed record, retention class, and the mode's
policy rule. A retained directory does not explain foreign children. Missing,
changed or extra members have no blanket group retention exception. A config
restore may change inode/mtime because it uses atomic replacement; only exact
S0 before-identity plus restored S0 content, size, uid/gid and mode authorizes
that difference. Its rule is
`restore-attempt-transition-replacement-inode-or-mtime`.

Synthetic output examples (sequence is the **commit** record's sequence):

```jsonl
{"type":"retained","object":"path:/var/lib/swarma-rehearsal/key","difference":"identity","mode":"rehearsal","seq":2,"retention":"d6","rule":"retain-d6"}
{"type":"unlisted_difference","object":"group:swarma_rehearsal/member:foreign","difference":"group-member","mode":"station","rule":"unrecorded-group-membership"}
{"excluded_volatile":["/run"],"type":"baseline_summary","mode":"station","compared":5,"retained":2,"unlisted":1}
```

`object` is `path:<absolute-path>`, `user:<name>`, `group:<name>` or
`unit:<name>`, with `/member:<name>` for a group-member difference.
`difference` is `identity`, `directory-entry` or `group-member`. A kept file may
have both an identity row and a parent directory-entry row; counts are
**differences**, not distinct objects. The summary JSON line is always emitted
even when no differences exist. Stderr also reports
`FINAL_BASELINE_COMPARE mode=... retained=N unlisted=N`.
All unlisted differences are emitted before exit 1 with
`UNLISTED_DIFFERENCE <first-object>`. Lookup/output failures also stop with a
named reason and exit 1. Final comparison detects drift; it never authorizes
additional cleanup or undoes earlier successful reversals.

Out of scope: recursive contents of unrecorded subdirectories, unrecorded
siblings' contents/metadata beyond their names and types, secret contents,
mutable directory size/timestamps, access/change timestamps, account fields
other than the recorded identity, memberships of unrecorded groups, active/running unit state,
open descriptors, mounts outside a removable tree, ACLs/xattrs, remote services, release verification,
and whole-host equivalence. Parent inventories are not recursive traversal.
Native privileged qualification remains separate work.

## Process-written rehearsal trees

Use `create-tree` only for an empty regtest datadir or fixture output root
whose later contents are written by its dedicated workload. Declare the path
as `kind: "tree"` at init, plus the owner user and its primary group. First
create the group if needed, then create the dedicated user through this same
ledger, then create the tree. Start the workload only after `create-tree`
returns success. A pre-existing account, including a service account, grants
no tree authority. A Core executable prefix or other binary install tree
requires **per-file `create-file` records**, never `create-tree`.

For example, with these targets already declared in a rehearsal scope:

```sh
deploy-kit g2-ledger create-group -dir "$LEDGER" -name rehearsal-data -gid 230302 -ret rehearsal
deploy-kit g2-ledger create-user -role tree-owner -dir "$LEDGER" -name rehearsal-runner -uid 230301 -gid 230302 -ret rehearsal
deploy-kit g2-ledger create-tree -dir "$LEDGER" -path "$REGTEST_DIR" -owner rehearsal-runner -mode 0700 -ret rehearsal
deploy-kit g2-ledger create-tree -dir "$LEDGER" -path "$FIXTURE_OUT" -owner rehearsal-runner -mode 0700 -ret rehearsal
```

The owner and its primary GID may never be 0, 1000, 210001, 210101, 210201, 210301, or the
syscall wildcard. Both creator validation and full journal loading enforce
this. The owner has a nologin shell and must be dedicated to this attempt's
trees. Recorded ordinary file/directory ownership and supplementary roles
cannot be mixed with that tree owner, in either order. This checks the
attempt's records; the operator must keep the account out of unrelated roles
and directory ownership outside the declared attempt. A pre-existing tree
root is exclusively refused, never adopted. Intent is durable before mkdir;
root descriptor identity is committed after ownership, mode and real root and
parent fsyncs. The ledger writes no workload contents.

A station ledger refuses `remove` retention for trees and refuses rehearsal
retention. It keeps state/d6 trees, with each immediate content-name difference
reported under the retained tree's policy reason in the final comparison.
`d6` stays retained in rehearsal too. Only a rehearsal-purpose ledger in
rehearsal mode can remove a tree. Its owner cannot be removed while any of its
recorded trees remains, including a retained tree. Same-name primary groups
must satisfy the [paired account removal rule](#account-removal-effect-boundary)
below; the recorded tree-owner role remains checked before account removal.

Removal is two phases, under the existing attempt lock:

1. Check the current owner against its creation receipt. Enumerate `/proc`
   processes and threads and parse all real, effective and saved UIDs. A live
   owner, unreadable status (including a PID that exits during the scan),
   unreadable task directory, malformed/missing UID data or any lookup error
   stops the pass. The caller stops services/processes first; the ledger never
   kills them. A fresh checked retry is permitted after a transient refusal.
2. Walk the entire tree with `openat(O_NOFOLLOW|O_DIRECTORY)` and
   `fstatat(AT_SYMLINK_NOFOLLOW)`. Pin every directory descriptor and record
   an in-memory postorder deletion list with stat identity, mount ID and exact
   child names. All entries must have the owner's UID and the root's device
   and mount ID. `statx` mount IDs also reject same-device bind mounts inside
   the tree; unavailable mount-ID support refuses. Any setuid/setgid bit,
   device, FIFO, unlisted socket or regular file with `nlink != 1` stops before
   deletion. Descriptor/resource exhaustion and all read errors also stop.
3. Verify every tree's complete list again before **any** replay deletion,
   then check processes and the full list again immediately before deleting
   that tree. Delete exactly the planned entries, deepest first, through
   `unlinkat` on the pinned parents. Recheck each entry's complete stat/mount
   identity immediately before unlink. After an own child unlink, account for
   its parent's changed directory timestamps/link count while preserving
   inode, mode, ownership and exact remaining planned names. Sync each changed
   parent through the real-sync seam. An observed change stops immediately.
4. Remove the root last, then the owner only after all its tree roots are gone
   and its account identity still matches. Run the existing final baseline
   comparison; a successful removal restores the absent S0 roots and accounts.

An OWNER-owned symlink is **unlinked as a link**, never followed: its target
has no creation receipt and gets no deletion authority. This permits ordinary
workload symlinks while preserving outside files/directories. `-socket` may be
repeated to name exact clean relative socket paths expected from the workload;
none are expected by default. FIFOs are always forbidden. Socket allowlisting
never waives ownership, process, mode, device or mount checks.

The deletion list is process-local, not an additional mutable journal record;
a restart builds and verifies a fresh list. Boundary changes detected before
phase 2 preserve the entire tree. Phase 2 is not a transaction: an I/O error or
concurrent change can leave earlier exact-list entries removed. No guessed
cleanup follows a failure. Rechecking then `unlinkat` is not an atomic kernel
compare-and-delete: **a concurrent root writer** can race the final check,
rename ancestors, start an owner process after inspection, or modify a parent
while its own-delete metadata is observed. Keep privileged writers serialized,
parents protected, and the trusted `/proc` view complete. No malicious-root,
mount-namespace isolation, hardware-durability or native privileged qualification
claim is made.

## Explicit account provisioning for draft 10

Draft 10 creates groups, users and memberships in a separate step using
`create-group`, `create-user` and `add-member` at the exact rendered IDs/names.
Create persistent directories separately with `create-dir`. Then run the
unchanged `g2-host-flow` with the rendered parameters as its verification and
activation gate. It retains its existing sysusers apply/check behavior; the
already-created accounts must match. There is no `g2-host-flow -ledger` flag
or ledger renderer-equivalence parser.

The exact draft 10 user arguments are:

```sh
"$KIT" g2-ledger create-user -role service -dir "$LEDGER" -name swarma-wallet -uid 210201 -gid 210201 -home /var/lib/swarma-wallet -gecos "Swarma G2 pay executor" -shell /usr/sbin/nologin -ret state
"$KIT" g2-ledger create-user -role service -dir "$LEDGER" -name g2-agent -uid 210001 -gid 210001 -home / -gecos "" -shell /usr/sbin/nologin -ret state
```

Create each same-name primary group first with `create-group` and its explicit
GID, then the user and explicit memberships. The rendered `u g2-agent 210001`
uses the omitted-field defaults: empty GECOS, home `/`, shell
`/usr/sbin/nologin`. See [sysusers.d(5), GECOS, Home Directory and Shell](https://www.freedesktop.org/software/systemd/man/latest/sysusers.d.html#GECOS).
The home field only sets passwd metadata; it creates no directory. Both rendered
names are lowercase, so uppercase-name support is unnecessary and remains
rejected. The fixed nologin shell is required; a login shell refuses before
intent. CLI defaults remain `/nonexistent`, empty GECOS and
`/usr/sbin/nologin` for older callers; draft 10 must pass the explicit values above.

Each new user receipt records observed home and GECOS in its committed identity.
Replay stops on either field changing, including retained users. The creator
also checks the requested profile against the observed passwd record before
commit. No old receipt is rewritten or profile adopted after creation; an older
receipt lacking fields can fail the stricter live comparison. Older engines
reject the new fields.

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
| B, after verified release and S0 | `init -manifest ... -baseline ... -purpose station -scope ...` |
| S1 | Four `create-dir` calls and `create-file` for the probe |
| S2 | One `exec-create ... -- "$KIT" g2-keygen ...` for each key |
| S4.3 | `modify-file -path ... -backup ... -new ...` |
| S5 | `exec-create ... -- "$KIT" g2-rpcauth ... -wallet-config-out ...` |
| S7 | `create-file` for tmpfiles config, service config, manifest, signature, install drop-in, binary, unit and status drop-in; `create-dir` for drop-in and executable directories |
| Accounts and persistent directories | `create-group`, `create-user`, `add-member`, `create-dir`; no post-hoc registration of sysusers/tmpfiles outputs |
| S8 | `enable -unit ...` |
| S9 | `create-user` with explicit IDs; `create-dir` / `create-file` for helper and staging paths; external installer publication still requires a creator-receipt integration |
| Rollback | `replay -mode ...`; stop the shell on the first nonzero result |

Service stopping, node readiness, native
ownership and installed adoption remain orchestration/qualification
responsibilities; tree removal performs its own checked process inspection.
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

Tree fixtures select known real process IDs through an unexported census seam
and read their actual `/proc` status and thread directories; UID mapping permits
non-root fixtures. The production default enumerates all `/proc` PIDs, with a
separate real-child census test. No process read error is ignored.

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
GOTOOLCHAIN=local go test -race ./g2ledger ./cmd/deploy-kit -run '^TestLedger' -count=1
GOTOOLCHAIN=local go vet ./...
GOTOOLCHAIN=local go test -race ./...
go build -trimpath -o /tmp/deploy-kit ./cmd/deploy-kit
```

`testdata/release-manifest.json` is a public schema fixture with synthetic hashes,
not a signed or deployable release. The tests' one-line claim comments specify
the scope and limits of the cross-check witnesses and positive neighbours.

### Account removal effect boundary

As documented by shadow-utils [userdel(8)](https://man7.org/linux/man-pages/man8/userdel.8.html)
and [login.defs(5)](https://man7.org/linux/man-pages/man5/login.defs.5.html),
`USERGROUPS_ENAB=yes` permits `userdel` to delete an empty same-name group.
Replay observes either documented outcome without reading or changing that
policy. A same-name user and its primary group may be removed as **one checked
logical operation** only when all of these conditions hold before `userdel`:

- Both have committed `create-user` and `create-group` receipts in this attempt's
  validated ledger. S0 absence or a current lookup never substitutes for either
  creation receipt. The user role must match its committed creating action;
  role is ledger metadata, not a passwd field.
- Live user name, uid, primary gid, home, GECOS and shell match the full user
  receipt. Live group name and gid match its group receipt, and that gid equals
  the user's primary gid.
- The group's explicit supplementary member list is empty after reversing this
  attempt's own `add-member` records. Full passwd enumeration through the
  account lookup boundary proves no other entry uses that gid as primary.
  Lookup/enumeration errors, unsupported enumeration, malformed or duplicate
  entries, or a missing/changed expected user stop; they never prove emptiness.
- Both retention decisions permit removal in rehearsal. Station never removes
  either account; a retained group cannot be paired with a removable user.

Rehearsal preflight checks pair authority, identities, policy and primary users
before any reversal, and rejects foreign supplementary members. Replay repeats
these checks at the user step after reversing recorded memberships, and
rechecks the group after passwd enumeration immediately before the effect.
A missing recorded same-name group while its user remains stops with
`PAIRED_GROUP_MISSING`. An unrecorded/pre-existing same-name group still refuses
with `USER_SAME_NAME_GROUP`, under either policy value, without deleting either
account. A recorded group with a different primary gid also refuses.

After successful `userdel`, replay verifies user absence and checks the group:
if absent, it records the verified implicit group removal in replay-local effect
bookkeeping. If the group survives (`USERGROUPS_ENAB=no`, for example), replay
rechecks its receipt identity, empty supplementary list and absence of primary
users, rechecks the group immediately before `groupdel`, then verifies absence.
Only then does it record that explicit removal. The older committed group step
accepts the recorded effect only while the group remains absent; reappearance
stops with `PAIRED_GROUP_REAPPEARED`. No journal schema or creation authority is
changed. The final baseline JSONL remains a comparison against S0.

A changed group, foreign member/primary user, failed tool, still-present account
or lookup error stops with a named reason before older reversals. This checked
operation is not an OS transaction: a failure after `userdel` may leave the
user absent and group present. Retrying the remaining group receipt repeats
its identity/member checks and the full passwd scan before `groupdel`; a failed
scan or another primary user still stops. Existing absence rules apply, and
privileged account writers must remain quiescent throughout replay. Tests use
the fake account boundary with both `USERGROUPS_ENAB=yes` and `no`; they never
invoke real account mutation commands.

### Unit enable receipts and undo

Before enable, the ledger parses `systemctl cat NAME` (unit and drop-ins) and
refuses any `[Install] Also=` assignment, including resets. See
[systemd.unit(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#Also=).
It repeats that inspection after intent and before enable. Privileged unit-file
writers must remain quiescent during the operation.

[systemctl(1)](https://www.freedesktop.org/software/systemd/man/249/systemctl.html)
documents that enable reports the filesystem operations it performs. The
[systemd v249 implementation](https://github.com/systemd/systemd/blob/v249/src/shared/install.c#L312)
prints `Created symlink A -> B.` in the C locale. The real seam captures enable's
stderr along with stdout with `LC_ALL=C`; every reported absolute link and
absolute target becomes part of the commit receipt only after no-follow
observation. Each receipt also stores lstat device, inode, UID, GID and full
symlink mode. Legacy receipts without these fields refuse validation.
Unknown output, empty output, duplicate paths, or missing/retargeted links leave
a named orphan. Other output formats are deliberately unsupported.

Undo checks the entire recorded set before any removal, then rechecks each link
through the same pinned parent descriptor used for `unlinkat`, comparing ALL
recorded fields and target text without following the symlink. A foreign
replacement with the same target text, or changed ownership, stops with a named
exit 1 and survives. Absent links are retry-safe. A retargeted link or a regular file stops replay, even
when the unit now reports disabled. Foreign symlinks are preserved. Undo never
calls `systemctl disable`: that command can remove additional links and units.
It invokes `daemon-reload` through the System seam and verifies the named unit
returned to its previous state. A remaining foreign enablement can cause STOP;
it never grants permission to remove that foreign link.

### Durable uncertain-seal guard

Every append first exclusively creates private `UNSEALED`, fsyncs that file,
and fsyncs the ledger directory. It then writes/fsyncs records, writes/fsyncs
the temporary HEAD, renames HEAD, and fsyncs the ledger directory. Only after
all these operations succeed does it unlink `UNSEALED` and accept the seal.
Any earlier failure preserves the marker and poisons the handle. A fresh Open
or replay refuses with `LEDGER_UNSEALED`, even if matching new records and HEAD
are visible. This also preserves uncertainty after process death at the final
HEAD-directory checkpoint. The marker is not automatically repaired or adopted.

There is deliberately no further fsync after the guard unlink: HEAD is already
durable at that point. A crash may resurrect the guard and conservatively
require inspection; it cannot grant authority to an incomplete seal. These
restart and injected-fsync tests do not certify storage hardware or power loss.

### Required ledger user role

Every `create-user` call requires exactly `-role tree-owner` or `-role service`
(the interface spelling is `-role tree-owner|service`; select one value). Missing
or unknown roles are usage refusals before ledger access. The role is a ledger
relation, recorded in both the creating intent and committed user identity,
and compared while replay validates the entire chain before effects. It is
not inferred from the UID, account name, shell, files or memberships. Existing
receipts without this required role are refused; no receipt is migrated.

Only a committed `tree-owner` user in this ledger can own a tree. From that
user's creation onward, even before its first tree, it cannot receive a
membership or own a separately recorded directory, file, modified file, or
exec-create output. A `service` user can never own a tree, even if it has no
files or memberships and has an otherwise allowed UID. Existing behavioral
dedication, ownership and replay checks remain in force; the forbidden UID/GID
list is additional defense. Creating a tree-owner also refuses a UID that
already owns a non-tree recorded object; dedication cannot relabel earlier
ownership. Draft-10 swarma-wallet and g2-agent are `service`.

Volatile-target classification walks symlink components with `readlinkat`
before applying subsequent `..`, restarting at `/` for absolute link targets.
More than 40 expansions refuses with ELOOP. A not-yet-created suffix can be
walked lexically because its absent components contain no symlinks; inspection
resumes if `..` returns to an existing ancestor. The same resolver classifies
baseline exclusions. Protected parents and serialized privileged writers are
still required.
