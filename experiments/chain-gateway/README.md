# Read-only chain view and observe-only snapshot helper

[CONTRACT.md](CONTRACT.md) defines CG1 for G1 T4.6 and D29.
[OPEN.md](OPEN.md) keeps consumer adoption, gateway witness qualification,
watcher/journal, book/spec and installation gates distinct. Source acceptance
`$Omp4AzWq`, backed by the lead, permits ordinary brackets for §5 OBSERVE ONLY.
The gateway (a) is not implemented here; its §4 witness requirement stays in full.

The Linux `snapshot-refresh` binary is a root oneshot. An operator scheduler
invokes it on startup, new blocks, same-height reorgs and at least every 30 s.
No daemon, scheduler, systemd unit or installation is included. Infra's proposed
snapshot and lock locations are quoted in the contract's INSTALL PROFILE.
Scheduling, read-only user provisioning and installed qualification belong to
Infra; fake-RPC evidence does not prove a deployed node's behavior or custody.

Each run reads the credential file fresh, takes a nonblocking exclusive flock,
checks genesis/network/IBD, and reads COMPLETE Tip {hash,height,time} before and
after every name and outpoint in the configured set. Only equal brackets write.
N=3 total attempts with 100 ms and 200 ms backoff; each RPC has a 1 s timeout
and the entire RPC collection has a 30 s context deadline. A retry recollects
all records. Each tip combines `getblockchaininfo` with `getblockheader` for
that hash. Names use `name_show` with `allowExpired:true`, ASCII names and hex
values, plus `getblockhash` for the operation height. Values become exact
base64 octets. `gettxout` always uses include-mempool=true; null means
`not_in_utxo_set`, not proof of a spend.

The writer emits only canonical v1 `consistency:"bracketed"` snapshots. Missing,
unknown and `"witnessed"` consistency are invalid in v1. Brackets cannot detect
hidden A→B→A excursions. The consumer LABELS only and NEVER refuses on a
snapshot. Observed closures go only to an observe journal and are NEVER
imported into enforcement state. Enforcement closures require the Q10 watcher
journal or a qualified witnessed read. A helper cannot elevate its own claim.

## Operator configuration

Invoke `snapshot-refresh -config "$CONFIG"`. The config is one UTF-8 JSON
object, at most 65536 bytes; whitespace/key order are allowed. All the fields
below are required and closed. Duplicate/folded/escaped keys, null members,
unknown fields, invalid typed numbers and trailing data are rejected. No
credentials are accepted through arguments, environment or inline JSON fields.

| Field | Required value |
| --- | --- |
| `rpc_url` | HTTP loopback **IP literal** and explicit port, no userinfo, path, query or fragment. Proxy environment is ignored; redirects are rejected. |
| `network` | `main` or `regtest` |
| `genesis` | 64 lowercase display-order hex characters; checked with `getblockhash(0)` |
| `credential_mode` | `cookie` or `rpcauth-user` |
| `credential_file` | Protected absolute clean path, reopened each run |
| `credential_group` | Exact numeric GID of the credential file |
| `output` | Protected absolute clean snapshot path |
| `lock` | Protected absolute clean lock path; stable across runs |
| `names` | 1..16 CG1 names in strict ASCII order, no duplicates |
| `seals` | 1..256 objects with exactly `txid` and `vout`; sorted by lowercase 64-hex txid then uint32 vout, no duplicates |

All four file paths (config, credential, snapshot and lock) must be distinct.
Configuration is root-owned regular mode 0600 or 0644; credentials are root-owned
regular 0600 or 0640 with the configured GID, within protected ancestry. Infra
must provision the 0640 group exclusively. File links and group/world writes
are rejected, as are extended POSIX access ACLs. Symlinks are never followed;
all path components are traversed descriptor-relatively from the trusted root.
The existing snapshot, if present, must be root-owned regular mode 0644 and have
one link. Its preprovisioned parent is root-owned 0755. Other ancestors must be
root-owned and not group/world writable. The helper creates no directories.

Cookie mode reads `__cookie__:PASSWORD` with an optional final LF. The
`rpcauth-user` mode reads `USERNAME:PASSWORD` with an optional final LF: the
client password of a dedicated read-only RPC user, **never** the node's
`rpcauth=...` verifier. Cookie usernames and verifier-shaped salt/hash strings
are rejected in that mode. No wallet/write method exists in this helper. The
operator must restrict this user to the five fixed read methods above;
credential capability itself is an external node configuration gate.

Publication creates a fresh 0600 O_EXCL temp in the output directory, writes
and validates the entire payload, chmods 0644, fsyncs the file, closes it,
renames atomically, and fsyncs the directory. Only this run's temporary file is
removed. A pre-rename failure retains the previous snapshot. If directory fsync
fails after rename, the new complete file may already be visible, but durability
is not claimed; crash recovery can retain either complete version. The stable
lock file is never unlinked. Lock/config/credential errors never replace output.

| Exit | Meaning |
| --- | --- |
| 0 | Complete bracketed snapshot published and directory synced |
| 10 | Arguments, root requirement, config, or input/lock custody invalid |
| 11 | Credential, node, malformed response, binding or collection deadline failure; previous file untouched |
| 12 | Three moved brackets; previous file **UNTOUCHED** (bytes, inode, mtime); let it age to stale |
| 13 | Another writer owns the lock; no credential read or node call |
| 14 | Publication failure; see the post-rename directory-sync limitation above |

Diagnostics are fixed strings, with no paths, credential values, HTTP headers,
upstream bodies or reflected errors. Projected name bytes matching credentials
(raw or Basic-auth encoding) suppress the whole publication, including when
those bytes would otherwise be hidden by base64. This suppression is not an
enforcement decision or a claim to general data-loss prevention.

## Tools and validation

Use Go 1.26.10 with `GOTOOLCHAIN=local`, `GOWORK=off`, `GOPROXY=off`,
`GOSUMDB=off`, `GOENV=off`, telemetry off, and a physical task-owned checkout
with absolute scratch HOME/config/cache and a short task-owned TMPDIR. There
are no external module dependencies. Run from this module in that checkout:

```sh
go test -count=1 -timeout=60s -v ./...
go vet ./...
go test -race -count=1 -timeout=120s ./...
go test -run '^TestSharedVectors$' -count=1 ./...
python3 -B omission_analysis_test.py fixtures/vectors.json
go build -o "$ARTIFACT_DIR/snapshot-refresh" ./cmd/snapshot-refresh
go test -race -count=1 -timeout=120s ./...
gofmt -w *.go cmd/snapshot-refresh/*.go
```

Tests run **unprivileged**, against an in-process loopback fake RPC server with
synthetic credentials. Internal tests anchor custody at a task-owned fixture
root; the public CLI has no override for root ownership/ancestry and refuses
unprivileged calls. No test contacts a real node or exercises root installation.
The fake server asserts name options, mempool inclusion, exact outpoints,
authentication and method order. Schema vectors remain shared consumer inputs;
D29 must bind them to its own real decoder, not copy this parser as agreement.
The named tests cover both accepted output and forbidden updates:

| Claim/control | Named test |
| --- | --- |
| Equal complete brackets, canonical snapshot, unspent/absent observation | `TestBracketEqualWrites` |
| Every Tip member matters; N=3/backoff/untouched previous file | `TestBracketMovedKeepsPrevious` |
| A moved first set is discarded and recollected | `TestBracketMovedRetriesThenWrites` |
| Errors/malformed responses/wrong bindings retain output | `TestNodeErrorKeepsPrevious` |
| Old open reader sees old bytes; new reader sees new inode/valid complete file | `TestAtomicPublication` |
| Second writer excluded during first writer's blocked read | `TestLockExcludesSecondWriter` |
| Both auth modes, fresh rotation, output/error/projection secrecy | `TestCredentialsNeverAppearInOutput` |
| Config and filesystem negative controls | `TestConfigNegatives`, `TestCustodyNegatives`, `TestMainRequiresRoot` |

The r2 fixture control plants an invalid tip time: in an isolated scratch copy,
set `response_tip_time_negative`'s `valid` to true and run
`go test -run '^TestSharedVectors/response_tip_time_negative$' -count=1 ./...`.
It must exit 1 with `verdict mismatch` and `validation=tip`; restore the fixture
and rerun green. Shared vectors include Tip.time bounds/invalid spellings on
all success types and the snapshot; observation vectors include mismatched tip
time and the consumer's default lag boundary at 7200/7201 seconds. Same-hash
header-time disagreement is backend inconsistency, not genuine tip movement.
For narrowing controls in an isolated source copy or Go overlay, (1) replace
the after-tip read with the before tip, or (2) bypass the mismatch branch:
`go test -run '^TestBracketMovedKeepsPrevious$' -count=1 ./...` must fail with
`expected tip exhaustion exit 12`. (3) Replace rename with an in-place write:
`go test -run '^TestAtomicPublication$' -count=1 ./...` must fail with
`atomic replacement violated`. (4) Bypass flock:
`go test -run '^TestLockExcludesSecondWriter$' -count=1 ./...` must fail with
`second writer was not excluded`. These controls do not qualify crash durability.

For the planted leak control, add a diagnostic in `runReport` that reads and
prints the synthetic credential file. Run
`go test -run '^TestCredentialsNeverAppearInOutput$' -count=1 ./...` and require
exit 1 with `credential disclosure in output`, not a timeout or build failure.
Restore source and rerun the complete baseline. No real secret is planted.

## Accepted observe-only amendment

Consumer acceptance and the lead's HELPER-B r3 brief amend §5.
The helper may bracket all reads with complete Tip comparisons, N=3 total
attempts, minimum 100/200 ms movement-only backoff; exit 12 retains the previous
file untouched on exhaustion whose third attempt is movement-only. After attempt
3 the exit is decided by attempt 3's row alone: rate-limit evidence in attempt 3
exits 11, movement-only evidence exits 12. Earlier attempts' classes affect only
the waits. The current §5 table resolves mixed refusals
(terminal > rate limiting > movement), uses ordinal minimum waits, reserves 13
for post-rename durability failure and 14 for lock-contention skip.
Snapshots require `consistency:"bracketed"`; missing, unknown and `witnessed`
are invalid in v1. Hidden A→B→A cannot be detected: labels and observe-journal
closures never enter enforcement state. §4's witness gate stays for (a) and
enforcement. No installation or live-node qualification is claimed.

The amendment control sets `snapshot_consistency_witnessed` to valid in an
isolated fixture copy, then runs
`go test -run '^TestSharedVectors/snapshot_consistency_witnessed$' -count=1 ./...`.
Require exit 1 with `verdict mismatch`, restore the fixture, and rerun green.

## Current correction controls

Both credential-holding v1 paths are Linux-only; no platform proof means no
publication. The Darwin owner decision and CGW-D1 dependency remain open in
OPEN.md. There is no live gateway/helper implementation in this module.

`fixtures/inventory.txt` pins EVERY scenario/vector name and kind; fixture
readers reject trailing data and unknown/mistyped inner fields. The omission aid
runs in CI. New scenario `claim`/`control` entries name their exact purpose and
an executable valid positive; label inputs require independent-tip provenance,
configured lag seconds and explicit `enforceable:false`.

To verify each changed oracle input, in isolated scratch flip its expected
`available`, `accepted`, label, helper exit, upstream/reflection code or history
decision, run its exact subtest in `TestObservationVectors` or
`TestSnapshotLabels`, require exit 1 with its named verdict/label witness, restore
and rerun green. To test deletion, remove a vector/scenario without editing the
inventory and require `TestFixtureInventory` to fail with
`required fixture inventory mismatch`; restore and rerun green.
`TestFixtureDecoderControls`, `TestUpstreamBounds` and
`TestReflectionRepresentations` each pair refusal controls with valid inputs.
`TestSnapshotDomainControls` rejects impossible sequences as domain errors, not
helper exit 11. `TestSnapshotFixtureEnums` checks closed stage/failure enums and
explicit rename facts. `TestUpstreamCapFixtures` proves every shared cap+1 body
is valid JSON and differs from its at-cap positive only by one whitespace byte.
Snapshot outcome inputs now include protected config, per-read requests,
wire-string middle replies, bracket refusals and explicit rename state. The
complete control contains both configured name and seal reads. Pure configured
name/seal omissions have a complete multi-record label control.
These remain contract oracles, not operating-system, live-node or publication
fault-injection qualification.
For the schema invalid control, mark `snapshot_consistency_witnessed` valid
in an isolated fixture copy, then run
`go test -run '^TestSharedVectors/snapshot_consistency_witnessed$' -count=1 ./...`.
Require exit 1 with `verdict mismatch`; restore and rerun green. The existing
invalid tip-time and forbidden-method fixtures remain unchanged.

From the repository root, run
`python3 -B .github/scripts/check-public-hygiene.py` after staging the reviewed
scope. Logs, real exits, source hashes and mutation evidence belong under
task-scoped `.temp/`. Remove owned HOME/config/caches/TMPDIR after capture.
