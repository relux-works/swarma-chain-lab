# Read-only chain gateway contract and snapshot helper

[CONTRACT.md](CONTRACT.md) is the normative candidate for G1 T4.6 and D29's
live ChainView. [OPEN.md](OPEN.md) lists acceptance/build gates. This directory
contains the shared contract corpus and a Linux direct-RPC snapshot helper;
the gateway listener (a) is not implemented.
Source accepted part (B) for helper build in answers r1. Tip.time is a requested
pre-freeze delta; Source's delta acceptance and review remain pending. Q3's
transition-witness feasibility gate applies to (a) and enforcement only.

## Tools and commands

Use Go 1.26.10, `GOTOOLCHAIN=local`, `GOWORK=off`, `GOPROXY=off`, `GOENV=off`
and a physical task-owned checkout with absolute scratch HOME/cache/config.
Keep TMPDIR short and task-owned. No dependencies, credentials, node or network
are required. Run from this module in that isolated checkout:

```sh
go test -count=1 -timeout=60s ./...
go vet ./...
go test -race -count=1 -timeout=120s ./...
go test -run '^TestSharedVectors$' -count=1 ./...
python3 -B omission_analysis_test.py fixtures/vectors.json
```

`gofmt -w *.go cmd/snapshot-refresh/*.go` formats the module. From the repository root, stage scoped
new files, then run `python3 -B .github/scripts/check-public-hygiene.py`.
Evidence and controls belong in task-scoped `.temp/`; caches and short temporary
directories are task-owned and removed after evidence capture.

To prove the fixture gate detects a violation, copy this module into owned
scratch, change the `valid` verdict of `request_write_method` in
`fixtures/vectors.json` to true, and run
`go test -run '^TestSharedVectors/request_write_method$' -count=1 ./...`.
It MUST exit nonzero with `verdict mismatch`, not a setup/build failure; then
revert only the scratch fixture and rerun green. This is a fixture expectation
plant, not a gateway implementation mutant. The cross-side mirror obligations
and the limits of schema-only evidence are specified in CONTRACT.md §6.

The r2 fixture control plants an invalid tip time: in an isolated scratch copy,
set `response_tip_time_negative`'s `valid` to true and run
`go test -run '^TestSharedVectors/response_tip_time_negative$' -count=1 ./...`.
It must exit 1 with `verdict mismatch` and `validation=tip`; restore the fixture
and rerun green. Shared vectors include Tip.time bounds/invalid spellings on
all success types and the snapshot; observation vectors include mismatched tip
time and the consumer's default lag boundary at 7200/7201 seconds. Same-hash
header-time disagreement is backend inconsistency, not genuine tip movement.


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
OPEN.md. The helper is an offline-tested implementation, not an installed or qualified service.

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


## Linux snapshot helper

`snapshot-refresh -config "$CONFIG"` is a root-only oneshot. It emits an
OBSERVE-GRADE, `observe_only`, `consistency:"bracketed"` file. There is no Darwin
implementation or platform fallback. No proof means no credential load, RPC or
publication. It is a NON-WITNESS: neither a fresh label, a bracketed snapshot nor
a qualified witnessed gateway read creates an enforcement closure. Only the
separately admitted CGW-J1 watcher/journal can supply enforcement closures
([CONTRACT.md §§1,4–5](CONTRACT.md)). No journal or supervisor is installed here.

Each invocation takes a nonblocking exclusive lock, verifies protected node
configuration and initial user/network namespace descriptors against host PID 1,
and applies `PR_SET_DUMPABLE=0` / `RLIMIT_CORE=0` before credential load. Every
HTTP connection authenticates the numeric loopback listener and connected reverse
socket tuple by kernel UID/inode/cookie before any application byte. Missing,
denied, wildcard, ambiguous or wrong-owner evidence fails closed. PID 1 must be
the host initial namespace authority; establishing that deployment binding is Q6.

The protected config is one UTF-8 JSON object of at most 65536 bytes. Every field
below is required and closed; duplicates/fold aliases/escaped keys, null, unknown
members and trailing data refuse. No secret is accepted in argv or environment.

| Field | Requirement |
| --- | --- |
| `profile` | Exactly `cg1-v1` |
| `node_uid` | Dedicated unprivileged node UID; reject 0, 65534, 65535, 4294967295 and every identity overlap |
| `server_uid` | Dedicated gateway service UID, different from node |
| `allowed_uids` | Complete protected gateway client UID list, including any root-helper exception |
| `workload_uids` | Complete helper, consumer and other non-node workload UID list |
| `node_dedicated` | Explicit true assertion of the exclusive account; installation must qualify it |
| `node_config` | Protected node- or root-owned config; explicit numeric loopback `rpcbind` AND `rpcallowip`; every bare/network-prefixed/section bind and allow is inspected; any includeconf is refused |
| `gateway_verifier_user`, `verifier_user` | Distinct dedicated service usernames |
| `cookie_source` | `none` for verifier mode; explicit `live` or separately admitted `admitted-root-copy` for cookie mode |
| `rpc_url` | Numeric loopback HTTP IP literal and explicit port; no userinfo, path, query, fragment, proxy, redirect or compression |
| `network`, `genesis` | Protected `main` or `regtest` and exact lowercase 64-hex genesis; no discovery |
| `credential_mode` | `rpcauth-user` or explicitly admitted same-host root-only `cookie` exception |
| `credential_file`, `credential_group` | Absolute protected path and exact GID; reopened each run with descriptor-relative no-follow traversal |
| `output`, `lock` | Distinct protected absolute clean paths; parent preprovisioned, output parent exactly 0755 |
| `names` | 1..16 names, strictly sorted ASCII bytes |
| `seals` | 1..256 exact `{txid,vout}` objects sorted by txid then uint32 vout |

Config, credential, node-config, output and lock paths must all differ. Config is
regular 0600/0644; root credentials 0600/0640, live cookie node-owned 0600, admitted
root copy root-owned 0600. Every file is single-link with protected ancestry and
no writable ACLs or symlinks. The output is regular 0644; the lock is regular
0600 and is never unlinked. No directory is created or repaired by this helper.

Verifier mode reads `USERNAME:PASSWORD` (optional final LF), never an rpcauth
verifier. It inspects exactly one configured five-method whitelist with
`rpcwhitelistdefault=1`, then requires 403 for the fixed `getrpcinfo` denial
probe. Cookie mode reads a fresh `__cookie__:SECRET`; no fallback or copied-cookie
admission is inferred. The probe closes its response without reading/projecting
its body. Cookie authority is broader, never described as least privilege.

The fixed upstream set is `getblockchaininfo,getblockhash,getblockheader,name_show,gettxout`.
Whole-entity cap+1 streaming and per-method token depth enforce
[the bounded upstream profile](CONTRACT.md#bounded-upstream-profile); selected
fields and the exact JSON-RPC 1.0 string id/envelope/status mapping are checked
before projection. Oversize streams close without draining. Projection limits
remain separate. Names require allowExpired and exact hex transport; seals use
both fixed false/true views and retain all four states/metadata. Unqualified
signed vout above 2147483647 refuses without a gettxout call.

The shared gateway-style model checks method/network/outpoint echoes. Direct
RPC carries no method/network or gettxout outpoint echo: those projected fields
come from the request and configuration. Real direct-RPC binding is one request
per authenticated connection with an exact string id, exact name echo, fixed
outpoint result slots, bestblocks, and the chain field on BOTH brackets. Canonical
ReplyWires validation exercises shared fixtures; production validates upstream
SJ1/selected fields before local projection and the final canonical snapshot. Known middle bestblocks participate even when outer
brackets agree. Same-hash header contradictions are terminal throughout the
invocation. Concurrent failures use terminal > rate limiting > movement > success.
Starting an opening bracket consumes an attempt; its refusal permits no later
reads. A failed attempt contributes no record to its successor. There are three
attempts and one 20-second monotonic budget, with one-second RPC deadlines.
Movement-only waits are at least 100/200 ms by ordinal; any rate limiting waits
at least one second. Attempt 3 alone decides retry exhaustion. A 512-token,
128/s invocation-local reservation and at most sixteen active RPCs pace reads.

Supervisors must use the single normative
[helper outcome table](CONTRACT.md#helper-outcome-classification): 0 durable
publication; 11 failure with old bytes untouched; 12 final movement-only
exhaustion; 13 successful rename with durability unconfirmed; 14 lock-contention
skip with no credential/node reads or snapshot writes (config read and lock open precede contention). Exit 10 is no longer emitted. These are candidate
helper semantics; external supervisor acceptance remains OPEN.

Publication writes and re-reads a validated exclusive same-directory temp,
sets/validates 0644 ownership/mode, fsyncs and closes the file, then renames and
opens/fsyncs/closes the directory. Pre-rename failures retain previous bytes,
inode and mtime. A post-rename directory failure returns 13 without rollback.
Cleanup under the held lock removes only recognized validated owned crash temps;
unknown files and active writers remain untouched. Whole raw credential, Basic
base64/header and secret-component equality are checked on projected strings and
decoded name-value octets. Fragments and embedded values do not trigger substring
heuristics. Diagnostics are fixed and expose no upstream text or secret values.

## Helper validation and OPEN qualification

The helper uses `fixtures/vectors.json`, `fixtures/observations.json` and their
strict inventory directly in this module; there are no helper fixture copies.
`TestHelperSharedSnapshotOutcomes`, `TestHelperSharedUpstream`,
`TestHelperSharedReflection` and `TestHelperPublicationStageFailures` bind the
contract's controls to helper entry points. Existing schema, observation, label,
fixture decoder, domain and omission tests remain. Unprivileged kernel tests use
an in-process loopback fake and synthetic credentials; custody fixtures pin their
own PID/UID/ancestry, with no public CLI override. They are not node qualification.

Build after tests with `go build -o "$ARTIFACT_DIR/snapshot-refresh" ./cmd/snapshot-refresh`.
The existing module CI runs race/tests, vet, build and omission analysis under
Go 1.26.10. From repository root run the module-graph and consumer scripts listed
in the root README. Logs/artifacts belong in task-scoped `.temp/`, with absolute
HOME/config/caches/TMPDIR; remove only owned caches after capture.

The following remain OPEN, by [OPEN.md](OPEN.md), not locally invented:

- Darwin/CGW-D1 platform/dump/endpoint profile or explicit owner-accepted residual;
  v1 remains Linux-only with no fallback (OPEN gate Darwin profile).
- Q3/Q6: exact Core 28.0 binary/config/status semantics, hidden A→B→A and negative
  witness feasibility, exclusive accounts and effective argv/config, initial
  namespaces, endpoint replacement, coherent mempool pair, signed-vout range and
  bounded competing-traffic fair progress. Fake replies and config assertions are
  not that qualification.
- Q5: maximal set serialization, real pacing/refill, one-second versus gateway
  five/six-second budget composition and 20-second completion/cadence under load;
  no oracle wait value claims elapsed-time qualification.
- Q7/S8: protected credential group membership, rotation/restart-synchronized copy
  invalidation, installed custody, provisioning and installation GO.
- Upstream owner, Opus R9 / Muse R6: accepted HTTP status/header/chunk/trailer and
  denial-probe profile; requested-name/network/genesis oracle extensions and
  null-in-ignored-extension oracle hardening. No new HTTP framing cap is chosen.
- Consumer/journal owner, Opus R10 / Muse R5: retention/eviction and durable
  per-hash/restart/multi-key state, same-check independent live-tip provenance.
  (b)-only is never fresh; the helper asserts neither freshness nor enforcement.
- Opus R11 / Muse R7: full legacy annotation/control hardening. Q8 book/spec and
  script-binding acceptance, separate Q10 CGW-J1 admission/qualification, amended
  exact-head consumer/supervisor acceptance and production adoption remain OPEN.


## PR 149 review follow-ups

The helper conforms to CONTRACT.md at the landed contract revision; CONTRACT.md,
OPEN.md, all original contract tests/oracles and fixtures are retained verbatim.
The helper has separate production schema/upstream code and helper-only fixture
decoding; independent landed oracles do not call the helper implementation.
No contract amendment is proposed by this rework.

- Opus 5928449303 MEDIUM-1: inspect bare, main., test., testnet4., signet.,
  regtest. and [section] settings, including inactive networks; refuse any
  non-loopback bind/allow and every includeconf. Only active/global settings
  satisfy the required explicit bind/allow policy.
- Opus 5928449303 LOW-1: indirect name/seal movement that first fails projection
  remains terminal exit 11. Movement-aware projection is deferred; this is the
  contract's fail-closed projection rule, with avoidable retries lost. It needs
  paired name/seal classification tests, beyond a one/two-line change.
- Opus 5928449303 LOW-2 / Muse 5928585801 F3: direct-RPC versus shared-wire
  correlation is distinguished above. Closing-network refusal has a run-level
  negative; method correlation in the shared model uses the unchanged oracle.
- Opus 5928449303 LOW-3: policy and independent oracles restored verbatim.
- Opus 5928449303 NIT-1 / Muse 5928585801 F5: redundant true-literal admission
  call removed; ordered concrete pre-credential checks are authoritative.
  Shared qualification tests exercise the predicate independently.
- Opus 5928449303 NIT-2 / Muse 5928585801 F7: contention wording is 14; config
  reading and lock opening precede that skip.
- Opus 5928449303 NIT-3: the unconfigured-decoy test is explicitly structural,
  not proof of a runtime credential selector. The public profile has one path.
- Opus 5928449303 NIT-4: output/lock crash-temp basenames are forbidden before
  cleanup. NIT-5: vout 2147483647 has a run-level dispatch/publication control
  beside the retained 2147483648 rejection with no dispatch.
- Muse 5928585801 F1: recognized owned-temp cleanup runs under the held lock
  before platform proof. It opens no credential, sends no RPC and publishes no
  snapshot; a stricter no-filesystem-side-effect profile is not claimed.
- Muse 5928585801 F2: **PRODUCTION ACTIVATION GATE**: independently establish
  exclusive-account completeness (including unlisted workloads), effective node
  argv/config equivalence, and host PID 1 initial-namespace authority. Protected
  assertions and fake-endpoint tests do not close this gate (OPEN Q3/Q6).
- Muse 5928585801 F4: reflection checks only whole entries named by the contract;
  fragments, embedded values and arbitrary transforms are outside this claim.
- Muse 5928585801 F6: the shared reflection test constructs its own entry list;
  production-list coverage comes from TestExactCredentialReflection,
  TestHelperSelectedCredentialMode and TestCredentialsNeverAppearInOutput.
- Muse 5928585801 runtime-evidence limits: local tests cannot prove power-loss
  durability, real-node behavior or activation. Opening-bracket no-middle-read
  ordering follows the shared classification and code; a dedicated end-to-end
  method-count control for that exact refusal remains a coverage limitation.
