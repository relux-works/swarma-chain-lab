# Read-only chain gateway: contract candidate

[CONTRACT.md](CONTRACT.md) is the normative candidate for G1 T4.6 and D29's
live ChainView. [OPEN.md](OPEN.md) lists acceptance/build gates. This directory
contains a schema-only test harness and shared vectors, no gateway or helper.
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

`gofmt -w *.go` formats only the harness. From the repository root, stage scoped
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
