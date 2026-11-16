# Read-only chain gateway: contract candidate

[CONTRACT.md](CONTRACT.md) is the normative candidate for G1 T4.6 and D29's
live ChainView. [OPEN.md](OPEN.md) lists acceptance/build gates. This directory
contains a schema-only test harness and shared vectors, no gateway or helper.
Source accepted part (B) for helper build in answers r1. Tip.time is a requested
pre-freeze delta; Source's delta acceptance and review remain pending. Q3's
transition-witness feasibility gate applies to both read paths.

## Tools and commands

Use Go 1.26.10, `GOTOOLCHAIN=local`, `GOWORK=off`, `GOPROXY=off`, `GOENV=off`
and a physical task-owned checkout with absolute scratch HOME/cache/config.
Keep TMPDIR short and task-owned. No dependencies, credentials, node or network
are required. Run from this module in that isolated checkout:

```sh
go test -count=1 -timeout=60s ./...
go vet ./...
go test -run '^TestSharedVectors$' -count=1 ./...
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
time and the consumer's default lag boundary at 7200/7201 seconds.


## Helper build blocker

Part (B) §5 requires §4's per-read transition witness. A helper using only
ordinary RPC tip reads before/after a collection cannot distinguish a stable A
from an A→B→A excursion inside a read. The shared `hidden_tip_return` and
`hidden_tip_return_exhausted` scenarios require an actual witness, not endpoint
equality. Infra's ZMQ sequence proposal is unqualified and specifies no RPC/
stream synchronization or loss/restart recovery contract yet. A fake-only
witness or a helper that always refuses would not supply the requested build.

To resume, supply a realizable witness contract and its Q3 qualification, or
obtain an explicit owner/consumer contract amendment allowing weaker RPC
bracketing for observe-only snapshots, with the limitation stated and tested.
Until then the helper build is blocked; no helper binary, systemd unit or
installation is included. This does not reopen Source's acceptance of the
snapshot file format.
