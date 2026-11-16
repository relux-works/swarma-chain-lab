# Read-only chain gateway: contract candidate

[CONTRACT.md](CONTRACT.md) is the normative candidate for G1 T4.6 and D29's
live ChainView. [OPEN.md](OPEN.md) lists acceptance/build gates. This directory
contains a schema-only test harness and shared vectors, no gateway or helper.
The consumer must accept an exact head before either side builds.

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
