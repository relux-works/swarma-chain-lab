# Gateway service boundary

Linux-only, separable broker/1 client and request-adapter seam. The module has
Go floor 1.26.0 and release toolchain 1.26.8, uses only the standard library,
and imports no other experiment. Move `service/` and its sibling `deploy/`
together. The parent command depends on this nested module through its
managed source; this module still imports no parent or other experiment.

`Client` implements the credential-lifecycle interface by speaking the existing
broker socket. It checks the broker kernel UID before hello and checks the
returned service triple. The role is broker-assigned; no role or credential
travels in hello. Stable operation IDs belong to the holder. Lost outcomes are
UNKNOWN; only identical operation/argument retries on a fresh, identically
bound connection can reconcile them. A different generation inherits nothing.

`Lease` hides material from formatting and JSON. The only adapter is `Claude`,
which constructs the fixed Anthropic Messages recipient and attaches the leased
OAuth token at request preparation. Material stays in the holder process;
there are no token files, child processes, environment injection or logging.
The returned HTTP request is a private holder object: never log, serialize or
return it to the agent. `Drop` removes its auth header when custody ends.
Immutable Go/runtime copies are not a secure-erasure guarantee.

`Prepare` requires a protected launch mapping and a `UseGuard` supplying both
current authorities and the issued-version matcher. It classifies the complete
bounded non-streaming text request, validates the placeholder, runs intake/scan/
dequeue gates, obtains a lease, polls, checks final preparation authority and
then attaches. A missing guard refuses. External providers are not plugins;
future adapters retain the same account-kind-agnostic interfaces.

`Source` supplies the parent command's structural credential boundary using
only standard-library method signatures. It binds one protected caller tuple,
checks revocation before returning a temporary material copy, renews the same
lease and releases on close. The parent owns conversion into its opaque
carrier and erasure of that temporary copy. No parent import is needed.

This module does not submit HTTP, qualify a harness, implement a production
`UseGuard` or provide its own daemon. The existing parent command owns wiring.
Post-dial submission fences, response/reflection protection,
stream closure, durable restart reconciliation, per-generation listener custody
and complete version-inventory ownership remain integration gates. Preparation
is not an outbound-use permit. See [open integration inputs](UNRESOLVED_QUESTIONS.md)
and [the service spec](../../../docs/gateway-service.md).

## Tools and verification

Run from this directory with Go 1.26.8, in a private absolute HOME/cache/temp
environment. Keep logs and plant outputs in task-owned `.temp/` scratch.
Check `/proc/loadavg` before full tests and race runs; wait at load 10 or higher.

| Tool | Command | Output |
| --- | --- | --- |
| gofmt | `gofmt -w *.go` | formatted source |
| Go vet | `go vet ./...` | terminal diagnostics |
| Go tests | `go test ./...` | terminal verdict; Unix fake broker, fixture material only |
| Go race | `go test -race ./...` | terminal verdict |
| Go build | `go build ./...` | package build cache; no service executable |
| Python plants | `python3 scripts/check-plants.py --out "$ABSOLUTE_NEW_SCRATCH"` | overlays, command logs, loads and `report.json` |
| Module inventory (repository root) | `python3 .scripts/check-module-graph.py --write-doc` | generated `experiments/MODULE-GRAPH.md` inventory |
| Module audit (repository root) | `python3 .scripts/check-module-graph.py` | terminal provenance and require-edge verdicts |

Broker sources and actual frame captures are pinned in
[wire provenance](internal/wire/PROVENANCE.md) and
[fixture provenance](testdata/PROVENANCE.md). The copied wire files retain their
Apache-2.0 license. No real credential or provider call is used by any test.
