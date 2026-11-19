# Gateway service boundary

Linux-only, separable broker/1 client and request-adapter seam. The module has
Go floor 1.26.0 and release toolchain 1.26.8, uses only the standard library,
and imports no other experiment. The install template lives under this module's
`deploy/` directory, so the module can be tested independently. The parent command
uses its managed source and explicitly opt-in Unix intake without a reverse import.

`Client` implements the credential-lifecycle interface by speaking the existing
broker socket. It checks the broker kernel UID before hello and checks the
returned service triple. The role is broker-assigned; no role or credential
travels in hello. Stable operation IDs belong to the holder. Lost outcomes are
UNKNOWN; only identical operation/argument retries on a fresh, identically
bound connection can reconcile them. A different generation inherits nothing.
Ordinary broker refusals preserve unrelated leases and the usable connection.
Renew and Check stop their target on every error; Release stops it before the
call. Hold stops its account before the call, and hold refusals on Request or
Renew block that account. Only `role_not_permitted`, `principal_ledger_mismatch`
and owned-handle `lease_not_owner` retire the connection on a known refusal.
All 12 `grant_*` codes and `revocation_state_unavailable` keep the socket.
Unknown wire codes are separate protocol failures that close cached use without
echoing the code. A local account block never clears after an owner lift; redial
requires holder-managed reconciliation, not an automatic unblock.
Caller fields use the pinned broker's nonempty ASCII
byte grammar (maximum 128 bytes), including `owner/claude/...` account labels;
installer listener generations separately require a leading alphanumeric.

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

`Gateway` is the owner-decided Claude launch intake: plaintext HTTP/1.1 on the
parent command's opt-in generation Unix socket. It checks kernel peer UID against
the holder-bound caller tuple. It admits only `POST /v1/messages` with one
`Authorization: Bearer ssh-placeholder` and a credentialless
`GET /api/claude_code/policy_limits`. The marker is never authority. Worker
credentials are not copied upstream; only the leased value is attached to the
fixed `https://api.anthropic.com` recipient. Queries and JSON bytes are preserved
for Messages, supported protocol headers are retained, and statuses/errors/SSE
are streamed rather than fabricated or fully buffered. Known material is screened
on input and redacted from output across read boundaries without logging bytes.
The holder supplies round-1 per-version cancellation and lifecycle supervision.
Before Messages acquisition, its `ReserveGeneration` method must durably admit
the request's model and output bound against the configured daily ceiling.
Policy GET never calls that generation meter. The command refuses zero ceilings
and missing accounting. Messages bodies admit up to 128 MiB; the wire probe
measured shapes, not body sizes. The pinned provider documents a 128 MB limit.
The aggregate raw-body window is 128 MiB plus one sentinel byte, with at most
eight body-owning calls; unknown lengths reserve the full window and exhaustion
refuses with 503 before allocation. Known lengths allocate once, not by doubling.
Headers use a separate ten-minute generation budget, including non-streaming
calls. Streams use a one-minute progress-idle budget, not a whole-stream duration
cap. Idle or authority cancellation expires the worker write deadline and closes
the upstream body, interrupting both Write and Flush. The allowed beta flags are
the measured Claude Code 2.1.328 OAuth profile; unknown flags and duplicate header
forms refuse. The parent's meter prices supported cache/geo modifiers and closes
unpriced speed, service tiers and server tools before forwarding.
Encoded upstream bodies refuse before output, while retry hints are preserved.

This is not a qualified harness, production `UseGuard` or standalone daemon.
Durable restart/UNKNOWN-hold reconciliation, production per-generation listener
custody, arbitrary encoded reflections and final outbound revocation remain
integration gates. The legacy `Prepare` fixture still describes preparation,
not an outbound-use permit. See [open integration inputs](UNRESOLVED_QUESTIONS.md)
and [the intake contract](../../../docs/gateway-service.md#claude-launch-intake-v1).

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
Apache-2.0 license, upstream NOTICE and checked source digests. The module also
runs the adapted upstream codec refusal and erasure tests. No real credential or provider call is used by any test.
