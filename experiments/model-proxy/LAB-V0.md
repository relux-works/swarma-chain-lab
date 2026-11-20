# API-key lab gateway v0

This is an **experiment**, not a production gateway profile, release, live spend
approval or qualified deployment. The separate command and all its implementation
and tests require **Linux and `gateway_lab`**. The production entry point, source,
OAuth contract, installer, release scripts and templates are unchanged.

## Contract and authority

The authoritative design is `swarma-credential-broker` at
`7a730950fb0965fdfc34081b7d390f02e8c9a3bd`, `docs/lab-profile-v0.md` sections 2–4,
5.1 (G1), 5.2 and 7, and `contracts/lab-v0/README.md`. Design section 1 names the book chapters **OS user and network**
(`book/ru/05-polzovatel-i-set.md`) and **Credentials**
(`book/ru/09-uchetnye-dannye.md`) at swarma-docs
`bc1132c9d9be60864ef7195efa83215357ad3011`: their isolation/custody rules are
**same**, reused rather than locally redesigned. Its **Operator's phone**
(`book/ru/12-interfeysy.md`) conflict is the explicit owner-reviewed lab exception,
not a production amendment. The existing [gateway contract](../../docs/gateway-service.md)
continues to govern. This code refines only the explicitly separate lab path; it
neither replaces the production contract nor invents a new authority ceremony.
[Contract provenance](service/testdata/lab-v0/PROVENANCE.md) records the frozen pins.

Admission requires the joined C0 activation, authority, start fence, persisted
manager-prefix floor and release-set records. Recursive CCJ-1 parsing refuses
missing/extra/duplicate fields, invalid scalar spellings and oversized records.
The source compares contexts, protected caller/gateway tuples, exact record
hashes, release contract-index digest, manager prefix and the sole 1..900-second
selector. The protected service mapping must agree independently with that
selector and the actual process UID/generation. The existing broker/1 handshake
checks the kernel broker peer. The worker HTTP connection uses SO_PEERCRED; no
worker-supplied header can substitute a caller tuple.

These local comparisons **do not establish** off-VM decisions, qualified NTS,
fence consumption, manager journal durability or the approved native assembly.
B1/B2/B3 own those authoritative checks. An unconsumed fence is not silently
consumed here. C opening and every DN-09 C precondition remain external gates.
Local wall time can shorten/refuse use; it cannot grant trusted-time authority.

## Frozen request profile

Only HTTP/1.1 `POST /v1/messages?beta=true` and
`GET /api/claude_code/policy_limits` are admitted. POST requires exactly one
`x-api-key: ssh-placeholder`, the frozen version and user-agent, and exactly the
eleven non-OAuth flags from C0. Flag order and SP/HTAB separator whitespace may
vary; upstream emission is exactly one field containing the frozen canonical
eleven-flag string, never the admitted worker spelling. Absent, unknown,
duplicated, case-variant or OAuth flags refuse. Both kinds
of duplicate header (field instances and case-folded map keys) refuse.

The C0 header projection is not a complete transport-header capture. Ordinary
Content-Length framing and the production adapter's supported protocol metadata
(Content-Type, Accept, x-stainless-*) remain admitted. Accept-Encoding is not
forwarded; compressed responses refuse. Unknown headers, trailers and chunked
request bodies refuse. This is a stricter fixed-length invocation, not a claim
that the capture observed every framing header.

The reconstructed body is closed recursively: model `claude-opus-5-5`,
`max_tokens: 128000`, stream true, empty tools, adaptive thinking/display,
medium effort, clear-thinking edit, required metadata/diagnostics strings and
all required paths. Three cache controls are compared as a multiset; the one
global cache control is not pinned to a system position. Missing paths, TTL 1h,
system clear_at, nonempty tools, unknown coupled fields and unpriced modifiers
refuse; nothing is stripped or normalized. Strings remain caller content.
Strict reading: the output bound uses integer spelling, matching the existing
accounting reader; fractional/exponent aliases and lossy float rounding refuse.
HTTP JSON need not otherwise use CCJ-1 ordering or whitespace. Admitted body
bytes are forwarded unchanged.

The only worker credential is `ssh-placeholder`. The managed source accepts only
`anthropic-api-key-lab/1` and injects a temporary API-key copy into the fixed
Anthropic recipient for POST. There is no key-file, environment-key or OAuth
fallback. Policy GET has no injected credential, even on genuine 401. Status,
retry headers, errors and incremental SSE are preserved. There is no generation
retry, 401 renewal retry or fabricated policy success. The ordinary durable
full-context/output reservation and positive daily ceiling run before POST
material acquisition; this intake does not claim arbitrary-client settlement.
The inert 128000 fixture is **not** permission to run a live invocation: changing
it for an approved bounded live run requires a reviewed profile/probe revision.

Header leak rule (strict, fail-closed): for each field, scan the field name plus
all values concatenated in order **without a separator**, without trimming or
normalizing bytes. This includes every complete value and detects a needle split
at any value boundary, including empty intervening values. Delimiter insertion
could hide a split match, so commas/spaces are not inserted. This conservative
rule may also hold on a synthetic cross-boundary match. Different field names
are not concatenated with each other. Multi-valued inbound fields still violate
the closed request shape: a clean duplicate refuses 400 with no hold; a material
match is detected first and holds with 403. Multi-valued allowlisted response
fields (Request-Id controls) preserve all clean values; material holds with 502
before any header or body reaches the worker.

## Deadlines, holds and shutdown

The broker result must match the outstanding operation, caller, full protected
context and floors, with the earliest authorized deadline and selected lifetime.
Renewal is scheduled at two thirds of the actual remaining lease, not every
500 ms. A call's existing deadline cannot be extended by a later renewal, and
an ended handle cannot be renewed back into use. An uncertain material issue
retires the source; it never reconnects to obtain another material effect.

Current revocation checks run every 250 ms with a separate 200-ms RPC timeout.
The independent 500-ms timer does not need the source controller mutex. A
missing/late current result cancels use, closes the broker connection and signals
the command to close the HTTP server, live streams/connections and generation
listener. The unit tests observe these closures within one second; the measured
independent-watchdog test separately blocks the supervisor. This is synthetic
local scheduling evidence, not the owner-run native Q4 timing qualification.
Upstream headers retain the production ten-minute budget; body/worker progress
retains its separate one-minute idle budget, with cancellation interrupting read,
write and flush.

A whole issued-needle match in inbound or outbound headers/body immediately
retires local use and starts `account.hold` reconciliation against the same
protected broker endpoint. The bridge retains one operation ID and request
digest across lost acknowledgments, UNKNOWN and reconnects. Only an exact
committed C0 result bound to the operation, digest, context and caller completes
it. The command first drains already-started intake after closing its sockets,
so a material match returned by an in-flight read during cancellation cannot
arrive after the hold-wait gate. It stays closed while awaiting acknowledgment;
there is no local clear/reopen or lift. Final explicit process termination
cancels recovery. A recovered source requires a new authorized
start, not reuse of this ended lease. B1 owns the actual durable journal and
restart/replay semantics; fake-broker tests prove this bridge, not B1 storage.

Strict watchdog reading: the 500-ms observation window begins at current-check
RPC start, not reply completion. Thus RPC latency consumes this budget; it never
extends cached authority. The timer remains independent of the source mutex.

The tagged constructor's optional `LabGatewayIO` collaborators and command-local
`runInputs` permit isolated composition testing. The shipped CLI supplies only
the original sealed/private readers, default fixed-recipient transport and real
kernel peer resolver. There are no flags or environment overrides for these
collaborators. Command tests inject a synthetic disjoint worker UID because an
ordinary unprivileged process cannot be both kernel principals. They keep the
real broker peer/hello, LabSource, LabGateway, accounting, listener and server.
Existing kernel-peer negatives and native caller controls remain unchanged;
these injected-identity tests are not native isolation qualification.

## Assembly and runbook boundary

Build the separate command explicitly; never rename it over the production
executable or add lab members to a production release. The new unit template is
`service/deploy/credential-gateway-lab.service.in`, not an installed unit. It
serves design section 7.4's protected bind/fence/activate/start, placeholder-only invocation,
current-control removal, leak hold/recovery and orderly-stop sequence. B5/RG
must produce and review the actual aggregate, exact paths, modes, digests,
account separation, socket ACLs and native hardening/readback before use.

The `-config` accounting/budget input and `-broker-config` protected mapping use
the existing root-owned 0640 sealed installed-file reader. The five canonical
nonsecret record snapshots (`-activation`, `-authority`, `-fence`,
`-manager-floor`, `-release-set`) use private, current-service-owned 0400 files
with symlink-free ancestors, suitable for systemd LoadCredential snapshots.
B5 must protect the installed ancestry and snapshot ownership. They
contain **no vendor key**. The template copies only these records into `%d`.
The broker remains the sole material custodian; do not put a vendor key into
LoadCredential. Concurrent/current checks remain required; a snapshot is not
current authority. The generation socket's new directory must be service-owned,
non-writable by group/other and free of symlink components. Worker access needs
the separately reviewed ACL; this producer does not change host policy.

## Coverage and exclusions

| Row | Composed controls and negatives | Overlay evidence |
| --- | --- | --- |
| A01 | TestLabBuildTagIsolation; TestLabLeaseBindingsThroughHTTP; unchanged C0 reader/cross-read catalogues | untag-source/contract/intake/command/testkit; open-object; noncanonical-record |
| A02 | TestLabServeHTTPWireCatalogue (all 76 frozen cases plus header controls); TestLabBodyOperatorsThroughHTTP; TestLabServeHTTPResponseGates; TestLabPayloadThroughHTTP; TestLabSSEThroughHTTP | shape/body/GET-body/beta-emission/encoded-response unwiring, exact flags, duplicate fields/members, integer aliases, cache relocation, real intake byte ceiling |
| A03 | TestLabKernelCallerRefusal; TestLabNativeCaller; TestLabRunAdmission; TestLabLeaseBindingsThroughHTTP | wrong-peer; uid-truncation; main-caller-*; caller-retarget |
| A07 | TestLabLeaseBindingsThroughHTTP; TestLabSequenceThroughHTTP; TestLabRenewalThroughHTTP; TestLabVersionRaceThroughHTTP | every lease join and deadline class, current/renew sequence regression, expired renewal, selected ceiling, cadence, per-call version binding |
| A08 | TestLabPostLoadHoldThroughHTTP; TestLabLeakSurfacesThroughHTTP; TestLabRunHoldBinding; TestLabRunStartupFloor; TestLabRunLateLeak | post-load/inbound/response scans; each hold-result binding; UNKNOWN/lost ACK; same ID; active floor; command wait/drain |
| A09 | TestLabAuthorityCancellationThroughHTTP; TestLabWatchdogAgeThroughHTTP; TestLabRunAuthorityTeardown; existing TestLabReadStall | source-context binding; independent 500-ms watchdog including RPC age; command listener/all connections; broker closure; body cancellation |

[Per-gate coverage map](LAB-V0-COVERAGE.md) lists every executable overlay and its
named composed HTTP/command test, or the build-graph test for tag gates. A
classifier-only kill is not credited as composed evidence. C0's exhaustive
operator/parser tests remain supplemental; their length-counter test is not a
claim that a padded record is valid at a frozen maximum. The byte-ceiling overlay
now drives the real HTTP handler at 128 MiB and one byte over, rather than only
calling the length helper. Every existing test name is retained.

The brief supplies acceptance rows, **not an attack-surface catalogue table**;
that missing surface-table input is a brief gap, not universal coverage. C0's
operator catalogue is reused for the frozen parsed surfaces and HTTP headers.
Other acceptance-row components are explicitly out of this unit's G1 clause:
B1 durable storage/holds/finite-plan accounting, B2 trusted time/fence/floors,
B3 authenticated root capture/unbind/lift, M1 executor/seccomp, B4 integrated
Q1–Q6 and lifecycle/encoding scans, B5/RG release/install, and Q native owner
qualification. A04–A06 and A10–A12 are assigned to those other unit rows, not
silently covered by local gateway tests. Production reviewer tests stay intact.

## Tools and verification

Use Go 1.26.8 (matching the pinned workflow) for fix-round-2 evidence, Python 3 for source-overlay controls and gofmt
for the new Go files. Run **in an isolated full checkout** with absolute private
HOME, USERPROFILE, XDG_CONFIG_HOME, XDG_CACHE_HOME, GOCACHE, GOMODCACHE, GOPATH,
TMPDIR/TMP/TEMP, unset GOTELEMETRYDIR, and pin GOTOOLCHAIN. Place every directory,
fixture and log under task-owned `.temp/`; a relative HOME is unsafe. Check host
load before full/race suites and wait at load 10 or higher. Nothing here calls a
vendor: HTTP tests use injected in-memory transports and local Unix sockets.
The only fake broker material is C0's public non-vendor sentinel.

| Tool | Exact entry point from isolated repository root | Output |
| --- | --- | --- |
| Production tests | `go -C experiments/model-proxy/service test -count=1 ./...` and `go -C experiments/model-proxy test -count=1 ./...` | private test logs |
| Tagged tests | `go -C experiments/model-proxy/service test -tags gateway_lab -count=1 ./...` and `go -C experiments/model-proxy test -tags gateway_lab -count=1 ./...` | private test logs |
| Race tests | `go -C experiments/model-proxy/service test -race -tags gateway_lab -count=1 ./...` and `go -C experiments/model-proxy test -race -tags gateway_lab -count=1 ./cmd/credential-gateway-lab` | private race logs |
| Production command repeat race | `go -C experiments/model-proxy test -race -count=3 ./cmd/model-proxy` and the same command with `-tags gateway_lab` | private race logs |
| Production build | `go -C experiments/model-proxy build -o /absolute/task/.temp/credential-gateway ./cmd/model-proxy` | scratch production binary |
| Lab build | `go -C experiments/model-proxy build -tags gateway_lab -o /absolute/task/.temp/credential-gateway-lab ./cmd/credential-gateway-lab` | separate scratch lab binary |
| Overlay controls | `python3 experiments/model-proxy/service/scripts/check-lab-plants.py --output /absolute/task/.temp/lab-plants` | replacement files, overlays, per-mutant logs and results.json; optional `--filter NAME` for a bounded rerun |
| Formatting | `gofmt -l experiments/model-proxy/service/lab*go experiments/model-proxy/cmd/credential-gateway-lab/*.go` | no paths when clean |

The overlay runner never edits the original source. Only a nonzero test exit
with its named failing test counts as killed; build errors and panics do not.
Any survivor is reported as such. See the producer handoff for exact checked
commits, real exits, surviving bounds if any and unresolved integration gates.

## Production test scheduling regression

Only two existing production **test** files change in fix round 2; production
runtime, configuration, workflow and release artifacts do not. The old
`TestManagedSourceRecovery/idle` asserted one broker connection since construction.
The real managed holder intentionally reconnects before first use when setup
has aged that connection by at least 250 ms. Accounting setup occurs after
connecting, so legitimate startup recovery could trip the idle assertion. On
unchanged main 87e8a7e4, a test-only 500-ms provisioning delay reproduced the
original failure: one connection/zero checks before first use, then two
connections/one request/one check immediately after the first admitted response.
This is not evidence of a lab runtime bypass.

The test now snapshots counts **after** admission and consumes broker check
notifications across the one-second idle horizon within its existing 1.5-second
wait budget. The idle-aged control deliberately ages provisioning before first
use; that setup-only timer induces the race, it is not the fix. The assertion
path adds no sleeps or wider budget. It still fails if autonomous polling stops
or if idle recovery replaces the admitted connection. Exact original-count and
poll-disabled source overlays must fail the named production test. All existing
production test names remain present. This test-only exception to the tagged
write scope is required by the round-2 brief.
