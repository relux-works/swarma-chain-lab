# G1b: lab-only per-attempt gateway accounting

Construction only. Not production acceptance, native qualification, a release,
owner consent, permission to enroll a credential or permission to call a vendor.
All new Go files require `linux && gateway_lab`; the ordinary gateway, installer,
OAuth contract, defaults and release template remain unchanged.

## Authority and book/spec disposition

Broker `9f1f90faadb6f51b3c4767c8276a4c3b5e0d1066`,
`docs/lab-profile-v0.md` §5.1 G1b, C0b bounded invocation and C0e per-attempt
sections govern. [Frozen provenance](service/testdata/lab-v0-c0e/PROVENANCE.md)
and its unchanged `bounded-invocation.md`, `attempt-accounting.md`, README and
surfaces/index define the byte formats. Existing [G1](LAB-V0.md) and
[the gateway contract](../../docs/gateway-service.md) still govern transport,
API-key custody, holds and revocation. Book dispositions are **same** as G1:
swarma-docs `bc1132c9d9be60864ef7195efa83215357ad3011`,
`book/ru/05-polzovatel-i-set.md`, `book/ru/09-uchetnye-dannye.md`; the declared
`book/ru/12-interfeysy.md` lab conflict is not a new production amendment.
C0e refines the tagged implementation only. No new approval ceremony or wire
surface is introduced.

## Protected local interface

The command now requires `--attempt-root ABSOLUTE_PHYSICAL_DIRECTORY`, in
addition to G1's existing protected inputs. The directory is service-owned 0700;
inputs are regular, single-link, service-owned 0400 files, with no symlinks.
Only B5/B1's trusted placement path may install these inputs. A worker never
supplies a path, a plan, a receipt, a price, an approval or a timestamp.

| File | Content / authoritative producer |
| --- | --- |
| `plan.json` | C0b full plan P / authenticated B5 preparation |
| `approval.json` | sealed off-VM A / authenticated B5 preparation |
| `release.json` | sealed R, exact gateway price member and manager executor asset / approved RG aggregate |
| `launch.json` | exact C0 launch L / B5/M1 |
| `price.json` | unchanged published C0e model-price bytes / approved RG member |
| `access.json` | complete owner-sealed human-only access/cap attestation / B5 |
| `approved-plan.sha256`, `approved-release.sha256`, `approved-access.sha256` | exact `sha256:` digests, no LF, from B5's authenticated owner baseline; never inferred from a hash/channel string |
| `available-cap-micro-usd` | canonical positive integer, no LF: B5's fresh protected available-cap readback, at least the plan budget and no greater than the attested hard cap |
| `client-profile.json`, `wire-profile.json` | exact approved frozen profile bytes / B5 |
| `start-operation-id`, `start-id` | exact known C0c native IDs, no LF / B5/M1 |
| `start-observation.json` | complete final response of B1's accepted C0d admission pair |
| `accepted-start.sha256` | exact digest of that accepted response from B1's protected baseline, not a self-authenticating observation |

File names and the cap integer are private placement interfaces, not additional
C0 formats. B5/B1 must bridge them in the approved native assembly; this unit
neither generates authenticated owner approval nor publishes a native result.
Actual NTS/fence/C opening, off-VM freshness, complete native owner rosters,
executor/client/archive measurement, B1 publication-pair acceptance and B4
qualification remain their respective units' gates. Matching local fixture
hashes or timestamps does not establish any of them. Missing inputs refuse;
there are no defaults or fixture fallbacks in the command.

1. After authenticated preparation but **before** M1 preauthorization, invoke
   `credential-gateway-lab --prepare-attempt-group --attempt-root "$ROOT"`.
   This creates `accounting/group.json` once, with a kernel CLOCK_BOOTTIME latch,
   current boot and exact P/A/R/L/price/native-ID joins. Failed or repeated
   creation cannot replace G or reset elapsed time. M1 must consume protected G.
2. B1 places the accepted native admission response/baseline. Start the command
   with the existing G1 flags plus `--attempt-root "$ROOT"`.
   The source's complete release/context/caller tuple joins the native response;
   its managed execution ID must equal the exact accepted native start ID.
   No listener opens without these bindings and unexpired approvals/group time.
3. For read-only reconciliation, invoke
   `credential-gateway-lab --attempt-status --attempt-root "$ROOT" --operation "$OP" --plan-sha256 "$FULL_P_DIGEST" --ordinal "$ORDINAL"`.
   It returns the exact protected current C0e ledger snapshot bytes. Hash all
   stdout bytes for the authoritative head; no wrapper/newline is added. B4's
   accounting `QRow.effect_sha256` must equal that digest and its R/context/start
   joins must match B1's current baseline. Status reuses the protected no-alias, same-inode, service-owned 0700
   store checks and verifies the current kernel boot. It never leases, forwards, settles,
   refunds, repairs or reopens. UNKNOWN/unresolved status exits 2; wrong tuple 1.

## Forward and settlement

Every admitted billable POST gets one serialized ordinal. No active queue exists:
a busy allocation/settlement critical section refuses immediately rather than
letting another request wait for a later admission opportunity.
Before any upstream byte: check current protected inputs, source, approvals,
qualification, wall/count/USD limits; reserve exactly 128000 output tokens and
`10.560000` USD from the pinned million-token context and greatest input/cache
rate plus full output. Snapshot append/file+directory fsync, protected head CAS,
head rename and directory fsync must all succeed. CAS is checked before writing
and again before publication. Failed persistence leaves full exposure held and
closes UNKNOWN; it never grants a forward. The already-existing daily meter is
an additional conservative backstop, not the C0b invocation count or settlement.

The lab HTTP transport is HTTP/1 only, nonpersistent, with no replayable GetBody;
redirects remain refused. Any allowed client retry returns through this gate,
gets a new ordinal and full reservation, and must still fit every bound.
Credential-free policy GET is not a billable attempt. G1's exact eleven flags,
material scans, genuine error/SSE bytes and durable hold bridge remain active.

Authoritative settlement combines message_start input/cache counters with the
**last cumulative** message_delta output, requiring message_stop, request ID,
approved model and standard tier. Both an explicit six-counter projection and
an explicit nested `cache_creation` 5m/1h pair with usage service_tier are mapped;
missing/extra billing dimensions, missing cache partitions, inconsistent totals,
regressing counters or ambiguous tier close UNKNOWN. No absent counter becomes
zero. A nonzero initial output counter is retained until replaced by a greater
cumulative delta. Five disjoint exact integer rate terms are summed and rounded
up once to micro-USD. No text/prompt/auth/credential is persisted.

Timeout, disconnect, cancellation, missing/partial/inconsistent usage or uncertain
settlement charges the full reservation and sticks UNKNOWN. A normal complete
settlement releases only proved unused exposure. Count equality permits the
last allocated ordinal to finish; output/cost/wall equality closes active use.
There is no extra cleanup grace or retry beyond a bound. UTC expiry is also
latched to a local monotonic deadline, so a wall-clock rewind cannot extend it;
this does not grant NTS authority. Deadline retirement runs independently of the
ledger mutex and filesystem persistence, using both a local deadline and kernel
CLOCK_BOOTTIME polling. A stalled startup/reservation fsync cannot retain broker
authority, listeners or downstream connections past the earlier bound. Once I/O
returns, an allocated but unsent attempt remains fully charged UNKNOWN. Idle
whole-group exhaustion after complete settlement is stopped/exit 0, not a refund
or a new group. No extra forwarding/cleanup authority is granted while durable
uncertainty is being recorded.

## Durability and refusal decisions

`accounting/` has an exclusive process lock, immutable numbered CCJ snapshots,
`claimed`, and an atomically published `head`; `head.next` is never accepted as a
committed head. Full history, contiguous ordinals, sequence/hash prefix,
immutable admission joins, reservation amounts, usage/settlement and first-bound
invariants are revalidated. A missing/torn/orphan/rewound/foreign prefix is UNKNOWN,
not empty. One active allocation is possible. No in-place snapshot rewrite,
retention, truncation or automatic repair exists.

A crash after reserve consumes the ordinal even before send; a crash after send
but before settle consumes its full allocation. Restart is always status-only:
unresolved reserve becomes full UNKNOWN; a conclusively settled/open prefix is
closed without another forward. Unknown/stopped never opens under a retry,
renewed approval or reboot. Reboot/clock mismatch is closed, not a reset. On a
filesystem error that prevents publishing UNKNOWN, durable outstanding reservation
plus refused reconciliation remains held; the program does not claim an
unwritten settlement or refund it. Authoritative owner recovery is separate.

The optional `LabAttemptIO` collaborator exposes actual file Sync/Close calls for
in-package fault injection only. The shipped command has no flag/environment
bypass for them; only private trusted test inputs inject those collaborators.
Tests observe pre-forward fsync and
exclusive immutable writes using Linux `strace`; simulated process death alone
would not prove a power-loss barrier because kernel page cache survives it.
The durability oracle waits for controlled downstream cancellation, child exit
and tracer exit before reading logs; an inode appearing is not a trace-output
barrier. Separate untraced SIGKILL cases exercise both actual crash points.

## Verification tools

Use Go 1.26.10 and absolute task-owned HOME/config/cache/tmp plus a populated
scratch checkout. Limit `GOMAXPROCS=2`, `-p 2`; defer heavy work at load >=10.
No test uses a credential other than the public frozen marker/worker placeholder,
and no test calls a vendor. Unix fake broker and loopback HTTP/TLS only.

| Tool / command from the service module | Purpose / outputs |
| --- | --- |
| `go test -p 2 -tags gateway_lab ./...` | parser catalogue and composed HTTP tests; terminal verdict |
| `go test -p 2 -race -tags gateway_lab ./...` | tagged concurrency checks; terminal verdict |
| `go test -p 2 ./...` | unchanged default graph and production tests |
| `python3 scripts/check-lab-attempt-plants.py --output "$NEW_ABSOLUTE_SCRATCH"` | G1b source overlays, named composed failures, exact exits and `results.json` |
| `python3 scripts/check-lab-plants.py --output "$NEW_ABSOLUTE_SCRATCH"` | retained G1 overlays; UID class includes the new redundant native caller guard |
| `go test -p 2 -tags gateway_lab ./cmd/credential-gateway-lab` (parent module) | real command/Unix broker, deadline, replay and process-crash tests |
| `strace -ff -ttt -yy --kill-on-exit -e trace=fsync,renameat,renameat2,openat,write ...` | durability test's owned child syscall oracle; private test scratch traces, no raw prompts/credentials |

[Coverage](LAB-G1b-COVERAGE.md) maps the unit's acceptance allocation, named tests
and narrowing mutants. Parser tests are not mislabeled as composed forwarding
proof. Synthetic local gates do not replace owner-run B4 Q evidence or native
release/acceptance. No native service, user, network ACL or production store is
created or adopted by these tests.
