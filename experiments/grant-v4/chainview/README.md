# Grant v4 observation, freshness and risk decisions

Experimental comparisons for **LIP-0022 Draft, sections 1–6**. This is a LAB
module, with no dependency on `wire` or an earlier grant module. All cited LIPs
remain **Draft**, with co-author agreement pending. Passing comparisons do not
admit a real grant, qualify node reads, or authorize a reservation or effect.

The public specification pin is
[`45054797ee9ad3e38213e067051dfbd3eb2a21a1`](https://github.com/relux-works/swarma-link-spec/tree/45054797ee9ad3e38213e067051dfbd3eb2a21a1):
[LIP-0022](https://github.com/relux-works/swarma-link-spec/blob/45054797ee9ad3e38213e067051dfbd3eb2a21a1/lips/LIP-0022-observation-freshness-and-risk.md),
[LIP-0021](https://github.com/relux-works/swarma-link-spec/blob/45054797ee9ad3e38213e067051dfbd3eb2a21a1/lips/LIP-0021-name-ownership-and-history.md),
[LIP-0008](https://github.com/relux-works/swarma-link-spec/blob/45054797ee9ad3e38213e067051dfbd3eb2a21a1/lips/LIP-0008-grant-v4.md)
sections 3, 3.1, 4, 6, 7 and 7.1, and
[LIP-0020 W7.6](https://github.com/relux-works/swarma-link-spec/blob/45054797ee9ad3e38213e067051dfbd3eb2a21a1/lips/LIP-0020-grant-v4-wire-registry.md).
The implementation plan is restricted to what the drafts' own buildability
tables permit on stated tips, octets, times, heights and numbers.

## API and assumptions

- `CheckObservation` checks the pinned genesis, both endpoint tips and an
  optional tip before an effect. `MovementObserved` is an independently
  established input: a known move-and-return refuses. Equal endpoints cannot
  discover a hidden move or freeze pending transactions.
- `FactBelongs` checks block height, active-chain hash and stated transaction
  membership. `BlockOnChain` checks block membership alone. Callers must supply
  **all facts from one observation**; these functions establish no provenance.
- `CheckHealth` checks the reading node and every configured comparison.
  Separate endpoint URLs do not override source labels. One healthy conflict,
  even with the reading node's source label, refuses despite agreeing nodes.
  The configuration and stated labels are trusted operator inputs, not proofs
  of independent processes, storage, validation or peers.
- `CheckClock` is the pure clock predicate. `Clock.Observe` additionally uses
  a `ClockStore` to preserve the largest used reading and each first sight.
  Pass independently computed profile findings in `ClockInput.Findings`; they
  are stated inputs, never substituted passing node reads. Re-read the clock
  and tip immediately before a reservation or effect, run `CheckObservation`
  on that tip, then run the clock predicate again. No effect is performed here.
- `CheckRecent` checks the recent block and `R < A <= R + K`. Its anchor height
  is an input of an **already established confirmed anchor**. Use `FactBelongs`
  for its transaction membership; height alone does not establish it. `RecentForIssuance` selects exactly the coherent, healthy
  issuance observation's tip, returning no tip on refusal. The grant member
  that commits it remains a gap.
- `CheckDepth` requires the same chain and uses `MAX(signed minimum, operator
  floor)`. A pending transaction has no depth. The class's two minima are inputs.
- `WindowAllows` checks the half-open height window and its lower bound at `R`
  (LIP-0008 Draft 7.1). That draft assigns no code to this predicate.
- `FirstRefusal` selects **one** code in the section 6 table order. The first six
  precede grant findings. `RECENT_BLOCK` must precede rules using `R`; anchor
  window and evidence depth checks remain at their B6.2 call sites. Unknown
  codes return an error, rather than inventing an order for another rule.

The clock and risk assumptions are explicit: `now` is trusted nonnegative whole UTC seconds;
header age is `max(0, now - headerTime)`, seen age is `now - firstSight`, and
both must be below the selected cutoff. Rollback below the durable kept mark
refuses; a header more than `S` ahead refuses. Source independence is the
operator's statement; agreement cannot defeat a shared eclipse. The evidence
minimum is the maximum of the signed minimum and operator floor.

`Parameters` has **no defaults or production values** for `S`, `LAG`, `K` or
either age cutoff. Action class is an input from the service's action profile;
an absent or unrecognized class uses the first class. Nothing classifies an
action, lets a caller lower its class, or freezes the provisional measurements.
Arithmetic uses nonnegative `int64` times/heights and avoids overflow at their
upper bound. It interprets stated hash strings only by equality.

## Kept state

`ClockStore.Transact` atomically updates the mark and the first-sight map. Both
implementations reject a decreased mark and changed/removed first sights, and
copy callback state so callers cannot mutate retained state after returning.
`MemoryStore` is for tests and has no durability guarantee.

`FileStore` targets a **trusted local Unix filesystem**. It locks a stable
sidecar file and reloads both records under that lock on every access. Version-2
snapshots carry a monotonic generation, the kept mark and all first sights. A
separate sentinel carries **both generation and kept mark**. Its directory must
be disjoint from the snapshot directory (neither may contain the other), so
restoring only the data directory cannot restore the sentinel. The default is
`<data-directory>.continuity/<snapshot-basename>.sentinel`, a sibling directory.
`CreateFileStoreAt` / `OpenFileStoreAt` accept explicit paths in disjoint existing
directories. Use canonical paths; do not alias paths, remove the lock file or
replace directories while any process is using the store.

For **each record**, a durable `PENDING` sidecar is written and file/directory
synced **before** the temporary data file is renamed. The temporary file is
written and fsynced, renamed, and its directory fsynced. Only then is the marker
cleared and that unlink directory-synced. Any failed step returns
`STORE_UNCERTAIN`; `Clock.Observe` returns that named code and an error, never a
passing decision. A retry/reopen/restart with a marker repeats the write barrier
on the visible record. Every access, including a no-op, also fsyncs each record
and its directory even when the marker appears absent: an unlink whose sync
failed must not become a passing retry. No decision is available before fresh
successful barriers. A repaired filesystem permits automatic recovery.

Commit order is **snapshot first, then sentinel**, each through the barrier
above. After settling pending I/O, open and every transaction compare records:

| Relation | Result |
| --- | --- |
| Equal generations and equal marks | Open |
| Snapshot exactly sentinel + 1, snapshot mark at least sentinel mark | Interrupted commit: durably roll sentinel forward; open without operator |
| Sentinel ahead, gap greater than 1, decreased/inconsistent mark, or missing sentinel | `STORE_CONTINUITY`; no decision |

`CreateFileStore` is explicit initialization and refuses replacement. The data
parent must exist; it creates the default sibling directory with mode `0700`.
State and marker files have mode `0600`. `OpenFileStore` never initializes or
migrates missing/version-1 records. Interrupted *initialization* is not an
acknowledged store: missing records still require operator inspection. Ordinary
commits after successful creation recover from process crashes without operator
intervention. Remote filesystems and storage hardware remain unqualified.

### Explicit operator recovery

Stop store users and inspect the snapshot, separate sentinel and existing audit.
Recovery is an explicit command, never a fallback from `OpenFileStore`:

```sh
mkdir -p .temp/chainview
go -C experiments/grant-v4/chainview build -o "$PWD/.temp/chainview/clock-store-recover" ./cmd/clock-store-recover
.temp/chainview/clock-store-recover -snapshot state/data/clock.json -sentinel state/data.continuity/clock.json.sentinel -audit state/data.continuity/recovery.json
```

The command durably logs a timestamped `started` event **before** altering state
and a `committed` event after both records are durable. It chooses the **MAX**
mark from every present snapshot, sentinel and prior audit event, and a generation
above every present generation. It never lowers a mark, retains every available
snapshot first sight, and can repair a missing sentinel. Malformed present
records and a missing snapshot refuse; lost first sights cannot be reconstructed
from the sentinel. Before creating a lock or writing anything, recovery compares
all seven managed names: snapshot, sentinel, both pending markers, snapshot lock,
audit and audit pending marker. Paths are cleaned and made absolute, resolving
parent-directory symlinks without following the final component. Any duplicate
returns `RECOVERY_PATH_COLLISION` without changing filesystem entries.
Recovery-log failure prevents unaudited mutation. These are
operator-owned local artifacts, not remote witnesses or a trusted hardware
anchor. Back up the audit and continuity directory separately from the data dir.

B3.7 writes a first sight for a coherent pinned observation with a clock at or
above the mark **even when health, skew, age or another rule refuses**. A void,
wrong-chain or below-mark observation writes no sight. The mark advances for a
new sight or successful decision; an existing-tip refusal leaves it unchanged.
First sights survive restart and tip return and are never evicted. This module
stores no closure and cannot erase a closure independently validated elsewhere.

**GAP: a deliberate same-authority rewrite of both files together with the clock
is outside the guarantee; LIP-0022 B3.2 assumes trusted storage, and the operator
owns storage integrity.** The separate sentinel detects accidental partial
restoration only; it provides no rollback resistance. There is no implicit reset,
hardware durability attestation or production storage qualification. Observation
cadence and recovery of lost first sights remain outside this implementation.

## Vectors and validation

`testdata/observation-vectors.json` is an **unchanged** copy of the public
specification pin's `vectors/LIP-0022/observation-vectors.json`.
Git blob: `08784b9ed7f8dacd415a1ecedf709c5a481972fd`; length: 102471 octets.
SHA-256: `5f6b4c735b6e519c892518e0ade689f4055e211aa4693f2b6ca93858e756518c`.
The fixture is CC BY 4.0; see its [attribution notice](testdata/NOTICE.md).
It contains **97 vectors over 28 proposed rules**, including **10 sequences**
and **6 order vectors**. Test-only numeric values come from that fixture.

`TestV4ObservationVectors` checks the pinned bytes, unique IDs, all results and
stated passing neighbours, with no skips. Every refused comparison runs its
named passing neighbour beside it. All sequences run against memory and files,
including actual reopen at their restart steps, and compare exact end states.
The Python second reader shares no implementation code with Go: it computes
all vectors from the draft rules and compares its results to **both** the draft
expectations and actual exported Go results. Any disagreement fails visibly.

Additional coverage includes `TestV4DualTimeAndRisk`, `TestV4ClockRollback`,
`TestV4ObservationMovement`, `TestV4NodeSources`, `TestV4HealthBoundaries`,
`TestV4RecentBoundaries`, `TestV4DepthMaximum`, `TestV4WindowBoundaries` and
`TestV4FirstRefusal`. Boundary triplets cover both ages, skew, mark, header lag,
comparison lag, recent-block distance, anchor-above-recent, depth, height-window
edges and fact height. File-store tests cover callback aborts, invalid state,
immutable sightings, aliases, actual process exit/reopen, concurrent writers and
a real write-permission refusal followed by repair.
`TestReviewDirectorySyncRetry` injects temp-fsync, rename, directory-fsync,
marker-clear and clear-directory-sync failures for **both** records, checking
same-handle retry, a new handle and an actual restarted process beside repaired
positive controls. `TestV4UncertainNoOp` prevents admission from a visible but
uncertain update. `TestReviewDirectoryOpenRetry` retains the real permission
witness. `TestReviewRolledBackStoreRefused`,
`TestReviewRestoredFileAfterProcessRestart` and `TestV4MissingSentinelRefused`
exercise partial restore, generation gaps, inconsistent marks and missing
continuity. `TestV4InterruptedCommitOpens` checks automatic +1 recovery.
`TestV4CommitCrashPoints` actually exits a process after every filesystem step
of an ordinary commit and reopens without operator intervention.
`TestV4OperatorRecoveryMaximum` and `TestRecoveryCommand` cover audited explicit
recovery and forbidden unaudited mutation. `TestV4BothFilesRestoreDocumentedLimit`
records the deliberate both-records-and-clock restore limit.
`TestDeltaRecoveryDerivedPathCollision` and
`TestDeltaRecoveryCommandDerivedPathCollision` refuse both destructive sidecar
overlaps beside disjoint-audit recovery controls. `TestRecoveryManagedPathCollisions`
covers every feasible pairwise equality before lock creation, and
`TestRecoveryCanonicalPaths` checks parent aliases and cleaned relative paths. These process/fault
controls do not qualify physical power loss, storage hardware or real nodes.

| Mutant | Narrows the gate to | Named failing test |
| --- | --- | --- |
| MIN depth instead of MAX | Both asymmetric minima with depth just below the maximum | `TestV4DepthMaximum` |
| Allow a clock below the mark | Known/new tip rollback and unchanged kept state | `TestV4ClockRollback` |
| Report the lower of two findings | Both input orders for every pair of profile codes | `TestV4FirstRefusal` |
| Collapse distinct sources at the same tip | Equal tips do not remove source independence | `TestV4NodeSources` |
| Allow age equal to the cutoff | Exact cutoff refuses for header and seen age, both classes | `TestV4DualTimeAndRisk` |
| Skip the directory fsync | Both records must cross the post-rename directory barrier | `TestReviewDirectorySyncRetry` |
| Admit an uncertain no-op | Visible same-state retry cannot authorize before a fresh barrier | `TestV4UncertainNoOp` |
| Skip sentinel comparison | Partial restore, mark mismatch and >1 gap refuse | `TestReviewRolledBackStoreRefused` |
| Drop derived audit sidecar check | Snapshot/sentinel named as the audit pending marker cannot be removed | `TestDeltaRecoveryDerivedPathCollision` |
| Treat missing sentinel as fresh | Loss of continuity never initializes implicitly | `TestV4MissingSentinelRefused` |

The runner requires exit **0** from each unchanged control and exit **1** with
the named failing test from each Go overlay. Compilation/setup failures and
skips are not kills. All ten mutants are killed; there are no survivors. The source-collapse and
exact-age overlays also export incorrect vector results that the second reader
rejects.
It also requires the independent reader to refuse a deliberately incorrect
passing Go result for the header `S+1` vector, with a valid-result control.

## Tools and commands

Run from the repository root with Go **1.26.10**, Python **3.14.4**, `git`, and
an available C toolchain for Go's race detector. This module has no external
requirements or local replacements. Commands below use no node or network.
Set `GOTOOLCHAIN=local`, `GOWORK=off`, `GOPROXY=off`, and `GOSUMDB=off`.
Use a short task-local `TMPDIR` and task-local Go caches; no downloaded code is
needed. `.temp/` is ignored scratch space.

```sh
mkdir -p .temp/chainview
# Format check: empty output is required.
gofmt -l experiments/grant-v4/chainview/*.go experiments/grant-v4/chainview/cmd/clock-store-recover/*.go
go -C experiments/grant-v4/chainview vet ./...
CHAINVIEW_VECTOR_RESULTS="$PWD/.temp/chainview/go-vectors.json" go -C experiments/grant-v4/chainview test -race -count=1 -json ./... > .temp/chainview/tests.json
python3 -B experiments/grant-v4/chainview/scripts/check-vectors.py --go-results .temp/chainview/go-vectors.json
go -C experiments/grant-v4/chainview build ./...
# The scratch directory below must not exist before the control run.
python3 -B experiments/grant-v4/chainview/scripts/check-mutants.py --scratch .temp/chainview/mutants
python3 -B .scripts/check-module-graph.py
python3 -B .scripts/check-strict-module-snapshots.py
python3 -B .github/scripts/check-public-hygiene.py
```

Go JSON test output and vector results go to `.temp/chainview/`; mutation
commands, PIDs, exit codes, overlays and control logs go to its `mutants/`.
The module-graph and hygiene scripts validate repository inventory/publication
boundaries. The dedicated hosted workflow runs formatting, vet, race tests,
the independent reader, build and narrowing controls and preserves evidence.
Git verifies the unmodified fixture bytes and unchanged sibling-module scope.

## Explicit gaps and remaining work

- **GAP: node reads.** No own-node/comparison-node RPC adapter, transaction
  index read, pending-transaction snapshot, or detector of an unstated
  move-and-return. Those await the observation-profile run on the pinned build.
- **GAP: action classes.** The service action profiles must assign classes;
  this module only accepts a stated class and applies its cutoff.
- **GAP: evidence classes/minimum depths.** No tiers or production minima
  are invented; callers supply the numbers for the appropriate chain/class.
- **GAP: pin members.** No owner pin inside grant, notary or pointer objects;
  their schemas/members await their drafts. No grant parser or wire change.
- **GAP: `swarma` extraction.** The rule defining those member octets is open;
  this module does not extract or interpret them.
- Owners' acceptance, co-author agreement, measurements, real-node and storage
  qualification, recovery of lost first sights and downstream integration remain pending.
