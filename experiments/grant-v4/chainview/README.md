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
sidecar file, reloads state under that lock on every access, writes a temporary
file, syncs it, atomically renames it and syncs its directory before success.
New state files have mode `0600`. The parent directory must already exist.
`CreateFileStore` explicitly initializes new state and refuses replacement;
`OpenFileStore` refuses missing or malformed state and never silently resets it.
Separate instances/processes using the same canonical path serialize updates.
Do not alias the path, remove the lock file, or replace the directory in use.
An I/O error must prevent admission, including an uncertain directory-sync
result after rename. Remote filesystems and storage hardware are unqualified.

B3.7 writes a first sight for a coherent pinned observation with a clock at or
above the mark **even when health, skew, age or another rule refuses**. A void,
wrong-chain or below-mark observation writes no sight. The mark advances for a
new sight or successful decision; an existing-tip refusal leaves it unchanged.
First sights survive restart and tip return and are never evicted. This module
stores no closure and cannot erase a closure independently validated elsewhere.

Loss or restoration of an older valid copy is not detectable here. Recovery
policy and the observation interval are open in the draft; there is no implicit
reset, hardware durability attestation, or production storage qualification.

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
They do not simulate every power-loss point or qualify real node behavior.

| Mutant | Narrows the gate to | Named failing test |
| --- | --- | --- |
| MIN depth instead of MAX | Both asymmetric minima with depth just below the maximum | `TestV4DepthMaximum` |
| Allow a clock below the mark | Known/new tip rollback and unchanged kept state | `TestV4ClockRollback` |
| Report the lower of two findings | Both input orders for every pair of profile codes | `TestV4FirstRefusal` |

The runner requires exit **0** from each unchanged control and exit **1** with
the named failing test from each Go overlay. Compilation/setup failures and
skips are not kills. All three mutants are killed; there are no survivors.
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
gofmt -l experiments/grant-v4/chainview/*.go
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
  qualification, lost-store recovery and downstream integration remain pending.
