# g2-run: the step engine (E1, runner core)

`deploy/g2run` runs a ledgered host install as a sequence of typed steps. It replaces a shell runner and shell step
bodies. Shell bodies kept producing one class of defect, a value evaluated by an interpreter (an arithmetic context, an
array subscript, a runtime-built option, an executing option of a program). This package removes that class instead of
chasing it.

## The rule

No value is ever evaluated by a shell or by any other interpreter.

- **Values are typed.** Every value is a Go value that a strict decoder parsed once and refused by name if malformed. The decoder is `StrictJSON`: unknown fields, trailing data, duplicate keys and non-canonical encodings are refused.
- **Steps are compiled.** A step is an ordered list of `Op` values compiled into the signed binary. Every op's `Validate` runs before any op of the step runs.
- **One exec path.** External programs are reached only through `ExecFixed`: an absolute path from the plan's program table, argv built from typed fields, the fixed environment `FixedEnv`, stdin from /dev/null and no shell.
  - The output file is opened before the program starts.
  - The kernel sets the credentials (`Cred`), with no runuser or setpriv.
  - The table refuses shells, interpreters and the programs that run other programs or do file work: `sh`, `python3`, `env`, `find`, `sed`, `install`, `runuser`, `setpriv` and the like.
- **Enforced in tests.** A static test fails if any non-test source of the package starts a process outside ExecFixed. A planted control proves the checker sees one.

## The on-disk discipline (`g2-run -state DIR STEP`)

| Order | Check | Refusal |
| --- | --- | --- |
| 1 | umask 077, read back | 90 |
| 2 | arity; a step of the compiled plan | 64, 65 |
| 3 | `DIR/run.lock`: exists, regular, opened read-only (never created), exclusive non-blocking flock | 66, 67 |
| 4 | DONE starts with the plan's bootstrap line | 69 |
| 5 | normal step: no STOPPED, CLOSED or INFLIGHT; follows exactly its predecessor in its purpose's sequence; admitted by the exclusive mkdir of INFLIGHT | 70-75 |
| 5 | recovery step: eligible per its rule (after a STOP, or after a named last step); admitted by an append to CLOSED | 76, 77 |
| 6 | the package: the pin, the tarball, its SHA256SUMS member, the required files, every listed digest (strict format, regular files) | 80-84 |
| 7 | the typed parameters (`pkg/<ParamsFile>`) | 85 |
| 8 | every op validates, then every op runs in order | 86, 1 |
| 9 | success: `OK STEP` appended to DONE, INFLIGHT removed | - |

Every refusal before admission changes no state; the tests compare the whole state tree before and after.

After admission, any error or panic is a STOP: `epoch-N STOP STEP rc=N` is appended to STOPPED, and INFLIGHT (or CLOSED) stays. A step is a Go function returning an error, so there is no completion sentinel and no abandoned body.

## Units

| Unit | Content |
| --- | --- |
| E1 | This package: the runner, the latch, the package check, ExecFixed, the plan and op interfaces, the tests |
| E2 | The typed operations: exact-state checks, ledger calls, the age backup, the node route, run-as checks |
| E3 | A concrete plan and its parameters type, and the `deploy-kit g2-run` subcommand |
| E4 | The witness-class map and negative suite, and rehearsals through the engine |

Instance values (names, pins, paths) never appear in this package. They arrive in the parameters file.
