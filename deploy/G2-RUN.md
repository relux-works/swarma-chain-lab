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
- **A closed program set.** A plan may name only programs registered by a reviewed typed wrapper (`RegisterProgram`, called from init functions). A denylist of interpreters and of tools that run other programs (`sh`, `python3`, `env`, `find`, `sed`, `install`, `tar`, `rsync`, `ssh`, `systemd-run`, `chroot`, `nsenter`, `unshare`, `flock`, `git`, `make` and more) is only the backstop.
- **Programs are pinned at construction.** The executor copies the table. Each link is resolved once: the link and every directory on both paths must be root-owned and closed to writes. The resolved file must be a root-owned regular file, neither setuid nor setgid and not group or other writable. Go cannot set no-new-privileges for one exec, so a set-id program is refused outright. The pinned file runs, with argv[0] kept as the table path so that a multicall binary picks the right tool.
- **Commands fail closed.** A status outside the command's `WantRC` (default `{0}`) is an error, so an operation that ignores the result still stops. Values travel as `Operands`: each is a `ValidOperand` (never empty, never starting with `-`, no NUL, CR or LF) and follows `--`.
- **Output stays where it is declared.** Output is a path relative to a declared output root, opened with openat2 beneath that root (no symlink, no magic link, no `..` or `//` spelling, never the state root where the runner's own files live). It is opened before the start, must be a regular file owned by the runner, and is set to 0600.
- **Capture is bounded.** Captured output is capped at 1 MiB; more is an error, and an endless producer is stopped.
- **No leaked descriptors.** Every descriptor the runner holds, the run.lock flock included, is close-on-exec; a test lists the child's descriptors.
- **Enforced in tests.** A static test resolves import aliases and allows exec-related symbols only inside `(*Executor).Run`. Dot or blank imports of those packages, `unsafe`, cgo, `plugin` and `go:linkname` are refused. Planted controls prove the checker sees each alternate path the review executed.

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

Every record is written durably: a temp file, fsync, rename and a directory fsync. DONE, STOPPED, CLOSED and PURPOSE follow this rule. Admission (INFLIGHT and its step record) is durable before any effect, and OK is durable in DONE before INFLIGHT is removed.

A refusal is truthful. A recovery whose CLOSED record cannot be written leaves the state unchanged and says so. If the rename landed but its directory fsync failed, the admission did happen, and the failure is recorded as a STOP.

DONE must end in a newline (rc 69 otherwise), so a record can never fuse with an incomplete one. Package files are opened beneath `pkg/` with no symlink anywhere on the way, so a linked ancestor cannot point the check at bytes outside the package.

Limits:
- Power-loss durability follows from the construction and from inspection, not from a test.
- A child is started in its own process group, so it survives a killed runner. INFLIGHT stays latched in that case, and the recovery steps handle the state. E2 adds per-operation timeouts.
- `Cred` with real uid changes is tested only as root, and the set-id branch of the table check needs root-owned fixtures.
- The exit codes keep the meanings of the shell runner they replace, but no oracle from the old runner is run against them.

## Units

| Unit | Content |
| --- | --- |
| E1 | This package: the runner, the latch, the package check, ExecFixed, the plan and op interfaces, the tests |
| E2 | The typed operations: exact-state checks, ledger calls, the age backup, the node route, run-as checks |
| E3 | A concrete plan and its parameters type, and the `deploy-kit g2-run` subcommand |
| E4 | The witness-class map and negative suite, and rehearsals through the engine |

Instance values (names, pins, paths) never appear in this package. They arrive in the parameters file.
