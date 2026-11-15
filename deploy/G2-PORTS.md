# G2 script ports

The ports in `g2run` are library operations, ready for composition by the typed
step plan. They never evaluate values or execute scripts. Instance names,
account IDs, pins and roots are supplied by callers, ultimately from the signed
parameters file. `PortFS` opens every path component without symlinks beneath
declared roots. Workspace outputs are exclusive atomic writes with explicit
modes, file sync, rename and parent-directory sync.

| Source | Go entry point | Vector table test |
| --- | --- | --- |
| g2-scope.py | BuildInstallScope / WriteInstallScope | TestScopeOriginalVectors / TestInstallScopeLayoutOriginalVectors |
| g2-drift.py | ReadDriftIdentity / FlipDrift / RestoreDrift | TestDriftOriginalVectors |
| g2-landlord-check.py | CheckLandlord | TestLandlordOriginalVectors |
| g2-manifest-check.py | CheckInstallManifest / BuildInstallManifest | TestManifestOriginalVectors |
| g2-ledger-owns.py | LedgerOwns | TestLedgerOwnsOriginalVectors |
| g2-node-restarted.py | CheckNodeRestarted | TestNodeRestartedOriginalVectors |

`testdata/g2run-ports/` holds the source oracle inputs and recorded verdicts.
`provenance.json` identifies the supplied source bytes. The landlord name is a
generic fixture substitution; temporary paths are expanded by Go in tests.
The sources are not copied because they contain deployment instance data.
No interpreter is used by the Go tests. The node script supplied no dedicated
vectors; its fixture records source executions of positive and missing-field
cases, plus the explicitly stricter malformed-field refusals.

Deliberate differences:

- `InstallScopeLayout` supplies instance roots/accounts, and `CompileInstallScope`
  compiles the source's fixed station/rehearsal path shapes and parent closure.
  `BuildScope` validates and binds those shapes; its lower-level `ScopeSpec` is
  compiled Go data, not a runtime-supplied operation list. Unit roots, staged
  upstream pins and node roots are instance parameters.
- All filesystem ports refuse symlink ancestors, not just the final component.
  Scope output and drift state use durable atomic exclusive creation.
- JSON evidence refuses duplicates, trailing data, invalid UTF-8 and nesting
  beyond 128 levels. Files are bounded; ledger input is at most 64 MiB with
  records at most 1 MiB. These bounds fail closed.
- Landlord heights and node block counts are bounded to signed 64-bit range.
  Errors are stable labels and never echo untrusted output. Node readback now
  checks chain/count/boolean types before printing the source-compatible line.
- Drift hashing detects concurrent size/time changes and restore syncs restored
  timestamps, including pre-epoch values within signed 64-bit range. State removal checks its observed inode. Restore requires typed
  state and a one-byte preimage before it touches the target.
  Descriptor-based timestamp restoration requires Linux 5.8 or newer, using
  [utimensat AT_EMPTY_PATH](https://man7.org/linux/man-pages/man2/utimensat.2.html);
  there is no path-based or lower-precision fallback.
- Manifest checks preserve the source's compact JSON convention and member
  order. The approved hash document additionally refuses duplicate keys.
- `LedgerOwns` returns `(bool, error)` instead of exit codes 0/1/2. It remains a
  predicate over a ledger already verified by the caller; it does not verify
  the hash chain or itself authorize stopping a service. Metadata mismatches
  are decided without opening the target; matching files use O_NOATIME.

Run the tests from the `deploy` module with `go test ./g2run -race` and
`go vet ./g2run`. The existing E1 static exec-site test and its planted controls
remain in force. No additional external program wrapper is introduced here.

## Host script ports and E2 integration

| Source | Go operation | Tests and source vectors |
| --- | --- | --- |
| g2-baseline.sh | Baseline | TestBaselinePort; source first-failure and rehearsal node-exclusion cases |
| g2-activate.sh | Activation | TestActivationPortPositive / Refusals; TestOperatorGroupsOriginalVectors (operator_groups.json) |
| g2-rollback.sh | RollbackPort | TestRollbackOriginalVectors (rollback.json); TestAttemptUnitStopOriginalVectors (unit_stop.json); TestRollbackPortBoundaries |

`Baseline`, `Activation`, and `RollbackPort` implement E1's `Op`. All required
capabilities must be present at validation; a missing E2 adapter is a named
refusal before effects. `port_host_linux.go` defines only the minimal capability
interfaces. It contains no fallback implementation or additional exec site.

E2 must provide these adapters using its reviewed typed operations:

- UserExact / GroupExact / getent lookups and complete numeric group readback.
- UnitProperty / Systemctl, including daemon-reload and unit inventory.
- ListenSetEqual's listener reader and a process UID inventory for rollback.
- Ledger create-file/create-dir/add-member/verify and in-process g2ledger
  RunRollback, with its System/NodeController routed through the engine boundary.
- ExpectStat / ExpectNonEmpty, a typed systemd-tmpfiles create operation, and a
  check-installed run-as wrapper with the fixed `--check-installed` argument,
  kernel credentials and output opened before execution.

`Activation` must be called from the existing `RunG2HostFlow` activation callback,
after that flow's preflight and post-sysusers account checks. The E2 integration
adapter and concrete step plan must establish that ordering. Native host
qualification is not provided by these fixture tests: uid/gid effects and host
capabilities are modeled, while bytes, modes, signatures, receipts and failure
ordering are exercised on real isolated files. The real E1 executor is covered
by its existing tests and static checker.

Further deliberate differences from the shell callers:

- Baseline requires an existing output parent. Directory and file modes are
  explicit, without changing the process-wide umask. Evidence files appear
  atomically, rather than leaving partially redirected text after a read error.
  A failure records its phase/key in errors.txt; taken-at.txt is written last.
  Directory listings are byte-sorted. Unit metadata is emitted in the documented
  requested-property order, rather than relying on systemctl's display order.
- Baseline receives a pinned CLI path instead of searching an inherited PATH;
  the E1/E2 adapter must also verify the program pin before any invocation.
  Rehearsal has no node parameter and performs no node-specific read.
- Activation receives the rendered directory directly instead of reading a
  free-form rendered.path. Configured live roots cannot overlap its stage/log
  workspace. Workspace outputs are exclusive, so a repeated activation refuses
  existing output instead of overwriting recovery evidence. Installed targets
  and memberships are changed only by the ledger capability.
- Install signing and anchor rendering are in process, using the existing DK5
  signature format. Private seed/key buffers are cleared best-effort; no private
  key file is created. Installed bytes must still match the approved candidate.
- Kernel credentials replace the transient systemd-run check, preserving service
  UID, peer primary GID and exactly the service/status supplementary GIDs.
- Operator exclusion also compares numeric peer GIDs, so an alias cannot grant
  wallet access. The source's similar-name vector still passes for another GID.
- Rollback requires a regular empty 0600 start receipt, and refuses linked
  receipts. Its engine output is read through the same descriptor that captured
  it; inode replacement is a refusal. The engine's status is carried by a typed
  error, rather than terminating the process from inside an operation.

The generic parameters decoder, compiled 34-step plan and `deploy-kit g2-run`
subcommand are deferred until E2's types land. These ports do not expose an
install command before those integration obligations are resolved.

## Signature, unit-text and named-group contracts

Install signatures use the original CLI's exact
`configguard.SignatureDomain || installed manifest` message. A deterministic
vector captured through the original `g2-install-sign -manifest` path is in
`testdata/g2run-ports/install_signature.json`. Tests also admit a full activation
set through the production DK5 validator and reject a raw-manifest signature.

The unit parser permits LF/CRLF boundaries and refuses all other C0/C1 controls
(including tabs), Unicode LS/PS and known Install keys with altered key spacing.
Scope retains Python's stripping of extracted value lines. Activation preserves
its source's exact raw line comparison: a trailing space or a CRLF key's CR
refuses there. `unit_text.json` records original Python/sed results separately
from the explicitly stricter control-character policy. The status drop-in is
subject to the same text refusal before its publication.

Activation binds both service and agent named groups to their declared GIDs.
The agent GID must also differ from the wallet, peer and status GIDs, before
ledger effects. This complements the existing host-flow preflight requirement.

The package directory contains Go files only; fixtures live outside it under
`deploy/testdata/g2run-ports/`. E1's exec detection, closed syscall-member policy,
foreign-source refusal and original controls are preserved. Added imports are
explicit; the ledger library is limited to six schema types, and configguard to
its domain/schema/anchor-rendering selectors. Ledger process entry points remain
forbidden by the same closed member gate.
