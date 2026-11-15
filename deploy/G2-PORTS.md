# G2 script ports

The ports in `g2run` are library operations, ready for composition by the typed
step plan. They never evaluate values or execute scripts. Instance names,
account IDs, pins and roots are supplied by callers, ultimately from the signed
parameters file. `PortFS` opens every path component without symlinks beneath
declared roots. Workspace outputs are exclusive atomic writes with explicit
modes, file sync, rename and parent-directory sync.

| Source | Go entry point | Vector table test |
| --- | --- | --- |
| g2-scope.py | BuildScope / WriteScope | TestScopeOriginalVectors |
| g2-drift.py | ReadDriftIdentity / FlipDrift / RestoreDrift | TestDriftOriginalVectors |
| g2-landlord-check.py | CheckLandlord | TestLandlordOriginalVectors |
| g2-manifest-check.py | CheckInstallManifest / BuildInstallManifest | TestManifestOriginalVectors |
| g2-ledger-owns.py | LedgerOwns | TestLedgerOwnsOriginalVectors |
| g2-node-restarted.py | CheckNodeRestarted | TestNodeRestartedOriginalVectors |

`g2run/testdata/ports/` holds the source oracle inputs and recorded verdicts.
`provenance.json` identifies the supplied source bytes. The landlord name is a
generic fixture substitution; temporary paths are expanded by Go in tests.
The sources are not copied because they contain deployment instance data.
No interpreter is used by the Go tests. The node script supplied no dedicated
vectors; its fixture records source executions of positive and missing-field
cases, plus the explicitly stricter malformed-field refusals.

Deliberate differences:

- Scope layout is supplied through `ScopeSpec`, rather than hardcoded instance
  paths/accounts. The concrete plan will compile its shapes once E2 is available.
  Unit roots, staged upstream pins and node roots are instance parameters.
- All filesystem ports refuse symlink ancestors, not just the final component.
  Scope output and drift state use durable atomic exclusive creation.
- JSON evidence refuses duplicates, trailing data, invalid UTF-8 and nesting
  beyond 128 levels. Files are bounded; ledger input is at most 64 MiB with
  records at most 1 MiB. These bounds fail closed.
- Landlord heights and node block counts are bounded to signed 64-bit range.
  Errors are stable labels and never echo untrusted output. Node readback now
  checks chain/count/boolean types before printing the source-compatible line.
- Drift hashing detects concurrent size/time changes and restore syncs restored
  timestamps. State removal checks its observed inode. Restore requires typed
  state and a one-byte preimage before it touches the target.
- Manifest checks preserve the source's compact JSON convention and member
  order. The approved hash document additionally refuses duplicate keys.
- `LedgerOwns` returns `(bool, error)` instead of exit codes 0/1/2. It remains a
  predicate over a ledger already verified by the caller; it does not verify
  the hash chain or itself authorize stopping a service. Metadata mismatches
  are decided without opening the target; matching files use O_NOATIME.

Run the tests from the `deploy` module with `go test ./g2run -race` and
`go vet ./g2run`. The existing E1 static exec-site test and its planted controls
remain in force. No additional external program wrapper is introduced here.
