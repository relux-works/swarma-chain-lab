// Package g2run is the step engine of a ledgered host install: `deploy-kit g2-run -state DIR STEP`.
//
// THE RULE: no value is ever evaluated by a shell or by any other interpreter. Every value is a typed Go value that a
// strict decoder parsed once and refused by name if malformed. A step is an ordered list of typed operations (Op)
// compiled into the signed binary; instance values (names, pins, paths, purposes) come from a typed parameters file in
// the signed install package. External programs are reached only through ExecFixed: an absolute path from the compiled
// program table, a fixed argv built from typed fields, an explicit environment, and no shell.
//
// The runner keeps the on-disk discipline of the plan it replaces, in this order, the first failure ending everything:
//
//	umask 077, read back                                  rc 90
//	arity and a step of the compiled plan                  rc 64, 65 (before the lock)
//	the lock: an exclusive non-blocking flock on STATE/run.lock, opened read-only and never created
//	                                                       rc 66 (missing or a symlink), 67 (held)
//	the bootstrap completed: DONE starts with the bootstrap line                         rc 69
//	ADMISSION. Every refusal so far changes no state. A normal step is refused while STOPPED, CLOSED or INFLIGHT
//	exists (rc 70, 71, 72) and unless it follows exactly the step its purpose's sequence names before it (rc 75); it
//	is admitted by the exclusive mkdir of INFLIGHT. A recovery step is admitted only in its eligible state (rc 76, 77)
//	by an append to CLOSED, after which no normal step runs again.
//	the package bytes, against the operator's pin                                       rc 80-83
//	the step's operations, in order; the first error (or a panic) is a STOP
//	success: `OK STEP` appended to DONE, INFLIGHT removed
//
// After admission every end but success appends `epoch-N STOP STEP rc=N` to STOPPED; INFLIGHT (or CLOSED) stays, so a
// failed STOP write still refuses every later normal step. A step is a Go function returning error, so there is no
// completion sentinel and no abandoned body: the language's control flow is the guarantee.
package g2run
