# Historical extraction input

`original-lab.py.txt` is the byte-for-byte original `lab.py` from commit
`c1979976bbf94f03443cebab82d0df8fd59ec100`, tree
`5195a61eb8defdd597c24d4abc73d129bad7c77a`, path
`experiments/fullnode-trusts/lab.py` (Git blob
`efddb8f7994a8e9dceb99d7edabcbf63ff9ce5ac`). Its SHA-256 is
`7efba9dff1231b6a88db500c27e2d1c0a1bcc7d944f30eac245a8d90085e88cd`.
This is the actual pre-extraction T1 source, under the repository's Apache-2.0
license and NOTICE. It contains source for generating disposable credentials,
not credential values. It has no private input, host credential or live state.
The later composed `lab.py` already delegates to `transaction.build_signed`
and cannot establish independence of the extraction.

The full historical bytes are retained rather than rewriting `raw_signed`.
`test_t1b.py` verifies the hash, parses the file as AST and compiles only that
function. It never imports or executes the historical top-level program. The
fixture is checked in at this location so shallow public checkouts need neither
a private archive nor an external `/inputs` mount. The seven original paired
success/failure comparisons, RPC traces and network checks remain unchanged.

The sibling test launcher pins the genuine verifier inputs from composed source
head `04a12b9f1732598e4d893f6b4206ea5a24955bd3`:

| Input | SHA-256 |
| --- | --- |
| `../protocol.py` | `be9351e0bfc3ce0c529b97961071f2884244e07c49595d1055baac142973983f` |
| `../pipe_verify.py` | `0adcaa842866c38e027778ef53bcc3c56eb79cd4a6f287c9ad9a147c56e23f1f` |

The test relay implements the historical sibling controller's
`verify/rpc/rpc_result/decision/verdict` exchange and 2101-request, 8-MiB-line,
110-second immutable bounds. It does not implement verification or mint an
admission. All four decisions and actual exit codes come from fresh executions
of the pinned `pipe_verify.py` in separate offline namespaces. No fallback or
in-process verifier is available. The Go relay itself runs offline, reads only
private FIFO channels, and cannot launch a process. The host shell only creates
FIFOs, launches namespaces, reports process exits and reaps children.

Tests use pinned CPython/Go from CI. The verifier preserves its original
`/usr/bin/python3 -I -B` invocation and strict environment; that interpreter and
system libraries belong to the declared Ubuntu runner image, which is not a
bit-reproducible build input. No third-party language module is acquired.
The pinned bubblewrap 0.6.1 lacks `--size`. Fresh verifier HOME/TMP/cache
directories are mode 0700 and mounted read-only, allowing zero private writes
within the historical 16-MiB ceiling. The unchanged verifier needs no writes.
These controls establish offline source behavior only, with no node, wallet,
provider, runtime admission, spending, replay protection or deployment claim.
