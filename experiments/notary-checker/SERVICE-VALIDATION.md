# Service validation

## NOTARY-REL r2 verifier refresh (2026-11-16)

The current release verifier requires eight arguments: `SOURCE_ROOT`,
`RELEASE_COMMIT`, `RELEASE_TAG`, `RELEASE_DIR`, `REBUILT_BINARY`,
`TAG_ALLOWED_SIGNERS`, `MANIFEST_ALLOWED_SIGNERS`, `MANIFEST_SIGNER_ID`.
Implementation revision: `36945bbf246f02a8ee5abea4e2a876f4c61f4ba2`.

The current release suite is **46 tests** (all 34 prior names retained),
exit 0. `bash -n` exits 0; both named release mutation controls are killed
(test exit 1, valid control exit 0). The guarded cross-signer fixture refuses
`SIGNER_ROLE_SEPARATION` (exit 1), while its guard-only mutant reaches
`RELEASE_VERIFIED` (exit 0). The freshly downloaded real v0.1.1 assets pass the
fixed verifier, exit 0. Two fresh exported-source Go 1.26.10 builds and both
byte comparisons exit 0, retaining published binary SHA-256
`9e63953c112b0cf0426a2db4ddc048faff053088d5cd1d447f1e6f598c91f7f5`.
Public hygiene and all six detector controls exit 0. Shellcheck is unavailable
and was not run. No Go/service code changed in this verifier revision.

The exact new negative codes, valid controls, baseline failing witnesses,
mutant table and limits are recorded in
[VALIDATION.md](VALIDATION.md#notary-rel-r2-release-verifier-2026-11-16).
The following 25-test verifier rows are historical N5 r2 evidence, superseded
by this record; their original counts and results are preserved.

## N7 signing-key containment (2026-11-16)

Current base: `22cdfd7c0ba132510c4d0baf8094714bb272c309`. The signing key is
now behind one unexported `**btcec.PrivateKey` field in `signingKey`; the
password retains one unexported `*string` field. Reflection tests pin both
shapes, and a calibrated bad-verb probe proves that the extra key indirection
prints an address instead of scalar limbs. No protocol, refusal, signature
algorithm, module dependency or production wire behavior changed.

The candidate's 61 non-Markdown module inputs have sorted path/SHA-256
manifest digest
`09a6464f258a0fc3bb10b5aa6cf85771f1b9534947ba0917bc2b4e3208a297f0`.
Go `/home/agent/sdk/go1.26.10/bin/go`, `GOTOOLCHAIN=local`, `GOWORK=off`,
`GOENV=off`, `GOFLAGS=-modcacherw` and pinned cached modules were used.
HOME, config, caches, GOPATH, fixture cwd and short TMPDIR all live inside
the owned workbench `.tmp/n7`; TMPDIR is its absolute `t` subdirectory.
No real node, cookie, credential or private key was used.

| Probe | Base leaks / pairs | N7 leaks / pairs |
| --- | --- | --- |
| Original Service key probe (constructor adapter only) | 21 / 92 | **0 / 92** |
| Full Service/key/holder battery, 36 forms × 43 sinks | 341 / 1548 | **0 / 1548** |
| Full password/reader battery, 36 forms × 43 sinks | 0 / 1548 | **0 / 1548** |
| Full Service password battery, 36 forms × 43 sinks | 0 / 1548 | **0 / 1548** |
| Actual runtime panic output | not recaptured | **0 / 72** (36 password forms + 36 Service forms) |

Plain controls leak in 59 key, 64 password/reader and 13 Service-password
form/sink pairs under the same detectors. They detect plaintext/raw bytes,
lower/upper hex, decimal bytes and the signing scalar's eight uint32 limbs.
Encoder refusal errors, partial output and recovered text/template diagnostics
for unexported reflect.Values are scanned too. This is finite diagnostic
coverage, not unsafe/reflection-traversal or process-memory protection.

| Command / check | Actual result |
| --- | --- |
| `gofmt -l .` and empty-output check | 0, no output |
| `go vet ./...`; `go mod verify`; `go build ./...` | 0 / 0 / 0 |
| `go test -count=1 -timeout 120s -v ./...` | 0, all six packages; every existing named test retained |
| `go test -race -count=1 -timeout 120s ./...` | 0, **ONE local invocation**, all six packages; scope note below |
| `python3 -B scripts/check-mutants.py --work-dir WORK` | 0; **73/73** named kills |
| `python3 -B scripts/check-revision-mutants.py --work-dir WORK` | 0; **36/36** named kills |
| `python3 -B scripts/check-service-mutant.py --work-dir WORK` | 0; **1/1**, `TestRefusalNeverSigns` |
| `python3 -B scripts/check-storage-mutants.py --work-dir WORK` | 0; **7/7**, both shape and diagnostic assertions per row below |
| 2886-input wire differential against the current base; `cmp` | 0 / 0 / 0; exact equality |
| Exact README service build twice; `cmp` | 0 / 0 / 0; SHA-256 below |
| Root credential-output guard / public hygiene / six hygiene controls | 0 / 0 / 0; guard's three controls pass |

| Storage mutant | Narrows gate to | Named failing tests | Result |
| --- | --- | --- | --- |
| service-key-inline | no raw inline scalar in Service | TestSigningKeyStorage; TestSigningKeyServiceContainer | KILLED, exit 1 |
| service-key-struct-pointer | exact base `Service.key *PrivateKey` failure | TestSigningKeyStorage; TestSigningKeyServiceContainer | KILLED, exit 1 |
| signing-key-inline | no inline scalar in holder | TestSigningKeyStorage; TestSigningKeyServiceContainer | KILLED, exit 1 |
| signing-key-struct-pointer | no aggregate-pointer holder storage | TestSigningKeyStorage; TestSigningKeyServiceContainer | KILLED, exit 1 |
| password-inline | no inline password string | TestRPCPasswordStorage; TestRPCPasswordDiagnostics | KILLED, exit 1 |
| password-byte-pointer | decimal-byte encoding is detected | TestRPCPasswordStorage; TestRPCPasswordDiagnostics | KILLED, exit 1 |
| password-struct-pointer | no aggregate-pointer password storage | TestRPCPasswordStorage; TestRPCPasswordDiagnostics | KILLED, exit 1 |

No panic, compilation error, unrelated failure or timeout counts as a kill;
there are no final survivors. Raw-Service mutants adapt fixture field access
to compile the former field type, while retaining the same shape and leak
assertions. Initial setup failures remain diagnostics in the producer report.

`TestSigningKeyVectors` loads the public fixed fixture scalar 4 through the
actual service loader and matches the base service's signatures and public
key over **all 15 existing positive-vector digests**. The baseline is captured
from the unmodified base, rather than confused with the independent Python
signer's different nonce convention. The original checker/service vectors
and their assertions remain intact. The older key-clear test changes only
its field access through the explicit accessor.

The differential has **2886 inputs, 442 accepted, 2444 NODE_CREDENTIALS
refusals and 1326 raw requests**. All outcomes, parsed user/password bytes and
normalized raw wire bytes match the base. Every Authorization header also
matches an independent Python base64 encoding exactly once. Both JSON files:
`3a73a557b507fe7a95ed2c6459434993d56d83c6c297160c470b4e849320ae99`.

Replacement **v0.1.1 candidate** SHA-256 (8,020,094 bytes, Linux/amd64):
`9e63953c112b0cf0426a2db4ddc048faff053088d5cd1d447f1e6f598c91f7f5`.
This supersedes the N6 r2 `2edfc98c…` candidate. Both exact builds use:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOWORK=off   go build -trimpath -buildvcs=false -ldflags='-s -w -buildid='   -o OUTPUT ./cmd/notary-service
```

Race scope: the single local invocation passed before two test-only followups:
keyed field names for vet-clean helper literals and strengthening the fixed-key
vector test to reload through `Load`. Those changes and the added raw-Service
mutant adapters do not change production Go inputs. The final test source
passes the full non-race suite and vet. The final published source's hosted
race/check result is recorded separately in the producer report; the earlier
local run is not misrepresented as an exact-source final race run.

The audit and bounded coverage map are in `PRODUCER-REPORT-notary-n7.md`,
delivered separately. The brief supplies no formal surface table (declared
brief gap). No requested row is treated as out of contract. Explicit secret
access, process-memory protection and live-node qualification are outside the
requested diagnostic boundary. No review, merge, tag, release, deployment,
module-graph replay or independent-reader replay is claimed by this local N7
validation. Prior sections below retain historical results and binary hashes.


## N6 r2 evidence (2026-11-16)

The RPC credential diagnostic boundary is validated at code commit
`dc43e4994d913b863099c0108e0e1f172c872ef4`; the later evidence-only commit
changes no source, test, fixture, script or build input. The validation copy's
54 non-documentation inputs were byte-compared with that commit. Their sorted
path/SHA-256 manifest digest is
`483243a20ba95606c9654d3149e1478c3011fe17ecd5915b704d1a10c60f166e`.
Go 1.26.10, `GOTOOLCHAIN=local`, `GOWORK=off`, `GOENV=off`,
`GOFLAGS=-modcacherw`, `GOPROXY=off`, `GOSUMDB=off` and task-owned absolute
HOME/cache directories were used. Module downloads were first seeded from the
existing local download cache. The one full race invocation used a short
absolute `mktemp -d /tmp/n6r2.XXXX` TMPDIR. Every network test is a loopback
mock; no node, release or deployment was used.

| Command / check | Real exit / result |
| --- | --- |
| `gofmt -l .` plus empty-output check | 0; empty |
| `go vet ./...` | 0 |
| `go mod verify` | 0 |
| `go test -count=1 -v -run TestRPCPassword . ./internal/service` | 0; holder/reader/copy, bad verbs, containers, Service, slog text, real XML text consumer, wire and exact credential boundaries |
| `go test -race -count=1 -timeout 120s ./...` | 0; ONE invocation, all five packages |
| `python3 -B scripts/check-mutants.py --work-dir WORK` | 0; **73/73** named controls killed, zero survivors (64 pre-N6, two N6, seven r2) |
| `python3 -B scripts/check-service-mutant.py --work-dir WORK` | 0; signing-on-refusal killed by `TestRefusalNeverSigns`, mutant exit 1 |
| `python3 -B scripts/check-revision-mutants.py --work-dir WORK` | 0; **36/36** killed, zero survivors |
| Reviewer's exact R1–R4 edits, each with `go test -count=1 -overlay OVERLAY ./...` | runner 0; **4/4** killed with exit 1 and named assertions, no build failure or panic |
| Reviewer's full fmt probe, changed to assert leaks | 0; **zero leaking form/sink pairs**, including the original 43 witnesses |
| Reviewer's 2886-input base/head differential | 0 / 0 / comparison 0; byte-identical parser outcomes and raw wire bytes |
| Root `go run .scripts/check-credential-output-boundaries.go` | 0; inventory byte-equivalent to the reviewed N6 head, three detector controls |
| Public hygiene scanner / six detector controls | 0 / 0 |
| Reproducible service builds A / B / `cmp` | 0 / 0 / 0; identical Linux/amd64 bytes |

The differential uses base `2091e9b1`, the reviewer's unchanged `make_corpus.py`
and base/head capture tests: **2886 inputs, 442 accepted, 2444 refused, 1326
requests** across three RPC methods. Each Authorization line also independently
matches Python base64(user + colon + password) exactly once. Both result JSON
files have SHA-256
`3a73a557b507fe7a95ed2c6459434993d56d83c6c297160c470b4e849320ae99`.
These are finite synthetic inputs, not live-node qualification.

The new service binary SHA-256 is
`2edfc98c2009e076c0760da65999443e7cb2fd22f4274c7e66270de437985ebf`.
Build flags: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOWORK=off`
and `go build -trimpath -buildvcs=false -ldflags='-s -w -buildid='`.
The old N6 hash `5ef4f7e5…` is superseded and is not the release candidate.
No release is produced by this validation.

The holder stays in notarycheck; the claim is **the sole `Reveal` call** in
production, not an enforced package-access boundary. The guard inventories
that spelling and does not block direct same-package field reads. Pointer
storage protects fmt's method-bypassing paths. The redundant reader
`MarshalJSON` is removed; `MarshalText` preserves JSON redaction. Existing
committed top-level tests remain; secret-bearing subtest labels were replaced
with descriptive labels as requested.

| N6 mutant | Boundary narrowed | Named failing test | Observed after disabling |
| --- | --- | --- | --- |
| rpc-password-format | password holder formatting always redacts | TestRPCPasswordRedaction/fmt/holder/value/%v | named assertion failed |
| rpc-password-json | password holder JSON always redacts | TestRPCPasswordRedaction/json/holder/value | named assertion failed |
| rpc-password-inline | scalar-pointer storage blocks method-bypassing fmt diagnostics | TestRPCPasswordRedaction/fmt/holder/value/%p | named assertion failed |
| rpc-password-text | holder text consumer redacts | TestRPCPasswordRedaction/text/holder/value | named assertion failed |
| rpc-reader-text | reader retains TextMarshaler without an assertion panic | TestRPCPasswordRedaction/text/reader/value | named assertion failed |
| rpc-password-first-colon | reviewer R1: first-colon fields, not only equivalent Basic Auth | TestRPCPasswordWireAndErrors/multiple-colons | named assertion failed |
| rpc-password-cap | reviewer R2: full 4096-byte positive remains accepted | TestRPCPasswordCredentialErrors/cap-4096 | named assertion failed |
| rpc-password-cr | reviewer R3: interior CR refuses without a partial reader | TestRPCPasswordCredentialErrors/interior-cr | named assertion failed |
| rpc-password-unicode-trim | reviewer R4: Unicode edge space is trimmed like base | TestRPCPasswordWireAndErrors/unicode-space | named assertion failed |

The last four rows implement the reviewer's exact R1–R4 mutations; their
separate whole-module overlay runs also kill. Every kill above is exit 1
with its named assertion, not an unrelated setup failure, crash, panic or
timeout. No mutant survives. The first focused run failed because XML rejects
an unnamed struct control; the named plain control fixes that setup, and the
second focused run is green. That failure is retained as diagnostic evidence;
it was not a race run or a passing gate.

The brief has no formal surface table; this remains a declared brief gap.
The finding/test/mutant map is in the producer report. No row in F1–F6 is
treated as out of contract; live-node/memory qualification and review/landing
are outside this producer round. Historical sections below retain their
original counts and hashes. Reference/release-verifier and module-graph runs
are not claimed anew by N6 r2.

## N4/N5 evidence refreshed in N5 r2 (2026-11-16)

These runs cover the N4 operator-file and J9 regressions and the N5 release
verifier at the current v0.1.51 pin, commit
`bd3bc80e5543d8a563343ec05abd1a5f3f67284c`. The source, tests, fixtures, modules
and scripts were byte-compared with the disposable validation checkout;
their sorted path/SHA-256 manifest digest is
`d0f6efc3dd1f87791ef8cfdb5550879ed433f5f21f3cd96c91e5227e5cb82db7`.
The producer report binds these inputs to the delivered commits. Go 1.26.10,
`GOTOOLCHAIN=local`, `GOWORK=off`, private caches and a short absolute TMPDIR
were used. Dependencies were seeded from the existing local module-download
cache, then `GOPROXY=off GOSUMDB=off` applied. No real node was contacted;
service/RPC tests use loopback mocks. Historical evidence below is retained
with its original counts, pin and binary hash.

| Command | Real exit / result |
| --- | --- |
| `gofmt -l .` | 0; no formatting output |
| `go vet ./...` | 0 |
| `go test -race -count=1 -timeout 120s ./...` | 0; one run, all five packages, including N4 J9 and all FIFO regressions |
| `python3 -B scripts/reference.py` | 0; 144 signed bundles and two isolated row vectors |
| `python3 -B scripts/check-mutants.py --work-dir WORK` | 0; 64/64 named checker controls killed, zero survivors |
| `python3 -B scripts/check-service-mutant.py --work-dir WORK` | 0; signing-on-refusal killed by `TestRefusalNeverSigns`, mutant exit 1 |
| `python3 -B scripts/check-revision-mutants.py --work-dir WORK` | 0; 36/36 controls killed, including F3/F4, zero survivors |
| `bash -n scripts/verify-release.sh` | 0 |
| `python3 -B scripts/test-verify-release.py` | 0; all 16 existing and nine new tests pass, 25 total; every negative requires its exact named FAIL, exit 1 and no `RELEASE_VERIFIED` |
| `python3 -B scripts/check-release-mutant.py --work-dir WORK` | 0; enumeration removal killed by `ReleaseVerification.test_extra_file`, mutant exit 1; `test_all_good` remains exit 0 |
| README reproducible service build, twice; `cmp` | 0 / 0 / 0; identical bytes |
| Public hygiene scanner and six detector controls | 0 / 0 |

Both Linux/amd64 builds have SHA-256
`e7dc2b5f77ad6cf63ec3b7ebd74ff5cc68691327ba4fc1b64beb92642f71e1ee`,
unchanged from N4/N5. The only Go delta is the checker FIFO **test** bound,
raised from one to three seconds like the serve helper; no production Go code
or build flags changed. Build flags remain
`CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOWORK=off` and
`go build -trimpath -buildvcs=false -ldflags='-s -w -buildid='`.

| FIFO boundary | Positive / exact negative | Named regressions | Killed controls |
| --- | --- | --- | --- |
| Config and deployment policy | Regular-file load/serve; `CONFIG` / `POLICY_FILE` | `TestOperatorFileFIFORefusal/config`, `/policy`; `TestServeFIFOAndFixtureFlag/config`, `/policy` | F3; required named failure `TestOperatorFileFIFORefusal/config` |
| Ten checker inputs and offline fixture | Regular `ATTEST`; `REFUSED INPUT_READ` with exit 2 | `TestInputFIFORefusal` (all eleven kinds, three-second child bound) | F4; required named failure `TestInputFIFORefusal/parent` |
| Key and credential | Regular-file load/serve; `KEY_FILE` / `NODE_CREDENTIALS` | `TestPrivateFileFIFORefusal/key`, `/credential`; `TestServeFIFOAndFixtureFlag/key`, `/credential` | F1, F2 |

| Mutant | What it narrows the gate to | Named failing test | Result / survivor bound |
| --- | --- | --- | --- |
| F3-operator-blocking-fifo | Config FIFO must refuse promptly | `TestOperatorFileFIFORefusal/config` | Killed; exit 1; no survivor |
| F4-checker-blocking-fifo | Checker input FIFO must refuse promptly | `TestInputFIFORefusal/parent` | Killed; exit 1; no survivor |
| release-directory-enumeration-removed | Exact three-file directory membership | `ReleaseVerification.test_extra_file` | Killed; exit 1, positive exit 0; no survivor |

The initial revision-control run exited 1: F4 hit the harness's 30-second
suite timeout after the eleven per-input bounds became three seconds each.
That panic was not counted as a kill. Raising the mutation suite budget to
60 seconds allows the actual named failures; the full 36-control rerun exits
0. The initial run's orphaned owned helper was identified and stopped by PID.
No reviewer test was removed or renamed. This brief has requirements rather
than a formal surface table; the gap remains declared. Infrastructure changes,
live-node qualification, key provisioning, installation, signing a product
release and landing remain outside this producer unit.

## Historical N3 r2 revision evidence

The rev374 findings are addressed by FIFO-safe private-file opens and targeted
regressions adopted from the reviewer packet. The default/zero policy remains
strict D8; the existing explicit MVP mode is an operator deployment exception,
never specification text. No protocol bytes or checker ownership rules changed.
The only production code delta in r2 is in the two private-file opens and their
blocking-mode restoration after descriptor validation.

All checks below used Go 1.26.10 with `GOTOOLCHAIN=local`, `GOWORK=off` and private
disposable caches. The Go/fixture/module input-manifest SHA-256 is
`5f89316e59f5a70b8b40b5241c52782342341c2f6ed2b0853d7afba850d8296a`. A separate producer report binds the evidence to the published
head. The previous 139 bundle objects and both row vectors remain unchanged;
one synthetic non-regtest bundle is appended.

| Command | Exit / result |
| --- | --- |
| `gofmt -l .` plus empty-output check | 0; empty |
| `go vet ./...` | 0 |
| `go test -race -count=1 -timeout 120s ./...` | 0; one race run, all four packages |
| `python3 -B scripts/reference.py` | 0; 140 signed bundles and two row vectors |
| `python3 -B scripts/check-mutants.py --work-dir WORK` | 0; 64/64 named checker controls killed |
| `python3 -B scripts/check-service-mutant.py --work-dir WORK` | 0; signing-on-refusal control killed |
| `python3 -B scripts/check-revision-mutants.py --work-dir WORK` | 0; all 31 rev374 controls plus F1/F2/D1 killed, zero survivors |
| README reproducible build, twice; `cmp` | 0 / 0 / 0; identical bytes |
| Public hygiene scanner and six detector controls | 0 / 0; staged tree and bounded control plants |
| Added-diff private identity/path inspection; `git diff --check` | 0 / 0 |

The N3 r2 static Linux/amd64 service binary SHA-256 is
`f7161b0fe9759237779e4102b464afca161c30fe8c255b6f8a23383d7c1efd5c`. Flags are exactly
`CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOWORK=off`
and `go build -trimpath -buildvcs=false -ldflags='-s -w -buildid='`.

The FIFO tests pair regular-file loading with exact `KEY_FILE` and
`NODE_CREDENTIALS` refusals, including separate, PID-recorded CLI helper
processes with a three-second bound. Depth tests use nested objects at levels
64 and 65; the valid RPC response is whitespace-padded to 1048575 and 1048577
bytes. The header test pairs a 100-byte extension with a 64 KiB extension;
it proves oversize refusal, not an exact wire boundary including Go's read slop.
All network fixtures are loopback mocks. The synthetic main-network bundle
never contacts a main-network node.

No regtest end-to-end run was repeated: node read/RPC semantics are unchanged
beyond the required private-file open flags and restoration. The original
Core 28.0 evidence below remains historical at the original binary hash.

The optional concurrency-slot movement is deferred: two slow-body clients can
occupy both configured slots until the read deadline. The existing loopback
listener also has no connection-count cap. Credentials remain immutable Go
strings; parent-directory symlinks are not checked. These limitations remain
explicit and are not qualified away by the passing suite.

### Revision finding map

| Finding | Named regression tests | Killed controls |
| --- | --- | --- |
| presign-refusal-guards | TestRev374ServiceRefusalsNeverSign, TestRev374FinalViewTipAdvance, TestRev374PreSignDeadline | S2, S4, S5, S8 |
| post-check-identity-guards | TestRev374RegistrationMismatch, TestRev374NotaryKeyMismatch, TestServiceAttestationNetworkGuard, TestNodeReaderBoundsAndNames/expiry-at | S6, S7, S9, N7 |
| custody rules | TestRev374CredentialRules, TestRev374KeyZeroAfterClose | N4, N5, K4 |
| FIFO opens | TestPrivateFileFIFORefusal/key and /credential, TestServeFIFOAndFixtureFlag/key and /credential | F1, F2 |
| bounds negatives | TestRev374MemberDepth, TestRev374HeaderCap, TestRev374RPCResponseCap | B1, B2, B4 |
| strict-default deployment policy | TestDeploymentPolicyStrictDefaultAndExplicitMVP, TestDeploymentPolicyOneOwnerStaysStrict | D1; existing checker owner-relation controls |

The brief supplies six requirements rather than a formal surface table; that
brief gap is declared. No existing reviewer test was removed or renamed.
Out-of-contract operational rows remain those explicitly excluded by the brief
and README: infrastructure deployment, funding/broadcast, owner provisioning
and full live-chain admission. Every r2 repository change stays in this module.

### All revision mutation controls

Each row is a real named-test failure at exit 1. The harness itself exits 0
only when every applied control yields its designated failure. An unapplied
substitution, compile/setup failure, panic, process timeout or unrelated failure
is not counted as a kill. The original 64 checker controls retain their named
per-mutant table in VALIDATION.md and were rerun successfully.

| Mutant | Boundary narrowed | Named failing test | Result / surviving bound |
| --- | --- | --- | --- |
| S1-sign-on-checker-refusal | Checker refusal cannot invoke signer | `TestRefusalNeverSigns` | Killed; exit 1; no survivor |
| S2-sign-in-service-fail-closure | Service fail closure cannot invoke signer | `TestRev374ServiceRefusalsNeverSign` | Killed; exit 1; no survivor |
| S3-sign-on-notary-lookup-refusal | Notary lookup refusal cannot invoke signer | `TestDeadlineNeverSigns` | Killed; exit 1; no survivor |
| S4-sign-before-final-view | Signing follows final verified view | `TestRev374FinalViewTipAdvance` | Killed; exit 1; no survivor |
| S5-delete-final-presign-view | Final pre-sign view is mandatory | `TestRev374FinalViewTipAdvance` | Killed; exit 1; no survivor |
| S6-delete-notary-registration-check | Chain registration equals designated contract registration | `TestRev374RegistrationMismatch` | Killed; exit 1; no survivor |
| S7-delete-notary-key-check | Published notary key equals loaded signer key | `TestRev374NotaryKeyMismatch` | Killed; exit 1; no survivor |
| S8-delete-presign-deadline-check | Deadline is checked after final view and before signing | `TestRev374PreSignDeadline` | Killed; exit 1; no survivor |
| S9-delete-attestation-network-check | Non-regtest candidate refuses before signing | `TestServiceAttestationNetworkGuard` | Killed; exit 1; no survivor |
| S10-refusal-body-carries-candidate | Refusal carries decision only | `TestRefusalNeverSigns` | Killed; exit 1; no survivor |
| N1-delete-lookup-post-read-view | Lookup rechecks view after name reads | `TestNodeReaderBoundsAndNames/mid-read-tip` | Killed; exit 1; no survivor |
| N2-delete-lookup-pre-read-view | Lookup verifies view before name reads | `TestNodeReaderBoundsAndNames/mid-read-tip` | Killed; exit 1; no survivor |
| N3-delete-getblockhash-crosscheck | getblockhash agrees with statement tip | `TestNodeReaderBoundsAndNames/blockhash` | Killed; exit 1; no survivor |
| N4-credential-mode-unchecked | Credential mode must be 0600 | `TestRev374CredentialRules` | Killed; exit 1; no survivor |
| N5-credential-follows-symlink | Credential symlink is refused | `TestRev374CredentialRules` | Killed; exit 1; no survivor |
| N6-registration-latest-not-history | Registration comes from history rather than latest update | `TestNodeReaderBoundsAndNames/update` | Killed; exit 1; no survivor |
| N7-reregistration-boundary-off-by-one | Fresh registration starts exactly at prior expiry | `TestNodeReaderBoundsAndNames/expiry-at` | Killed; exit 1; no survivor |
| N8-expired-current-accepted | Nonpositive expires_in refuses even with expired=false | `TestNodeReaderBoundsAndNames/zero-expiry` | Killed; exit 1; no survivor |
| K1-key-follows-symlink | Key symlink is refused | `TestKeyCustody` | Killed; exit 1; no survivor |
| K2-key-mode-unchecked | Key mode must be 0600 | `TestKeyCustody` | Killed; exit 1; no survivor |
| K3-key-cleared-before-drain | Key remains valid until active signer drains | `TestShutdownDrainsBeforeKeyClear` | Killed; exit 1; no survivor |
| K4-key-never-cleared | Close leaves key scalar zero | `TestRev374KeyZeroAfterClose` | Killed; exit 1; no survivor |
| B1-strict-depth-cap-removed | Nested object depth 64 accepted; 65 refused | `TestRev374MemberDepth` | Killed; exit 1; no survivor |
| B2-header-cap-removed | Oversize headers refuse with 431 | `TestRev374HeaderCap` | Killed; exit 1; no survivor |
| B3-read-timeout-removed | Header/body reads have deadlines | `TestNetworkTimeBounds/slow-body` | Killed; exit 1; no survivor |
| B4-rpc-response-cap-raised | Valid RPC response below 1 MiB accepted; above refused | `TestRev374RPCResponseCap` | Killed; exit 1; no survivor |
| B5-concurrency-unbounded | Concurrent operation limit refuses BUSY | `TestRequestBounds/busy` | Killed; exit 1; no survivor |
| B6-body-cap-removed | Oversize request body refuses 413 | `TestRequestBounds/size` | Killed; exit 1; no survivor |
| B7-rate-unbounded | Empty rate bucket refuses RATE_LIMIT | `TestRequestBounds/rate` | Killed; exit 1; no survivor |
| B8-dup-key-allowed | Duplicate JSON members refuse | `TestRequestBounds/json` | Killed; exit 1; no survivor |
| C1-serve-accepts-fixture-flag | Serve rejects offline fixture flag before config loading | `TestServeFIFOAndFixtureFlag` | Killed; exit 1; no survivor |
| F1-key-blocking-fifo | FIFO key refuses promptly through Load and CLI | `TestPrivateFileFIFORefusal/key` | Killed; exit 1; no survivor |
| F2-credential-blocking-fifo | FIFO credential refuses promptly through Load and CLI | `TestPrivateFileFIFORefusal/credential` | Killed; exit 1; no survivor |
| D1-strict-default-relaxed | Omitted/zero local policy mode retains strict D8 | `TestDeploymentPolicyStrictDefaultAndExplicitMVP/omitted` | Killed; exit 1; no survivor |

### Diagnostic failures

An initial regenerated corpus inserted the new positive before positional
fixture dependencies and changed a prior negative; the unit run exited 1.
Appending the new vector restores all old vectors unchanged. An initial D1
mutation selector matched twice and was NOT_APPLIED (harness exit 1). It was
narrowed to the intended owner-relation condition; the final full 34-control
run exits 0. Neither diagnostic was treated as green evidence.

## Historical N3 validation at a302350a

The following sections record the original service delivery and original
binary, not a new regtest run or new build measurement for r2.

At that original delivery, the spec pin was v0.1.48 /
`2012ac9155568af80d610bdf9b7683881a46e5cb`.
The service uses the landed checker from base
`8d961622e7bbadb97ded0c04dc10281910774aa3` in the same module.
These are bounded laboratory results, not deployed or full live-admission
qualification. All listed acceptance commands exited 0 unless explicitly
marked as an expected failing control.

## Local checks

| Command | Result / scope |
| --- | --- |
| `gofmt -l .` | Empty output |
| `go vet ./...` | Exit 0 |
| `go test -race -timeout 120s ./...` | Exit 0; checker, both CLIs, RPC reader and service |
| `python3 -B scripts/reference.py` | 139 signed bundles and two isolated row vectors; exit 0 |
| `python3 -B scripts/check-mutants.py --work-dir WORK` | 64/64 original checker controls killed; exit 0 |
| `python3 -B scripts/check-service-mutant.py --work-dir WORK` | Refusal-signing control killed by its named test; exit 0 |
| Service reproducible build from README, twice | Identical bytes and SHA-256 |
| Public hygiene scan and six detector controls | Exit 0; bounded identifier scanner supplemented by added-diff inspection |
| Repository module inventory | 24 manifests, 19 consumers, 101 internal edges, zero violations |
| `git diff --check` | Exit 0 |

The measured Linux/amd64 Go 1.26.10 static service binary SHA-256 is
`601b4227453cf25f1006f1e5a2677c2b16d240103f3018dd465937289efbbf38`.
Both builds used `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOWORK=off`,
`GOTOOLCHAIN=local` and
`go build -trimpath -buildvcs=false -ldflags='-s -w -buildid='`.
The source, toolchain, target and flags bound this reproducibility claim.

During development, the new fake-RPC timeout test initially blocked its own
server teardown. Captured stacks identified an unread body/blocked fixture
handler; the fixture now drains the body and has explicit release cleanup.
The interrupted diagnostic runs are failing evidence, superseded by complete
passing race runs. An initial inventory scan included disposable untracked
module-cache files; the root `.tmp/` ignore fixes the scratch boundary, and the
inventory subsequently passed. Neither diagnostic was reported as success.

## Contract coverage

No formal surface table was supplied with the brief; the requested service
contracts are mapped below. Existing reviewer tests and all checker vector
names are retained. No behavior outside the checker/service module is changed;
the root README/ignore and dedicated CI workflow support discovery and checks.

| Contract | Named tests / evidence |
| --- | --- |
| Generated 0600 exclusive key, unchanged on overwrite; mode and symlink rejection | `TestKeyCustody`, `TestCLIKeyOutputAndNoFixtureFlag` |
| No secret in CLI output, error or refusal response | Same two tests plus `TestRefusalNeverSigns` |
| Check precedes BIP-340 signing; exact refusal and empty signed output | `TestRefusalNeverSigns`, `TestMVPNodeRefusalPassthrough`; independent regtest verification |
| Exact signed envelope and action-0x04 script | `TestRefusalNeverSigns`; independent regtest envelope signature and complete frame comparison |
| Policy selected only by configured-file SHA-256 | `TestRequestBounds/policy` |
| One POST endpoint; duplicate/unknown/aliased/trailing/deep JSON rejection | `TestRequestBounds/json`, `TestRequestBounds/routes` |
| Request/rate/concurrency/time and configuration bounds | `TestRequestBounds`, `TestConfigLimitRanges`, `TestDeadlineNeverSigns`, `TestNetworkTimeBounds` |
| Shutdown waits for signer before key clearing and refuses new work | `TestShutdownDrainsBeforeKeyClear` |
| Name RPC, matching tip/hash, current values and registration history | `TestNodeReaderBoundsAndNames` and real regtest cases below |
| Named reader failures, no injected/offline fallback, unconfigured MVP refusal | `TestNodeReaderNoFallback`, `TestMVPNodeRefusalPassthrough`, `TestRunningRejectsFixture`, `TestServeCannotSelectOfflineFixture` |

| Mutant | What it narrows the gate to | Named failing test | Result / survivor bound |
| --- | --- | --- | --- |
| signing-on-refusal | No signer invocation after Check refuses, even if no signature is returned | `TestRefusalNeverSigns` | Killed; mutated `go test` exits 1 with `GRANT_ENCODING signs=1`; zero survivors |

A compile/setup error, skipped mutation, timeout, panic or unrelated failed
test does not count as a kill. The control runner verifies the exact assertion.
Original checker controls retain their table in VALIDATION.md; all 64 were
rerun successfully after wiring the reader.

## Official Core 28.0 regtest

The x86-64 Linux archive came from the
[official release download](https://www.namecoin.org/files/namecoin-core/namecoin-core-28.0/namecoin-28.0-x86_64-linux-gnu.tar.gz).
Its SHA-256 matched the published
[release checksum set](https://github.com/namecoin/guix.sigs/tree/main/28.0):
`6f12031926f0999b8507e073648cc2b4488d452531301a2244a562a92f2f7860`.
This is published-checksum verification over HTTPS, not an additional release
signature-verification claim. The binary reported version 28.0 before use.

The reproducible harness command is documented in README. It starts a fresh
regtest node with loopback RPC, no listening P2P socket or peers, name history
and a disposable wallet. It mines only regtest blocks, registers synthetic
`id/certifier`, `id/owner-a` and `id/owner-b` names with the notary/owner-grant
values, then runs the compiled `serve` CLI using real RPC reads. Grant signing
keys are fresh throwaway values held only in memory; the service key comes
only from its own `keygen`. No key or cookie is printed.

| End-to-end case | Exact decision | Signature / anchor |
| --- | --- | --- |
| Strict positive | `ATTEST` | Independently verified BIP-340 and exact complete frame |
| Statement height differs from node | `NODE_TIP_MISMATCH` | Absent |
| Unregistered name | `NODE_NAME_UNREGISTERED` | Absent |
| Same-owner MVP request | `MVP_MODE_PAIR_REQUIRED` | Absent |
| Two independently registered owners, bilateral current-grant-key approvals | `ATTEST` | Independently verified BIP-340 and exact complete frame |

The harness exited 0. Peer count was zero. Its own service/node processes were
stopped and waited by PID, the regtest datadir and generated attestation key
were removed, and the cleanup record confirmed all four conditions. The final
run used the binary SHA-256 above. Synthetic grant issuance, seal and checkpoint
locators remain inputs: this exercise proves service/name/tip/signature
integration, not those deferred live-chain obligations.

Out-of-contract operational rows are the explicit README/DESIGN exclusions:
transaction funding/broadcast (treasury and owner gated), operator network ACLs
and infrastructure deployment from a signed reviewed release. The checker’s
existing historical owner/checkpoint proof, seal/issuance and durable journal
limitations remain declared, with no acceptance claim for them.
