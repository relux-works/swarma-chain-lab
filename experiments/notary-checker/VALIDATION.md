# Bounded validation evidence

## N7 follow-up diagnostic battery (2026-11-16)

The test-only follow-up to landed N7 preserves all production Go and the
released binary hash. The strengthened producer battery detects 436/1548
pairs on the adapted N6 base (341 was a lower bound), with zero at head.
The independent review forms detect 421/1548 at base, covering all 93 formerly
missed pairs, and zero at head. All prior test names remain; the module tests,
vet and single race invocation pass on the final test/helper source.

The checker/revision/service runners kill 73/36/1 controls; storage controls
now kill 9/9, including a Load-populated second key and cached Basic Auth.
See [Service validation](SERVICE-VALIDATION.md#n7-follow-up-diagnostic-battery-2026-11-16)
for named tests, individual calibration counts, mutation bounds, exact build
flags and the unchanged go1.26.10 build hash. The original N7 measurements
below are historical.

## Historical N7 signing-key containment (2026-11-16)

Current base: `22cdfd7c0ba132510c4d0baf8094714bb272c309`. The signing key is
now behind one unexported `**btcec.PrivateKey` field in `signingKey`; the
password retains one unexported `*string` field. Reflection tests pin both
shapes, and a calibrated bad-verb probe proves that the extra key indirection
prints an address instead of scalar limbs. No protocol, refusal, signature
algorithm, module dependency or production wire behavior changed.

The candidate's 61 non-Markdown module inputs have sorted path/SHA-256
manifest digest
`09a6464f258a0fc3bb10b5aa6cf85771f1b9534947ba0917bc2b4e3208a297f0`.
Toolchain `go1.26.10`, `GOTOOLCHAIN=local`, `GOWORK=off`,
`GOENV=off`, `GOFLAGS=-modcacherw` and pinned cached modules were used.
HOME, config, caches, GOPATH, fixture cwd and short TMPDIR all live inside
the owned workbench `.tmp/n7`; TMPDIR is its absolute `t` subdirectory.
No real node, cookie, credential or private key was used.

| Probe | Base leaks / pairs | N7 leaks / pairs |
| --- | --- | --- |
| Original Service key probe (constructor adapter only) | 21 / 92 | **0 / 92** |
| Original full Service/key/holder battery, 36 forms × 43 sinks | 341 / 1548 (lower bound; strengthened replay: 436) | **0 / 1548** |
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


Environment: Go 1.26.10, Python 3.14.4, Linux amd64. Go uses
`GOTOOLCHAIN=local`; verification and mutations ran with cached pinned
modules, `GOPROXY=off`, and `GOSUMDB=off`. No real node was used; service/RPC
tests use loopback mocks. Historical sections retain their original evidence.

| Check | Real exit | Evidence / limit |
| --- | --- | --- |
| `gofmt -l .` | 0 | No output |
| `go vet ./...` | 0 | This module |
| `go test -race -count=1 -timeout 120s ./...` | 0 | This module, both CLIs and service; 144 complete signed-bundle vectors and two isolated row vectors; N6 r2 evidence below |
| `go build ./cmd/notary-check` | 0 | CLI builds |
| `python3 -B scripts/reference.py` | 0 | All 144 signed bundles and two isolated row vectors; exact candidate octets, digest, positive signatures, envelope IDs and frames |
| `python3 scripts/check-mutants.py --work-dir <fresh-scratch>` | 0 | 73/73 named controls killed; zero survivors; each mutant test exits 1 with the named assertion failure |
| Boundary regressions | 0 | `TestAttestationOutputSize`, `TestCLIAttestationOutputSize`: fitting statements compose to 8191/8192 accepted bytes or a named empty 8193-byte refusal; signed decoder also rejects correctly signed oversized bytes |
| Positive CLI fixture at `1700000100` | 0 | `ATTEST bbc8faeb27b65ce4460c92228ec0487496e586b2c4ee5e216943036bdc3fc051` |
| Same CLI fixture at `1700000200` | 1 | Expected refusal `GRANT_EXPIRED`; this is a failing command as required, not a green gate |

An additional temporary contract-only probe compared the parser with the
pinned LIP-0014 corpus: all 149 applicable cases passed, exit 0. The two
remaining eleven-member cases exercise profile `/1` reader selection and
were explicitly excluded from this fifteen-member `/2` reader. The upstream
comparison used v0.1.46/v0.1.48. The current pin is v0.1.51 at
`bd3bc80e5543d8a563343ec05abd1a5f3f67284c`; the v0.1.49 and v0.1.51 cited-file
diffs and unchanged Grant v3/profile `/2` rules are recorded in DESIGN.md.
That historical parser probe is not a new whole-corpus v0.1.51 run and does
not qualify chain state or all possible inputs.

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

The current corpus contains **144 signed bundles and two isolated row
vectors**. The v0.1.51 pin is stated above; original v0.1.48-era results later
in this file remain historical. All current commands below actually ran with
Go 1.26.10 and `GOTOOLCHAIN=local` against byte-identical source/test inputs;
[SERVICE-VALIDATION.md](SERVICE-VALIDATION.md#n4n5-evidence-refreshed-in-n5-r2-2026-11-16)
records the input-manifest digest, environment, FIFO map and build hash.

| Current command | Real exit / result |
| --- | --- |
| `go test -race -count=1 -timeout 120s ./...` | 0; one full-module run, five packages, N4 J9 and FIFO tests included |
| `python3 -B scripts/reference.py` | 0; 144 bundles / two rows |
| `python3 -B scripts/check-mutants.py --work-dir WORK` | 0; 64/64 killed |
| `python3 -B scripts/check-revision-mutants.py --work-dir WORK` | 0; 36/36 killed; F3 requires `TestOperatorFileFIFORefusal/config`, F4 requires `TestInputFIFORefusal/parent` |
| `python3 -B scripts/check-service-mutant.py --work-dir WORK` | 0; `TestRefusalNeverSigns` kills signing-on-refusal |
| `python3 -B scripts/test-verify-release.py` | 0; 25 tests, including all previous controls |
| `python3 -B scripts/check-release-mutant.py --work-dir WORK` | 0; `ReleaseVerification.test_extra_file` kills enumeration removal; valid neighbor still passes |

Every reported mutant kill is its named assertion failure with exit 1, not a
crash, timeout or setup failure. The initial F4 timeout was a failing diagnostic;
the complete rerun after the 60-second harness budget adjustment is the green
36/36 evidence. Current gofmt, vet, two service builds, byte comparison and
public hygiene/control runs also exit 0. The checker FIFO bound is test-only;
both builds retain `e7dc2b5f77ad6cf63ec3b7ebd74ff5cc68691327ba4fc1b64beb92642f71e1ee`.

## Mutation controls

Each control disables a rule only in a disposable copy and must fail the
named test below. Compile failures, panics, timeouts, unrelated failures and
non-applied edits do not count. An `ATTEST` observation means the disabled
rule allowed this finite witness; another refusal means the test narrows
first-refusal precedence and a later defense still rejected it. The isolated
row-cap case does not enable spend delegation. The ordinal control selects
row 1 after removing the bound; the designation control substitutes a known
pin after removing membership, to avoid counting a crash as detection.

| Mutant | Boundary narrowed | Named failing test | Observed after disabling |
| --- | --- | --- | --- |
| explicit-time | time-input refusal precedes window refusal | TestVectors/negative-no-time | GRANT_NOT_YET_VALID |
| grant-shape | unknown grant members refuse | TestVectors/negative-grant-unknown-member | ATTEST |
| grant-fields | version 4 is unsupported | TestVectors/negative-grant-version | ATTEST |
| grant-signature | grant signature is mandatory | TestVectors/negative-signature | ATTEST |
| not-before | not-before boundary | TestVectors/negative-child-not-yet-valid | ATTEST |
| not-after | exclusive end boundary | TestVectors/negative-child-expired | ATTEST |
| grant-consent | countersignature is mandatory | TestVectors/negative-consent-signature | ATTEST |
| contract-hash | hash refusal precedes malformed contract refusal | TestVectors/negative-contract-hash | CONTRACT_ENCODING |
| contract-members | unknown contract members refuse | TestContractRules/negative-contract-unknown-member | ATTEST |
| contract-profile | profile /2 is required | TestContractRules/negative-profile | ATTEST |
| contract-fields | text hash syntax | TestContractRules/negative-field | ATTEST |
| contract-actions | closed action vocabulary | TestContractRules/negative-unknown-action | ATTEST |
| contract-repos | repository grammar | TestContractRules/negative-repo-grammar | ATTEST |
| contract-budget | budget requires spend action | TestContractRules/negative-budget-without-spend | ATTEST |
| contract-note | note length | TestContractRules/negative-note | ATTEST |
| contract-parent | ordinal and parent are coupled | TestContractRules/negative-parent-shape | ATTEST |
| delegate-members | nested row member set | TestContractRules/negative-row-unknown-member | ATTEST |
| delegate-notary | missing-notary refusal precedes delegate refusal | TestVectors/negative-no-notaries | CONTRACT_DELEGATE |
| parent-id | exact signed parent identity | TestVectors/negative-parent-id | ATTEST |
| depth | ancestor refusal precedes not-delegable refusal | TestVectors/negative-depth-two | NOT_DELEGABLE |
| delegable | not-delegable refusal precedes ordinal refusal | TestVectors/negative-not-delegable | CHILD_ORDINAL |
| subject | common principal | TestVectors/negative-subject | ATTEST |
| request | complete signed request | TestVectors/negative-request-missing | ATTEST |
| ordinal | ordinal bounds before row selection | TestVectors/negative-ordinal | ATTEST |
| executor | row executor equality | TestVectors/negative-executor | ATTEST |
| grantee | row grantee equality | TestVectors/negative-grantee | ATTEST |
| actions | child within delegable action set | TestVectors/negative-actions | ATTEST |
| repos | exact repository subset | TestVectors/negative-repositories | ATTEST |
| budget | isolated cap defense; not spend admission | TestRowVectors/row-budget-over | ATTEST |
| window | nested window | TestVectors/negative-window-after | ATTEST |
| text | different text requires judgement and refuses | TestVectors/negative-text-different | ATTEST |
| text-octets | text octets bind the signed hash | TestVectors/negative-text-octets | ATTEST |
| policy | policy binds exact parent and child IDs | TestVectors/negative-policy-binding | ATTEST |
| designation | designated notary required; unsafe known-pin fallback | TestVectors/negative-not-designated | ATTEST |
| owner-pin | notary owner must match signed pin | TestVectors/negative-owner-pin-mismatch | ATTEST |
| owner-relation | same-owner issuer affiliation | TestVectors/negative-owner-relation | ATTEST |
| cross-owner-relation | strict default requires a third owner despite bilateral agreement | TestVectors/negative-cross-owner-not-third-party | ATTEST |
| cross-owner-agreement | both owners agree | TestVectors/negative-cross-owner-missing-certifier | ATTEST |
| notary-delegator | key independence from delegator | TestVectors/negative-notary-is-delegator | ATTEST |
| notary-delegatee | key independence from delegatee | TestVectors/negative-notary-is-delegatee | ATTEST |
| notary-executor | name independence from executors | TestVectors/negative-notary-is-executor | ATTEST |
| statement | explicit statement fields | TestVectors/negative-statement | ATTEST |
| attestation-output-size | complete candidate cap, not just the smaller statement | TestVectors/negative-attestation-8193 | ATTEST |
| policy-mode | unknown deployment modes refuse | TestVectors/negative-mvp-unknown-mode | NOTARY_OWNER_RELATION |
| policy-mode-required | approvals never infer an absent mode | TestVectors/negative-mvp-approvals-without-mode | NOTARY_OWNER_RELATION |
| mvp-distinct-pair | two-owner mode rejects a one-owner pair before approval checks | TestVectors/negative-mvp-one-owner-pair | MVP_MODE_APPROVAL_REQUIRED |
| mvp-both-approvals | mode requires both signed exact-scope approvals, not just agreed_by | TestVectors/negative-mvp-no-approvals | ATTEST |
| lexical | no normalization of signed string spelling | TestVectors/negative-contract-escape | ATTEST |
| notary-value | notary key must be a curve point | TestVectors/negative-notary-key | ATTEST |
| row-selection | ordinal selects its own row | TestVectors/negative-other-row-executor | ATTEST |
| attestation-signature | service signature binds the candidate | TestSignedAttestationRejectsMismatch/signature | named assertion failed |
| row-pool-sum | row caps fit the separate signed pool | TestContractRules/negative-parent-row-cap | ATTEST |
| delegate-spend | D12 independently forbids delegated spend | TestContractRules/negative-delegated-spend | ATTEST |
| anchor-id | frame IDs must be 32-byte digests | TestAnchorRejectsMalformedID | named assertion failed |
| attestation-size-off-by-one | 8193 refuses while the 8192-byte control passes | TestVectors/negative-attestation-8193 | ATTEST |
| attestation-decode-size | signed decode also rejects an oversized correctly signed candidate | TestAttestationOutputSize/negative-attestation-8193 | named assertion failed |
| mvp-signature | owner signatures bind even another designated notary name | TestVectors/negative-mvp-different-notary | ATTEST |
| mvp-approval-order | approval owner order is canonical | TestVectors/negative-mvp-approval-order | ATTEST |
| mvp-signing-authorities | opposite compressed parities cannot reuse one BIP-340 signing authority for both owners | TestVectors/negative-mvp-opposite-owner-key | ATTEST |
| mvp-current-grant-key | current chain grant key verifies independently of policy owner identifiers | TestVectors/positive-mvp-current-grant-key | MVP_MODE_APPROVAL_REQUIRED |
| mvp-distinct-registration | different names with one registration cannot count as two owners | TestVectors/negative-mvp-owner-registration-reused | ATTEST |
| mvp-distinct-name | one name cannot approve twice with two keys | TestVectors/negative-mvp-owner-name-reused | MVP_NAME_REGISTRATION_MISMATCH |
| mvp-name-view | observed height must match the statement | TestVectors/negative-mvp-name-height | ATTEST |
| mvp-name-registration | current registration must equal the approved identity | TestVectors/negative-mvp-name-registration | ATTEST |

No generated mutation tree, binary, cache or private execution log is part of
the public change. No independent review, live service, name registration,
node/journal qualification or production attestation is claimed.

The three new boundaries have statements of 7459, 7460 and 7461 bytes,
respectively, each below the separate statement cap. Their script padding uses
pushes of at most 520 bytes and drops before the fixed synthetic P2PKH script.
No node execution is claimed. The 8193-byte witness fails against each original
reader: the Go named regression reports an accepted oversized candidate, and
the original Python reader reports `ATTEST` instead of `ATTESTATION_TOO_LARGE`.
These are intended failing controls (exit 1), not passing product gates. The
fixed candidate passes the same fixtures, and positives retain their exact
envelope ID and 72-byte anchor frame. The produced-object audit is in
[DESIGN.md](DESIGN.md#produced-object-size-audit).

Round 3 adds 27 deployment-policy vectors; all 94 earlier bundle vectors and
both isolated row vectors are unchanged. Positive controls accept either
pair-owned notary and a strict third-party notary under the explicit mode.
Negatives bind both signatures to the exact grant pair, owner identities and
roles, notary name and owner pin; neither agreement identifiers alone nor one
owner signature suffices. Absent mode retains the strict refusals. The named
`mvp-both-approvals` mutation removes the bilateral mode gate and fails
`TestVectors/negative-mvp-no-approvals` with erroneous `ATTEST`; signature and
approval-order mutations likewise fail their named vectors. Opposite-parity
compressed owner keys are rejected even with valid signatures: the
`mvp-signing-authorities` mutant erroneously accepts that named witness. No survivors.


## Historical round 4: chain-resolved MVP identities

At that historical round, the Go and independent-reader gates covered 139
bundles and two row vectors; N4/N5 now cover 144 bundles as recorded above.
All 94 strict-default fixtures remained byte-for-byte unchanged; every
prior vector name and expected refusal remains present. New fixtures cover
name/registration reuse, the current grant-key binding, unreadable/malformed
values, registration changes, and both mismatched height and hash.
`TestRunningRejectsFixture` checks a valid offline positive against refusal
of an injected source and refusal of the unwired node path; its strict default
control passes without a names input. `TestLookupPinsStatementView` asserts
both signed names and the explicit height/hash passed to the source.
`TestCLIMVPNameFixtures` exercises every MVP vector through files and flags,
checks the LAB/OFFLINE banner and success marker, and refuses a valid MVP
bundle when the offline name input is omitted.

The distinct-registration mutant yields erroneous `ATTEST` in
`TestVectors/negative-mvp-owner-registration-reused`; the original checker
refuses `MVP_OWNER_REGISTRATION_REUSED`. Distinct-name removal is a refusal-order
control: the fixture still fails registration binding. The table does not
claim that every removed guard independently causes false acceptance.
All 64 final controls fail their named tests, with zero survivors, panics,
setup failures or non-applied edits counted as detections. The initial
control revision detected only 61/63: a length-gate deletion crashed and the
order mutation survived the new signature binding. They were corrected to
exercise unsafe early acceptance and correctly signed reversed identities;
the final control run is the green evidence above.

No node read, production observation, person-level identity proof or live
admission is established by these fixtures. The running MVP path remains
`MVP_CHAIN_READ_REQUIRED` pending N3. The pinned offline snapshot and its
precondition are documented in testdata/README.md and DESIGN.md.


`positive-mvp-current-grant-key` additionally proves the current chain grant
key can differ from the compressed policy owner identifier: approval verifies
under the former. The stale-key negative remains paired with it. Replacing
the current key with the policy identifier fails that named positive, as shown
by `mvp-current-grant-key`. A producer self-review removed an unintended extra
key-equality restriction before handoff; it was appended as a signed correction
to preserve the already published commit without rewriting history.
