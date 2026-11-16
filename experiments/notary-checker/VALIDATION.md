# Bounded validation evidence

Environment: Go 1.26.10, Python 3.14.4, Linux amd64. Go uses
`GOTOOLCHAIN=local`; verification and mutations ran with cached pinned
modules, `GOPROXY=off`, and `GOSUMDB=off`. No real node was used; service/RPC
tests use loopback mocks. Historical sections retain their original evidence.

| Check | Real exit | Evidence / limit |
| --- | --- | --- |
| `gofmt -l .` | 0 | No output |
| `go vet ./...` | 0 | This module |
| `go test -race -count=1 -timeout 120s ./...` | 0 | This module, both CLIs and service; 144 complete signed-bundle vectors and two isolated row vectors; N4/N5 evidence below |
| `go build ./cmd/notary-check` | 0 | CLI builds |
| `python3 -B scripts/reference.py` | 0 | All 144 signed bundles and two isolated row vectors; exact candidate octets, digest, positive signatures, envelope IDs and frames |
| `python3 scripts/check-mutants.py --work-dir <fresh-scratch>` | 0 | 64/64 named controls killed; zero survivors; each mutant test exits 1 with the named assertion failure |
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
