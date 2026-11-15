# Bounded validation evidence

Environment: Go 1.26.10, Python 3.14.4, Linux amd64. Go uses
`GOTOOLCHAIN=local`; verification and mutations ran with cached pinned
modules, `GOPROXY=off`, and `GOSUMDB=off`. No runtime network or node was used.

| Check | Real exit | Evidence / limit |
| --- | --- | --- |
| `gofmt -l .` | 0 | No output |
| `go vet ./...` | 0 | This module |
| `go test -race ./...` | 0 | This module and CLI; 91 complete signed-bundle vectors and two isolated row vectors |
| `go build ./cmd/notary-check` | 0 | CLI builds |
| `python3 scripts/reference.py` | 0 | All 91 signed bundles and two isolated row vectors; exact candidate octets, digest, positive signatures, envelope IDs and frames |
| `python3 scripts/check-mutants.py --work-dir <fresh-scratch>` | 0 | 49/49 named controls killed; zero survivors; each mutant test exits 1 with the named assertion failure |
| Positive CLI fixture at `1700000100` | 0 | `ATTEST bbc8faeb27b65ce4460c92228ec0487496e586b2c4ee5e216943036bdc3fc051` |
| Same CLI fixture at `1700000200` | 1 | Expected refusal `GRANT_EXPIRED`; this is a failing command as required, not a green gate |

An additional temporary contract-only probe compared the parser with the
pinned LIP-0014 corpus: all 149 applicable cases passed, exit 0. The two
remaining eleven-member cases exercise profile `/1` reader selection and
were explicitly excluded from this fifteen-member `/2` reader. The upstream
corpus is unchanged between v0.1.46 and v0.1.48. This finite comparison does
not qualify chain state or all possible inputs.

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
| cross-owner-relation | bilateral approval cannot waive third-party rule | TestVectors/negative-cross-owner-not-third-party | ATTEST |
| cross-owner-agreement | both owners agree | TestVectors/negative-cross-owner-missing-certifier | ATTEST |
| notary-delegator | key independence from delegator | TestVectors/negative-notary-is-delegator | ATTEST |
| notary-delegatee | key independence from delegatee | TestVectors/negative-notary-is-delegatee | ATTEST |
| notary-executor | name independence from executors | TestVectors/negative-notary-is-executor | ATTEST |
| statement | explicit statement fields | TestVectors/negative-statement | ATTEST |
| lexical | no normalization of signed string spelling | TestVectors/negative-contract-escape | ATTEST |
| notary-value | notary key must be a curve point | TestVectors/negative-notary-key | ATTEST |
| row-selection | ordinal selects its own row | TestVectors/negative-other-row-executor | ATTEST |
| attestation-signature | service signature binds the candidate | TestSignedAttestationRejectsMismatch/signature | named assertion failed |
| row-pool-sum | row caps fit the separate signed pool | TestContractRules/negative-parent-row-cap | ATTEST |
| delegate-spend | D12 independently forbids delegated spend | TestContractRules/negative-delegated-spend | ATTEST |
| anchor-id | frame IDs must be 32-byte digests | TestAnchorRejectsMalformedID | named assertion failed |

No generated mutation tree, binary, cache or private execution log is part of
the public change. No independent review, live service, name registration,
node/journal qualification or production attestation is claimed.
