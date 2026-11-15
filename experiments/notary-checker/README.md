# Deterministic notary checker — LAB

Offline depth-1 mechanical certification for Grant v3 and
`swarma-trust-contract/2`, pinned to **swarma-link-spec v0.1.48** at
`2012ac9155568af80d610bdf9b7683881a46e5cb`.

The Go library checks complete signed parent/child grants, contracts, consent,
the kind-8186 delegation request, row limits, explicit time and trusted local
D8 policy. It returns the exact unsigned eighteen-member attestation candidate
and its signing digest. The CLI prints `ATTEST <digest>` or `REFUSED <code>`;
refusals exit nonzero. `ATTEST` is an offline candidate decision, **not** a
signed attestation or live authority. This is a laboratory, not production.

There is no node implementation, model, system clock, randomness, signer or
real key handling in this unit. MVP verification takes explicit name reads
through a `NameSource` interface; the running adapter is reserved for N3. The sole external Go dependency is the pinned
BIP-340 library already used in this repository. It is needed because the
specification requires secp256k1 Schnorr signatures.

See [VALIDATION.md](VALIDATION.md) for the bounded results and named mutation
table. Read [DESIGN.md](DESIGN.md) for signed octets, rule-by-rule references, refusal
order, deferred online obligations and conservative choices. The
[open questions](UNRESOLVED_QUESTIONS.md) cover pending J5 text semantics and
D8 affiliation/agreement evidence. Different text hashes refuse; no text is
interpreted. Every admitted v3 row names a certifier; v4 optional-notary and
recipient-class proposals are unsupported.

The strict specification reading remains the default. An explicit local
`mvp-pair-owned-notary` deployment mode permits a notary owned by one of the
two owners only with both owners' signatures over the exact policy scope
and chain-resolved names, distinct registrations and current grant keys.
The running MVP entry point refuses `MVP_CHAIN_READ_REQUIRED` until N3 wires
the node. A file is allowed only with `-offline-name-fixture FILE`; it prints
a LAB/OFFLINE banner and `ATTEST <digest> offline-fixture`. The pinned synthetic
positive observation file is `testdata/mvp-names.json`; its offline precondition
is stated in DESIGN.md. Strict default checking needs no name input.
This MVP exception is not in the specification and changes no protocol bytes.
See [MVP deployment policy](DESIGN.md#mvp-deployment-policy-not-protocol) for
signature bytes, named refusals and future directions.

## Build and verification

Run from this module with Go 1.26, Python 3.10+ and a C compiler for the Go race
runtime. Toolchain downloading is disabled. Put caches and temporary work in
your chosen disposable workbench; the commands below use repository-relative
scratch directories and never write to another module.

```sh
export GOTOOLCHAIN=local
mkdir -p .temp
# Require no output from this formatting check.
gofmt -l .
go vet ./...
go test -race ./...
go build -o .temp/notary-check ./cmd/notary-check
python3 scripts/reference.py
python3 scripts/check-mutants.py --work-dir .temp/mutants-01
git diff --check -- experiments/notary-checker
```

The first Go invocation may obtain the dependencies in `go.sum`; runtime
checking is offline. Once cached, `GOPROXY=off GOSUMDB=off` also works. Mutation
runs set those variables themselves and require a **new** work directory.
They remove only their own copied source trees, retain per-mutant logs/PIDs,
and print a table naming every failed test and any surviving bound.

Example using only the clearly marked, public fixed test fixtures:

```sh
.temp/notary-check \
  -parent testdata/positive/parent.json \
  -child testdata/positive/child.json \
  -parent-contract testdata/positive/parent-contract.json \
  -child-contract testdata/positive/child-contract.json \
  -request testdata/positive/request.json \
  -policy testdata/positive/policy.json \
  -notary-value testdata/positive/notary-value.json \
  -statement testdata/positive/statement.json \
  -at 1700000100
```

Text-bearing cases additionally take `-parent-text` and `-child-text` files.
Inputs are exact bytes: adding a newline to a grant, contract, request, policy
or statement changes acceptance. The name-value top level follows its own
LIP-0010 extension rules; its authority span remains canonical.

## Tools and artifacts

| Tool | Use / exact entry point | Output |
| --- | --- | --- |
| Go | `go build -o .temp/notary-check ./cmd/notary-check` | Disposable CLI binary |
| Go | `go vet ./...`; `go test -race ./...` | Diagnostics; tests check exact codes, no partial result on refusal, deterministic candidate octets, signatures and anchor frames |
| gofmt | `gofmt -l .` (must print nothing) | Formatting violations on stdout |
| Python stdlib reader | `python3 scripts/reference.py` | Independently verifies all signed-bundle and isolated row vectors, exact candidate bytes and digest; no Go calls |
| Python fixture writer | `python3 scripts/make-fixtures.py` | Reproduces `testdata/vectors.json` and `testdata/positive/` using only public fixed test secrets; no randomness or real keys |
| Python mutation controls | `python3 scripts/check-mutants.py --work-dir .temp/mutants-01` | Named-test table, individual logs and `mutation-results.md`; nonzero on any survivor, panic, timeout, non-applied mutation or compile failure |
| Git | `git diff --check -- experiments/notary-checker` from the repository root | Whitespace diagnostics only |

The independent Python reader uses its own JSON member/span handling and
stdlib big-integer curve arithmetic for BIP-340. It shares no Go parser or
crypto implementation. Expected negative codes are fixture requirements, not
learned from the candidate. Each positive fixes the complete attestation
bytes, digest, test signature, envelope ID and 72-byte anchor script.

The `row-budget-over` test isolates an otherwise unreachable cap defense:
D12 forbids delegating spend, so no production flag enables the counterfactual
spend profile. Mutation controls distinguish end-to-end acceptance errors
from first-refusal precedence errors; see their boundary column. Agreement
between readers is evidence for these finite fixtures, not a proof of all
possible inputs or node behavior.

## Later service unit

The later service must generate and retain its attestation key **on its
isolated VM**, expose a typed attest endpoint, register its own notary name,
and provision authenticated D8 affiliation/agreement policy. It must resolve
names and checkpoints on its own node, validate issuance and seal state,
maintain a durable per-row record, obtain validated tip claims, sign, fund and
anchor real attestations, and process durable withdrawals. Neither caller
assertions nor a passing offline digest replace these obligations. No such
key, VM, endpoint, registration, funding or chain operation is delivered here.

The complete canonical candidate is limited to 8192 bytes before any digest is
returned. Oversize composition refuses as `ATTESTATION_TOO_LARGE`; the signature
helper uses the same candidate limit. See [DESIGN.md](DESIGN.md#produced-object-size-audit)
for the envelope, ID, anchor-frame and input-encoding audit.
