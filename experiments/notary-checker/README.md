# Deterministic notary checker — LAB

Offline depth-1 mechanical certification for Grant v3 and
`swarma-trust-contract/2`, pinned to **swarma-link-spec v0.1.51** at
`bd3bc80e5543d8a563343ec05abd1a5f3f67284c`.

The Go library checks complete signed parent/child grants, contracts, consent,
the kind-8186 delegation request, row limits, explicit time and trusted local
D8 policy. It returns the exact unsigned eighteen-member attestation candidate
and its signing digest. The CLI prints `ATTEST <digest>` or `REFUSED <code>`;
refusals exit nonzero. `ATTEST` is an offline candidate decision, **not** a
signed attestation or live authority. This is a laboratory, not production.

The checker library has no model, system clock, randomness or signer. The
service below adds generated-key custody, system time and a concrete regtest
node reader around that same checker. MVP verification takes explicit name
reads through `NameSource`. The sole external Go dependency is the pinned
BIP-340 library already used in this repository. It is needed because the
specification requires secp256k1 Schnorr signatures.

See [VALIDATION.md](VALIDATION.md) for the bounded results and named mutation
table. Read [DESIGN.md](DESIGN.md) for signed octets, rule-by-rule references, refusal
order, deferred online obligations and conservative choices. The
[open questions](UNRESOLVED_QUESTIONS.md) cover pending J5 text semantics and
D8 affiliation/agreement evidence. Different text hashes refuse; no text is
interpreted. Every admitted v3 row names a certifier. In v0.1.51, J10, J11 and J12
are in force: an eligible v4 row without a certifier admits a child through
its landlord/holder checks and needs no attestation. This module supports
Grant v3 and profile `/2` only; the notary still never signs for a row without
a certifier. It does not implement v4 admission, classes or groups.

The default service config and zero-valued `Policy.Mode` retain strict D8.
MVP is reachable only through `"mode":"mvp-pair-owned-notary"` in the operator
file selected by `deployment_policy_file`; no request field selects it. This is
a deployment exception, never specification text or protocol. An explicit local
`mvp-pair-owned-notary` deployment mode permits a notary owned by one of the
two owners only with both owners' signatures over the exact policy scope
and chain-resolved names, distinct registrations and current grant keys.
The unconfigured checker entry point retains `MVP_CHAIN_READ_REQUIRED`; the
service uses the concrete RPC reader. A file is allowed only with `-offline-name-fixture FILE`; it prints
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
| Python revision controls | `python3 -B scripts/check-revision-mutants.py --work-dir .temp/revision-mutants-01` | Service, custody and bounds controls plus private/operator FIFO and strict-default controls; per-control logs, PIDs and `results.json`; every kill requires its specific named test |
| Bash, Python 3 stdlib, Git, OpenSSH, coreutils | `bash -n scripts/verify-release.sh`; `git rev-parse`; `git cat-file`; `ssh-keygen -Y verify`; `sha256sum`; `cmp` | Exact download-directory membership and `os.lstat` file types, local release authentication and checksum verdicts; exact combined command below |
| Target operator tools | `install`, `stat`, `namei -l` as in [RELEASE.md](RELEASE.md#install-the-verified-executable) | Installed checksum, owner/mode and directory-chain checks on the target |
| Offline release verification | `scripts/verify-release.sh SOURCE_ROOT RELEASE_COMMIT RELEASE_TAG RELEASE_DIR REBUILT_BINARY TAG_ALLOWED_SIGNERS MANIFEST_ALLOWED_SIGNERS MANIFEST_SIGNER_ID` | Verdicts only; one pinned SSH tag object/name/commit, separate tag/manifest authorities and matching downloaded/independent-rebuild hashes; absolute physical paths, isolated Python and config-free offline Git reads; run from a clean operator-controlled directory; see [RELEASE.md](RELEASE.md) |
| Release controls | `python3 -B scripts/test-verify-release.py` | Named offline positive/negative checks; disposable keys and fixture tags under the configured temporary directory |
| Release mutation control | `python3 -B scripts/check-release-mutant.py --work-dir .temp/release-mutant` | Eight disposable enumeration, whole/per-operand role-separation and tag-header mutants; each named negative must fail and positive pass; logs, exit codes, PIDs and `mutation-results.md`; requires fresh work directory |
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

## Notary service (regtest laboratory)

`cmd/notary-service` and `internal/service` stay in this module to call the
landed checker and its `SignedAttestation`/anchor helpers directly, with the
same dependency and specification pin. No protocol bytes or offline fixture
semantics change. This is a bounded signing service, not live chain admission:
issuance/seal validation, historical ownership/checkpoint proof, durable row
anti-equivocation, withdrawals and authenticated D8 provisioning remain
operational obligations described in DESIGN.md.

Generate the attestation key on the machine that will retain it:

```sh
notary-service keygen -out attestation.key
notary-service serve -config service.json
```

Keygen prints only the x-only public key and a newline, suitable for
`{"swarma":{"notary":{"attest":"PUBLIC_KEY"}}}` in the LIP-0010 section 9 name
value. The file is create-exclusive, regular and mode 0600; existing files and
symlinks refuse. There is no secret import/export command. Runtime key and RPC
credential files must be owner-only regular files owned by the process user;
symlinks refuse. Errors are fixed names and never echo input, credentials or
file locations. A key stays in process memory until shutdown; no secure-memory
or compromised-process claim is made.

Example `service.json` (replace endpoint ports and filenames for an isolated
regtest node; all fields are mandatory):

```json
{
  "listen": "127.0.0.1:8080",
  "key_file": "attestation.key",
  "rpc_endpoint": "http://127.0.0.1:18443",
  "rpc_credential_file": "rpc.cookie",
  "deployment_policy_file": "deployment-policy.json",
  "limits": {
    "request_bytes": 65536,
    "requests_per_second": 10,
    "burst": 10,
    "timeout_ms": 3000,
    "concurrent": 2
  }
}
```

The RPC credential file contains `user:password` (a Core cookie is supported).
The node must enable `-namehistory=1`. Listen and RPC addresses must use literal
loopback IPs; HTTP redirects and proxy discovery are disabled for RPC. Every
view requires `chain=regtest`. There is no mainnet service mode.

The sole route is **POST /v1/attest**. Its JSON members are `parent`, `child`,
`parent_contract`, `child_contract`, `request`, `policy_reference`, `statement`,
and optional UTF-8 `parent_text`/`child_text`. Protocol objects are nested JSON
objects retaining their exact canonical checker octets. `policy_reference` is
the lowercase SHA-256 of the exact configured deployment policy file, not a
path or a request-supplied policy. Notary value and owner-name observations
come exclusively from the configured node; time comes from the service clock.
Unknown, duplicate, aliased, trailing or excessively nested JSON refuses.
Offline fixture flags/configuration are unsupported and tested as refusals.

On success the response is `{"decision":"ATTEST","signed_attestation":...,
"anchor_frame":"..."}`. The envelope is exactly the checker's signed form;
`anchor_frame` is hex for the 72-byte action-0x04 OP_RETURN script. It is handed
to the operator without broadcast. On refusal the body has only
`{"decision":"EXACT_REFUSAL_NAME"}`; no signature, candidate or anchor field.
Checker names pass through unchanged. Node names include `NODE_TIP_MISMATCH`,
`NODE_NAME_UNREGISTERED`, `NODE_NAME_VALUE`, `NODE_NAME_HISTORY`,
`NODE_RPC_FAILURE`, `NODE_NETWORK` and `NODE_CREDENTIALS`. Input/limit refusals
include `REQUEST_INVALID`, `REQUEST_TOO_LARGE`, `RATE_LIMIT`, `BUSY`,
`POLICY_REFERENCE` and `REQUEST_TIMEOUT`. RPC deadline failures retain
`NODE_RPC_FAILURE`; an expired body read is `REQUEST_READ`.

The rate bucket is global and in memory, avoiding a per-client allocation map.
Config accepts 1–100 requests/s, burst 1–100, 1–32 concurrent operations,
1024–1048576 request bytes and a 10–30000 ms timeout. Header/body read deadlines,
a request-wide RPC context, bounded RPC responses and pre-sign deadline checks
bound work. Limits reset at restart; there is no durable rate/replay journal.

**Out of scope:** broadcasting or funding the seal or anchor transaction
(treasury and owner gated); network ACL configuration (operator owned); and
deployment (infrastructure owned, from a signed reviewed release). Registering
or updating names is also an operator action; the service reader never writes
to the node. The test harness alone registers disposable synthetic names.

Slow-body clients can occupy both concurrency slots until the configured read
deadline. The listener has no connection-count cap; it remains loopback-only.

See [RELEASE.md](RELEASE.md) for the release artifact name, checksum verification,
target key generation and deployment boundary.

### Reproducible service build

With **Go 1.26.10**, Linux/amd64, `GOAMD64=v1`, `GOTOOLCHAIN=local`, `GOWORK=off`
and `CGO_ENABLED=0`, run from this module:

```sh
mkdir -p .temp
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOWORK=off \
  go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
  -o .temp/notary-service-a ./cmd/notary-service
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOWORK=off \
  go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
  -o .temp/notary-service-b ./cmd/notary-service
sha256sum .temp/notary-service-a .temp/notary-service-b
cmp .temp/notary-service-a .temp/notary-service-b
```

Two builds of the candidate must produce identical SHA-256.
[SERVICE-VALIDATION.md](SERVICE-VALIDATION.md) records earlier measured hashes;
rebuild and verify the exact release candidate as described in RELEASE.md. Stripping
VCS metadata and build ID and trimming source paths makes repository location
irrelevant. This claim is bound to that toolchain, target, source and flags.

### Service verification tools

| Tool | Exact entry point | Output |
| --- | --- | --- |
| Go | `go vet ./...`; `go test -race -timeout 120s ./...` | Checker, RPC, service, key custody, refusal and HTTP bounds tests |
| Python | `python3 -B scripts/check-service-mutant.py --work-dir .temp/service-mutant` | Named signing-on-refusal control table and logs; requires fresh work directory |
| Python | `python3 -B scripts/regtest-service.py --namecoind NAMECOIND --service NOTARY_SERVICE --work-dir .temp/service-regtest` | Five real-node outcomes, independent signature/frame verification, child PIDs and cleanup record; requires fresh work directory |
| Core 28.0 | Harness starts `namecoind` with `-regtest=1 -listen=0 -connect=0 -dnsseed=0 -discover=0 -fixedseeds=0 -namehistory=1`, loopback RPC | Disposable node state; removed in harness cleanup |
| SHA-256 | `sha256sum` and published release SHA256SUMS | Binary provenance and reproducible-build evidence |

Obtain Core only through the [official download page](https://www.namecoin.org/download/),
and verify the archive against the release's published
[noncodesigned.SHA256SUMS](https://github.com/namecoin/guix.sigs/tree/main/28.0)
before executing it. The regtest harness requires version 28.0, never enables
peers, never prints wallet keys, and stops only its own children by PID. It
removes its node datadir, attestation key and configuration files in `finally`.
It does not download or trust arbitrary binaries on the caller's behalf.

The complete canonical candidate is limited to 8192 bytes before any digest is
returned. Oversize composition refuses as `ATTESTATION_TOO_LARGE`; the signature
helper uses the same candidate limit. See [DESIGN.md](DESIGN.md#produced-object-size-audit)
for the envelope, ID, anchor-frame and input-encoding audit.


Operator input files are opened read-only with no symlink following,
nonblocking open and close-on-exec. The opened descriptor must be a regular
file before blocking reads are restored. Config and deployment-policy
violations retain `CONFIG` and `POLICY_FILE`; checker file flags retain
`INPUT_READ`. The private key and RPC credential retain their stricter
ownership/mode checks and existing named refusals. `TestOperatorFileFIFORefusal`,
`TestServeFIFOAndFixtureFlag` and `TestInputFIFORefusal` pair regular controls
with bounded FIFO negatives. Revision controls F3/F4 restore a blocking open
and require those named tests to fail.

The checker CLI uses `operatorfile.Read(path, 65536)`: each of its ten file
flags (`-parent`, `-child`, `-parent-contract`, `-child-contract`, `-request`,
`-policy`, `-notary-value`, `-statement`, `-parent-text`, `-child-text`) and
`-offline-name-fixture` is capped at 64 KiB (65536 bytes). A larger file refuses
as `REFUSED INPUT_READ` with exit 2 before checking or hashing it. This adds an
operator-file limit for scope texts and offline name fixtures; the encoded
grant, contract, request, policy, name-value and statement decoders retain their
separate smaller caps. Service config and deployment policy retain their own
16 KiB/8 KiB limits and `CONFIG`/`POLICY_FILE` refusals.

### N6 RPC password diagnostic boundary

The RPC password is retained behind a private `*string` in `rpcPassword`,
following the scalar-pointer pattern in `single-use/payloadbootstrap/codec`.
`newRPCPassword` makes the single password-bytes-to-string conversion; the
file read buffer is cleared after loading. The holder and `NodeNameReader`
redact ordinary fmt, JSON and text output in value, pointer and context-copy
forms. Bad-verb diagnostics such as `%p` on a value and `%w` bypass formatting
methods; scalar-pointer storage keeps those paths, unexported containers and
containing services from printing the password (an address may be printed).
The reader's `MarshalText` also supplies JSON redaction, so it needs no separate
`MarshalJSON` method. This protects diagnostic output, not process memory.

The sole `Reveal` call in production is the existing `SetBasicAuth` call;
RPC request and Authorization bytes stay unchanged. The holder remains in
notarycheck: the inventory guard counts `Reveal` calls, not direct same-package
field access. This is a call-site claim, not an enforced package-access boundary.

`TestRPCPasswordRedaction`, `TestRPCPasswordContainers` and the real
`TestRPCPasswordServiceContainer` cover the listed fmt/encoding sinks, including
method-bypassing diagnostics and a slog text handler. The text control uses a
real XML encoder, and missing text methods fail by a named assertion.
`TestRPCPasswordWireAndErrors` checks parsed user/password fields as well as
exact Basic Auth and RPC body bytes, first-colon/Unicode-space neighbors and
fixed RPC/transport refusals. `TestRPCPasswordCredentialErrors` pairs an
accepted 4096-byte file with an exact 4097-byte refusal and refuses interior
CR/LF and an empty first-colon user without a partial reader.
`scripts/check-mutants.py` exercises holder fmt/JSON/text redaction, inline
storage reversion (killed by the holder `%p` test), reader text removal and the
reviewer's R1–R4 parsing/boundary controls; each requires its named failure.

Inventory audit: the root credential-output guard records exactly one new
`Reveal` call at `NodeNameReader.rpc`. Its existing carrier-name rules do not
select `NodeNameReader.password`; no detection rule was changed. The retained
field is now `rpcPassword`, and no additional plain password carrier is added.


### N7 signing-key diagnostic boundary

`Service.key` now holds a private `signingKey` with exactly one unexported
`**btcec.PrivateKey` field, constructed by `newSigningKey` and read through
`privateKey`. A `*btcec.PrivateKey` is unsafe: fmt's bad-verb restart can
print its scalar limbs. The extra indirection points to a non-aggregate, so
that restart prints only an address. `TestSigningKeyBadVerbStorage` proves
both the unsafe plain control and the contained Service path. Signing and
shutdown still use and clear the original key object.

On the original 92-pair Service probe, key leaks fall from **21 to 0**.
The full **36 forms × 43 sinks = 1548 pairs** report **0** key leaks,
against **341** on the base. The password holder/reader battery and the
Service password battery each report **0/1548** leaks. The forms cover
values, pointers, copies, zero/nil values, nested containers, arrays, maps,
interfaces and `reflect.Value`; sinks include bad verbs, slog, JSON, XML,
text/template, log and errors. Actual runtime panic output is also tested
for all **36 password forms and 36 Service forms**. Encoders' refusal errors
and text/template's recovered unexported-reflection diagnostics are scanned.

The detector checks raw/plaintext, lower/upper hex, decimal bytes and the
key's eight uint32 limbs. Plain inline, `*struct` and `*[]byte` controls
calibrate it. `TestSigningKeyStorage` and `TestRPCPasswordStorage` pin each
holder to its exact one-field pointer shape; formatting methods alone are
insufficient. All **seven storage controls** are killed by both a named
shape test and a named full diagnostic test, without panic-only kills.
Run `python3 -B scripts/check-storage-mutants.py --work-dir .temp/storage-controls`
from this module with a fresh task-owned work directory; it records logs,
PIDs, exact exits, `results.json` and `mutation-results.md` there.
The original **73 checker, 36 revision and one service controls** remain
separate runners. [SERVICE-VALIDATION.md](SERVICE-VALIDATION.md) records the
current counts, signing-vector compatibility and replacement build hash.

These are bounded diagnostic-output guarantees. Explicit accessors,
reflection traversal or unsafe/process-memory access can read the material.
RPC passwords are deliberately revealed into the outbound Basic Auth header;
no secrecy guarantee applies to explicitly formatting that wire request.
