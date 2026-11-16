# Service validation

Spec pin remains v0.1.48 / `2012ac9155568af80d610bdf9b7683881a46e5cb`.
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
