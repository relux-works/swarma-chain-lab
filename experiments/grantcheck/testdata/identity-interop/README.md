# Swarma Identity issuance junction (G1.0)

These are public, offline laboratory bytes, generated from
`swarma-identity` **48a32fb05e214bc656c640bfb0dd36edf8ab6293** by its
actual CLI dispatcher and existing regtest-pinned loopback RPC fixtures.
The generator adds only an export test; upstream product source and module
requirements stay unchanged. There is no module import of the issuer in
chain-lab. Published BIP-340 test keys are loaded by the issuer's existing
`internal/testsigner` in test code only. No custody key is used.

Target: Grant v3, canonical `swarma-trust-contract/1`, actions `instruct`
and `review`, implied delegation depth zero, no repositories or spend budget,
and legacy landlord values without `holders`. These actions map to the
**empty but non-null** v3 scope array under LIP-0013 section 2.2; they must not
be substituted with invented v3 action names.

CG1 is explicitly constructed with `ContractProfileTrust`, `Network: regtest`,
the pinned regtest genesis, `ExecutorKey: ""`, and construction profile `W`.
Its verifier time is 1795000000; freshness uses age 600 seconds, skew zero,
and floor zero. These are fixture values, not deployment recommendations.

## Pins and specification comparison

| Object | Exact source / specification |
| --- | --- |
| Issuer | `48a32fb05e214bc656c640bfb0dd36edf8ab6293` |
| Issuer rental dependency | `v0.5.1-0.20261112085009-7ea1800ed187` |
| Issuer Grant v3, seal, frame, /2 | spec 0.1.48, `2012ac9155568af80d610bdf9b7683881a46e5cb`, LIP-0004/0005/0014 |
| Issuer /1 vectors | LIP-0013 `8ea31e039881bc8d51a510534b13118490bd9219` |
| Initial CG1 trust product base | `166fc9213a714c71019ee49a52de684c5aaebe5f`, PR150 |
| CG1 declared spec | 0.1.49, `1c3bcafc8bfc1450c3c0cefb69a122f6a97a448e` |
| Notary declared spec | 0.1.51, `bd3bc80e5543d8a563343ec05abd1a5f3f67284c` |
| Notary `SpecCommit` constant | Still `1c3bcafc8bfc1450c3c0cefb69a122f6a97a448e`; documentary discrepancy, not an observed /1 byte difference |
| Toolchain | Go 1.26.10, `GOTOOLCHAIN=local`; no 1.26.8 fallback |

The earlier junction compared LIP-0004/0005/0010/0013/0014/0026 across
0.1.48, 0.1.49 and 0.1.51. Grant/frame bytes and the /1-/2 vector bytes are
unchanged. The 0.1.51 holders extension is intentionally excluded by the
owner-selected legacy compatibility profile (LIP-0010 section 10).
CG1's previous pay-only gate is superseded by its explicit trust profile.
No spec or issuer patch is included here.

## Reproduction and byte provenance

From the repository root with Go 1.26.10 selected:

```sh
bash .scripts/regenerate-identity-interop.sh "$PWD/.temp/identity-interop-regenerated"
```

The output directory must not exist. The script creates an isolated scratch
clone/HOME/caches and short TMPDIR, checks out the full immutable issuer SHA,
adds `.scripts/identity-interop/issuer_test.go` as a test-only exporter, then
runs exactly:

```sh
go test -mod=readonly -p 1 -parallel 1 -count=1 -run '^TestJunctionExport$' -v ./internal/facade
```

The export test drives `grant seal`, `grant draft`, `grant consent`, both
`grant sign` stages, and `grant anchor` through the existing CLI dispatcher
with explicit config/request/ledger and `--json`. `issuer-outcomes.json`
records dispatcher exit codes, not separately spawned CLI process exits.
The test's process exits zero only when all asserted controls/refusals hold.
Its fixture nodes are closed by `t.Cleanup`; no Core daemon is launched.

`signed-grant.json`, `contract.json` and the presentation/mutations preserve
canonical octets without trailing newlines. Requests/results and issuer
refusal envelopes are indented JSON with a trailing newline. Request and
plan files contain public funding parent transactions and public signatures.
`presentation.json` uses the anchor plan's unsigned txid. `seal-result.json`
and `anchor-result.json` retain `dry_run: true`; neither is chain evidence.
The transaction plans use the public laboratory scalar-1 P2WPKH program.

`identity_interop_node_test.go` follows the existing single-use
`witnessGraph` model. It signs the **unchanged unsigned transaction bodies**
with that public funding scalar, preserving their stripped txids. It supplies
synthetic name_update generations, headers, block membership, and an empty
mempool. CG1 uses its actual kernelbind/rental backend, not a live-verdict stub.
The kernel independently checks signatures, exact RPC/raw projections,
name links, issuance frame/commitment, witness funding, liveness, time and
freshness against this graph. Header hashes/membership are fixture claims;
this does not demonstrate proof of work, consensus, registration or broadcast.

## Measured accept/refuse matrix

Every refusal test runs a valid legacy control. CG1 cached inbound and outbound
also perform fresh kernel checks. A negative input never enters CG1's cache;
wrong sender/contract bytes cannot replace an already admitted proof.

| Case | Issuer dispatcher | CG1 trust | Notary |
| --- | --- | --- | --- |
| Legacy target | `OK`, exit 0; signed plus seal/anchor plans | `live/live`, inbound, cached inbound, outbound | v3 `readGrant` accepts; certification `Check` refuses `/1` as `CONTRACT_ENCODING` |
| Wrong consent | `CONSENT_SIGNATURE`, exit 3 | `refused/invalid_presentation` | `GRANT_CONSENT` |
| Wrong grantee | `CONSENT_SIGNER`, exit 3 | `refused/invalid_presentation` | `GRANT_CONSENT` |
| Elapsed valid window | **accepted**, exit 0; no ambient clock | `exchange/expired` under Nostr; no admission | `GRANT_EXPIRED` |
| Wrong seal | `SEAL_KEY_MISMATCH`, exit 3, anchor sees wrong script | `refused/issuance_mismatch`, changed signed outpoint no longer matches issuance | v3 parser accepts changed signed outpoint; no chain check |
| Missing/spent seal | `SEAL_MISSING_OR_SPENT`, exit 3 | `exchange/seal_spent`, closed, for a modeled spent seal | no chain/liveness API in this parser |
| Tampered contract / signed byte | `CONTRACT_HASH`, exit 3, contract bytes changed | `terms_invalid` for changed resolved contract; `invalid_presentation` for changed signed byte | `GRANT_SIGNATURE` for changed signed byte |
| Unsupported contract profile `/9` | `CONTRACT_PROFILE`, exit 3 | `terms_invalid` with valid public-test signatures | v3 parser accepts; certification remains `CONTRACT_ENCODING` |
| Wrong request schema / grant version | `BAD_INPUT`, exit 2 | `invalid_presentation` for v9 signed grant | `GRANT_FIELD` |
| Wrong issuance locator | no issuer locator admission API | `refused/issuance_mismatch` | v3 parser accepts; no own-node verification |
| Empty holders | `LANDLORD_NOT_V3`, exit 3 | `refused/binding_mismatch`, not retryable | outside parser/certification input |
| Populated holders | `LANDLORD_NOT_V3`, exit 3 | `refused/binding_mismatch`, not retryable | outside parser/certification input |

Wrong-consent/grantee/version/seal vectors are re-signed with the public
issuer test signer to isolate their changed inner field. Tampered-byte keeps
the old signature. The seal outpoint change necessarily also invalidates the
issuance commitment, so this vector establishes that earlier gate; it does
not isolate the later seal-script gate. The issuer wrong-seal case instead
isolates its anchor script/key precheck. Codes differ across these distinct
APIs; both sides deny use. Refusal does not mean issuance rejects every
verifier-time expiry: that asymmetry is intentional and measured.

## Ceremony: offline no-holders checker

Run from `experiments/grantcheck`:

```sh
go run ./cmd/no-holders < operator-supplied-landlord-value.json
```

Input is the landlord VALUE as raw JSON bytes, or that value encoded as the
JSON string of `name_show.value`; do not supply a whole RPC envelope. Output:
`LEGACY-OK` (exit 0), or `REFUSE HOLDERS_PRESENT` (exit 1) for any holders
member, empty/populated/null included. Malformed, oversized or otherwise
invalid legacy values refuse with a fixed reason and exit 1. The command
reads stdin only and contains no node/client/config lookup. `LEGACY-OK` is
only a format/compatibility result, not on-chain or custody authority.

Tests cover valid raw/string controls, empty/populated/null holders,
malformed/foreign/duplicate fields, and the input bound. The ceremony operator
must supply the real values offline; this junction never queries them.

`SHA256SUMS` lists every JSON file; `TestIdentityInteropCorpus` checks all hashes,
manifest coverage and the exact target profile/actions/network/empty v3 scope.
Issuer negative calls also assert unchanged seal-ledger bytes and no partial result.

## Validation and limits

From the respective modules:

```sh
go test -mod=readonly -p 1 -parallel 1 -count=1 ./...
go vet -mod=readonly -p 1 ./...
```

The producer's single race invocation is `go test -race -mod=readonly -p 1
-parallel 1 -count=1 ./...` from grantcheck. Notary's tests include the existing
complete /2 certification controls and these /1 boundary tests; the issuer
cannot produce a delegated parent or child. No fabricated child/notary bundle
is substituted. No mainnet node, real-name value, live Core regtest node,
registration, signing wallet, broadcast, confirmation, consensus, mempool
race, reorg, transport integration, owner custody or production freshness
qualification is exercised. Real-chain qualification remains a separate gate.
