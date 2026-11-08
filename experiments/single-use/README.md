# Single-use grant laboratory

Go executor and genuine Namecoin Core 28 regtest harness for CIP-0002. The only
implemented effect is a local JSONL append labelled `simulated-repository.create`.
This is not production authorization, a wallet, or a mainnet runtime qualification.
The executable deliberately accepts regtest only. Mainnet output consists solely
of offline JSON plans, with no serialized transaction hex or network operations.

## Contract

The seal is legacy P2SH of `OP_1 <issuer compressed key> <grantee compressed key>
OP_2 OP_CHECKMULTISIG`, in that order. Two distinct secp256k1 keys are operator
pins; no new name-value key field is introduced. The executor independently
recomputes the legacy transaction signature digest and verifies the actual
signature against both pins using Decred secp256k1 v4.4.0. It requires NULLDUMMY,
strict DER, low S and SIGHASH_ALL. Issuer-only verification always means
revocation, even if a request hash is present. Grantee-only verification means a
candidate use. Neither-key or both-key attribution refuses.

A use transaction must contain exactly one zero-valued OP_RETURN with the exact
minimal script `6a20<SHA256(exact signed request envelope bytes)>`. Whitespace
changes in an envelope change this hash. Ordinary payment/change outputs are
allowed and covered by SIGHASH_ALL. Seal, anchor and use must occur in strictly
increasing active block heights; same-block ordering refuses. One active
confirmation is required before the local effect. Pending use creates no
journal record or effect (an executor lock file can exist).

The owner name must still select the exact pinned confirmed anchor. The executor
checks its raw name_update output, payment script, owner SPKI, certificate hash,
seal, certificate OP_RETURN and active block membership. The existing pinned
public KeyVault verifier checks the P-256 certificate/request signatures and
scope before observation and again immediately before journal reservation.
Existing enrollment and certificate formats remain unchanged. The verifier runs
with private ephemeral state and an absent provider path, never a custody route.

Compared with the draft CIP, this laboratory fixes the P2SH/legacy profile,
operator key pins, exact envelope bytes, minimal OP_RETURN, strict height order,
low-S SIGHASH_ALL, and local reservation semantics explicitly. Other script
profiles and a chain-key attestation protocol are outside this implementation.

## Journal and limits

Use one stable, private mode-0700 state directory per executor. An exclusive
flock protects a seal-keyed journal. A mode-0600 temporary record is written and
fsynced, renamed, and its directory fsynced **before** any effect. The record
binds the full policy, request hash and spend txid. Files reject symlinks, foreign
owners, permissive modes and multiple hard links. The harmless effect append is
fsynced before the journal is marked complete.

A surviving `reserved` record is terminal for retries. `already-executed` with
`journal_phase: reserved` means the effect outcome is unknown, not proof that it
happened. A crash before reservation permits retry; a crash after reservation
may lose the effect permanently; a crash after the effect must not duplicate it.
No exactly-once claim is made. These tests exercise process exits, not power-loss
or filesystem corruption guarantees. Corrupt journals refuse without repair.
Never delete or relocate executor state to retry. Different executor directories
are independent and can each execute once. Cooperative local ownership and
filesystem locking/fsync semantics are assumptions, not hostile same-UID
confinement. Reorgs after an effect do not undo it. One confirmation is not
finality; observation and journal reservation cannot be atomic with consensus.

The node is an independently trusted, fully validating own Core instance. The
read-only HTTP adapter accepts only loopback IPs and a dedicated `w3-observer`
account, no proxy, redirect or wallet endpoint. Configure server-side RPC
whitelisting as well. Methods: `getblockchaininfo`, `getblockhash`,
`getblockheader`, `getrawtransaction`, `gettxout`, `name_show`, `getrawmempool`,
`getblock`. `gettxout` is permitted but currently unused. W7 sealwatch exports
provide duplicate/fold-alias rejection and exact relevant-field projections;
unrelated Core metadata remains allowed. Raw transaction bytes are bound to
projected inputs/outputs, txid and active block membership.

Limits: 30 seconds, 1,024 calls, 32 MiB total replies, 8 MiB per reply, at most
64 blocks of seal age (65 inclusive block positions), 256 mempool entries,
1 MiB legacy transactions, 64 inputs/outputs, 10,000-byte scripts. Witness
transactions encountered in the scan refuse; coinbase is skipped. This bounded
legacy-only scan is unsuitable for arbitrary busy chains without further work.
The `headers` counter is bounded metadata, not an active-tip authority: genuine
Core after invalidate/reconsider can report `blocks=117, headers=116, IBD=false`.
Active hashes, headers, membership and repeated tip checks provide the proof.

## Tools and commands

Go 1.26.8 was used on Darwin arm64. Dependencies are pinned in go.mod/go.sum;
the sealwatch sibling module is imported directly. No copied projection parser.

```sh
cd experiments/single-use
go mod download
go mod verify
go vet ./...
go test -race -count=1 ./...
go build -trimpath -o .temp/single-use ./cmd/single-use
go build -trimpath -o .temp/single-use-plan ./cmd/single-use-plan
.temp/single-use --policy policy.json --route private-route.json \
  --certificate certificate.json --request request.json
.temp/single-use-plan --spec use-spec.json --request request.json
```

Executor input structs are in policy.go/node.go. Route files contain credentials
and must stay private. Policy and request files are public inputs, but their
local paths are not portable. `--test-at RFC3339` is a regtest clock override;
the runtime still refuses non-regtest policies. Receipt exits: 0 for pending,
executed or already-executed; 1 for refused; 2 for malformed CLI/input. The CLI
has no crash-injection switch. The separate Go test child owns that test seam.

Genuine Core tests are opt-in and require explicit locally admitted tools:

```sh
export W3_REGTEST=1 W3_RUN_ROOT=/absolute/new/private-run-root
export W3_CORE_CLI=/pinned/namecoin-cli W3_CORE_DAEMON=/pinned/namecoind
export W3_EXECUTOR=/clean-head/single-use W3_LAB_SIGNER=/pinned/labtestsigner
export W3_PUBLIC_VERIFIER=/pinned/swarma-keyvault
export W3_PUBLIC_FIXTURE=/public/certificate-cycle2
go test -count=1 -v -run '^TestGenuineCoreMatrix$' .
```

The harness refuses an existing root, pins Core tool hashes, creates its own
no-peer regtest node and two throwaway wallets, and stops only its recorded PID.
The public fixture directory supplies certificate.json, request.json and
enrollment.json. The lab signer uses the previously admitted throwaway P-256
requester key in place; no key material is read/exported by the harness. The
public verifier and signer are separately pinned dependencies, not built here.
Per-run `public/` holds commands, exit codes, receipts, control results and node
lifecycle. `private/` holds wallets, cookie, routes, node logs and executor state;
never distribute that directory. Tests require valid, unexpired public fixtures.

The 47 matrix controls each assert the specified refusal/pending/replay outcome
and state/effect counts next to a valid control. Three named alias/conflict cases
mutate real Core responses and are labelled as such; the other 44 use unmodified
Core responses. Invalid OP_RETURN policy cases require `acceptnonstdtxn=1` in
this closed regtest. A separate `acceptnonstdtxn=0` probe establishes standard
P2SH signing/admission, not grant-executor qualification. The external control
plant bypasses request commitment in an isolated build; the wrong-hash case must
fail with an unexpected effect, not a setup error.

## Offline mainnet plans

`single-use-plan` has no RPC, wallet, signer or broadcast capability. Funding
prevouts, amounts and scripts are operator parameters, not independently proven
UTXOs. Each of seal/anchor/use emits inputs, output scripts, conservative maximum
signed vbytes and a fee reserve at 200 sat/vB. It requires at least 1,000 sat of
change, bounded integer amounts, P2PKH funding and P2PKH name-control inputs;
payment/change outputs may be P2PKH or P2SH. P2PKH input bounds include an
uncompressed public key. The anchor retains the TS-01 owner-value shape. The
planner does not validate funding ownership, previous name consensus semantics,
P-256 authority, current fees or the final signed transaction. Names and owner
pins must be independently validated. Example outpoints are inert placeholders.

A plan is not permission to spend. Mainnet needs independent review and a new
admitted runtime path, then owner GO for each exact signed transaction hex.
