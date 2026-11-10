# Single-use grant laboratory

## SW1 witness construction

The shared W verifier retains and validates native P2WPKH witness stacks for v3 seal creation and issuance; the historical legacy decoder and name/seal-spend APIs below retain their narrower contracts.

See [the W boundary/reason inventory](../WITNESS-PROFILE.md). This first delivery is linkage-only: unconfirmed payment Q is deferred to SW1b with an authenticated GV4 proof contract. Existing signed v3 grant bytes are unchanged.

Go executor and genuine Namecoin Core 28 regtest harness for CIP-0002. The only
implemented effect is a local JSONL append labelled `simulated-repository.create`.
This is not production authorization, a wallet, or a mainnet runtime qualification.
The executor accepts only explicitly pinned regtest or main networks. Mainnet
CLI observations require the operator CLI route described below and a separate
runtime admission; this source change alone grants no permission to run them.
The offline planner emits JSON plans, never serialized transaction hex.

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

The node is an independently trusted, fully validating own Core instance. The regtest
HTTP adapter accepts only loopback IPs and a dedicated `w3-observer`
account, no proxy, redirect or wallet endpoint. Configure server-side RPC
whitelisting as well. Methods: `getblockchaininfo`, `getblockhash`,
`getblockheader`, `getrawtransaction`, `gettxout`, `name_show`, `getrawmempool`,
`getblock`. `gettxout` is permitted but currently unused. W7 sealwatch exports
provide duplicate/fold-alias rejection and exact relevant-field projections;
unrelated Core metadata remains allowed. Discovery projects exact `txid` and
`vin[].{txid,vout}` from verbose Core replies. Unrelated transactions are not
required to fit the seal spend's legacy profile. Candidate raw bytes remain
bound to all projected inputs/outputs, txid and active block membership;
selection and raw validation use the same reply. This relies on the admitted
own-node's input projection for discovery, not on arbitrary remote JSON.

Blocks use `getblock HASH 2`, one bounded verbose reply per block. Candidates
inherit the enclosing block context; explicitly supplied conflicting context
refuses. Independent active-header and membership checks still apply. Mempool
entries use `getrawtransaction TXID true`; there is no 256-entry cutoff. With
N scanned blocks and M distinct mempool entries not already in those blocks,
a successful fresh confirmed execution takes at most **26 + 2N + M RPCs**,
including the final pre-reservation checks (public signature verification is
local). Replay takes zero. Exhausted resource budgets still refuse before any
journal/effect; this is not a claim of availability for unbounded chain load.

Limits: 30 seconds, 1,024 calls, 32 MiB total replies, 8 MiB per reply, at most
64 blocks of seal age (65 inclusive block positions), 10,000 transactions per
block. Anchor, seal and candidate transactions retain the strict 1 MiB legacy
profile, 64 inputs/outputs and 10,000-byte scripts. Unrelated witness and
larger-input transactions are allowed; a witness or oversized candidate still
refuses. Coinbase is skipped. Busy chains can still exhaust the observation
time/call/byte budgets; a spend-index/proof adapter remains separate work.
The `headers` counter is bounded metadata, not an active-tip authority: genuine
Core after invalidate/reconsider can report `blocks=117, headers=116, IBD=false`.
Active hashes, headers, membership and repeated tip checks provide the proof.

## Payload provisioning byte contracts

The standard-library-only [`payloadjournal`](payloadjournal/FORMAT.md) package
defines DK5b v1 binding/lock bytes, fixed refusal codes and public golden files
for Infra and the station payload. It performs no I/O and is not yet wired into
the DA1 consumer; it does not migrate or initialize runtime state on its own.
The [`payloadlaunch`](payloadlaunch/FORMAT.md) package defines the dynamic
manifest/anchor and [typed launch argv](payloadlaunch/LAUNCH.md), also without
filesystem or process effects. The format documents specify exact obligations
and scoped test commands. Source version and golden hashes must be pinned together.

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
local paths are not portable. `--test-at RFC3339` is a regtest clock override. Mainnet rejects this flag,
including an explicitly empty value; the mainnet library also samples its own
wall clock instead of trusting a caller-supplied observation time. Receipt exits: 0 for pending,
executed or already-executed; 1 for refused; 2 for malformed CLI/input. The CLI
has no crash-injection switch. The separate Go test child owns that test seam.

Genuine Core tests are opt-in and require explicit locally admitted tools:

```sh
export W3_REGTEST=1 W3_RUN_ROOT=/absolute/new/private-run-root
export W3_CORE_CLI=/pinned/namecoin-cli W3_CORE_DAEMON=/pinned/namecoind
export W3_EXECUTOR=/clean-head/single-use W3_LAB_SIGNER=/pinned/labtestsigner
export W3_PUBLIC_VERIFIER=/pinned/swarma-keyvault
export W3_PUBLIC_FIXTURE=/public/certificate-cycle2
export SUG_CORE_REQUESTER_KEY=/private/admitted-requester.pk8
go test -count=1 -v -run '^TestGenuineCoreMatrix$' .
```

The harness refuses an existing root, pins Core tool hashes, creates its own
no-peer regtest node and two throwaway wallets, and stops only its recorded PID.
The public fixture directory supplies certificate.json, request.json and
enrollment.json. The lab signer uses the previously admitted throwaway P-256
requester key at the explicit absolute `SUG_CORE_REQUESTER_KEY` path in place;
there is no home-directory default. No key material is read/exported by the harness. The
public verifier and signer are separately pinned dependencies, not built here.
Per-run `public/` holds commands, exit codes, receipts, control results and node
lifecycle. `private/` holds wallets, cookie, routes, node logs and executor state;
never distribute that directory. Tests require valid, unexpired public fixtures.

Discovery regressions use the same environment and a **different new run root
for each test**:

```sh
for name in WitnessMempool WitnessBlock ManyInputsMempool ManyInputsBlock LargeMempool DiscoveryRefusals; do
  W3_RUN_ROOT="/absolute/new/discovery-$name" \
    go test -count=1 -v -run "^TestGenuineCore${name}$" .
done
```

They cover genuine unrelated witness traffic in blocks and mempool, 65-input
noise, 257 independent mempool transactions (including the operator CLI
transport), unchanged candidate commitment rejection, and explicitly labelled
Core-reply corruption. The original executor is a bounded regression control:
the witness/65-input cases must fail with `LEGACY_INPUT_BOUND`, and the 257-entry
case with `MEMPOOL_BOUND`, while their clean neighbors execute. Fixture setup
failures or skipped tests do not establish those controls. Block projection and
candidate raw/context binding also have offline positive/negative unit tests.

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

A plan is not permission to spend. Mainnet needs independent delta review and
explicit runtime admission, then owner GO for each exact signed transaction hex.

## W3-02 explicit network and operator route

Both policy fields are mandatory: `network` and `genesis`. Accepted pairs are
`regtest` / `0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206`
and `main` / `000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770`.
There is no default. The observed node must independently match both pins.

For main, `--route` is an OperatorRoute JSON object with exact fields `Network`,
`Genesis`, `NodeCLI`, `NodeCLISHA256`, `NodeConfig`, `NodeDataDir`. It contains no
password or configurable argv. The binary must match its SHA256 pin and all
paths must be absolute and clean. NodeConfig and NodeDataDir are references
only; this program never reads their contents. The admitted Namecoin CLI alone
loads its own configuration when a separately authorized observation runs.
Main has no HTTP-route fallback. The library Execute entry also requires the
operator capability bound to the same network, genesis and state root. The same CLI adapter is exercised against
isolated regtest in `TestGenuineCoreOperatorRoute`.

Each child uses exactly `-conf=... -datadir=... -chain=main
-rpcclienttimeout=2 METHOD PARAMS`, a cleared environment, a temporary private
working directory, a two-second context and bounded output. Only the eight read
methods listed above are allowed. `getindexinfo` is within the operator's larger
whitelist but is not needed or enabled here. Wallet, signing, transaction send,
stop, remote-URL and option-like string arguments are refused. Raw getblockhash
and gettxout-null CLI output are normalized before W7 JSON projection.

Policy and route files, as well as the other public-file inputs and pinned
executables, refuse group/world write bits. The open descriptor is checked again
against the inspected file. Readable mode0644 public inputs are supported; keep
credential-bearing regtest routes0600. This does not protect against a hostile
same-UID owner replacing trusted inputs or parent directories.

Immediately before reservation, after public request revalidation, the executor
rechecks the active tip, fetches the exact spend again, requires its original
block, verifies that block's active height/hash/confirmations and transaction
membership, then rechecks the tip once more. A genuine-Core control invalidates
the spend block at this seam: accepted W3-01 executes incorrectly, while this
delta refuses TIP_CHANGED with no journal/effect; restoring the block permits a
valid execution. The residual window after the final RPC and before journal
fsync/effect remains unavoidable without a different consensus/effect protocol.
No atomic finality or rollback is claimed.

Mainnet CLI route/clock/network tests use offline fixtures only. The complete
47-case regtest matrix, late-reorg control and real operator-CLI regtest control
cover the changed shared path. These tests do not assert that any mainnet
observation or transaction has been admitted or performed.

### Staged static inputs

The pure public configguard.ValidateStagedSet validates custody-checked static
anchor/manifest/signature/config bytes against independently expected final
paths, release, service and GID before installation. It opens no files and does
not waive installed admission. See [the staged API and trust boundary](configguard/STAGED.md).
Run go test -race -count=1 ./configguard and go vet ./configguard here.
From the repository root, go run .scripts/dk5-guards.go -out /absolute/task-scratch/guards
runs calibrated controls and writes logs/overlays/hash/PID/exit evidence there.
