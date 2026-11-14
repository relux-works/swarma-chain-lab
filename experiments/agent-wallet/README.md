# Agent wallet experiments (W1 / W2)

**W2 changes the default CLI.** `agent-wallet` is now a signing socket client;
`agent-walletd` holds custody in a separate non-root service user. See
[SERVICE.md](SERVICE.md) for exact LIP-0006 bytes, supported actions, deployment,
recovery and the limits of local same-UID test evidence. W2 v1 supports spend,
balance/history/receive and budget; name operations are deferred. W2 main
requires explicit matching network/genesis in service, client and private wallet
configuration, a matching nested policy and positive fee rate. Legacy entrypoints
remain regtest-only. See [M5 test config](../../deploy/templates/m5-test/README.md).

The following documents the retained **`agent-wallet-legacy`** W1 command.

One-off generation history now uses the signed-content digest rather than the
signature-bearing external grant ID, so re-signing cannot create another
generation record or bypass sticky key-rotation closure. Legacy signature-keyed
state refuses with `ONEOFF_STATE_MIGRATION_REQUIRED`; preserve that state for
an explicit migration. See [the format and recovery boundary](FORMAT.md#standalone-single-use-grant).
Run `go test -race -run '^TestOneoffSecondSignatureSharesGenerationState$' .`
for the state-identity, closure and legacy-refusal regression; output goes to stdout.

**Experimental, regtest only.** A bounded Go CLI checks authority before using
an agent's hot wallet. It supports ordinary payments, two-stage name registration
and separate W3 single-use grants. It is not a sandbox or a custody boundary:
the agent and wallet share an OS user, and a hostile same-user process can bypass
this tool, change state or use wallet credentials directly. The Curator skill
expresses behavioral restrictions and makes no guarantee against that behavior.

This module requires the integrated K1 rental grant v3, `names.register` scope
and `ResolveLandlordGrantKey` API. It does not reinterpret legacy v1/v2 authority.
See [FORMAT.md](FORMAT.md) for exact public inputs and [the skill draft](../../skills/namecoin-wallet/SKILL.md).

## PX1: G2 pay limits

`agent-walletd` runs the G2 profile when its service config carries a `g2`
block (terms v2, operator ceilings, journal v2, tracker, canary and status
socket); without it the service stays W2. The documents:

- [PX1-INTERFACES.md](PX1-INTERFACES.md): the frozen contracts, ownership,
  test ids T1-T18, integration order and freeze amendment 1.
- [FORMAT-TERMS-V2.md](FORMAT-TERMS-V2.md): terms v2, operator ceilings, the
  cap checker, the request fee limit and the wallet-layer spend path.
- [FORMAT-JOURNAL-V2.md](FORMAT-JOURNAL-V2.md): journal v2, day buckets,
  track and reconcile records and the receipt-key release authorization.
- [RECONCILE-RUNBOOK.md](RECONCILE-RUNBOOK.md): F6 service-UID operator CLI,
  six-confirmation conflict-only release, separate journald alert forwarder,
  hourly refusals, exact verified-conflict startup recognition and Infra
  installation-rehearsal procedure.
- [STATUS.md](STATUS.md): the tracker, canary, float monitor, alerts and the
  operator status projection.
- [SERVICE.md](SERVICE.md): the service, its G2 operations section, the
  status socket and the crash-restart runbook.
- [FORMAT.md](FORMAT.md): the W1/W2 public inputs.
- [PAYGRANT-V2.md](../rental/PAYGRANT-V2.md): the terms-v2 pay-grant issuance
  helper (rental module).
- [SMOKE-G2.md](../../deploy/SMOKE-G2.md): the G2 deploy inputs, the
  target-host flow, T18 and the mainnet-safe smoke values.

## Commands

Build from this module, with the sibling dependencies present:

```sh
go test -race ./...
go vet ./...
go build -trimpath -o ../../.temp/agent-wallet-legacy ./cmd/agent-wallet-legacy
```

The operator supplies a private config; the agent receives only its installed
path and public grant/request files. Global `--config` precedes the command:

```sh
agent-wallet-legacy --config CONFIG balance
agent-wallet-legacy --config CONFIG receive
agent-wallet-legacy --config CONFIG history
agent-wallet-legacy --config CONFIG budget --grant GRANT_FILE_OR_ID
agent-wallet-legacy --config CONFIG spend --grant GRANT_FILE_OR_ID --request REQUEST
agent-wallet-legacy --config CONFIG spend --grant ONEOFF_GRANT --request REQUEST --use-txid TXID
agent-wallet-legacy --config CONFIG name-register --grant GRANT_FILE_OR_ID --request REQUEST
```

Balance/history report atoms (100,000,000 per NMC). History projects at most 50
wallet entries without wallet labels, comments or private fields. Receive asks
for a legacy regtest P2PKH address. Grant IDs resolve only as `ID.json` in the
configured public object directory. A K1 ID hashes the signed grant, excluding
its issuance locator; it is **not** the hash of the whole presentation file.
Standalone IDs hash the canonical one-off envelope. Loaded IDs are verified.

Mutation results are JSON receipts with a bounded reason and explanation.
Exit 0 means read success, executed or already reserved; 2 means refused;
3 means pending; 4 means uncertain. Always inspect `status`, `phase` and
`reason`: exit 0 with `already-executed` does not prove an unknown broadcast
happened. No test clock, private-key input, grant issuer or arbitrary RPC mode
exists in the production CLI.

## Authority and accounting

Rental authority uses the real K1 `Check`, with independent policy pins for the
agent name, landlord name, network/genesis, seal script and durable kernel state.
The request must be signed by the named grantee, reference that exact stable
ID, use an allowed action/recipient and fit the contract-bound terms. The tool
checks authority before planning, before signing and immediately before its
journal reservation. These checks do not make chain observation and broadcast
atomic; the chain can change after the last observation.

Separate spend/name buckets are cumulative and fee-inclusive; their sum cannot
exceed the signed grant total. No missing budget becomes a default. The issuing
operator can choose a 3,000,000-atom name cap with at most three names; fees mean
three complete 0.01-NMC deposits will not fit that cap. `NameCount` is capped at
three, and any lower signed count is binding. Name reservations initially charge
`1,000,000 + 2 * request.fee_limit_sat`; after successful reveal they charge the
deposit plus both actual fees. A request can therefore be refused conservatively
even if a future actual fee might have been lower. Spend charges actual fees.

A standalone grant independently authorizes one exact amount and recipient with
its own fee maximum. The current issuer key resolves from the pinned landlord
**name**, never from a new key pin supplied alongside the grant. Pending key
rotation refuses. An observed forward confirmed rotation from a still-active,
previously admitted generation closes that grant durably, including after
rollback or rotate-back. A first-observer mismatch refuses without inventing
historical rotation evidence. Unobserved rotate-away/back is not reconstructed.

For standalone execution, the caller supplies only a use-txid locator. W3
primitives verify the funding transaction, exact P2SH key pair, raw SIGHASH_ALL
signature attribution, exact signed-request commitment, active block membership,
one confirmation and a strictly later use height. Issuer use refuses; mempool
grantee use remains pending. This is separate from rental accounting and does
not add allowance to an existing rental grant. No seal is spent by this tool.

## Transactions and durable recovery

Funding and signing do not broadcast. The tool constructs outputs locally,
requires confirmed legacy P2PKH inputs (or the exact prior name commitment),
rejects inputs at the current grant issuer or pinned seal script, and checks
change, all amounts, fees, version, input uniqueness/reservations and the
final signatures. It accepts at most 16 inputs per stage. Each signing result
must preserve the complete unsigned plan. Names use Namecoin version `0x7100`,
20-byte random commitments and exact firstupdate scripts; their recipient is
the signed address. A name reveal waits for 12 commitment confirmations and
rechecks live authority. Existing names or another consensus/policy rejection
can leave the reserved name operation uncertain or incomplete; no automatic
reclaim/refund is implemented.

A private durable store holds one wallet-wide lifetime lock and at most 32
records / 65,536 bytes. Nonces are per grant. The journal binds exact request
bytes, transaction IDs, input reservations, budget debits and configuration
(excluding rotatable RPC passwords). It reserves **before** broadcasting.
A surviving reservation is never rebroadcast, including after a process exit,
transport uncertainty or a lost acknowledgment. Different bytes under a used
nonce refuse. A successful name commitment permits only its separate reveal
stage; a reserved reveal never retries. The commitment salt stays in private
state, not the receipt. State write uncertainty poisons the current handle.

Preserve journal/kernel state and ask the operator to reconcile uncertain work.
Do not delete state, change config/state roots, re-sign a new nonce, or restore
old state to retry. This demo has no safe automatic state garbage collection,
backup rollback protection or recovery command.

## Operator configuration and RPC routes

`Config` in `wallet.go` is the schema; `LoadConfig` rejects unknown fields and
requires an owner-only regular config file with one link, no symlink, at most
65,536 bytes. State and object paths are explicit absolute paths. The private
wallet config contains RPC credentials and must never be included in reports.

- `version: 1`, `network: regtest`, `genesis`: W3's pinned regtest genesis.
- `policy`: required `construction_profile: "W"`, K1 network/genesis,
  `agent_name`, `landlord_name`, `seal_script`,
  separate private `state_dir` (see rental's policy schema).
- `observer`: loopback `host`, `port`, username `w3-observer`, password.
- `wallet`: `route` with username `w1-wallet`, plus one fixed `wallet` name.
- `broadcast`: route with username `w1-broadcast`.
- `state_dir`, `objects_dir`, `change_address` (legacy regtest P2PKH),
  `fee_rate_sat_vb` (1..1000, explicit operator choice).
- `wallet_dir`, `memory_zone`: forbidden-path metadata for the Curator profile,
  defaults `.local/share/swarma/agent-wallet/node` and `.local/share/swarma/memory`
  relative to the agent user's home. The tool does not open these locations.
  Curator must pin the actual resolved paths at deployment.

All routes must target the same loopback host/port; no proxy, redirect or RPC
retry is used. Each HTTP call is bounded to five seconds and a 2-MiB reply.
Use separate Core `rpcwhitelist` entries with exactly these methods:

| Route | Allowed methods |
| --- | --- |
| `w3-observer` | `getblockchaininfo,getblockhash,getblockheader,getrawtransaction,gettxout,name_show,getrawmempool,getblock` |
| `w1-wallet` | `getbalances,getnewaddress,listtransactions,fundrawtransaction,signrawtransactionwithwallet` |
| `w1-broadcast` | `sendrawtransaction` |

The agent must not call these RPCs itself. The tool never calls
`sendtoaddress`, `name_new`, `name_firstupdate`, key export/import or wallet
maintenance RPC. Operator setup and the isolated test harness use their own
administrative route; that route is not a product capability.

## Tools and reproducible checks

For F6 investigation, `journalctl --unit=swarma-wallet.service --no-pager`
reads the supplied unit's captured alerts. The
[reconciliation runbook](RECONCILE-RUNBOOK.md) gives exact
`agent-wallet-reconcile` and `agent-wallet-alert-forwarder` build/run commands,
the separate unit/config templates and explicit `namecoin-cli` regtest evidence
commands. Keep outputs, real exit codes and evidence hashes in private operator
records, with local scratch logs under `.temp/`; never archive credentials or
wallet files. The forwarder uses only an operator-provisioned a2a infrastructure
identity through its admitted absolute CLI path; tests send to no real room.

F6 unit and real-socket checks run with the normal race-enabled suite. Its
focused mutation controls use the existing runner:

```sh
W1_MUTATIONS=1 W1_MUTATION_ROOT=FRESH_ABSOLUTE_DIRECTORY \
W1_DEP_ROOT=ABSOLUTE_EXPERIMENTS_DIRECTORY \
go test -count=1 -run '^TestGuardPlants/F6-' -v .
```

Native F6 qualification belongs to Infra's draft-6 signed install rehearsal;
[the runbook](RECONCILE-RUNBOOK.md#infra-installed-rehearsal) gives the exact
private-node/agent/service-shell steps, commands, refusals and capture contract.
Do not use a local SDK reader stub or the historical function diagnostic as a
substitute. `DK5_SERVICE_GROUP` remains a correct refusal outside a provisioned
installation. The existing optional `TestF6CoreRehearsal` name is retained as a
function-only diagnostic; it no longer invokes a native CLI or expects the old
startup hold. It is not the installed rehearsal or T18 proof.

The six startup-policy groups in `reconcile_startup_test.go` cover named X,
unknown Y, T13 rollback, tampered/unchained releases, the k=6 append boundary and
replay for later conflicts, each with a valid neighbor. They run with the normal
race-enabled suite and need no node or privileged user.

Go 1.26.8 builds, races, vets and runs controls. Unit checks skip Core/plant
suites unless explicitly enabled. No external library update is implicit.

The opt-in harness starts a fresh private Core node with networking disabled,
separate fixture wallets, public deterministic test keys and pinned Core 28
executables. It records its PID and stops that PID on test cleanup. Supply
absolute binary paths and a **fresh** `W1_RUN_ROOT` for each test invocation:

```sh
W1_REGTEST=1 W1_RUN_ROOT=FRESH_ABSOLUTE_DIRECTORY \
W1_CORE_CLI=ABSOLUTE_NAMECOIN_CLI W1_CORE_DAEMON=ABSOLUTE_NAMECOIND \
go test -race -count=1 -run '^TestCoreWalletSpend$' .
```

Repeat with fresh roots for `TestCoreWalletControls`, `TestCoreWalletCrash`,
`TestCoreNameRegistration`, `TestCoreOneoff`, `TestCoreRevocation`,
`TestCorePlanControls`, `TestCoreSealFunding`, and `TestCoreCLI`. They cover actual effects and nearby
negative cases; plan-response corruption is explicitly a negative injector,
not an authority substitute. CLI controls build a fresh production executable
and use real wall-clock grant windows. The crash case exits a real subprocess
with 73 after reservation, before effect.

The executable pins are two pairs (`px1CorePins`); a mixed pair never runs:

| Executable | macOS pair | official x86_64-linux-gnu release pair |
| --- | --- | --- |
| `namecoind` | `86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f` | `dc7430676e445af3992430e036f7c1a17bea44f757e9cf25b69205e39625f2f7` |
| `namecoin-cli` | `5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d` | `318b6c881c8071abbafd984550172369c3498b4c65c389797350f2d458f085b1` |

The Linux pair comes from `namecoin-28.0-x86_64-linux-gnu.tar.gz` (SHA-256
`6f12031926f0999b8507e073648cc2b4488d452531301a2244a562a92f2f7860`, as listed
by the Guix attestations in `namecoin/guix.sigs`).

Harness `private/` contains node credentials, wallet data and local fixture
secrets; never publish it. Its `public/` contains sanitized receipts, command
names/results and binary metadata. Test output and build artifacts belong in
`.temp/`; an admitted runtime's fresh root can be elsewhere within its bench.

Guard-removal controls copy source and sibling dependencies into a fresh root,
apply each exact unique manifest replacement, and require a compiled test to
fail its intended assertion. A skip, setup error, timeout or crash is not a
successful detection. From this module:

```sh
W1_MUTATIONS=1 W1_MUTATION_ROOT=FRESH_ABSOLUTE_DIRECTORY \
W1_DEP_ROOT=ABSOLUTE_EXPERIMENTS_DIRECTORY \
W1_CORE_CLI=ABSOLUTE_NAMECOIN_CLI W1_CORE_DAEMON=ABSOLUTE_NAMECOIND \
go test -count=1 -run '^TestGuardPlants$' -v .
```

`testdata/mutations.json` lists each claim/selector/expected failure marker.
Per-plant logs and `results.json` remain in the fresh mutation root. These
controls establish that the selected assertions detect their planted guard
violations; they do not establish exhaustive security or removal of all
redundant defenses. Signed delivery evidence is separate from these
reproducible instructions.

### PX1 gate of record (`px1-core-gate`)

The hosted job `px1-core-gate` (`.github/workflows/agent-wallet.yml`) is the
PX1 gate of record. It downloads the official Namecoin Core 28.0 Linux
tarball, verifies it against the upstream SHA256SUMS (three Guix builder
attestations at a pinned `namecoin/guix.sigs` commit) and the repository pin,
checks both executables, and runs every test of
`.scripts/px1-core-gate.json` with `W1_REGTEST=1`: each Core test in its own
`go test -json` invocation with a fresh `W1_RUN_ROOT`, then the unit tests.
Each T-id in the manifest declares its required layers (`unit`, `core`)
exactly as the test table in `PX1-INTERFACES.md` says; a unit test checks
that against the table. `.scripts/check-px1-core-gate.py` fails the job on:

- an open T-id;
- a required layer with no test;
- any skip or failure anywhere in the input files, in any `-count`
  repetition, before or after a pass of the same test (the checker keeps
  every terminal action of every test, not the last one);
- a missing required test;
- a Core test that passed fewer times than its `core_runs` count (T9 runs
  with `-race -count=50`);
- a package or build failure, or an empty stream.

It prints `PX1_GATE PASS` only when every required layer of T1-T17 passed.
The S2 Core layers (T3, T5, T8, T9, T10) are in `px1_s2_core_test.go`. Its
known-bad controls run first: `.scripts/test_check_px1_core_gate.py`, and a
real `go test` skip without `W1_REGTEST` that must fail the gate. After the
gate, that real skip stream is checked again in front of the passing streams,
and must still fail. Locally,
from the repository root:

```sh
python3 -B -m unittest discover -s .scripts -p 'test_check_px1_core_gate.py' -v
python3 -B .scripts/check-px1-core-gate.py list --manifest .scripts/px1-core-gate.json core
python3 -B .scripts/check-px1-core-gate.py check --manifest .scripts/px1-core-gate.json EVENTS.json...
```

The deploy job runs the S5 client-consumer test the same way
(`.scripts/px1-s5-consumer-gate.json`: every case passes, no skip). Outputs go
to the runner's temporary directory; locally keep them under `.temp/`.

## SW1 grant-v3 compatibility

This module consumes `rental.Check`. Its trusted rental policy must explicitly
set `"construction_profile": "W"`; missing or other values refuse
`W_PROFILE_REQUIRED` before node RPC or durable cache access. Existing v3 seals
and issuance anchors must also satisfy native P2WPKH / SIGHASH_ALL W construction;
adding the pin does not migrate legacy transactions. Preserve existing state.

SW1 does not qualify this module's historical opt-in Core fixtures or legacy
configs for W. They are knowingly incompatible until the named
`SW1-consumer-fixtures` follow-up migrates their funding, T/A graphs and trusted
policies and reruns both modules' Core suites. Default-suite success is not
consumer end-to-end qualification. Do not deploy those fixtures as W examples.

## Installed static inputs (DK5)

Installed daemon configs/secrets now require root:exclusive-service-group0640,
root:same-group0750 parents and the signed manifest/root anchor in
[the install contract](../../deploy/INSTALL-CONFIG.md). Legacy owner0600/0400
examples below or in historical smoke fixtures are not installed-service inputs.
Mutable state, standalone tool/client keys and dynamic payload bootstrap retain
their separate contracts. No production mode fallback exists. Full signed
admission tests live in `single-use/configguard`; local ownership seams are
synthetic and do not qualify Linux deployment. See the deploy runbook for
same-binary preflight and the separate DK5b payload launch gate.
