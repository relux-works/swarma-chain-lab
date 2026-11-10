# Local composition rehearsal

This opt-in Go harness exercises native V2 booking, relay, signer, grant store,
gateway, manager and scripted payload against a fresh isolated Namecoin Core
regtest. Run the expiry and early-revoke variants separately. Preparation/build
checks do not establish that either runtime scenario passed: consult the exact
run's public result and exit status. Product integration gaps are reported at the
first failing stage, never patched or bridged by the harness.

The full scenario sends terms/book/consent through the actual relay and gateway,
pays the frozen NMC V2 contract, and lets the actual SG1 CLI consume the original
booking outbox. SG1 enrolls disposable regtest inventory using its native config,
signs, broadcasts, stores the grant in S1 and publishes the confirmed presentation.
The harness never creates a replacement booking Item or grant presentation.
At `not_before`, the gateway starts the real manager and payload path. Two model
requests reach a fake HTTPS upstream through the real MP1 Service; further
requests return the fixed cap refusal. The expiry variant waits for `not_after`
through more than 90 seconds without application messages, beyond the explicitly
configured relay read deadline; normal WebSocket heartbeats remain enabled.
It requires End, cleared channel credentials, helper cleanup and closed model
credentials. Journal Destroyed is recorded separately: Tick does not run the
explicit closer.
The revoke variant sends a native operator revoke Item to the actual SG1 CLI,
checks that the exact issued seal is spent, then probes the closed grant.

Controls cover missing/unoffered coins preserving the slot, foreign consent
preserving the package, no pre-grant slot, no unconfirmed presentation, original
bootstrap bytes, real payload TLS leaf-pin refusal, model accounting and caps,
terminal-client no retry, closed credentials, and no extra delivery after closure.
The known-secret scanner checks recorded credentials and encodings in process
logs and public evidence; it is not an unknown-secret detector. No real paid API,
existing wallet, mainnet funds or external host is used.

## Declared macOS substitutions

1. The manager alone uses `-tags slotdfake`. Its real r4 codec connects to a
   harness-owned Unix helper. On create, that helper writes the original canonical
   bootstrap bytes; on start, it launches the exact PL1 payload binary with fixed
   operator arguments. Stop targets only its recorded PID; destroy removes only
   its owned bootstrap file. This exercises protocol, process and disposable-file
   cleanup. **Linux users, cgroups, filesystem isolation and physical disk wipe
   are not exercised.**
2. `fixtures/registrar.go.txt` supplies a Go build overlay used only by this
   rehearsal. `overlay_test.go` requires exactly one occurrence of the production
   `proxy.Client` constructor and replaces only that expression with a direct
   registrar into a real MP1 Service in the gateway process. `pinnedRegistrar`,
   endpoint/caps checks, lifecycle and kernel code remain unchanged. The real
   Service serves TLS requests; only Linux peer-credential admin transport is
   replaced. Normal product/release builds cannot load this fixture. Public
   evidence records original, replacement, helper and overlay-binary hashes.

The gateway is explicitly reported as an overlay build, not an unchanged native
binary. SG1 remains its actual CLI. Relay compatibility AUTH is explicitly off.
The model CLI is Linux-only and is not claimed as executed here.

## Release isolation gate

Before any Core activity, the full test requires `IT2_RELEASE_DIR`. It verifies
that this release describes identical relevant product sources, then builds
ordinary and overlay Linux/amd64 gateways using the release's toolchain/flags.
The manifest gateway hash must equal the ordinary build and differ from the
same-platform overlay build. A Darwin-vs-Linux difference is not accepted as proof.
The release directory is read-only input; neither the fixture nor the overlay is
installed into it. Release signatures, hosted CI and Linux runtime remain
separate delivery obligations.

## Tools and artifacts

Use Go 1.26.8 on Darwin with the pinned module cache. Core hashes are in
`lab_test.go`. Every Core run requires an exact signed clean task head and a new
absolute run root. Keep paths short enough for the macOS Unix socket limit.

```sh
export GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly
go mod verify
go vet ./...
go test -race -count=1 ./... # scanner; opt-in builds/Core explicitly skipped
```

Produce the normal release from a clean checkout using the deploy kit:

```sh
go -C ../../deploy run ./cmd/deploy-kit build \
  -repo /absolute/clean-checkout -commit <exact-product-commit> \
  -out /absolute/new-release
```

Preparation-only build proof (no Core, service, wallet or signing key):

```sh
IT2_BUILD_ONLY_ROOT=/absolute/new-build-root \
 IT2_RELEASE_DIR=/absolute/new-release \
 go test -run '^TestOverlayReleaseIsolation$' -count=1 -v -timeout 3m
```

The gate's bounded negative control plants the already-built Linux overlay into
an independent, deliberately invalid manifest/artifact fixture. The source
release is untouched. The second command must exit 1 with exactly the
`release builder overlay isolation failed` assertion; setup/build failures are
not successful control evidence.

```sh
go run .scripts/plant-release-overlay.go /absolute/new-release \
  /absolute/new-build-root/private/overlay-linux-gateway /absolute/new-control
IT2_BUILD_ONLY_ROOT=/absolute/new-control-build \
 IT2_RELEASE_DIR=/absolute/new-control \
 go test -run '^TestOverlayReleaseIsolation$' -count=1 -v -timeout 3m
```

After the required product dependencies are landed, run each full variant with
its own fresh root:

```sh
IT1_REGTEST=1 IT2_SCENARIO=revoke IT1_PRODUCT_HEAD=<exact-signed-task-head> \
 IT1_RUN_ROOT=/absolute/new-revoke-run IT2_RELEASE_DIR=/absolute/new-release \
 IT1_CORE_DAEMON=/absolute/pinned/namecoind \
 IT1_CORE_CLI=/absolute/pinned/namecoin-cli \
 go test -race -run '^TestFullComposition$' -count=1 -v -timeout 8m
# Repeat with IT2_SCENARIO=expiry and a different IT1_RUN_ROOT.
```

`<run>/public/result.json` records stages, pins, build isolation, accounting,
known-secret scan and direct-PID absence. `<run>/private` holds fixture keys,
wallets, configs, binaries and process logs; never export it. Compiler descendants
are not inventoried. Preparation logs and control sources belong under `.temp/`.
Historical pre-G6 diagnostics remain opt-in via `IT1_PRE_G6_DIAGNOSTIC=1`; they
are intentionally incompatible with a G6 gateway and are not a fallback.

## Current result

SP2 adds `TestResponsesComposition`, selecting MP2's Responses profile and the
payload's explicit pinned mode. It reuses the full IT2 assertions and genuine
isolated Core flow, with a fake TLS OpenAI upstream. Run the full command above
with `-run '^TestResponsesComposition$'` in separate revoke/expiry roots. The
fixture passes a canonical public model config copy and explicit dialect/model
flags; no credential path in that copy is opened by the payload. Public receipts
include `responses_mode` and `payload_profile`. Legacy full/partial test entry
points keep their Messages default and assertions. Compare both before/after
when changing shared helpers. This does not qualify a paid API or Codex harness.

The [historical startup ordering gap](GAP-IT2-STARTUP.md) was fixed by SR1; RK1
keeps expiry alive through relay idle periods and transport loss. The resumed
full runs use these landed product sources. Read each public result for the
runtime outcome; dependency landing alone does not prove composition success.
`TestStartupOrderingWitness` now asserts real TLS/HMAC admission while a durable
Starting attempt is active, refuses a wrong credential, and admits the identical
correct credential after Started. Its explicit kernel/driver stubs do not prove
Core or native payload execution. The bounded control restores the old Hello
gate and must fail at `active Starting Hello was not admitted`.

```sh
go test -race -run '^TestStartupOrderingWitness$' -count=1 -v -timeout 30s
go run .scripts/plant-startup-gate.go /absolute/repo /absolute/new-gate-control
go test -overlay /absolute/new-gate-control/overlay.json -race \
  -run '^TestStartupOrderingWitness$' -count=1 -v -timeout 30s
# The last command must exit 1 at the exact admission assertion above.
```

## Independent partial legs while startup is blocked

`TestIndependentPartialLegs` is a separate, explicit opt-in. With `revoke`, it
checks that the issued seal is unspent, runs the native SG1 operator revoke and
requires JSON-RPC null afterwards, before any payload start. With `expiry`, it
sends the existing model-free `__extend__` control, requires durable start, then
checks expiry journal state, helper bootstrap removal and model-credential
refusal without waiting for a payload reply. This can exercise bookkeeping even
when the payload has lost the startup race. Neither case proves first model
reply, full revoke/expiry completion or Linux wipe; receipts say `PASS_PARTIAL`.

Use the same pinned inputs as a full run, but select a new root and test:

```sh
IT2_PARTIAL=1 IT2_SCENARIO=revoke IT1_REGTEST=1 \
 IT1_PRODUCT_HEAD=<exact-signed-task-head> IT1_RUN_ROOT=/absolute/new-partial-run \
 IT2_RELEASE_DIR=/absolute/new-release \
 IT1_CORE_DAEMON=/absolute/pinned/namecoind IT1_CORE_CLI=/absolute/pinned/namecoin-cli \
 go test -race -run '^TestIndependentPartialLegs$' -count=1 -v -timeout 8m
# Repeat with expiry and another fresh root.
```

## External host runner self-test

`TestHostRunnerComposition` runs the new [external client](../m5-host-smoke/README.md) against this same isolated Darwin composition. Select `IT2_SCENARIO=expiry|revoke`, the same pinned Core/release inputs and a fresh root. The result is explicitly `PASS_SELF_TEST`, never Linux host evidence. The fixture adapter alone owns disposable payment/signing/private probes; the external client receives public bound receipts only. It also restarts its owned gateway/model overlay without resetting the journal and checks durable closed-state accounting.

## E2E1 independent-node interim

`TestCanonicalComposition` uses the implemented V2 order: booking/consent,
confirmed payment, then issuance. This is not a spec-adopted profile. A separate
miner funds disposable fixtures; booking, issuer, gateway and the independent
verifier each have their own Core process, datadir, RPC credentials and port.
Observer nodes connect only to the owned miner over loopback P2P. No credentials
or node datadir are shared between services. Active-chain convergence is required before dependent observations. Issuer
transactions must reach the miner and gateway before mining or revocation checks;
whole-mempool equality is not assumed to be a P2P guarantee. Service code is unchanged.

Use the full scenario inputs above and select `-run '^TestCanonicalComposition$'`.
The verifier is disconnected before issuance; it must refuse the unknown anchor
without persisting admission state, then admit the identical presentation after
P2P convergence. Only then is the original SG1 presentation atomically mirrored
into the gateway's presentation directory, with byte-equality and hash readback.
The issuer output is preserved unchanged; no replacement grant or admitted-cache
entry is constructed. This does not prove freshness of unseen revocations. The same
Darwin manager/admin substitutions and release-isolation check still apply.

Success is `PASS_INTERIM`. Gateway/station crash recovery is pending the accepted
DA1 composition. Issuer/booking crash barriers, complete action/refusal probes and
the remote control adapter remain pending;
this entry point must not be presented as complete E2E1 or gate-7 qualification.
Default tests check the topology validator with duplicate/missing/aliased-node
controls; these metadata controls do not replace actual multi-node execution.

`go run .scripts/compare-canonical.go /absolute/first/public/result.json
/absolute/second/public/result.json` compares two completed same-head/same-scenario
interim reports. It validates required success observations and normalizes random
identity/path/port/time/process metadata into role labels. It retains effect
counts, full model accounting, closure, ordered phases and pending crash labels.
Input reports remain the source of detailed evidence. Controls demonstrate that
fresh identities compare equal, changed effect/accounting counts differ, and
failed/missing/aliased/unclean evidence refuses. It does not compare every byte or
certify pending contracts.

The confirmed underquote remains `refund_review` with no selected payment,
issuance or slot and with its consent package preserved; a subsequent exact
quote follows the native positive path. The independent verifier refuses another
executor as `GRANT_POLICY` before node calls with an unchanged admission journal.
It rechecks the original grant after revoke/expiry for `SEAL_SPENT`/`EXPIRED`.
These are specific existing API checks, not a universal v4 service-action matrix.
