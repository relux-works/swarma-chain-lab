# M5 deploy preparation (DK1 and DK2)

Go release tooling and public templates for regtest preparation. It builds
gateway, rental-booking, grant-store, swarma-relay, swarma-signer, model-proxy,
station-manager, station-payload and agent-walletd from an exact clean HEAD twice, refuses
any byte difference, then emits an unsigned bundle with SHA256SUMS and a manifest.
No source product changes, key creation, signing, installation or host deployment
occur inside the tool. [SMOKE.md](SMOKE.md) is the separate Infra handoff plan.

Gateway now wires the real kernel, E1 and remote station manager, with explicit
screening off in its manifest row and native config. Gateway, booking, store and relay
have systemd templates. The gateway still requires operator-pinned payload/TLS
inputs and real Linux host acceptance; compilation is not deployment evidence.
Signer, model proxy and station manager have separate units; the scripted payload
has only a documented root-policy requirements table for Infra. a2a daemon (a2ad)/CG1
remains a pending manifest row. [SMOKE-DK2.md](SMOKE-DK2.md) gives the new services'
install order and explicit external transport/host qualification gates.

The model config validator also accepts the optional per-model
`openai-responses-functions-default-v1` profile and its pinned HTTPS
`/v1/responses` endpoint. Unknown profiles, unknown model IDs and unpinned
endpoints refuse. With all models explicitly profiled, the required top-level
`upstream` must use the Responses path. Legacy Messages config bytes remain
unchanged. See the [Responses profile](../experiments/model-proxy/RESPONSES-PROFILE.md)
for the wire subset and separate harness/TLS qualification requirements.

## Build contract

Use Go1.26.8 and pre-download the landed modules' dependencies into the local
module cache (`go mod download` and `go mod verify` in each service module).
The kit shares the single-use configguard module and its pinned dependencies. It forces GOTOOLCHAIN=local,
GOWORK=off, GOENV=off, GOPROXY=off and empty GOFLAGS; there is no toolchain/network
fallback. Exact release flags are GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0
and `go build -trimpath -buildvcs=false -mod=readonly`.

The source argument must be a canonical repository root, with clean tracked,
index and untracked state, and the supplied full40-hex commit must equal HEAD.
Two `git archive` extractions and separate build caches prevent a working-tree
file or previous compiled output from standing in for the second build.
Archive traversal/link entries refuse. Source cleanliness/HEAD are checked again
before publication; existing output is preserved. The complete candidate is
renamed into a new output directory only after all nine binary pairs match.
Temporary source/build trees are removed, including on refusal.

Outputs: `bin/`, `templates/`, `README.md`, `SMOKE.md`, `SMOKE-DK2.md`, `INSTALL-CONFIG.md`, `manifest.json`,
`SHA256SUMS`. Checksums cover every output file except the checksum file itself;
the release signer signs that file separately with namespace `swarma-release`.
The manifest records commit, Go version, target, flags, module/package, binary
hash and readiness status. No timestamp, home path or build-directory path is
embedded in the manifest. A successful build is not a deployment acceptance.

## Public configuration validation

`validate -config` checks a separate public deployment policy JSON, rather than
injecting extra fields into native service config. It refuses missing or inconsistent network/genesis pins,
unresolved placeholders, invalid/duplicate/unknown fields, wildcard listeners,
foreign writable/credential paths and unpinned node CLI references. Complete
gateway/booking/store/relay regtest descriptors accept without opening referenced files.
Gateway permits distinct literal unicast listener addresses and requires the
manager driver and screening off. Its native `gateway validate -config` performs
the full public schema/pin checks and rejects test mode without `-allow-test`.
Use repeated `-public` for every staged native public JSON file; those extra
files receive bounded JSON/duplicate/placeholder/network/inline-secret checks.
Native service schema, profile/key/clock checks still run at service startup;
this validator does not claim to validate unseen credentials or live nodes.

Templates are intentionally incomplete: no live keys, private RPC configs,
public branch or profile bytes are fabricated. Booking's zero rate/time/slot
values are sentinels to replace. See [SURVEY.md](SURVEY.md) for the landed native
schemas and [UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md) for deployment inputs.

## Tools and artifacts

The relay templates are in `templates/relay/` and `templates/systemd/`.
Caddy must overwrite `X-Real-IP` with the direct client's address; the relay
trusts only its configured proxy peer. Direct local services without that header
share the loopback budget. Validate resolved public staging bytes with
`deploy-kit validate -config "$STAGING/relay/deploy.json" -public "$STAGING/relay/service.json"`.
After signed installation, the relay unit runs its own `--check-installed`
preflight as the service user against installed paths. Native `-check` now
requires installed signed inputs and cannot validate a staging path. The initial compatibility profile leaves AUTH restrictions and outer PoW
off; E1 still checks inner work. Recipient privacy requires configured gateway
AUTH and the exact URL binding below before restricted gift-wrap reads are enabled. See the
[relay contract](../experiments/relay/README.md).

- From `deploy/`: `go test -race ./...`, `go vet ./...`,
  `go build -trimpath -o ../.temp/deploy-kit ./cmd/deploy-kit`, and
  `go mod tidy -diff`. Use `GOTOOLCHAIN=go1.26.8` when selecting the installed
  pinned toolchain explicitly.
- `go run ./cmd/deploy-kit build -repo "$SOURCE_ROOT" -commit "$REVIEWED_COMMIT"
  -out "$RELEASE_DIR"` builds the release. Enter it as one shell command;
  the output must be a new absolute directory outside the source repository.
- `go run ./cmd/deploy-kit validate -config "$STAGING/booking/deploy.json"
  -public "$STAGING/booking/service.json" -public "$STAGING/booking/operator-route.json"`
  validates staged public booking inputs without reading credentials. The store
  equivalent uses its descriptor and service.json, as does gateway. After signed
  installation, let the unit run its own `--check-installed` and, for gateway,
  native `validate` preflights as the service user against installed paths.
  Native validators cannot admit unsigned staging paths. Enter each staging
  command as one command.
- `DK1_RELEASE_TEST=1 DK1_RELEASE_REPO="$CLEAN_SOURCE_ROOT"
  DK1_RELEASE_OUT="$NEW_EVIDENCE_PARENT" go test -count=1 -timeout 20m
  -run '^TestReleaseIntegration$' -v .` runs actual double Linux builds and a
  second-tree source nondeterminism plant. Set all variables in one command.
  The evidence parent must already exist and be empty. It retains the successful
  release and release-control.json; the refused release must remain absent.
- `gofmt -l *.go cmd/deploy-kit/*.go` checks Go formatting.
- `git diff --check -- deploy` checks documentation whitespace.
- `limactl list --json` inspects existing local Linux VM availability. The survey
  found none; systemd verification is explicitly not run. No VM may be created
  for this task. Infra must run the command in SMOKE.md before the first start.

The static unit checks only establish required template directives, not Linux
enforcement. For memory/IP cgroup controls see the primary
[systemd resource-control reference](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html).
Host support must be checked by Infra; text presence is not runtime proof.

## G2 pay deploy and T18 (PX1 S5)

The G2 pay executor's deploy inputs are rendered from one canonical parameters
file, `templates/g2-pay/parameters.json`. The frozen contract is
`g2_pay_api.go`, and the implementation is `g2_pay.go`. The procedure, the
target-host order and the limits are in [SMOKE-G2.md](SMOKE-G2.md).
The real-host T18 and setpriv qualification report is in [T18-REAL-HOST.md](T18-REAL-HOST.md).

- `go run ./cmd/deploy-kit g2-render -params "$PARAMS" -out "$NEW_ABSOLUTE_DIR"`
  validates the parameters and writes the six frozen G2 files (0600) into a new
  directory. It never overwrites. It reads no credential and renders none, and
  it leaves no placeholder. Rendering is pure: it reads no account database.
- `deploy-kit g2-host-flow -params "$PARAMS" -- ACTIVATION...` is the
  target-host provisioning order (freeze amendment 1), run as root on the
  target host only: the preflight `ValidateG2PayIdentity` over this host's
  accounts, `systemd-sysusers -` on the `sysusers.conf` rendered from the same
  parameters, the required post-apply `VerifyG2AgentAccount`, and only then the
  activation command. A refused step stops the flow; it prints
  `G2_HOST_FLOW_ACTIVATED` only after a successful activation.
- `deploy-kit g2-custody-probe -spec custody-spec.json` runs T18 as the agent
  UID and prints a `CustodyReportV1`. It exits 1 unless every probe passes. A
  denied path passes only if the agent can neither read nor traverse it, so a
  searchable but unlistable directory fails.
- `deploy-kit g2-custody-verify -spec custody-spec.json -report REPORT` checks a
  stored report against the launch spec and prints `T18_CUSTODY_VERIFIED <spec sha256>`.
- `deploy-kit g2-custody-hash -spec custody-spec.json` prints
  `T18_CUSTODY_SPEC_SHA256 <spec sha256>`, the hash a probe report carries and
  verify checks, for a spec read exactly as probe and verify read it. It is
  read-only (no probe, no network, no write) and refuses a spec file their
  reader refuses, with the same error.
- `deploy-kit g2-agent-groups -params "$PARAMS" -gid GID -- GID...` is the
  T18 credential readback. `-gid` (the agent's observed `id -g`) must equal
  the agent's own primary GID, derived from its sysusers declaration, and the
  GIDs after `--` (the agent's `id -G`) must be exactly that primary GID and
  `agent_socket_gid`: in any order, nothing else, never the operator GID. It
  prints `G2_AGENT_GROUPS_OK observed_gid=<gid> declared_primary_gid=<gid>
  socket_gid=<gid>` only then.
- `deploy/g2-custody-check.sh SPEC CLIENT GRANTEE PARAMS OUTDIR` is the T18
  host script, run with the slot's credentials (`setpriv --reuid="$AGENT_UID"
  --regid="$AGENT_GID" --init-groups` with the numeric UID and declared
  primary GID, see `SMOKE-G2.md` §4). It first hands the observed `id -g` and
  `id -G` to `deploy-kit g2-agent-groups`. It then runs the probe, sends one
  own-agent `balance` request and runs verify, and prints `T18_PASS` or
  `T18_FAIL`. Evidence goes into the new `OUTDIR`.
- `W1_REGTEST=1 W1_CORE_DAEMON=/abs/namecoind W1_RUN_ROOT=/abs/new-dir go test
  -count=1 -run '^TestPX1T18CoreNodePolicy$' .` runs the Core layer against a
  regtest node that the test starts and stops by PID.
- `go test -count=1 -run '^TestPX1S5HostFlow' .` is the end-to-end tripwire of
  the target-host order over a fixture account database: a refused preflight
  stops before the apply, a post-apply mismatch (substituted UID, missing peer
  membership, operator-group membership) stops before activation, the clean
  path reaches activation, and the rendered `sysusers.conf`, `tmpfiles.conf`
  and `custody-spec.json` carry the numeric agent declaration, the status
  directory and its denial. Its T18 readback part shows that the clean account
  (own primary group plus `swarma-wallet-peer`) passes the readback, and that
  an activated account with an extra group of its own is refused.
- `go test -count=1 -run '^TestPX1S5Sysusers' .` gives the rendered
  `sysusers.conf` to the real `systemd-sysusers`, only with `--dry-run` and a
  new fixture root under the test temp directory. The consumer part skips where
  `systemd-sysusers` is not installed or has no `--dry-run` option (systemd 249,
  for example).
- `go test -count=1 -run '^TestPX1S5ClientConsumerResolved$' .` builds the
  agent-wallet CLI from `../experiments/agent-wallet` into the test temp
  directory and runs it on the rendered `client.json`. This is a subprocess;
  `deploy` does not import agent-wallet. The rendered file must pass the
  loader; the same file with a quoted UID, a relative key path or a
  placeholder key path must be refused with `CLIENT_CONFIG`. It reads no key
  and opens no socket. It skips, and
  says so, only where `GOPROXY=off` and the agent-wallet dependencies are not
  in the module cache, as in the gateway-auth-model job, which downloads only
  deploy's and rental-gateway's. The deploy workflow downloads them, because
  agent-wallet is a release module, and so runs the test.
- `W1_MUTATIONS=1 W1_MUTATION_ROOT=/abs/new-dir W1_CORE_DAEMON=/abs/namecoind go
  test -count=1 -timeout 30m -run '^TestPX1S5GuardPlants$' .` runs the S5
  narrowing plants in `testdata/px1-mutations-s5.json`. Each plant must fail its
  named test with its marker, and `results.json` is written to the root. The
  agent-wallet runner cannot host these plants, because it copies only
  agent-wallet. The S5 copy includes the unmodified agent-wallet module and its
  local replace targets, for the client-consumer test.

## Optional gateway AUTH and model proxy

The gateway template sets `relay_auth: off`; choose `when_challenged` or `required`
only with a compatible relay and the existing gateway signing key. The separate
`templates/gateway/model-proxy-section.json` is an optional merge fragment for
native `gateway/service.json`, not a standalone service configuration. Replace
every placeholder with approved numeric UID/caps and exact origin/leaf pin before
merging. Leave the section absent for bootstrap v1. There are no spending defaults.

Before switching gateway AUTH on or restricting relay gift-wrap reads, configure
`gateway.relay_url` byte-for-byte equal to the relay's `public_url`, including
scheme, host, port and any trailing slash. The gateway signs its configured URL;
RL1 compares that tag to `public_url` without normalization. A loopback `ws://`
URL and a public-domain `wss://` URL do not match, even if they reach the same
relay. The shipped templates deliberately differ and therefore cannot authenticate
until aligned; mismatch fails closed. The current gateway CLI accepts only
loopback `ws://` with no path, so a supported local AUTH profile must use that
same exact URL on both sides (for example `ws://127.0.0.1:18818`, without `/`).
Public `wss://` gateway connectivity requires separate transport/configuration
work; changing only the template cannot enable it. Keep AUTH restrictions off
until a supported matching route is configured and qualified.

`deploy-kit validate -public` checks the AUTH mode and refuses a partial/null
model section, unknown fields, invalid UID/caps or non-manager selection. Integer
limits retain uint64 precision. Native `gateway validate` independently checks
the same boundary before startup effects. Main requires the explicit NMC profile and model caps. The kit refuses all
unresolved placeholders. See the gateway's [configuration contract](../experiments/rental-gateway/RELAY_MODEL.md)
for the Linux socket ownership/peer checks and bootstrap lifecycle.

### Booking V2 exchange configuration

Gateway `exchange.booking_version` must be `2` for deployment. Set
`exchange.payment_coins` explicitly to the nonempty, duplicate-free subset of
`nmc`, `btc`, `ltc` offered by the booking service. The example template enables
NMC only. Provision this list alongside `template_sha256`: it must equal the
keys of the matching booking service's `ConfigV2.Coins`. CatalogueV2 does not
advertise that list; the gateway neither guesses it nor probes by creating holds.
The service remains authoritative and rejects unavailable coins before a hold.

Host smoke check: compare the gateway's `exchange.payment_coins` with the keys
of booking config `config.coins` as sets, and compare their template hashes,
before enabling the exchange. A mismatch blocks rollout; successful catalogue
access alone does not prove the two services use the same booking version.
Check an explicit `book <template> <slot> <coin>` request and its frozen version-2
contract, then verify the payment reply's coin, amount in atoms, address and
minimum confirmations against that contract. Never reinterpret a V1 response.

`booking_version: 1` is legacy NMC test wiring only. It requires gateway
`mode: test`, the explicit test-mode CLI flag, and `payment_coins: ["nmc"]`;
native deployment validation rejects it. Switching an existing exchange between
versions requires a new exchange state directory; existing holds and ambiguous
bookings must be reconciled using their original service, not converted.

## DK2 native modes and public validation

New descriptor service IDs are `issuer`, `model`, `stations`, `payload`. The
first three require exactly one `-public` native service JSON file; omitting it
or passing duplicate native files refuses. References and bounded public values
are checked without opening credentials, connecting to a node or creating state.
Payload requires exactly two ordered `-public` inputs: the canonical
`payload/pairing.json` (dialect, model, max_tokens, model_endpoint,
model_cert_sha256), then the actual model service config. Missing or empty
dialect, either direction of profile mismatch, unknown model or endpoint/pin
drift refuses before deployment. The pairing describes the exact pinned launch
argv; the payload independently checks it at startup using `-dialect` and
`-model-config`. Legacy omitted-dialect startup is test-only and unqualified.
The main profile requires the same explicit payload/model pairing. Its executable is launched solely by Infra's reviewed
root policy; [POLICY-NEEDS.md](templates/payload/POLICY-NEEDS.md) is a table of
requirements, not an installable policy fragment.

Model and manager native loaders require canonical compact JSON in the exact
field order shown in their one-line templates. Replace quoted numeric placeholder
values with JSON integers, retain field order, and sort the model-name map by key.
Do not pretty-print those files or pass a generic alphabetically sorted object.
The signer permits ordinary JSON whitespace. Every placeholder remains inert:
no production model/rate/cap or numerical UID is selected by this kit. Synthetic
test caps are not operator proposals or approval. Explicit main configurations use the separate [M5 test config](templates/m5-test/README.md);
all monetary limits come from configuration, with no mainnet defaults.

The new structural validators check closed fields, explicit private file
references, key/public digest shape, per-coin route matching, cap/price arithmetic,
manager range/endpoint, and model listen/origin port equality. They do not prove
curve-point validity, key/script correspondence, certificate trust, file modes,
live balances or inventory ownership. Native startup checks and Infra smoke
remain required. The stricter deployment profile uses only the fixed credential
paths in the table and explicit positive watcher limits; it does not reproduce
every optional native configuration. New CLI controls run in
`cmd/deploy-kit/services_test.go`, alongside the package's descriptor/native
positive and negative fixtures.

### Credential and private-input ownership

DK5 installs every static config and secret as root:<exclusive service group>
0640 in root:<same group>0750 directories. All ancestors are root-owned,
non-writable by services, and free of symlinks. See [the signed install
contract](INSTALL-CONFIG.md) for schemas, signature domain, pins and refusal codes.
The public release manifest remains separate from the private resolved manifest.

| Consumer | Static installed inputs (all0640) | Private group |
| --- | --- | --- |
| Issuer | service.json, grant.key, funding.key, read/broadcast/payment route JSON | swarma-issuer |
| Gateway | service.json, agent key, observer route, TLS certificate/key/CA | swarma-gateway |
| Model proxy | service.json, TLS certificate/key, api.key | swarma-model |
| Booking | service.json, profile.bin, provider.hex, operator/payment routes, namecoin.conf | swarma-booking |
| Store | service.json | swarma-store |
| Relay | service.json | swarma-relay |
| Wallet daemon | service.json, wallet.json, receipt.key | swarma-wallet |
| Station manager | service.json, mTLS certificate/key, gateway CA | swarma-stations |
| Payload static assets | per-slot CA and canonical model config copy | exclusive slot group |

Signer intake mirrors and mutable journals retain service-owned0600 files in
0700 parents. Public confirmed presentations retain0644/0755. Dynamic per-slot
bootstrap remains slot-owned0600/0700 pending DK5b; it is not covered by the
static manifest. Standalone wallet/client/issuer tools retain their separate
owner-private file contracts. No migration changes existing funds, keys or state.

Wallet W2 uses `templates/wallet/{deploy,service}.json` and the separate
`swarma-wallet.service.in`, sysusers and tmpfiles templates. Replace the numerical
UID/GID/key placeholders with approved per-agent pins; add only that agent to
`swarma-wallet-peer`, never `swarma-wallet`. `/run/swarma-wallet` is service-owned0750, socket0660;
wallet/service/kernel/object roots remain private0700. The client receives only
its own action key and public service UID/receipt-key/socket pins, never the
private wallet configuration. Build `cmd/agent-wallet` separately from the same
reviewed head for the agent; it is not an additional daemon in the release.
Run `deploy-kit validate -config WALLET_DEPLOY_JSON -public WALLET_SERVICE_JSON`
before native startup. This is structural validation and opens no private files.
The daemon requires a different peer UID, exact file modes and regtest authority.
Before rollout, Infra must prove that the agent cannot read the wallet
credential/journal or connect to another agent's socket, alongside a successful
own-agent action. Template tests and cross-builds do not prove host isolation.
See the [wire and recovery profile](../experiments/agent-wallet/SERVICE.md).

Installed loaders require regular single-link files, check descriptor metadata
before reading bytes, and verify membership/content against the signed private
manifest before decoding. Refusal returns a stable DK5 reason without paths,
secret bytes or private hashes. Services do not provision or reseal their inputs.

Model admin socket: `/run/swarma-model/admin.sock`, model-owned0660 in model-owned
0750 `/run/swarma-model` with group `swarma-model-peer`. Infra adds the gateway user only to `swarma-model-peer`, the model socket group
and pins both numerical UIDs; the gateway remains a different UID. The unit uses
`RuntimeDirectory=swarma-model` with0750 and a narrowly scoped writable runtime
path in addition to persistent state. SO_PEERCRED is checked in both directions.
Gateway and model must be on the same host. An existing socket is not deleted by
the service; preserve and investigate stale state instead of adding an automatic
`rm`/restart cleanup command.

Slotd socket: `/run/swarma-slotd-demo/sock`, root-owned0660 in root-owned0750 parent.
Infra owns its group and manager caller admission; replace the unit's explicit
supplementary-group placeholder with that approved group. Do not give the manager
root or CAP_SYS_ADMIN. Its ordinary Linux binary delegates all host effects to
the independently installed helper. The payload gets no manager or model API key.

Additional tools (outputs remain under `.temp/` unless a new release is selected):

```sh
go -C deploy run .scripts/dk2-guards.go -out .temp/dk2-guards
go -C deploy run ./cmd/deploy-kit validate -config "$STAGING/issuer/deploy.json" -public "$STAGING/issuer/service.json"
go -C deploy run ./cmd/deploy-kit validate -config "$STAGING/model/deploy.json" -public "$STAGING/model/service.json"
go -C deploy run ./cmd/deploy-kit validate -config "$STAGING/stations/deploy.json" -public "$STAGING/stations/service.json"
go -C deploy run ./cmd/deploy-kit validate -config "$STAGING/payload/deploy.json" -public "$STAGING/payload/pairing.json" -public "$STAGING/model/service.json"
```

`deploy-kit check-coins -gateway PUBLIC_GATEWAY_JSON -booking PUBLIC_BOOKING_JSON`
compares the explicit G6/ServiceV2 coin sets and prints only `COIN_SETS_MATCH` on
success. It rejects legacy versions, duplicate/unknown coins and unequal sets;
it does not validate all native fields or probe a payment node. Run it on the
installed public-host inputs after G6 lands and after either config changes.

## Signed model limits

`deploy-kit check-model-terms -booking FILE -profile FILE -gateway FILE -model FILE -payload FILE` verifies public signed-cap and template/profile/payload bindings after individual native validation. Success prints `MODEL_TERMS_MATCH`; failures exit1. No credentials or referenced host paths are read. See [CC1 terms](../experiments/rental-booking/MODEL-CAPS.md). M5 model configs require the positive signed default as well as the original five caps.

## SW1 construction pins

Issuer policies and gateway kernel templates explicitly carry `construction_profile: "W"`. Issuer funding is `0014` plus the 20-byte compressed-key hash (native P2WPKH); the grant seal remains its separately pinned script. Templates do not migrate funds or state. Missing/unknown/L pins refuse in the consuming service, and prior durable bindings are not silently adopted. See [the W inventory](../experiments/WITNESS-PROFILE.md) for the linkage-only scope and SW1b payment-proof deferral.

## DK5 tools

`go run ./cmd/deploy-kit render-install-anchor --manifest /etc/swarma/model/install-manifest.json --signature /etc/swarma/model/install-manifest.json.sig --manifest-sha256 "$PRIVATE_MANIFEST_SHA256" --release-sha256 "$ACCEPTED_RELEASE_SHA256" --algorithm ed25519 --public-key "$PKIX_PUBLIC_KEY_BASE64"`
prints only the validated public drop-in. Infra supplies approved pins; this
command does not read files, generate keys or sign an install. Run from `deploy/`.
Never publish per-file secret hashes or the resolved private manifest.

From the repository root, `go run .scripts/dk5-guards.go -out "$NEW_ABSOLUTE_SCRATCH_DIR"`
calibrates21 bounded Go-overlay plants; inputs/source remain unchanged. Run tests
with the repository's isolated HOME/cache/temp contract. Ownership seams are
synthetic; modes, descriptors, hashes and scratch-key signatures are real.
Three plants check exact reasons with downstream rejection still intact.

Gateway service configs require `relay_max_event_bytes` without a default. Both
shipped gateway templates explicitly use65536, matching the unchanged relay
default. Operators must keep this value at or below the deployed relay
`max_event_bytes`; the gateway cannot attest the remote config. Native startup
validates the usable range and pending immutable outbox. Large replies become a
fixed terminal size notice; this field does not enable chunking.
