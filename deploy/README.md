# M5 deploy preparation (DK1 and DK2)

Go release tooling and public templates for regtest preparation. It builds
gateway, rental-booking, grant-store, swarma-relay, swarma-signer, model-proxy,
station-manager and station-payload from an exact clean HEAD twice, refuses
any byte difference, then emits an unsigned bundle with SHA256SUMS and a manifest.
No source product changes, key creation, signing, installation or host deployment
occur inside the tool. [SMOKE.md](SMOKE.md) is the separate Infra handoff plan.

Gateway now wires the real kernel, E1 and remote station manager, with explicit
screening off in its manifest row and native config. Gateway, booking, store and relay
have systemd templates. The gateway still requires operator-pinned payload/TLS
inputs and real Linux host acceptance; compilation is not deployment evidence.
Signer, model proxy and station manager have separate units; the scripted payload
has only a documented root-policy requirements table for Infra. Courier/CG1
remains a pending manifest row. [SMOKE-DK2.md](SMOKE-DK2.md) gives the new services'
install order and explicit external transport/host qualification gates.

## Build contract

Use Go1.26.8 and pre-download the landed modules' dependencies into the local
module cache (`go mod download` and `go mod verify` in each service module).
The builder itself has no third-party dependencies. It forces GOTOOLCHAIN=local,
GOWORK=off, GOENV=off, GOPROXY=off and empty GOFLAGS; there is no toolchain/network
fallback. Exact release flags are GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0
and `go build -trimpath -buildvcs=false -mod=readonly`.

The source argument must be a canonical repository root, with clean tracked,
index and untracked state, and the supplied full40-hex commit must equal HEAD.
Two `git archive` extractions and separate build caches prevent a working-tree
file or previous compiled output from standing in for the second build.
Archive traversal/link entries refuse. Source cleanliness/HEAD are checked again
before publication; existing output is preserved. The complete candidate is
renamed into a new output directory only after all eight binary pairs match.
Temporary source/build trees are removed, including on refusal.

Outputs: `bin/`, `templates/`, `README.md`, `SMOKE.md`, `SMOKE-DK2.md`, `manifest.json`,
`SHA256SUMS`. Checksums cover every output file except the checksum file itself;
the release signer signs that file separately with namespace `swarma-release`.
The manifest records commit, Go version, target, flags, module/package, binary
hash and readiness status. No timestamp, home path or build-directory path is
embedded in the manifest. A successful build is not a deployment acceptance.

## Public configuration validation

`validate -config` checks a separate public deployment policy JSON, rather than
injecting extra fields into native service config. It always refuses mainnet,
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
share the loopback budget. Run `bin/swarma-relay -config
"$STAGING/relay/service.json" -check` as one command after substituting the public
URL. The initial compatibility profile leaves AUTH restrictions and outer PoW
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
  equivalent uses its descriptor and service.json, as does gateway. For gateway,
  also run `bin/gateway validate -config "$STAGING/gateway/service.json"`.
  Enter each as one command.
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
the same boundary before startup effects. The kit still refuses mainnet and all
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
Payload has no native JSON: its descriptor pins only the release identity and
rejects `-public` inputs. Its executable is launched solely by Infra's reviewed
root policy; [POLICY-NEEDS.md](templates/payload/POLICY-NEEDS.md) is a table of
requirements, not an installable policy fragment.

Model and manager native loaders require canonical compact JSON in the exact
field order shown in their one-line templates. Replace quoted numeric placeholder
values with JSON integers, retain field order, and sort the model-name map by key.
Do not pretty-print those files or pass a generic alphabetically sorted object.
The signer permits ordinary JSON whitespace. Every placeholder remains inert:
no production model/rate/cap or numerical UID is selected by this kit. Synthetic
test caps are not operator proposals or approval. The kit refuses mainnet even
with fully filled values, consistent with the signer regtest-only boundary.

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

Native loader requirements supersede a blanket0400 rule. This table covers every
new service's credential/config/bootstrap file; no secret file is included in
release templates. Parents are canonical, symlink-free and owned by the listed
service user unless noted. State roots and private mirrors are separate from
`/etc`, and the units mount `/etc/swarma/<service>` read-only.

| File | Owner | File mode | Immediate parent mode | Native enforcement |
| --- | --- | --- | --- | --- |
| `/etc/swarma/issuer/service.json` | `swarma-issuer` | 0600 | 0700 | signer `privateRead` / `durable.PrivateRegular` |
| `/etc/swarma/issuer/grant.key` (raw32-byte scalar) | `swarma-issuer` | 0600 | 0700 | signer `loadKey` / `privateRead`, key-script pin |
| `/etc/swarma/issuer/funding.key` (distinct raw32-byte scalar) | `swarma-issuer` | 0600 | 0700 | signer `loadKey` / `privateRead`, key-script pin |
| `/etc/swarma/issuer/read-route.json` | `swarma-issuer` | 0600 | 0700 | signer `privateRead`, `w3-observer` RPC identity |
| `/etc/swarma/issuer/broadcast-route.json` | `swarma-issuer` | 0600 | 0700 | signer `privateRead`, distinct `sg1-broadcaster` principal |
| `/etc/swarma/issuer/payment-<coin>.json` for every configured coin | `swarma-issuer` | 0600 | 0700 | signer `privateRead`, `payment-issuer` identity |
| Issuer booking/operator mirror `index.json` and immutable hash-named items | `swarma-issuer` | 0600 | 0700 | signer `OpenFileSource` / `privateRead`; producer root is not shared across users |
| `/etc/swarma/model/service.json` | `swarma-model` | 0600 | 0700 | proxy `LoadConfig` / exact-mode `ReadPrivateFile` |
| `/etc/swarma/model/tls.pem` | `swarma-model` | 0600 | 0700 | proxy exact-mode `ReadPrivateFile`, leaf pin |
| `/etc/swarma/model/tls.key` | `swarma-model` | 0600 | 0700 | proxy exact-mode `ReadPrivateFile`, certificate pair |
| `/etc/swarma/model/api.key` | `swarma-model` | 0400 | 0700 | proxy exact-mode `ReadPrivateFile`; printable ASCII, no trailing newline |
| `/etc/swarma/stations/service.json` | `swarma-stations` | 0400 | 0700 | manager `readPrivate`: owner, single link, no group/world bits; canonical config |
| `/etc/swarma/stations/client.pem` | `swarma-stations` | 0400 | 0700 | manager `readPrivate`, mTLS pair |
| `/etc/swarma/stations/client.key` | `swarma-stations` | 0400 | 0700 | manager `readPrivate`, mTLS pair |
| `/etc/swarma/stations/gateway-ca.pem` | `swarma-stations` | 0400 | 0700 | manager `readPrivate`, CA parsing |
| Infra-selected per-slot bootstrap file | that slot's user | 0600 | 0700 | payload exact-mode proxy `ReadPrivateFile` plus closed bootstrap codec |
| Infra-selected per-slot CA bundle | that slot's user | 0600 | 0700 | payload exact-mode proxy `ReadPrivateFile`, normal TLS trust plus pins |

All these loaders also require regular single-link files owned by the process;
model/manager/payload reject symlink path components. Signer key paths and source
roots reject symlink components; its generic config/RPC reader rejects a final
symlink and enforces ownership/mode/link count. Infra additionally provisions all
parents without symlinks. Do not stage a second writable copy of a secret to
work around a mode mismatch. Runtime journals retain their native0600 files in
0700 state directories. Public confirmed signer presentations are0644 under a
0755 presentation directory; they are distinct from credentials/private intake.

Model admin socket: `/run/swarma-model/admin.sock`, model-owned0660 in model-owned
0750 `/run/swarma-model`. Infra adds the gateway user to the model socket group
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
go -C deploy run ./cmd/deploy-kit validate -config "$STAGING/payload/deploy.json"
```

`deploy-kit check-coins -gateway PUBLIC_GATEWAY_JSON -booking PUBLIC_BOOKING_JSON`
compares the explicit G6/ServiceV2 coin sets and prints only `COIN_SETS_MATCH` on
success. It rejects legacy versions, duplicate/unknown coins and unequal sets;
it does not validate all native fields or probe a payment node. Run it on the
installed public-host inputs after G6 lands and after either config changes.
