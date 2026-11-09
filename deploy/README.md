# M5 deploy preparation (DK1)

Go release tooling and public templates for regtest preparation. It builds
gateway, rental-booking, grant-store and swarma-relay from an exact clean HEAD twice, refuses
any byte difference, then emits an unsigned bundle with SHA256SUMS and a manifest.
No source product changes, key creation, signing, installation or host deployment
occur inside the tool. [SMOKE.md](SMOKE.md) is the separate Infra handoff plan.

Gateway now wires the real kernel, E1 and remote station manager, with explicit
screening off in its manifest row and native config. Gateway, booking, store and relay
have systemd templates. The gateway still requires operator-pinned payload/TLS
inputs and real Linux host acceptance; compilation is not deployment evidence.
Signer and Courier/CG1 are pending manifest rows with no guessed units.

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
renamed into a new output directory only after all four binary pairs match.
Temporary source/build trees are removed, including on refusal.

Outputs: `bin/`, `templates/`, `README.md`, `SMOKE.md`, `manifest.json`,
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
off; E1 still checks inner work. Recipient privacy requires the pending gateway
AUTH adapter before enabling restricted gift-wrap reads. See the
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

`deploy-kit validate -public` checks the AUTH mode and refuses a partial/null
model section, unknown fields, invalid UID/caps or non-manager selection. Integer
limits retain uint64 precision. Native `gateway validate` independently checks
the same boundary before startup effects. The kit still refuses mainnet and all
unresolved placeholders. See the gateway's [configuration contract](../experiments/rental-gateway/RELAY_MODEL.md)
for the Linux socket ownership/peer checks and bootstrap lifecycle.
