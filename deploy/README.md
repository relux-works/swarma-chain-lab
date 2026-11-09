# M5 deploy preparation (DK1)

Go release tooling and public templates for regtest preparation. It builds
gateway, rental-booking and grant-store from an exact clean HEAD twice, refuses
any byte difference, then emits an unsigned bundle with SHA256SUMS and a manifest.
No source product changes, key creation, signing, installation or host deployment
occur inside the tool. [SMOKE.md](SMOKE.md) is the separate Infra handoff plan.

Gateway is a blocked, non-startable reference in the manifest: its current CLI
still uses a stub kernel and does not wire E1. There is no gateway unit. Real
serve wiring belongs to GW1. Only booking/store have systemd templates. Signer,
Courier/CG1 and Nostr transport are pending manifest rows with no guessed units.

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
renamed into a new output directory only after all three binary pairs match.
Temporary source/build trees are removed, including on refusal.

Outputs: `bin/`, `templates/`, `README.md`, `SMOKE.md`, `manifest.json`,
`SHA256SUMS`. Checksums cover every output file except the checksum file itself;
the orchestrator signs that file separately with namespace `swarma-release`.
The manifest records commit, Go version, target, flags, module/package, binary
hash and readiness status. No timestamp, home path or build-directory path is
embedded in the manifest. A successful build is not a deployment acceptance.

## Public configuration validation

`validate -config` checks a separate public deployment policy JSON, rather than
injecting extra fields into native service config. It always refuses mainnet,
unresolved placeholders, invalid/duplicate/unknown fields, wildcard listeners,
foreign writable/credential paths and unpinned node CLI references. Complete
booking/store regtest descriptors accept without opening any referenced file.
Use repeated `-public` for every staged native public JSON file; those extra
files receive bounded JSON/duplicate/placeholder/network/inline-secret checks.
Native service schema, profile/key/clock checks still run at service startup;
this validator does not claim to validate unseen credentials or live nodes.

Templates are intentionally incomplete: no live keys, private RPC configs,
public branch or profile bytes are fabricated. Booking's zero rate/time/slot
values are sentinels to replace. See [SURVEY.md](SURVEY.md) for the landed native
schemas and [UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md) for deployment inputs.

## Tools and artifacts

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
  equivalent uses its descriptor and service.json. Enter each as one command.
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
