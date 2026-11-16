# Building and deploying the notary service

This document prepares a reviewed source revision for deployment. The release
owner chooses the revision, creates the tag and publishes the release and its
`SHA256SUMS` after review. A candidate PR is not a published release.

## Reproduce the executable

Use **Go 1.26.10**, `GOTOOLCHAIN=local`, `GOWORK=off`, Linux/amd64,
`GOAMD64=v1`, and `CGO_ENABLED=0`. Check out the exact reviewed release source,
then run from `experiments/notary-checker`. These are the README build flags:

```sh
set -eu
export GOTOOLCHAIN=local
export GOWORK=off
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1
test "$(go env GOVERSION)" = go1.26.10
mkdir -p .temp
go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
  -o .temp/notary-service-a ./cmd/notary-service
go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
  -o .temp/notary-service-b ./cmd/notary-service
sha256sum .temp/notary-service-a .temp/notary-service-b
cmp .temp/notary-service-a .temp/notary-service-b
```

Both SHA-256 values must be identical and `cmp` must exit 0. The expected
release artifact name is **`notary-service-linux-amd64`**. The release owner
copies the identical executable under that name and generates the manifest:

```sh
mkdir -p .temp/release
cp .temp/notary-service-a .temp/release/notary-service-linux-amd64
(cd .temp/release && sha256sum notary-service-linux-amd64 > SHA256SUMS)
```

The operator obtains the executable and `SHA256SUMS` from the same trusted
release, checks that the manifest names `notary-service-linux-amd64`, and
runs in the download directory:

```sh
sha256sum --check --strict SHA256SUMS
```

Require exit 0 before execution. Compare the release executable against both
local builds (`cmp` with each build, or compare all three SHA-256 values).
Equality is bound to the exact source, toolchain, target and flags above.
A checksum downloaded alongside an untrusted binary establishes consistency,
not release authenticity; use the reviewed release's trusted source.

## Generate the key on the target

Run as the service account on the intended target system, in its protected
working directory. Generate a fresh key there after verifying the executable:

```sh
umask 077
mkdir -m 700 notary-private
./notary-service-linux-amd64 keygen -out notary-private/attestation.key
```

The command prints only the x-only public key. It creates a new owner-only
0600 regular key file exclusively; an existing path refuses as `KEY_FILE`
and is never overwritten. Do not generate the production key on a build
machine, copy it between systems, or use the public test keys. Keep the
private directory and key readable only by the service account. Publish only
the returned public key in the notary name binding described in the README.

Provision the strict configuration, deployment policy and owner-only regular
RPC credential file as described in [README.md](README.md#notary-service-regtest-laboratory).
Use `./notary-service-linux-amd64 serve -config CONFIG_FILE` after those
operator obligations are satisfied. Config, policy, key, credential and
checker inputs must be regular files; FIFOs and symlinks refuse promptly.
The service remains limited to regtest node reads and loopback HTTP.

## Deployment boundary

This release does not fund or broadcast the notary seal or the attestation
anchor. It returns a signed attestation and anchor frame; transaction
construction, funding, broadcast and confirmation are operator work.
Network ACLs, service-account isolation, authenticated policy provisioning,
name registration and the deferred operational obligations in DESIGN.md
also remain deployment work. A reproducible executable and passing tests
are not evidence that those obligations have been performed.
