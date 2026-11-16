# Building and deploying the notary service

This document prepares a reviewed source revision for deployment. The release
owner chooses the landed revision, creates the signed tag
`notary-service/v0.1.0` at that exact commit, and publishes the release,
`SHA256SUMS` and `SHA256SUMS.sig` after review. A candidate PR is not a published release.

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

## Authenticate the release before installation

The release key is **OWNER-held** and signs outside this repository. No private
release key belongs in the source tree, a build cache, a test fixture or CI.
Reuse the repository convention in [deploy/SMOKE.md](../../deploy/SMOKE.md#1-release-workstation-build-review-and-sign):
in the release directory, the owner signs the exact published manifest:

```sh
ssh-keygen -Y sign -f "$SIGNING_KEY" -n swarma-release SHA256SUMS
```

The operator provisions `ALLOWED_SIGNERS` and `SIGNER_ID` independently from the
download, using the owner's approved public signing identity. Verify the
signed tag and its exact target in an already obtained local source checkout:

```sh
git -c gpg.ssh.allowedSignersFile="$ALLOWED_SIGNERS" verify-tag notary-service/v0.1.0
test "$(git rev-parse 'refs/tags/notary-service/v0.1.0^{commit}')" = "$RELEASE_COMMIT"
test "$(git rev-parse HEAD)" = "$RELEASE_COMMIT"
```

`RELEASE_COMMIT` is the full landed commit stated in the release record, not a
moving branch. GitHub's Verified tag signature is an alternative operator
check; the offline script below always runs `git verify-tag`. Rebuild from a
clean checkout of that commit using the toolchain and flags above. Both local
build hashes must equal the published binary's SHA-256, as authenticated by
this manifest. A supplied rebuild path alone cannot prove how it was built.

In the download directory, verify the manifest signature **before** its hashes:

```sh
ssh-keygen -Y verify -f "$ALLOWED_SIGNERS" -I "$SIGNER_ID" -n swarma-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum --check --strict SHA256SUMS
```

Verification **FAILS CLOSED**: no install without a good signature, matching
tag target, published binary checksum and independent rebuild checksum.
Missing inputs or any nonzero verification exit forbid installation. The
namespace is exactly `swarma-release`, never an inferred or fallback namespace.

For the combined local checks, from `experiments/notary-checker`:

```sh
scripts/verify-release.sh "$SOURCE_ROOT" "$RELEASE_COMMIT" "$RELEASE_DIR" \
  "$REBUILT_BINARY" "$ALLOWED_SIGNERS" "$SIGNER_ID"
```

Use absolute paths for the source checkout, download directory, independent
rebuilt executable and allowed-signers file. The script checks the fixed tag
`notary-service/v0.1.0`, its signature and target, the detached manifest
signature, and both hashes. `SHA256SUMS` must contain only the single lowercase
SHA-256 entry for `notary-service-linux-amd64`; other paths refuse. It prints
only `PASS`/`FAIL` verdicts, exits nonzero on any failure or missing file, and
performs no network access, build, executable launch or install. Run it against
immutable operator-controlled files; it does not make concurrent substitution
of a mutable release safe.

`python3 -B scripts/test-verify-release.py` creates throwaway local signers and
a local signed fixture tag outside the source repository. It checks the good
release and named refusals for a tampered binary, tampered manifest, wrong
namespace, wrong signer, missing signature, invalid tag, wrong target, changed
rebuild and foreign manifest path. It never uses the release owner's key.

## Install the verified executable

The authorized target operator installs into a root-owned service directory:

```sh
install -m 0755 -o root -g root notary-service-linux-amd64 "$SERVICE_DIR/notary-service"
sha256sum "$SERVICE_DIR/notary-service"
stat -c '%U:%G %a %n' "$SERVICE_DIR/notary-service"
namei -l "$SERVICE_DIR/notary-service"
```

Compare the SHA-256 **at the installed path** with the authenticated manifest
entry; the changed basename does not change the expected digest. Require the
installed file to be a regular root:root executable of mode 0755. Check every
directory from `/` through the service directory: root ownership, appropriate
traversal permissions, no group or world write, and no symlink redirection.
Inspect effective ACLs too if present: they must grant no write authority to
non-root users. A mismatched hash, owner, mode or writable directory chain
forbids starting the service; resolve it with the target operator. These are
operator instructions, not installation actions performed by the verifier.

## Generate the key on the target

Run as the service account on the intended target system, in its protected
working directory. Generate a fresh key there after verifying the executable:

```sh
umask 077
mkdir -m 700 notary-private
"$SERVICE_DIR/notary-service" keygen -out notary-private/attestation.key
```

The command prints only the x-only public key. It creates a new owner-only
0600 regular key file exclusively; an existing path refuses as `KEY_FILE`
and is never overwritten. Do not generate the production key on a build
machine, copy it between systems, or use the public test keys. Keep the
private directory and key readable only by the service account. Publish only
the returned public key in the notary name binding described in the README.

Provision the strict configuration, deployment policy and owner-only regular
RPC credential file as described in [README.md](README.md#notary-service-regtest-laboratory).
Use `"$SERVICE_DIR/notary-service" serve -config CONFIG_FILE` after those
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
