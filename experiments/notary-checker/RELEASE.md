# Building and deploying the notary service

This document prepares a reviewed source revision for deployment. The release
owner chooses the landed revision, creates the signed tag
`notary-service/vMAJOR.MINOR.PATCH` at that exact commit, and publishes the release,
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

### Approved signer roles and release record

The operator provisions **two separate allowed-signers files** independently of
untrusted downloads. A tag author and a release owner have different authority:

| Purpose | Principal | ED25519 fingerprint | Required SSH namespace |
| --- | --- | --- | --- |
| Signed Git tag only (bot) | `262682706+reluxbot@users.noreply.github.com` | `SHA256:63rp3DJz29F8BZCMoD8HbG+fgPaIat2wBRse0vRp34E` | `git` |
| Detached checksum manifest only (owner release key) | `ivan-platform-release` | `SHA256:x3t8hOxl+PixTw1eTqV+qCqSp88Vw7AEMrmGUvs213I` | `swarma-release` |

The corresponding public keys are:

```text
# Bot tag public key
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDDOr+BTDP5KSmsORCo6YKBb8DZp/PhsjJMZtnA07VWh
# Owner release public key
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF9OaCfCki1tEczuA4hE2DaaToEpFteweRW3IBJkwbgT
```

The bot key matches the repository's configured Relux Nexus / `reluxbot`
signing identity and the fingerprint reported by `git verify-tag
notary-service/v0.1.1`. Git reports a fingerprint, not the public-key bytes;
those bytes come from the configured public signing identity. The release
public-key bytes are embedded in the published v0.1.1 `SHA256SUMS.sig` and
match the owner's independently approved fingerprint above. The embedded key
alone is not authority: always compare its fingerprint with the approved pin.
No private key is needed for verification, and no production private key is
used by these tests.

Write these public keys to `TAG_PUBLIC_KEY` and `MANIFEST_PUBLIC_KEY` files,
then check the exact fingerprints before provisioning the trust files:

```bash
set -euo pipefail
test "$(ssh-keygen -lf "$TAG_PUBLIC_KEY" | awk '{print $2}')" = \
  'SHA256:63rp3DJz29F8BZCMoD8HbG+fgPaIat2wBRse0vRp34E'
test "$(ssh-keygen -lf "$MANIFEST_PUBLIC_KEY" | awk '{print $2}')" = \
  'SHA256:x3t8hOxl+PixTw1eTqV+qCqSp88Vw7AEMrmGUvs213I'
```

`TAG_ALLOWED_SIGNERS` must contain exactly the bot entry, scoped to `git`:

```text
262682706+reluxbot@users.noreply.github.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDDOr+BTDP5KSmsORCo6YKBb8DZp/PhsjJMZtnA07VWh
```

`MANIFEST_ALLOWED_SIGNERS` must contain exactly the owner release entry,
scoped to `swarma-release`:

```text
ivan-platform-release namespaces="swarma-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF9OaCfCki1tEczuA4hE2DaaToEpFteweRW3IBJkwbgT
```

Do not combine these entries or substitute one key for the other. Protect both
files from modification. The verifier rejects the same file supplied twice;
it trusts the operator to provision each file with only its approved role.
A future key rotation requires a separately approved release record.

### Version-generic verification

Each release record must state the exact tag, full landed commit, artifact
name/hash and both approved signer roles above. `RELEASE_TAG` is a **required**
argument: exactly `notary-service/vMAJOR.MINOR.PATCH`, where each component is a
nonnegative decimal integer without leading zeros. There is no default, ref
prefix, wildcard, prerelease suffix, shell expansion or evaluation. Set
`RELEASE_COMMIT` from the release record, never from a moving branch or by
inferring it from an unverified tag.

Verify the tag and its recorded target in an already obtained local checkout:

```sh
git -C "$SOURCE_ROOT" -c gpg.ssh.allowedSignersFile="$TAG_ALLOWED_SIGNERS" \
  verify-tag "refs/tags/$RELEASE_TAG"
test "$(git -C "$SOURCE_ROOT" rev-parse "refs/tags/$RELEASE_TAG^{commit}")" = "$RELEASE_COMMIT"
```

Rebuild from a clean checkout of that exact commit using the toolchain and
flags above. Both local build hashes must equal the published binary's
SHA-256, authenticated by the manifest. A supplied rebuild path alone cannot
prove how it was built. Run the current verifier from a separate checkout if
the release revision predates this verifier interface.

In the download directory, authenticate the manifest before checking hashes:

```sh
ssh-keygen -Y verify -f "$MANIFEST_ALLOWED_SIGNERS" -I "$MANIFEST_SIGNER_ID" \
  -n swarma-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum --check --strict SHA256SUMS
```

The combined verifier accepts eight positional arguments, in this order:

```sh
scripts/verify-release.sh "$SOURCE_ROOT" "$RELEASE_COMMIT" "$RELEASE_TAG" \
  "$RELEASE_DIR" "$REBUILT_BINARY" "$TAG_ALLOWED_SIGNERS" \
  "$MANIFEST_ALLOWED_SIGNERS" "$MANIFEST_SIGNER_ID"
```

Verification **FAILS CLOSED**: no install without a good tag signature,
matching tag target, owner manifest signature, published binary checksum and
independent rebuild checksum. Any nonzero exit forbids installation. Tag
verification uses only `TAG_ALLOWED_SIGNERS` in namespace `git`; manifest
verification uses only `MANIFEST_ALLOWED_SIGNERS` in namespace `swarma-release`.

Use absolute paths for all filesystem arguments. The download directory must
contain only `notary-service-linux-amd64`, `SHA256SUMS` and `SHA256SUMS.sig`.
Keep rebuilds and trust files outside it. The script enumerates the directory
non-recursively, including dotfiles, using Python 3's `os.lstat`. Extra regular
files refuse as `UNEXPECTED_RELEASE_FILE`, subdirectories as
`RELEASE_SUBDIRECTORY`, symlinks as `RELEASE_SYMLINK` and special files as
`RELEASE_NON_REGULAR_FILE`. Read errors refuse as `RELEASE_DIRECTORY_READ`;
a non-directory release path refuses as `MISSING_RELEASE_DIRECTORY`.

A missing or malformed tag parameter refuses as `ARGUMENTS`; an absent or
untrusted tag signature as `TAG_SIGNATURE`; a tag peeling to a different
recorded commit as `TAG_COMMIT`; an altered or wrongly signed manifest as
`MANIFEST_SIGNATURE`. Missing trust files refuse as
`MISSING_TAG_ALLOWED_SIGNERS` or `MISSING_MANIFEST_ALLOWED_SIGNERS`.
Every refusal prints its exact `FAIL CODE`, exits **1** and never prints
`PASS RELEASE_VERIFIED`; success exits **0** with that terminal verdict.
`SHA256SUMS` must have precisely one lowercase SHA-256 entry for the fixed
artifact basename; other paths refuse as `MANIFEST_FORMAT`. The script makes
no network request, build, executable launch or install. Use immutable,
operator-controlled inputs; concurrent file substitution is outside its claim.

### Worked example: v0.1.1

The [published pre-release](https://github.com/relux-works/swarma-chain-lab/releases/tag/notary-service/v0.1.1)
records:

```sh
RELEASE_TAG=notary-service/v0.1.1
RELEASE_COMMIT=8a47f1a984cd93864402f7fdc09d2eba0d890b90
MANIFEST_SIGNER_ID=ivan-platform-release
```

Its artifact is `notary-service-linux-amd64`, SHA-256
`9e63953c112b0cf0426a2db4ddc048faff053088d5cd1d447f1e6f598c91f7f5`.
The signer principals, public keys, fingerprints and purposes are exactly the
two approved roles above. After provisioning those trust files, obtaining the
signed tag locally, and independently rebuilding the recorded commit:

```sh
gh release download "$RELEASE_TAG" --repo relux-works/swarma-chain-lab \
  --dir "$RELEASE_DIR" --pattern notary-service-linux-amd64 \
  --pattern SHA256SUMS --pattern SHA256SUMS.sig
scripts/verify-release.sh "$SOURCE_ROOT" "$RELEASE_COMMIT" "$RELEASE_TAG" \
  "$RELEASE_DIR" "$REBUILT_BINARY" "$TAG_ALLOWED_SIGNERS" \
  "$MANIFEST_ALLOWED_SIGNERS" "$MANIFEST_SIGNER_ID"
```

Expect exit 0 and `PASS RELEASE_VERIFIED`. Pairing the previous
`notary-service/v0.1.0` tag with this v0.1.1 record and its assets must refuse
as `TAG_COMMIT`; v0.1.0 is superseded and must not be deployed.

### Verifier controls

`python3 -B scripts/test-verify-release.py` uses two disposable local keys and
signed fixture tags outside the source repository. It asserts the current
version's valid control, missing/malformed tag, wrong target, old-tag/new-assets
pairing, tampered manifest and binary, both cross-signer refusals, wrong
namespace/principal/key, missing files, invalid tags, changed rebuild and
foreign manifest paths. It retains extra visible/hidden files, directory,
symlink and FIFO controls, and prints each exercised verdict and exit code.
It proves local verification behavior, not operator custody or deployment.

`python3 -B scripts/check-release-mutant.py --work-dir .temp/release-mutant`
removes enumeration in a disposable copy: `ReleaseVerification.test_extra_file`
must fail while `ReleaseVerification.test_all_good` still passes. Logs, PIDs
and `mutation-results.md` remain in that fresh work directory. Python 3 is a
verifier dependency for explicit non-following `lstat` checks; no third-party
Python package is required. If available, run
`shellcheck scripts/verify-release.sh`; use `bash -n scripts/verify-release.sh`
for syntax validation as well. Keep local test/build logs in task scratch.

## Install the verified executable

The authorized target operator installs into a root-owned service directory:

```sh
install -m 0755 -o root -g root "$RELEASE_DIR/notary-service-linux-amd64" "$SERVICE_DIR/notary-service"
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
