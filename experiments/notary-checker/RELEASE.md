# Building and deploying the notary service

This document prepares a reviewed source revision for deployment. The release
owner chooses the landed revision, authorizes the bot-signed tag
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
files from modification. The verifier rejects the same file supplied twice
and rejects either actual signature key appearing in the opposite role's file,
even when the operator supplies two copies of a merged file. Namespace options
alone do not substitute for this key separation. The operator still approves
the authority of each provisioned key.
A future key rotation requires a separately approved release record.

### Version-generic verification

Each release record must state the exact tag, full landed commit, artifact
name/hash and both approved signer roles above. `RELEASE_TAG` is a **required**
argument: exactly `notary-service/vMAJOR.MINOR.PATCH`, where each component is a
nonnegative decimal integer without leading zeros. There is no default, ref
prefix, wildcard, prerelease suffix, shell expansion or evaluation. Set
`RELEASE_COMMIT` from the release record, never from a moving branch or by
inferring it from an unverified tag.

Obtain the signed tag in a fresh, operator-owned local source checkout, as in the
example below. Run the verifier from a **clean, operator-controlled directory**;
do not run from a download directory or reuse an existing work directory. The
verifier also isolates itself: every Python invocation uses an absolute
interpreter path and `-I` (no cwd imports, user site or `PYTHON*` settings).
The combined verifier resolves
`refs/tags/$RELEASE_TAG^{tag}` exactly once to an immutable annotated-tag object.
It requires SSH armor, verifies that object's payload directly with
`ssh-keygen -Y verify -f "$TAG_ALLOWED_SIGNERS" -n git`, and compares the signed
`tag` header byte for byte with `RELEASE_TAG`, without newline normalization. The signed direct commit target must equal
`RELEASE_COMMIT`. Every subsequent Git read uses an object ID, never the mutable
ref. Git reads through a private bare view containing only a snapshot of the
release ref/packed refs and a link to the source object store. Source repository
configuration (including includes, remotes, promisor settings, fsmonitor and
hooks) is not loaded. Each Git read has a cleared environment, disabled
system/global configuration, replacement objects and lazy fetching, and explicit
protocol, hook and program guards. `GIT_ALLOW_PROTOCOL=none` and
`protocol.allow=never` also forbid transports on Git versions without
`GIT_NO_LAZY_FETCH` support. Git signature backends, user keyrings and inherited
`gpg.*` configuration cannot choose a trust source or verifier program. Ordinary,
bare, packed-ref and linked-worktree source layouts are supported; the verifier
expects SHA-1 object IDs. Use the combined command below for these checks.

Export that exact release commit into a fresh source directory, and build into
a separate fresh output directory using the toolchain and flags above. Both
local build hashes must equal the published binary's SHA-256, authenticated by
the manifest. The rebuilt file must be outside the download directory and a
different inode from the download (including hardlinks). Those checks prevent
a trivial self-comparison; a supplied path alone cannot prove build provenance.
Run the verifier from the separately pinned `VERIFIER_ROOT` checkout below:
v0.1.1's source revision contains an older incompatible verifier.

In the download directory, authenticate the manifest before checking hashes:

```sh
ssh-keygen -Y verify -f "$MANIFEST_ALLOWED_SIGNERS" -I "$MANIFEST_SIGNER_ID" \
  -n swarma-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum --check --strict SHA256SUMS
```

The combined verifier accepts eight positional arguments, in this order:

```sh
"$VERIFIER_ROOT/experiments/notary-checker/scripts/verify-release.sh" "$SOURCE_ROOT" "$RELEASE_COMMIT" "$RELEASE_TAG" \
  "$RELEASE_DIR" "$REBUILT_BINARY" "$TAG_ALLOWED_SIGNERS" \
  "$MANIFEST_ALLOWED_SIGNERS" "$MANIFEST_SIGNER_ID"
```

Verification **FAILS CLOSED**: no install without a good tag signature,
matching tag target, owner manifest signature, published binary checksum and
independent rebuild checksum. Any nonzero exit forbids installation. Tag
verification accepts only SSH signatures and uses only `TAG_ALLOWED_SIGNERS`
in namespace `git`; manifest verification uses only `MANIFEST_ALLOWED_SIGNERS` in namespace `swarma-release`.

All filesystem arguments must be absolute (relative paths refuse as
`ARGUMENTS`); the verifier canonicalizes them to physical paths before use.
The download directory must contain only `notary-service-linux-amd64`, `SHA256SUMS` and `SHA256SUMS.sig`.
Keep rebuilds and trust files outside it. The script enumerates the directory
non-recursively, including dotfiles, using Python 3's `os.lstat`. Extra regular
files refuse as `UNEXPECTED_RELEASE_FILE`, subdirectories as
`RELEASE_SUBDIRECTORY`, symlinks as `RELEASE_SYMLINK` and special files as
`RELEASE_NON_REGULAR_FILE`. Read errors refuse as `RELEASE_DIRECTORY_READ`;
a non-directory release path refuses as `MISSING_RELEASE_DIRECTORY`.

A missing or malformed tag parameter refuses as `ARGUMENTS`; an absent,
untrusted or non-SSH tag signature as `TAG_SIGNATURE`; a different or duplicate
tag name as `TAG_IDENTITY`; duplicate object/type headers, a non-commit type,
a signed tag-of-tag or a different recorded target as `TAG_COMMIT`. An unsigned
outer tag refuses as `TAG_SIGNATURE`, without borrowing an inner signature.
Shared trust files or a downloaded rebuild alias refuse as `ARGUMENTS`;
actual signature keys trusted across roles as `SIGNER_ROLE_SEPARATION`; an
altered or wrongly signed manifest as `MANIFEST_SIGNATURE`. Missing trust files refuse as
`MISSING_TAG_ALLOWED_SIGNERS` or `MISSING_MANIFEST_ALLOWED_SIGNERS`.
Every refusal prints its exact `FAIL CODE`, exits **1** and never prints
`PASS RELEASE_VERIFIED`; success exits **0** with that terminal verdict.
`SHA256SUMS` must have precisely one lowercase SHA-256 entry for the fixed
artifact basename; other paths refuse as `MANIFEST_FORMAT`. The script makes
no network request, build, downloaded-executable launch or install. It uses
Git, OpenSSH, Python and coreutils, with an automatically removed private
scratch directory under `TMPDIR` (or `/tmp`). Use immutable,
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
two approved roles above. Provision the absolute trust-file paths first.
Set `VERIFIER_COMMIT` to the full, immutable **landed and accepted** verifier
revision from the follow-up review record. Its script blob must equal the pin
below; do not reuse the earlier PR #148 implementation pin, which predates this
isolation hardening. The landing record must supply the final commit (including
a rewritten squash/rebase commit); a candidate is not a deployment approval.
The verifier checkout and release source checkout are distinct, and neither
follows a moving branch during verification.

```sh
set -eu
: "${VERIFIER_COMMIT:?Set the full landed verifier commit from the accepted follow-up record}"
VERIFIER_BLOB=118de24218b15a9e126e722fc7cbc82639687fbf
# Start in a clean operator-owned parent; mkdir refuses to reuse an existing run.
mkdir -p .temp
WORK_ROOT="$(pwd -P)/.temp/notary-v0.1.1"
mkdir "$WORK_ROOT"
VERIFIER_ROOT="$WORK_ROOT/verifier"
SOURCE_ROOT="$WORK_ROOT/release-source"
EXPORT_ROOT="$WORK_ROOT/export"
BUILD_ROOT="$WORK_ROOT/build"
RELEASE_DIR="$WORK_ROOT/downloads"
REBUILT_BINARY="$BUILD_ROOT/notary-service-a"
git clone --no-checkout https://github.com/relux-works/swarma-chain-lab.git "$VERIFIER_ROOT"
git -C "$VERIFIER_ROOT" fetch --no-tags origin "$VERIFIER_COMMIT"
git -C "$VERIFIER_ROOT" checkout --detach "$VERIFIER_COMMIT"
test "$(git -C "$VERIFIER_ROOT" rev-parse HEAD)" = "$VERIFIER_COMMIT"
test "$(git -C "$VERIFIER_ROOT" rev-parse HEAD:experiments/notary-checker/scripts/verify-release.sh)" = "$VERIFIER_BLOB"
git clone --no-checkout https://github.com/relux-works/swarma-chain-lab.git "$SOURCE_ROOT"
git -C "$SOURCE_ROOT" fetch origin "refs/tags/$RELEASE_TAG:refs/tags/$RELEASE_TAG"
git -C "$SOURCE_ROOT" archive --format=tar -o "$WORK_ROOT/source.tar" "$RELEASE_COMMIT"
mkdir "$EXPORT_ROOT" "$BUILD_ROOT" "$WORK_ROOT/home" "$WORK_ROOT/config" \
  "$WORK_ROOT/cache" "$WORK_ROOT/tmp" "$WORK_ROOT/go-build" \
  "$WORK_ROOT/go-mod" "$WORK_ROOT/go-path"
tar -xf "$WORK_ROOT/source.tar" -C "$EXPORT_ROOT"
gh release download "$RELEASE_TAG" --repo relux-works/swarma-chain-lab \
  --dir "$RELEASE_DIR" --pattern notary-service-linux-amd64 \
  --pattern SHA256SUMS --pattern SHA256SUMS.sig
GO_BIN=$(command -v go)
test "$("$GO_BIN" env GOVERSION)" = go1.26.10
(
  export HOME="$WORK_ROOT/home" USERPROFILE="$WORK_ROOT/home"
  export XDG_CONFIG_HOME="$WORK_ROOT/config" XDG_CACHE_HOME="$WORK_ROOT/cache"
  export TMPDIR="$WORK_ROOT/tmp" TMP="$WORK_ROOT/tmp" TEMP="$WORK_ROOT/tmp"
  export GOCACHE="$WORK_ROOT/go-build" GOMODCACHE="$WORK_ROOT/go-mod" GOPATH="$WORK_ROOT/go-path"
  unset GOTELEMETRYDIR
  export GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1
  cd "$EXPORT_ROOT/experiments/notary-checker"
  "$GO_BIN" build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
    -o "$REBUILT_BINARY" ./cmd/notary-service
  "$GO_BIN" build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' \
    -o "$BUILD_ROOT/notary-service-b" ./cmd/notary-service
)
# The verifier does not require the caller to enter either checkout.
cd "$WORK_ROOT"
test "$REBUILT_BINARY" != "$RELEASE_DIR/notary-service-linux-amd64"
test ! "$REBUILT_BINARY" -ef "$RELEASE_DIR/notary-service-linux-amd64"
sha256sum "$REBUILT_BINARY" "$BUILD_ROOT/notary-service-b" "$RELEASE_DIR/notary-service-linux-amd64"
cmp "$REBUILT_BINARY" "$BUILD_ROOT/notary-service-b"
TMPDIR="$WORK_ROOT/tmp" \
  "$VERIFIER_ROOT/experiments/notary-checker/scripts/verify-release.sh" \
  "$SOURCE_ROOT" "$RELEASE_COMMIT" "$RELEASE_TAG" \
  "$RELEASE_DIR" "$REBUILT_BINARY" "$TAG_ALLOWED_SIGNERS" \
  "$MANIFEST_ALLOWED_SIGNERS" "$MANIFEST_SIGNER_ID"
```

Expect exit 0 and `PASS RELEASE_VERIFIED`. Pairing the previous
`notary-service/v0.1.0` tag with this v0.1.1 record and its assets must refuse
as `TAG_COMMIT`; v0.1.0 is superseded and must not be deployed.

### Verifier controls

`python3 -B scripts/test-verify-release.py` uses two disposable local keys and
signed fixture tags outside the source repository. The 61 tests retain all
47 previous test names and put a valid control beside every refusal. New
isolation controls plant a cwd `re.py` and `PYTHONPATH` startup module, prove
non-isolated Python executes them, and prove the verifier ignores them. A
malformed local config include is ignored; promisor uploadpack stubs execute
under raw Git but never during verification of missing tag/commit objects.
Bare, packed-ref and linked-worktree inputs retain valid controls. Signed
literal objects exercise duplicate tag headers in both orders, duplicate
object/type headers, non-commit types, and signed/unsigned outer tags, with
exact verdicts and raw-Git signature preconditions for signed malformed tags.
One-sided honest-signature trust overlaps exercise each separation operand.
Earlier controls reject ambient-only tag trust, non-SSH
armor, relative trust paths, wrong signed tag names (including a CR suffix),
and a moved ref attempting
to replace a wrong pinned target, copied merged trust files, and downloaded
rebuild aliases. Positive controls assert physical trust paths, ignore ambient
verifier programs, and retain a valid pinned target despite a moved ref.
The suite also asserts the current
version's valid control, missing/malformed tag, wrong target, old-tag/new-assets
pairing, tampered manifest and binary, both cross-signer refusals, wrong
namespace/principal/key, missing files, invalid tags, changed rebuild and
foreign manifest paths. It retains extra visible/hidden files, directory,
symlink and FIFO controls, and prints each exercised verdict and exit code.
It proves local verification behavior, not operator custody or deployment.

`python3 -B scripts/check-release-mutant.py --work-dir .temp/release-mutant`
runs eight disposable mutants: directory enumeration, the complete role guard,
each of its two operands independently, and four header relaxations (tag-name
membership, object count, type membership, and the direct-commit type check).
Each named negative must detect its specific relaxation by an assertion failure
on an unexpectedly accepted verdict while `ReleaseVerification.test_all_good`
still passes; setup errors, tool failures and crashes do not count as kills.
`test_role_separation_mutant` additionally runs the exact cross-signer fixture
against the guarded verifier (exit 1, `SIGNER_ROLE_SEPARATION`) and the guard-only
mutant (exit 0, `RELEASE_VERIFIED`); this proves the guard is load-bearing. Logs,
exit-code files, PIDs and `mutation-results.md` remain in that fresh work
directory. Python 3 is a verifier dependency for explicit non-following `lstat` checks; no third-party
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
