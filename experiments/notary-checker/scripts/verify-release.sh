#!/usr/bin/env bash
# Offline verdicts only. Trust inputs and the independent rebuild are operator supplied.
set -euo pipefail
export LC_ALL=C
fail() { printf 'FAIL %s\n' "$1"; exit 1; }
pass() { printf 'PASS %s\n' "$1"; }
# No version default: the operator supplies the tag and its release-record commit.
[[ $# == 8 ]] || fail ARGUMENTS
repo=$1 commit=$2 version=$3 release=$4 rebuilt=$5 tag_allowed=$6 manifest_allowed=$7 signer=$8
[[ $version =~ ^notary-service/v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || fail ARGUMENTS
tag=refs/tags/$version
for tool in git ssh-keygen sha256sum cmp python3 env mktemp rm; do
    command -v "$tool" >/dev/null 2>&1 || fail TOOL_MISSING
done
[[ $commit =~ ^[0-9a-f]{40}$ && -n $signer ]] || fail ARGUMENTS
# Relative paths could make the caller and Git inspect different trust files.
for path in "$repo" "$release" "$rebuilt" "$tag_allowed" "$manifest_allowed"; do
    [[ $path == /* ]] || fail ARGUMENTS
done
[[ -d $repo ]] || fail MISSING_REPOSITORY
# BEGIN RELEASE_DIRECTORY_CHECK
# Enumerate only this directory, including dotfiles. lstat never follows links;
# no trust input or independent rebuild belongs beside the three downloads.
python3 - "$release" <<'PY'
import os
import stat
import sys

def fail(verdict):
    print('FAIL ' + verdict)
    sys.exit(1)

try:
    mode = os.lstat(sys.argv[1]).st_mode
    if stat.S_ISLNK(mode):
        fail('RELEASE_SYMLINK')
    if not stat.S_ISDIR(mode):
        fail('MISSING_RELEASE_DIRECTORY')
    expected = {'notary-service-linux-amd64', 'SHA256SUMS', 'SHA256SUMS.sig'}
    with os.scandir(sys.argv[1]) as entries:
        for entry in sorted(entries, key=lambda item: item.name):
            mode = os.lstat(entry.path).st_mode
            if stat.S_ISLNK(mode):
                fail('RELEASE_SYMLINK')
            if stat.S_ISDIR(mode):
                fail('RELEASE_SUBDIRECTORY')
            if not stat.S_ISREG(mode):
                fail('RELEASE_NON_REGULAR_FILE')
            if entry.name not in expected:
                fail('UNEXPECTED_RELEASE_FILE')
except OSError:
    fail('RELEASE_DIRECTORY_READ')
PY
# END RELEASE_DIRECTORY_CHECK
[[ -f $tag_allowed && ! -L $tag_allowed ]] || fail MISSING_TAG_ALLOWED_SIGNERS
[[ -f $manifest_allowed && ! -L $manifest_allowed ]] || fail MISSING_MANIFEST_ALLOWED_SIGNERS
# A single trust file would collapse the two operator-approved signing roles.
[[ ! $tag_allowed -ef $manifest_allowed ]] || fail ARGUMENTS
[[ -f $release/notary-service-linux-amd64 && ! -L $release/notary-service-linux-amd64 ]] || fail MISSING_BINARY
[[ -f $release/SHA256SUMS && ! -L $release/SHA256SUMS ]] || fail MISSING_SHA256SUMS
[[ -f $release/SHA256SUMS.sig && ! -L $release/SHA256SUMS.sig ]] || fail MISSING_SIGNATURE
[[ -f $rebuilt && ! -L $rebuilt ]] || fail MISSING_REBUILD
# Canonicalize parent components only after rejecting final-component links.
# Every later consumer receives the same absolute physical path.
physical() {
    local canonical
    # A slash sentinel preserves even trailing newlines through command substitution.
    canonical=$(python3 -c 'import os,sys; sys.stdout.write(os.path.realpath(sys.argv[1]) + "/")' "${!1}") || fail ARGUMENTS
    printf -v "$1" '%s' "${canonical%/}"
}
for input in repo release rebuilt tag_allowed manifest_allowed; do
    physical "$input"
done
[[ $rebuilt != "$release/"* && ! $rebuilt -ef $release/notary-service-linux-amd64 ]] || fail ARGUMENTS
scratch=$(mktemp -d "${TMPDIR:-/tmp}/nv.XXXXXXXX") || fail ARGUMENTS
trap 'rm -rf -- "$scratch"' EXIT
# Git only reads objects. No inherited environment/config selects a signature
# verifier or trust store: SSH verification below calls ssh-keygen directly.
git_object() {
    env -i PATH="$PATH" LC_ALL=C HOME="$scratch" GIT_CONFIG_NOSYSTEM=1 \
        GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 GIT_NO_REPLACE_OBJECTS=1 \
        git -C "$repo" "$@"
}
# Resolve the mutable ref exactly once. All later reads use immutable object IDs.
tag_object=$(git_object rev-parse --verify "$tag^{tag}" 2>/dev/null) || fail TAG_SIGNATURE
[[ $tag_object =~ ^[0-9a-f]{40}$ ]] || fail TAG_SIGNATURE
git_object cat-file tag "$tag_object" > "$scratch/tag" 2>/dev/null || fail TAG_SIGNATURE
# Only SSH armor is admitted; never dispatch to an ambient GPG backend.
python3 - "$scratch" "$version" <<'PYTAG'
from pathlib import Path
import re
import sys
root = Path(sys.argv[1])
raw = (root / 'tag').read_bytes()
marker = b'-----BEGIN SSH SIGNATURE-----\n'
if raw.count(marker) != 1 or not raw.endswith(b'-----END SSH SIGNATURE-----\n'):
    print('FAIL TAG_SIGNATURE')
    sys.exit(1)
payload, signature = raw.split(marker)
headers = payload.split(b'\n\n', 1)[0].splitlines()
# Require a direct commit tag with one unambiguous signed name and target.
names = [line[4:] for line in headers if line.startswith(b'tag ')]
objects = [line[7:] for line in headers if line.startswith(b'object ')]
types = [line[5:] for line in headers if line.startswith(b'type ')]
if names != [sys.argv[2].encode()]:
    print('FAIL TAG_IDENTITY')
    sys.exit(1)
if len(objects) != 1 or not re.fullmatch(b'[0-9a-f]{40}', objects[0]) or types != [b'commit']:
    print('FAIL TAG_COMMIT')
    sys.exit(1)
(root / 'payload').write_bytes(payload)
(root / 'signature').write_bytes(marker + signature)
(root / 'target').write_bytes(objects[0] + b'\n')
PYTAG
ssh-keygen -Y find-principals -f "$tag_allowed" -s "$scratch/signature" \
    > "$scratch/principals" 2>/dev/null || fail TAG_SIGNATURE
tag_valid=false
while IFS= read -r principal; do
    if ssh-keygen -Y verify -f "$tag_allowed" -I "$principal" -n git \
        -s "$scratch/signature" < "$scratch/payload" >/dev/null 2>&1; then
        tag_valid=true
        break
    fi
done < "$scratch/principals"
[[ $tag_valid == true ]] || fail TAG_SIGNATURE
pass TAG_SIGNATURE
IFS= read -r target < "$scratch/target"
[[ $target == "$commit" ]] || fail TAG_COMMIT
[[ $(git_object cat-file -t "$target" 2>/dev/null) == commit ]] || fail TAG_COMMIT
pass TAG_COMMIT
ssh-keygen -Y verify -f "$manifest_allowed" -I "$signer" -n swarma-release \
    -s "$release/SHA256SUMS.sig" >/dev/null 2>&1 < "$release/SHA256SUMS" || fail MANIFEST_SIGNATURE
pass MANIFEST_SIGNATURE
# BEGIN SIGNER_ROLE_SEPARATION
# Check the actual signature keys against the opposite trust input, including
# copied merged files. find-principals checks key membership, not namespace.
if ssh-keygen -Y find-principals -f "$tag_allowed" -s "$release/SHA256SUMS.sig" >/dev/null 2>&1 ||
    ssh-keygen -Y find-principals -f "$manifest_allowed" -s "$scratch/signature" >/dev/null 2>&1; then
    fail SIGNER_ROLE_SEPARATION
fi
# END SIGNER_ROLE_SEPARATION
# Accept precisely the one published artifact, never manifest-controlled paths.
{ IFS= read -r manifest < "$release/SHA256SUMS"; } 2>/dev/null || fail MANIFEST_FORMAT
[[ $manifest =~ ^([0-9a-f]{64})\ \ notary-service-linux-amd64$ ]] || fail MANIFEST_FORMAT
expected=${BASH_REMATCH[1]}
printf '%s  notary-service-linux-amd64\n' "$expected" | cmp -s - "$release/SHA256SUMS" || fail MANIFEST_FORMAT
actual=$(sha256sum -- "$release/notary-service-linux-amd64" 2>/dev/null) || fail BINARY_SHA256
[[ ${actual%% *} == "$expected" ]] || fail BINARY_SHA256
pass BINARY_SHA256
actual=$(sha256sum -- "$rebuilt" 2>/dev/null) || fail REBUILD_SHA256
[[ ${actual%% *} == "$expected" ]] || fail REBUILD_SHA256
pass REBUILD_SHA256
pass RELEASE_VERIFIED
