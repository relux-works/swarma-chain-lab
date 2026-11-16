#!/usr/bin/env bash
# Offline verdicts only. Trust inputs and the independent rebuild are operator supplied.
set -euo pipefail
fail() { printf 'FAIL %s\n' "$1"; exit 1; }
pass() { printf 'PASS %s\n' "$1"; }
# No version default: the operator supplies the tag and its release-record commit.
[[ $# == 8 ]] || fail ARGUMENTS
repo=$1 commit=$2 version=$3 release=$4 rebuilt=$5 tag_allowed=$6 manifest_allowed=$7 signer=$8
[[ $version =~ ^notary-service/v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || fail ARGUMENTS
tag=refs/tags/$version
for tool in git ssh-keygen sha256sum cmp python3; do
    command -v "$tool" >/dev/null 2>&1 || fail TOOL_MISSING
done
[[ $commit =~ ^[0-9a-f]{40}$ && -n $signer ]] || fail ARGUMENTS
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
# Explicit local refs only: no fetch, remote lookup, build, execution or install.
git -C "$repo" -c gpg.ssh.allowedSignersFile="$tag_allowed" verify-tag "$tag" >/dev/null 2>&1 || fail TAG_SIGNATURE
pass TAG_SIGNATURE
target=$(git -C "$repo" rev-parse --verify "$tag^{commit}" 2>/dev/null) || fail TAG_COMMIT
[[ $target == "$commit" ]] || fail TAG_COMMIT
pass TAG_COMMIT
ssh-keygen -Y verify -f "$manifest_allowed" -I "$signer" -n swarma-release \
    -s "$release/SHA256SUMS.sig" >/dev/null 2>&1 < "$release/SHA256SUMS" || fail MANIFEST_SIGNATURE
pass MANIFEST_SIGNATURE
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
