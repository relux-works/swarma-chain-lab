#!/usr/bin/env bash
# Offline verdicts only. Trust inputs and the independent rebuild are operator supplied.
set -euo pipefail
fail() { printf 'FAIL %s\n' "$1"; exit 1; }
pass() { printf 'PASS %s\n' "$1"; }
[[ $# == 6 ]] || fail ARGUMENTS
repo=$1 commit=$2 release=$3 rebuilt=$4 allowed=$5 signer=$6
tag=refs/tags/notary-service/v0.1.0
for tool in git ssh-keygen sha256sum cmp; do
    command -v "$tool" >/dev/null 2>&1 || fail TOOL_MISSING
done
[[ $commit =~ ^[0-9a-f]{40}$ && -n $signer ]] || fail ARGUMENTS
[[ -d $repo ]] || fail MISSING_REPOSITORY
[[ -f $allowed && ! -L $allowed ]] || fail MISSING_ALLOWED_SIGNERS
[[ -f $release/notary-service-linux-amd64 && ! -L $release/notary-service-linux-amd64 ]] || fail MISSING_BINARY
[[ -f $release/SHA256SUMS && ! -L $release/SHA256SUMS ]] || fail MISSING_SHA256SUMS
[[ -f $release/SHA256SUMS.sig && ! -L $release/SHA256SUMS.sig ]] || fail MISSING_SIGNATURE
[[ -f $rebuilt && ! -L $rebuilt ]] || fail MISSING_REBUILD
# Explicit local refs only: no fetch, remote lookup, build, execution or install.
git -C "$repo" -c gpg.ssh.allowedSignersFile="$allowed" verify-tag "$tag" >/dev/null 2>&1 || fail TAG_SIGNATURE
pass TAG_SIGNATURE
target=$(git -C "$repo" rev-parse --verify "$tag^{commit}" 2>/dev/null) || fail TAG_COMMIT
[[ $target == "$commit" ]] || fail TAG_COMMIT
pass TAG_COMMIT
ssh-keygen -Y verify -f "$allowed" -I "$signer" -n swarma-release \
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
