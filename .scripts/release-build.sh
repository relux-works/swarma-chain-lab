#!/usr/bin/env bash
# Build only the gateway product, using the input table from main's policy.
set -euo pipefail
export LC_ALL=C TZ=UTC GOTOOLCHAIN=local GOWORK=off GOENV=off
export CGO_ENABLED=0 GOOS=linux GOAMD64=v1 GOARM64=v8.0 GOEXPERIMENT=
export GOFLAGS='-mod=readonly -p=2'
fail() { printf 'release build: %s\n' "$1" >&2; exit 1; }
[[ ( $# == 1 || $# == 2 ) && $1 == /* ]] || fail absolute-new-output-directory-required
out=$1
go_bin=${GO:-go}
policy_root=$(cd "$(dirname "$0")/.." && pwd -P)
root=${2:-$(git rev-parse --show-toplevel)}
[[ $root == /* ]] || fail absolute-source-directory-required
cd "$root"
[[ -z $(git status --porcelain --untracked-files=all) ]] || fail dirty-build-source
commit=$(git rev-parse HEAD)
[[ $("$go_bin" env GOVERSION) == go1.26.8 ]] || fail go1.26.8-required
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || fail invalid-source-epoch
inputs=$(python3 "$policy_root/.scripts/release-metadata.py" inputs "$root")
mkdir "$out"
printf 'Go: %s; SOURCE_DATE_EPOCH=%s\n' "$("$go_bin" env GOVERSION)" "$SOURCE_DATE_EPOCH"
for arch in amd64 arm64; do
  export GOARCH=$arch
  stage="$out/.stage-$arch"
  mkdir "$stage"
  while IFS=$'\t' read -r kind source package member mode; do
    destination="$stage/$member"
    mkdir -p "$(dirname "$destination")"
    case $kind in
      go)
        (cd "$root/$source" && "$go_bin" build -trimpath -buildvcs=false -ldflags=-buildid= -o "$destination" "$package")
        ;;
      file) cp "$root/$source" "$destination" ;;
      *) fail invalid-input-kind ;;
    esac
    chmod "$mode" "$destination"
  done <<< "$inputs"
  python3 "$policy_root/.scripts/release-metadata.py" pack "$stage" \
    "$out/gateway_linux_$arch.tar.gz" "$SOURCE_DATE_EPOCH"
  rm -r "$stage"
done
cd "$out"
python3 "$policy_root/.scripts/release-metadata.py" create "$out" "$commit" \
  "$("$go_bin" env GOVERSION)" "$SOURCE_DATE_EPOCH"
sha256sum --strict --check SHA256SUMS
