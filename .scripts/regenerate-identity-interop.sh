#!/usr/bin/env bash
# Reproduce public byte fixtures using only the immutable issuer and its
# existing regtest loopback RPC fixture. No node, wallet or publication.
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
output=${1:?usage: regenerate-identity-interop.sh ABSOLUTE-OUTPUT-DIRECTORY}
case "$output" in /*) ;; *) echo 'absolute output directory required' >&2; exit 2;; esac
if [[ -e "$output" ]]; then echo 'output must not already exist' >&2; exit 2; fi
scratch=$(mktemp -d /tmp/identity-interop.XXXXXX)
scratch=$(cd "$scratch" && pwd -P)
cleanup() { chmod -R u+w "$scratch"; rm -rf -- "$scratch"; }
trap cleanup EXIT
mkdir -p "$scratch"/{home,config,cache,build,mod,gopath,tmp}
export HOME="$scratch/home" USERPROFILE="$scratch/home"
export XDG_CONFIG_HOME="$scratch/config" XDG_CACHE_HOME="$scratch/cache"
export GOCACHE="$scratch/build" GOMODCACHE="$scratch/mod" GOPATH="$scratch/gopath"
export TMPDIR="$scratch/tmp" GOTMPDIR="$scratch/tmp" TMP="$scratch/tmp" TEMP="$scratch/tmp"
export GOTOOLCHAIN=local GOMAXPROCS=2 GOWORK=off LC_ALL=C
unset GOTELEMETRYDIR GOFLAGS
# The release toolchain and original export toolchain are supported; byte
# comparison, not a patch-version restriction, qualifies reproduction.
# Both must already be selected by PATH; never download a toolchain.
case "$(go version)" in
  'go version go1.26.8 '*|'go version go1.26.10 '*) ;;
  *) echo 'Go 1.26.8 or 1.26.10 required' >&2; exit 2 ;;
esac
git clone --no-checkout https://github.com/relux-works/swarma-identity.git "$scratch/issuer"
git -C "$scratch/issuer" checkout --detach 48a32fb05e214bc656c640bfb0dd36edf8ab6293
[[ $(git -C "$scratch/issuer" rev-parse HEAD) == 48a32fb05e214bc656c640bfb0dd36edf8ab6293 ]]
cp "$repo/.scripts/identity-interop/issuer_test.go" "$scratch/issuer/internal/facade/junction_export_test.go"
cd "$scratch/issuer"
export IDENTITY_INTEROP_OUT="$scratch/export"
go test -mod=readonly -p 1 -parallel 1 -count=1 -run '^TestJunctionExport$' -v ./internal/facade
mkdir -p "$output"
cp "$scratch/export/"* "$output/"

# Seal the exact generated filename set as well as every JSON octet.
(cd "$output" && sha256sum -- *.json > SHA256SUMS && sha256sum -c SHA256SUMS)
