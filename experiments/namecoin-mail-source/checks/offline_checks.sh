#!/bin/sh
# Sandbox launcher contract (external, never a host-service installer): clearenv,
# unshare-all, drop all capabilities, source/tools readonly, /upstream readonly
# canonical ncdns git tree plus proxy/ and sumdb/ acquisitions, /evidence writable,
# /private/{home,tmp,cache} absolute mode 0700; no host homes/keys/sockets/caches.
# Bound wall 180s, CPU 120s per process, address-space 2 GiB, file size 64 MiB.
set -eu
umask 077
: "${HOME:?absolute private HOME required}"
: "${TMPDIR:?absolute private TMPDIR required}"
case "$HOME:$TMPDIR" in /private/home:/private/tmp) ;; *) exit 64;; esac
export GOPROXY=file:///upstream/proxy GOSUMDB=off GOTOOLCHAIN=local
export GOPATH=/private/cache/go GOCACHE=/private/cache/build CGO_ENABLED=0
here=/source/experiments/namecoin-mail-source
python3 "$here/checks/verify_modules.py"
work=$(mktemp -d /private/tmp/mail-source.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
cp -R /upstream/ncdns/. "$work/"
rm -rf "$work/.git"
cd "$work"
cp testdata/go.mod testdata/go.sum .
go mod download github.com/coreos/go-systemd/v22
go mod edit -replace github.com/coreos/go-systemd=/private/cache/go/pkg/mod/github.com/coreos/go-systemd/v22@v22.7.0
go mod download
go mod verify
# Upstream suite expects this legacy GOPATH location; preserve pinned contents.
mkdir -p "$GOPATH/src/github.com/hlandau"
ln -sfn "$GOPATH/pkg/mod/github.com/hlandau/nctestsuite@v0.0.0-20151129185958-a9b78806c85c" "$GOPATH/src/github.com/hlandau/nctestsuite"
go build -mod=readonly -trimpath -o "$work/ncdns-source-check" .
go test -mod=readonly -count=1 ./ncdomain
go run -mod=readonly "$here/checks/parser_probe.go" "$here/fixtures"
# No ncdns, DNS server, Postfix master, validator or mail delivery is started.
