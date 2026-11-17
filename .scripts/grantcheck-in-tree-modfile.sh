#!/usr/bin/env bash
# Reproduce the wallet's sibling graph without changing grantcheck's published manifest.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd -P)"
modfile="${1:?absolute output .mod path required}"
case "$modfile" in /*.mod) ;; *) echo 'absolute output .mod path required' >&2; exit 2 ;; esac
test ! -e "$modfile"
test ! -e "${modfile%.mod}.sum"
mkdir -p "$(dirname "$modfile")"
cp "$root/experiments/grantcheck/go.mod" "$modfile"
cp "$root/experiments/grantcheck/go.sum" "${modfile%.mod}.sum"
for sibling in rental rental-gateway rental-gateway/kernelbind single-use sealwatch rental-booking payment-chain station-lifecycle station-lifecycle/gatewaybind model-proxy; do
  test -f "$root/experiments/$sibling/go.mod"
  go -C "$root/experiments/grantcheck" mod edit -modfile="$modfile" -replace="github.com/relux-works/swarma-chain-lab/experiments/$sibling=$root/experiments/$sibling"
done
