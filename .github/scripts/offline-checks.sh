#!/bin/bash
# Execute only inside the workflow's offline namespace, never on a host.
set -euo pipefail
case "${1:?supply a suite}" in
  fullnode-trusts|utxo-age|thin-regtest-assembly)
    cd "/source/experiments/$1"
    python3 -B -m unittest discover -s . -p 'test_*.py' -v
    ;;
  notary)
    cd /source/experiments/notary
    python3 -B test_lab_paths.py
    python3 -B offline-counterexamples.py /source/experiments/notary/lab.py
    python3 -B offline-counterexamples.py /source/experiments/notary/baseline-lab.py
    ;;
  sealwatch)
    cd /source/experiments/sealwatch
    go vet -mod=readonly ./...
    go test -mod=readonly -count=1 -timeout=120s ./...
    ;;
  *) printf 'unknown offline suite\n' >&2; exit 64 ;;
esac
