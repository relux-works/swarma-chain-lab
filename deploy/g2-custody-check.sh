#!/bin/sh
# T18: different-UID custody check for the G2 pay executor (PX1 stream S5).
#
# Run as the AGENT user on the executor host, after the owner has provisioned
# the users, rendered and resolved templates/g2-pay (see deploy/SMOKE-G2.md)
# and started agent-walletd. This script never needs root, never reads a
# credential and never spends: the positive request is a "balance" read.
#
#   g2-custody-check.sh SPEC CLIENT GRANTEE OUTDIR
#
#   SPEC     resolved custody-spec.json (launch layout)
#   CLIENT   the agent's resolved client.json
#   GRANTEE  the agent's x-only action public key (64 lowercase hex)
#   OUTDIR   new evidence directory (must not exist)
#
# DEPLOY_KIT and AGENT_WALLET name the binaries built from the reviewed head
# (defaults: deploy-kit and agent-wallet on PATH).
#
# Prints T18_PASS and exits 0 only when all three hold:
#   1. deploy-kit g2-custody-probe: every denied read is EACCES/EPERM, every
#      credential-less node RPC call is refused, the wallet socket connects;
#   2. agent-wallet returns an "executed" receipt for the own-agent request;
#   3. deploy-kit g2-custody-verify accepts the stored report for the spec.
# Otherwise prints T18_FAIL and exits 1. Usage errors exit 64.
set -eu
umask 077

usage() {
	echo "usage: g2-custody-check.sh SPEC CLIENT GRANTEE OUTDIR" >&2
	exit 64
}
[ "$#" -eq 4 ] || usage
spec=$1
client=$2
grantee=$3
out=$4
case $grantee in
'' | *[!0-9a-f]*) usage ;;
esac
[ "${#grantee}" -eq 64 ] || usage
[ -f "$spec" ] && [ -f "$client" ] || usage
deploy_kit=${DEPLOY_KIT:-deploy-kit}
agent_wallet=${AGENT_WALLET:-agent-wallet}

# A new directory only: earlier evidence is never overwritten.
mkdir "$out" || usage

set +e
"$deploy_kit" g2-custody-probe -spec "$spec" >"$out/custody-report.json" 2>"$out/custody-probe.err"
probe=$?

nonce=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
now=$(date +%s)
printf '{"v":1,"service":"wallet.nmc","action":"balance","params":{},"grant":{"kind":"none"},"nonce":"%s","created_at":%s,"grantee":"%s"}' \
	"$nonce" "$now" "$grantee" >"$out/positive-request.json"
"$agent_wallet" --config "$client" --request "$out/positive-request.json" >"$out/positive-receipt.json" 2>"$out/positive.err"
positive=$?

"$deploy_kit" g2-custody-verify -spec "$spec" -report "$out/custody-report.json" >"$out/custody-verify.txt" 2>&1
verify=$?
set -e

printf 'uid=%s probe_exit=%s positive_exit=%s verify_exit=%s\n' "$(id -u)" "$probe" "$positive" "$verify" >"$out/exits.txt"
if [ "$probe" -eq 0 ] && [ "$positive" -eq 0 ] && [ "$verify" -eq 0 ] &&
	grep -q '"verdict":"executed"' "$out/positive-receipt.json"; then
	echo T18_PASS
	exit 0
fi
echo T18_FAIL
exit 1
