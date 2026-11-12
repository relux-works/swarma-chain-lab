#!/bin/sh
# T18: different-UID custody check for the G2 pay executor (PX1 stream S5).
#
# Run with the agent's slot credentials on the executor host, after
# deploy-kit g2-host-flow provisioned and verified the accounts and activated
# agent-walletd (see deploy/SMOKE-G2.md). Those are the credentials the slot
# applies (User= and Group= the agent account, supplementary groups through
# initgroups): UID agent_uid, the account's own primary group and
# swarma-wallet-peer. This script never needs root, never reads a credential
# and never spends: the positive request is a "balance" read.
#
#   g2-custody-check.sh SPEC CLIENT GRANTEE PARAMS OUTDIR
#
#   SPEC     rendered custody-spec.json (launch layout)
#   CLIENT   the agent's rendered client.json
#   GRANTEE  the agent's x-only action public key (64 lowercase hex)
#   PARAMS   the parameters.json the files were rendered from (no secret)
#   OUTDIR   new evidence directory (must not exist)
#
# DEPLOY_KIT and AGENT_WALLET name the binaries built from the reviewed head
# (defaults: deploy-kit and agent-wallet on PATH).
#
# Prints T18_PASS and exits 0 only when all four hold:
#   0. deploy-kit g2-agent-groups accepts the readback `id -G`: exactly the
#      set {the agent's own primary GID, agent_socket_gid}, both derived from
#      PARAMS (the primary GID from the agent's sysusers declaration), in any
#      order, nothing else and never operator_gid (otherwise nothing else
#      runs);
#   1. deploy-kit g2-custody-probe: every denied read is EACCES/EPERM, every
#      credential-less node RPC call is refused, the wallet socket connects;
#   2. agent-wallet returns an "executed" receipt for the own-agent request;
#   3. deploy-kit g2-custody-verify accepts the stored report for the spec.
# Otherwise prints T18_FAIL and exits 1. Usage errors exit 64.
set -eu
umask 077

usage() {
	echo "usage: g2-custody-check.sh SPEC CLIENT GRANTEE PARAMS OUTDIR" >&2
	exit 64
}
[ "$#" -eq 5 ] || usage
spec=$1
client=$2
grantee=$3
params=$4
out=$5
case $grantee in
'' | *[!0-9a-f]*) usage ;;
esac
[ "${#grantee}" -eq 64 ] || usage
[ -f "$spec" ] && [ -f "$client" ] && [ -f "$params" ] || usage
deploy_kit=${DEPLOY_KIT:-deploy-kit}
agent_wallet=${AGENT_WALLET:-agent-wallet}

# A new directory only: earlier evidence is never overwritten.
mkdir "$out" || usage

# Readback of the credentials this run holds. `id -G` prints the effective
# GID and every other group of the process; deploy-kit g2-agent-groups gets
# one argument per GID and accepts exactly {own primary GID,
# agent_socket_gid} as derived from PARAMS. A failed `id` reads back nothing,
# which is refused.
groups=$(id -G) || groups=
printf 'uid=%s gid=%s groups=%s\n' "$(id -u)" "$(id -g)" "$groups" >"$out/credentials.txt"
set -f
# shellcheck disable=SC2086 # one argument per GID of the readback
if ! "$deploy_kit" g2-agent-groups -params "$params" -- $groups >"$out/credentials-check.txt" 2>&1; then
	printf 'credentials=refused\n' >"$out/exits.txt"
	echo T18_FAIL
	exit 1
fi

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
