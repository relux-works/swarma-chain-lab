#!/bin/sh
# G2 real-host qualification: the T18 and setpriv half of the report.
#
# Operator procedure: deploy/T18-REAL-HOST.md. This runner adds no check of
# its own to the custody rule. It runs the existing tools (deploy-kit g2-render,
# g2-host-flow, g2-agent-groups through g2-custody-check.sh, g2-custody-probe
# and g2-custody-verify), keeps their output as evidence and turns that
# evidence into one line per T18 item:
#
#   <item-id> PASS|FAIL|STAND_IN|COVERED_BY_HOSTED <evidence>
#
# followed by one OVERALL line, which is PASS only when every required item is
# present once, no item is FAIL, every line is consistent with its own
# evidence, STAND_IN appears only for the placeholder-backed items of a
# stand-in run (and no such item is PASS there), and every COVERED_BY_HOSTED
# item carries exactly its pin (test name, commit, hosted run, job).
#
# The real-wallet POSITIVE path (an authorized request that executes) is not
# proven by T18 or by this report: it is proven by the separate
# owner-authorized, bounded mainnet smoke gate. On a host the wallet client
# sends nothing; positive-request is COVERED_BY_HOSTED, pinned to
# TestPX1CoreServiceG2FailClosed in run 43360330369, and turns FAIL if the host
# evidence shows that any frame was sent.
#
#   t18-real-host-report.sh node-capture OUT SPEC -- CLI [CLI-OPTION...]
#       as the node's operator (r10): one node call, `CLI CLI-OPTION...
#       -rpcconnect=HOST -rpcport=PORT getindexinfo txindex`, against the one
#       denied_rpc entry HOST:PORT of SPEC, bracketed by two UTC times taken
#       by this script. OUT (new) gets the capture: the lines
#       `T18-NODE-CAPTURE v1`, `rpc=HOST:PORT`, `start=<UTC>`, `end=<UTC>`,
#       `exit=<n>` and `answer=<answer without white space>`. The method is
#       fixed here; CLI-OPTION may only be -datadir=, -conf=, -rpccookiefile=,
#       -chain= or -rpcclienttimeout=, so no other call (no wallet call, no
#       -getinfo, no -generate) can be made through this mode
#   t18-real-host-report.sh operator OPDIR PARAMS RENDERED CAPTURE
#       as the operator (no root needed): re-render, account checks, txindex.
#       CAPTURE is the pre-probe node capture (node-capture output, kept as
#       OPDIR/node-pre.txt); a bare saved getindexinfo answer is still read
#       for node-txindex, but carries no time and no target
#   t18-real-host-report.sh agent AGDIR SPEC CLIENT GRANTEE PARAMS
#       as the agent, launched by root with setpriv exactly as SMOKE-G2.md §4.
#       r10: the probe window, `probe_start=<UTC>` and `probe_end=<UTC>` taken
#       right before and right after the custody script (which runs the
#       probe), is kept in AGDIR/probe-window.txt
#   t18-real-host-report.sh denied-stat SPEC
#       as root (r10), read-only: prints one line per denied_reads path of
#       SPEC, in spec order: `<path> exists=yes type=<%F, spaces as _>
#       owner=<uid>:<gid> mode=<octal>` (stat -L) or `<path> exists=no`. The
#       operator saves it as OPDIR/denied-paths-stat.txt
#   r10, live runs (`real`): a denied-rpc row is PASS only when, beside the
#       r9 rule, the pre-probe capture (OPDIR/node-pre.txt) and the post-probe
#       capture (OPDIR/node-post.txt) both name the row's target, carry their
#       times, and pre start <= pre end <= probe start <= probe end <= post
#       start <= post end, and the post-probe answer is synced; a denied-read
#       row is PASS only when OPDIR/denied-paths-stat.txt holds exactly one
#       `exists=yes` line for its path. Stand-in runs are unchanged
#   t18-real-host-report.sh report OPDIR AGDIR RENDERED PARAMS real|stand-in
#       reads both evidence directories and prints the report. The last
#       argument is the stand-in flag: `stand-in` marks a run on the stand-in
#       station, whose wallet files are root-owned placeholders and whose
#       socket is a planted listener; every placeholder-backed item (each
#       denied-read, status-dir, allowed-socket) is then STAND_IN, never PASS,
#       and the OVERALL line says the run is valid only as a stand-in run.
#       r9: a denied-rpc row is PASS only for an explicit refusal (HTTP_401
#       or HTTP_403) while node-txindex is PASS in the same report; a refused
#       connection (REFUSED: nothing listens) is FAIL reason=node-not-listening
#       on a real run and STAND_IN on a stand-in run, never PASS
#   t18-real-host-report.sh check REPORT SPEC
#       recomputes the OVERALL line of a stored report with one strict
#       parser: a duplicate field, a field that contradicts its verdict, the
#       header or another item, and a trailing, unterminated or unparsable
#       line are each refused with a named reason, and the report must end
#       with exactly the recomputed OVERALL line. SPEC is required: it is the
#       rendered custody-spec.json the run used. The report's one
#       `custody_spec_sha256 <hex>` line must be the SHA-256 of that file, and
#       so must the render line's custody_spec_file_sha256; the header's
#       spec_sha256 must be the canonical hash of that file as the product
#       computes it (see "Canonical spec hash" below). Every denied_reads and
#       denied_rpc entry of SPEC must have exactly one row, with no row for
#       anything else. r8: the header's agent_uid, primary_gid and
#       service_uid must be those of SPEC, and no header ID may be reserved
#   t18-real-host-report.sh peer SOCKET
#       connects, reads SO_PEERCRED, sends nothing
#   t18-real-host-report.sh items
#       prints the COVERED_BY_HOSTED pin table
#   t18-real-host-report.sh self-test
#       dry run on synthetic evidence: no root, no station. It builds the real
#       deploy-kit from this checkout (go on PATH) and uses that binary, never
#       DEPLOY_KIT
#
# DEPLOY_KIT names the deploy-kit binary built from the reviewed head
# (default: deploy-kit on PATH).
#
# Canonical spec hash (r6): report and check take the canonical hash of a
# custody spec ONLY from the product, `$DEPLOY_KIT g2-custody-hash -spec
# SPEC`, which reads the spec with the reader of g2-custody-probe and
# g2-custody-verify and prints CustodySpecSHA256 of it. Its output must be
# exactly one line `T18_CUSTODY_SPEC_SHA256 <64 lowercase hex>` with exit 0.
# When the product cannot be run, exits non-zero, refuses the spec or prints
# anything else, check refuses with the reason canonical-hash-unavailable and
# report refuses to compose (REFUSED canonical-hash-unavailable, exit 1).
# There is no fallback: this script computes no canonical hash itself.
# r8: that output, and the verifier outputs the report reads, are judged on
# their raw bytes (exact_line), never after a command substitution.
#
# The wallet is never asked for anything. The agent phase runs
# g2-custody-check.sh unchanged, but with AGENT_WALLET set to this script in
# its no-request mode: it sends nothing, prints T18_REAL_HOST_REQUEST_NOT_SENT
# and exits 3. The custody script therefore always prints T18_FAIL here (its
# own verdict needs the positive request), and this report does not use that
# verdict; it reads the per-step evidence instead. The only contact with the
# wallet socket is a connect without a frame: once by the probe and once by the
# peer identity check.
#
# Exit status: 0 when the report (or check) is OVERALL PASS, 1 when it is
# OVERALL FAIL or a phase failed, 3 in no-request mode, 64 on a usage error.
set -eu

pinned_commit=ca5edc6809ae71f5365c142a0010ba95c43b27be
run_deploy=43360330648
run_wallet=43360330369
# TestPX1T18CoreNodePolicy needs W1_REGTEST=1, which the Deploy kit job does
# not set; it first ran (and passed, no skip) in the px1-core-gate step added
# at this commit, in this workflow_dispatch run of Agent wallet checks.
node_policy_commit=dcad699da8cbc7e03436b00b85f667a5b2093b04
run_node_policy=43404324238
apply_noop_line="apply no-op: account pre-created by Infra"
positive_note="# positive-path: the real-wallet positive path (an authorized request that executes) is proven by the separate owner-authorized, bounded mainnet smoke gate, not by T18. On this host the wallet client sends nothing: positive-request is COVERED_BY_HOSTED, pinned to TestPX1CoreServiceG2FailClosed in run $run_wallet, and is FAIL if the host evidence shows that any frame was sent."
stub_marker=T18_REAL_HOST_REQUEST_NOT_SENT
status_dir=/run/swarma-wallet-status
rendered_files="client.json custody-spec.json namecoin-rpc.conf service.json sysusers.conf tmpfiles.conf"

usage() {
	echo "usage: t18-real-host-report.sh operator|agent|report|check|peer|items|self-test ... (see the header)" >&2
	exit 64
}

# covered_table prints the items that a host run cannot show without a
# destructive or privileged fixture. Each is pinned to the test that shows it
# at the pinned commit and to the hosted push run on main at that commit in
# which that test ran: id, test, run, job.
covered_table() {
	cat <<EOF
cov-enoent-not-denied TestPX1T18DeniedReadMustBeEACCES $pinned_commit $run_deploy checks
cov-searchable-dir TestPX1T18SearchableDirectory $pinned_commit $run_deploy checks
cov-rpc-not-refused TestPX1T18RPCClassification $pinned_commit $run_deploy checks
cov-probe-uid-gate TestPX1T18ProbeUIDGate $pinned_commit $run_deploy checks
cov-verify-refusals TestPX1T18VerifyRefusals $pinned_commit $run_deploy checks
cov-host-flow-tripwire TestPX1S5HostFlowTripwire $pinned_commit $run_deploy checks
cov-readback-refusals TestPX1T18CustodyScript $pinned_commit $run_deploy checks
cov-core-node-policy TestPX1T18CoreNodePolicy $node_policy_commit $run_node_policy px1-core-gate
cov-wallet-foreign-peer TestPX1T5ServiceRefusals $pinned_commit $run_wallet px1-core-gate
cov-positive-request-client TestCoreActionClient $pinned_commit $run_wallet w2-core
EOF
}

# positive_pin is the pin of the positive own-agent request (T18 item 2),
# which this qualification never sends. The pin table of check holds it too.
positive_row="positive-request TestPX1CoreServiceG2FailClosed $pinned_commit $run_wallet px1-core-gate"
positive_pin="pin=TestPX1CoreServiceG2FailClosed commit=$pinned_commit run=$run_wallet job=px1-core-gate"

covered_lines() {
	covered_table | while read -r id test commit run job; do
		echo "$id COVERED_BY_HOSTED pin=$test commit=$commit run=$run job=$job"
	done
}

self_path() {
	case $0 in
	/*) echo "$0" ;;
	*) echo "$(cd "$(dirname "$0")" && pwd)/$(basename "$0")" ;;
	esac
}

# One field of a compact JSON object of public values (a string or a number).
json_member() {
	sed -n "s/.*\"$2\":\"\{0,1\}\([^\",}]*\)\"\{0,1\}[,}].*/\1/p" "$1" | head -n 1
}

# The members of one JSON string array, one per line. A member outside
# [A-Za-z0-9._/:-] stops the run: the runner fails closed on paths it cannot
# carry through the shell unchanged.
json_array() {
	raw=$(sed -n "s/.*\"$2\":\[\([^]]*\)\].*/\1/p" "$1" | head -n 1)
	[ -n "$raw" ] || return 1
	printf '%s\n' "$raw" | tr ',' '\n' | while read -r m; do
		case $m in
		\"*\") m=${m#\"} && m=${m%\"} ;;
		*) return 1 ;;
		esac
		case $m in
		'' | *[!A-Za-z0-9._/:-]*) return 1 ;;
		esac
		echo "$m"
	done
}

sha_of() { sha256sum "$1" | cut -d ' ' -f 1; }

# exact_line TEXT FILE: 0 only when FILE is, byte for byte, TEXT and one
# newline. The raw bytes are compared (r8): a command substitution would drop
# NUL bytes and trailing newlines before any comparison could see them.
exact_line() {
	[ -f "$2" ] || return 1
	printf '%s\n' "$1" | cmp -s - "$2"
}

# product_spec_sha SPEC: the canonical spec hash, from the product only. It
# prints the hex and returns 0 only when `$deploy_kit g2-custody-hash -spec
# SPEC` exits 0 and its standard output is, byte for byte, the one line
# `T18_CUSTODY_SPEC_SHA256 <64 lowercase hex>` and one newline (89 bytes).
# r8: the output goes to a file and the raw bytes are compared with that line
# rebuilt from the 64 hex characters, so a NUL byte, a CR, a second or empty
# line, binary garbage or a missing newline is refused; nothing is judged
# after a command substitution has normalized it. The exit status is checked
# on its own, with or without errexit. Otherwise it prints nothing and
# returns 1.
product_spec_sha() {
	pt=$(mktemp) || return 1
	"$deploy_kit" g2-custody-hash -spec "$1" >"$pt" 2>/dev/null && st=0 || st=$?
	ok=0
	if [ "$st" = 0 ]; then
		sha=$(head -c 88 "$pt" 2>/dev/null | tr -d '\000')
		sha=${sha#"T18_CUSTODY_SPEC_SHA256 "}
		case $sha in
		'' | *[!0-9a-f]*) ;;
		*) if [ "${#sha}" -eq 64 ] && exact_line "T18_CUSTODY_SPEC_SHA256 $sha" "$pt"; then ok=1; fi ;;
		esac
	fi
	rm -f "$pt"
	[ "$ok" = 1 ] || return 1
	echo "$sha"
}

# spec_ids SPEC: "<agent_uid> <service_uid>" of SPEC, read only after the
# product accepted SPEC (product_spec_sha). The product's reader accepts
# exactly the canonical encoding of CustodySpecV1 with surrounding white
# space, which starts with these members in this order; a quote inside a
# string member is escaped there, so this prefix stands only at the start.
spec_ids() {
	tr -d '\n' <"$1" | sed -n 's/^[[:space:]]*{"v":1,"agent_uid":\([1-9][0-9]*\),"service_uid":\([1-9][0-9]*\),"denied_reads":\[.*$/\1 \2/p'
}

# exact_pair LIST A B: 0 only when the comma list LIST is the exact set {A, B}
# of two distinct GIDs, in either order (CheckG2AgentGroups: order does not
# matter). A third, missing or repeated entry is refused.
exact_pair() {
	[ "$2" != "$3" ] && { [ "$1" = "$2,$3" ] || [ "$1" = "$3,$2" ]; }
}

# r10: times are UTC with nanoseconds (GNU date), one fixed width, so the
# order of two times is the byte order of their text.
capture_head="T18-NODE-CAPTURE v1"
synced_re='^\{"txindex":\{"synced":true,"best_block_height":[0-9]+\}\}$'
utc_now() { date -u +%Y-%m-%dT%H:%M:%S.%NZ; }
is_ts() {
	printf '%s\n' "$1" | grep -Eqx '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
}

# kv_once KEY FILE: the value of the one KEY=... line of FILE, or nothing when
# FILE is missing or KEY stands there other than exactly once.
kv_once() {
	[ -f "$2" ] && [ "$(grep -c "^$1=" "$2" 2>/dev/null)" = 1 ] || return 0
	sed -n "s/^$1=//p" "$2"
}

# cap_val FILE KEY: kv_once in a node capture, whose first line is the
# capture header; nothing otherwise.
cap_val() {
	[ -f "$1" ] && [ "$(head -n 1 "$1")" = "$capture_head" ] || return 0
	kv_once "$2" "$1"
}

# ordered T...: 0 only when every time is well formed and each is at or
# after the one before it.
ordered() {
	for x in "$@"; do is_ts "$x" || return 1; done
	awk 'BEGIN { for (i = 1; i < ARGC - 1; i++) if (ARGV[i] "" > ARGV[i + 1] "") exit 1; exit 0 }' "$@"
}

# stat_rec PATH RECORD: the stat of PATH from the root-side record
# (denied-stat output): `exists=yes type=.. owner=..:.. mode=..` or
# `exists=no`, only when exactly one well-formed line names PATH; nothing
# otherwise (a missing, repeated or malformed line).
stat_rec() {
	[ -f "$2" ] || return 0
	awk -v p="$1" '$1 == p { n++; l = $0 } END { if (n == 1) print substr(l, length(p) + 2) }' "$2" |
		grep -Ex 'exists=yes type=[a-z][a-z_]* owner=(0|[1-9][0-9]*):(0|[1-9][0-9]*) mode=[0-7]+|exists=no' || true
}

# tok VALUE: VALUE as one evidence token (every byte outside printable ASCII,
# space included, a comma), or none. Display only.
tok() {
	v=$(printf '%s' "$1" | tr -c '\041-\176' ',')
	printf '%s\n' "${v:-none}"
}

# no-request mode: the AGENT_WALLET of the custody script. It sends nothing.
if [ "$#" -eq 4 ] && [ "$1" = --config ] && [ "$3" = --request ]; then
	[ "${T18_REAL_HOST_NO_REQUEST:-}" = 1 ] || usage
	echo "$stub_marker"
	exit 3
fi

[ "$#" -ge 1 ] || usage
mode=$1
shift
deploy_kit=${DEPLOY_KIT:-deploy-kit}

# ---------------------------------------------------------------- operator
operator_phase() {
	[ "$#" -eq 4 ] || usage
	op=$1 params=$2 rendered=$3 txindex=$4
	[ -f "$params" ] && [ -d "$rendered" ] || usage
	umask 022
	mkdir "$op" || usage
	op=$(cd "$op" && pwd)

	# Render: the parameters re-rendered at this head give the installed files.
	set +e
	"$deploy_kit" g2-render -params "$params" -out "$op/render" >"$op/render.out" 2>&1
	echo "render_exit=$?" >"$op/exits.txt"
	set -e
	for f in $rendered_files; do
		if [ -f "$op/render/$f" ] && [ -f "$rendered/$f" ] && cmp -s "$op/render/$f" "$rendered/$f"; then
			echo "same $f"
		else
			echo "differ $f"
		fi
	done >"$op/render-cmp.txt"

	# Account: preflight, VerifyG2AgentAccount and the exact group set, in the
	# RunG2HostFlow order, over this host's account database. The account was
	# pre-created by Infra, so the apply and the activation are no-ops: nothing
	# is applied and nothing is started. The mode is recorded as evidence.
	set +e
	echo "apply=noop activation=noop sysusers=true" >"$op/host-flow-mode.txt"
	"$deploy_kit" g2-host-flow -params "$params" -sysusers true -- true >"$op/host-flow.out" 2>&1
	echo "host_flow_exit=$?" >>"$op/exits.txt"
	# The exact set {own GID == UID, agent_socket_gid} once more, read from the
	# REAL account (not from a launch): its UID, its primary GID and its group
	# list from this host's account database, given to g2-agent-groups. This
	# runs in every operator phase; the account item needs both checks.
	user=$(json_member "$params" agent_user)
	id -- "$user" >"$op/account-id.txt" 2>&1
	a_uid=$(id -u -- "$user" 2>/dev/null)
	a_gid=$(id -g -- "$user" 2>/dev/null)
	a_groups=$(id -G -- "$user" 2>/dev/null)
	echo "uid=${a_uid:-none} gid=${a_gid:-none} groups=$(echo "${a_groups:-none}" | tr ' ' ',')" >"$op/account-real.txt"
	# shellcheck disable=SC2086 # one argument per GID, as id -G prints them
	"$deploy_kit" g2-agent-groups -params "$params" -gid "${a_gid:-none}" -- $a_groups >"$op/account-groups.txt" 2>&1
	echo "account_groups_exit=$?" >>"$op/exits.txt"
	set -e

	# Node precondition: the operator's saved `getindexinfo txindex` answer.
	# r10: a node capture (node-capture output) is kept whole as node-pre.txt,
	# the pre-probe capture of the denied-rpc liveness rule, and its answer is
	# the node-txindex evidence when the call exited 0. A bare saved answer
	# is still read for node-txindex, but carries no time and no target.
	if [ -f "$txindex" ] && [ "$(head -n 1 "$txindex")" = "$capture_head" ]; then
		cp "$txindex" "$op/node-pre.txt"
		if [ "$(kv_once exit "$txindex")" = 0 ]; then
			kv_once answer "$txindex" | tr -d ' \t\r\n' >"$op/txindex.json"
		else
			: >"$op/txindex.json"
		fi
	elif [ -f "$txindex" ]; then
		tr -d ' \t\r\n' <"$txindex" >"$op/txindex.json"
	else
		: >"$op/txindex.json"
	fi
	echo "T18_REAL_HOST_OPERATOR_DONE $op"
}

# ---------------------------------------------------------------- node-capture
# r10: one `getindexinfo txindex` node call against the spec's one denied_rpc
# target, between two UTC times. The method and the target are this script's;
# the operator adds only the options that locate the node's datadir, config
# and cookie. Any other option is refused before the CLI runs (and is not
# printed: it could be a credential).
node_capture() {
	[ "$#" -ge 4 ] && [ "$3" = -- ] || usage
	out=$1 spec=$2
	shift 3
	[ -f "$spec" ] && [ ! -e "$out" ] && [ ! -L "$out" ] || usage
	rpc=$(json_array "$spec" denied_rpc) || usage
	[ -n "$rpc" ] && [ "$(printf '%s\n' "$rpc" | wc -l)" = 1 ] || usage
	host=${rpc%:*} port=${rpc##*:}
	case $port in '' | *[!0-9]*) usage ;; esac
	[ -n "$host" ] && [ "$host" != "$rpc" ] || usage
	cli=$1
	shift
	for a in "$@"; do
		case $a in
		-datadir=?* | -conf=?* | -rpccookiefile=?* | -chain=?* | -rpcclienttimeout=?*) ;;
		*)
			echo "REFUSED node-capture option not allowed (allowed: -datadir= -conf= -rpccookiefile= -chain= -rpcclienttimeout=)" >&2
			exit 64
			;;
		esac
	done
	umask 022
	(set -C && : >"$out") || usage
	ans=$(mktemp) || exit 1
	start=$(utc_now)
	"$cli" "$@" -rpcconnect="$host" -rpcport="$port" getindexinfo txindex >"$ans" 2>/dev/null && st=0 || st=$?
	end=$(utc_now)
	{
		echo "$capture_head"
		echo "rpc=$rpc"
		echo "start=$start"
		echo "end=$end"
		echo "exit=$st"
		echo "answer=$(tr -d ' \t\r\n' <"$ans")"
	} >"$out"
	rm -f "$ans"
	echo "T18_REAL_HOST_NODE_CAPTURE_DONE exit=$st $out"
	[ "$st" = 0 ] || exit 1
}

# ---------------------------------------------------------------- denied-stat
# r10: the root-side existence record of every denied_reads path, read-only:
# stat -L follows a link to the object an open of the path reaches. A path
# stat cannot reach (missing, a dangling link) is `exists=no`.
denied_stat() {
	[ "$#" -eq 1 ] && [ -f "$1" ] || usage
	reads=$(json_array "$1" denied_reads) || reads=
	if [ -z "$reads" ]; then
		echo "REFUSED denied-stat: no readable denied_reads in $1" >&2
		exit 1
	fi
	for p in $reads; do
		if s=$(stat -L -c '%F|%u|%g|%a' -- "$p" 2>/dev/null); then
			ty=$(printf '%s' "${s%%|*}" | tr ' ' '_')
			r=${s#*|}
			u=${r%%|*}
			r=${r#*|}
			echo "$p exists=yes type=$ty owner=$u:${r%%|*} mode=${r#*|}"
		else
			echo "$p exists=no"
		fi
	done
}

# ---------------------------------------------------------------- agent
agent_phase() {
	[ "$#" -eq 5 ] || usage
	ag=$1 spec=$2 client=$3 grantee=$4 params=$5
	[ -f "$spec" ] && [ -f "$client" ] && [ -f "$params" ] || usage
	umask 077
	mkdir "$ag" || usage
	ag=$(cd "$ag" && pwd)
	here=$(dirname "$(self_path)")

	# Launch form: what this process holds, as the kernel reports it.
	grep -E '^(Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapAmb):' "/proc/$$/status" >"$ag/launch.txt" || true
	sha256sum "$spec" "$client" "$params" | cut -d ' ' -f 1 >"$ag/inputs.sha256"

	# T18 through the unchanged custody script; the request is not sent.
	# r10: the probe window. The custody script runs g2-custody-probe, whose
	# report holds no time, so the window is taken right before and right
	# after the whole script: it contains the probe.
	set +e
	echo "probe_start=$(utc_now)" >"$ag/probe-window.txt"
	T18_REAL_HOST_NO_REQUEST=1 DEPLOY_KIT=$deploy_kit AGENT_WALLET=$(self_path) \
		sh "$here/g2-custody-check.sh" "$spec" "$client" "$grantee" "$params" "$ag/custody" >"$ag/custody-check.out" 2>&1
	echo "custody_check_exit=$?" >"$ag/agent-exits.txt"
	echo "probe_end=$(utc_now)" >>"$ag/probe-window.txt"

	# Launch layout (r7): the launch layout is a property of the run, which
	# g2-custody-verify enforces with its -launch check. verify runs here on
	# the custody script's report twice, read-only, with -launch=true and with
	# -launch=false; the first is the launch-layout item's evidence, the
	# second only names the cause when the first refuses (the same report
	# accepted without the launch check: the layout was refused).
	"$deploy_kit" g2-custody-verify -launch=true -spec "$spec" -report "$ag/custody/custody-report.json" >"$ag/launch-layout-on.txt" 2>&1
	echo "launch_true_exit=$?" >>"$ag/agent-exits.txt"
	"$deploy_kit" g2-custody-verify -launch=false -spec "$spec" -report "$ag/custody/custody-report.json" >"$ag/launch-layout-off.txt" 2>&1
	echo "launch_false_exit=$?" >>"$ag/agent-exits.txt"

	# Peer identity of the wallet socket: connect, SO_PEERCRED, no frame. Its
	# precondition is perl with the core Socket module: the first version line
	# of `perl -v` is kept as evidence.
	perl -v 2>/dev/null | grep -m 1 'version' >"$ag/perl-version.txt"
	socket=$(json_member "$spec" allowed_socket)
	sh "$(self_path)" peer "$socket" >"$ag/peer.txt" 2>&1
	echo "peer_exit=$?" >>"$ag/agent-exits.txt"
	stat -c '%F|%u|%g|%a' -- "$socket" >"$ag/socket-stat.txt" 2>&1
	set -e
	echo "T18_REAL_HOST_AGENT_DONE $ag"
}

peer_phase() {
	[ "$#" -eq 1 ] || usage
	perl -MSocket -e '
		socket(my $s, PF_UNIX, SOCK_STREAM, 0) or do { print "PEER connect=failed\n"; exit 2 };
		connect($s, pack_sockaddr_un($ARGV[0])) or do { print "PEER connect=failed\n"; exit 2 };
		my $c = getsockopt($s, SOL_SOCKET, SO_PEERCRED);
		defined $c or do { print "PEER connect=ok cred=failed\n"; close $s; exit 2 };
		my ($pid, $uid, $gid) = unpack("iII", $c);
		close $s;
		print "PEER connect=ok uid=$uid gid=$gid\n";' "$1"
}

# ---------------------------------------------------------------- report
# probe_observed KIND TARGET REPORT: the one observation of that probe.
probe_observed() {
	[ -s "$3" ] || return 1
	tr '{' '\n' <"$3" | sed -n 's/^"kind":"\([a-z]*\)","target":"\([^"]*\)","expect":"[a-z]*","observed":"\([A-Z0-9_]*\)","pass":[a-z]*}.*$/\1 \2 \3/p' |
		awk -v k="$1" -v t="$2" '$1 == k && $2 == t { o = $3; n++ } END { if (n != 1) exit 1; print o }'
}

# file_line FILE: the first line of FILE, or nothing.
file_line() { [ -f "$1" ] && head -n 1 "$1" || true; }

# shown FILE: the bytes of FILE as one FAIL evidence token: a space is a
# comma, a newline a semicolon (the last one dropped), and every other byte
# outside printable ASCII (NUL, CR, binary) a comma. Nothing when FILE is
# missing. Display only: no verdict is taken from it.
shown() {
	[ -f "$1" ] || return 0
	v=$(tr ' \n' ',;' <"$1" | tr -c '\041-\176' ',')
	printf '%s\n' "${v%;}"
}

# agent_exit KEY FILE: the value of the one KEY=<digits> line of FILE, or
# nothing when KEY stands there other than exactly once.
agent_exit() {
	[ "$(grep -c "^$1=" "$2" 2>/dev/null)" = 1 ] || return 0
	sed -n "s/^$1=\([0-9][0-9]*\)\$/\1/p" "$2"
}

report_items() {
	op=$1 ag=$2 rendered=$3 params=$4 wallet=$5
	spec=$rendered/custody-spec.json
	sys=$rendered/sysusers.conf
	cr=$ag/custody/custody-report.json
	ex=$(file_line "$ag/custody/exits.txt")

	user=$(json_member "$params" agent_user)
	uid=$(awk -v u="$user" '$1 == "u" && $2 == u { split($3, id, ":"); print id[1] }' "$sys")
	gid=$(awk -v u="$user" '$1 == "u" && $2 == u { n = split($3, id, ":"); print id[n] }' "$sys")
	sgid=$(awk '$1 == "g" && $2 == "swarma-wallet-peer" { print $3 }' "$sys")
	suid=$(awk '$1 == "u" && $2 == "swarma-wallet" { print $3 }' "$sys")
	spec_sha=$spec_canon
	echo "T18-REAL-HOST v1 wallet=$wallet commit=$pinned_commit spec_sha256=$spec_sha agent_uid=$uid primary_gid=$gid socket_gid=$sgid service_uid=$suid"
	# The exact spec file this report was composed from. check needs that file
	# and refuses unless its SHA-256 is this value.
	echo "custody_spec_sha256 $(sha_of "$spec")"

	# Precondition: txindex=1 and the index synced.
	tx=$(cat "$op/txindex.json" 2>/dev/null || true)
	node_live=0
	if printf '%s\n' "$tx" | grep -Eq "$synced_re"; then
		node_live=1
		echo "node-txindex PASS getindexinfo=$tx"
	else
		echo "node-txindex FAIL getindexinfo=${tx:-missing}"
	fi

	if grep -qx render_exit=0 "$op/exits.txt" 2>/dev/null && [ "$(grep -c '^same ' "$op/render-cmp.txt" 2>/dev/null)" = 6 ]; then
		echo "render PASS files=6 custody_spec_file_sha256=$(sha_of "$spec")"
	else
		echo "render FAIL differ=$(grep '^differ ' "$op/render-cmp.txt" 2>/dev/null | cut -d ' ' -f 2 | tr '\n' ',')none $(grep '^render_exit' "$op/exits.txt" 2>/dev/null || echo render_exit=none)"
	fi

	# Account. This runner only adopts an account Infra pre-created: the apply
	# is a no-op, and the report says so in one literal line. The account item
	# then needs both the frozen host-flow checks (preflight,
	# VerifyG2AgentAccount, the exact group set) and the exact set read from
	# the REAL account: uid == agent_uid, primary GID == UID, and
	# g2-agent-groups accepting its group list as {primary, agent_socket_gid}.
	noop=0
	if [ "$(file_line "$op/host-flow-mode.txt")" = "apply=noop activation=noop sysusers=true" ]; then
		noop=1
		echo "$apply_noop_line"
	fi
	real=$(file_line "$op/account-real.txt" | tr ' ' '_')
	want_real="uid=${uid}_gid=${gid}_groups="
	ag_ok="G2_AGENT_GROUPS_OK observed_gid=$gid declared_primary_gid=$gid socket_gid=$sgid"
	# r8: the real account's group list, as `id -G` printed it, is the exact
	# set {primary, socket} in either order (CheckG2AgentGroups).
	case $real in "$want_real"*) real_groups=${real#"$want_real"} ;; *) real_groups= ;; esac
	if [ "$noop" = 1 ] && grep -qx host_flow_exit=0 "$op/exits.txt" 2>/dev/null && [ "$(cat "$op/host-flow.out" 2>/dev/null)" = G2_HOST_FLOW_ACTIVATED ] &&
		grep -qx account_groups_exit=0 "$op/exits.txt" 2>/dev/null && [ "$(cat "$op/account-groups.txt" 2>/dev/null)" = "$ag_ok" ] &&
		[ -n "$uid" ] && [ "$gid" = "$uid" ] && exact_pair "$real_groups" "$gid" "$sgid"; then
		echo "account PASS steps=preflight,VerifyG2AgentAccount,group-set apply=noop activation=noop user=$user real_account=$real group_set=G2_AGENT_GROUPS_OK"
	else
		echo "account FAIL host_flow=$(file_line "$op/host-flow.out" | tr ' ' '_') apply_noop=$noop real_account=${real:-none} group_set=$(file_line "$op/account-groups.txt" | tr ' ' '_')"
	fi

	want=$(printf '%s\n' "$(sha_of "$spec")" "$(sha_of "$rendered/client.json")" "$(sha_of "$params")")
	if [ -f "$ag/inputs.sha256" ] && [ "$(cat "$ag/inputs.sha256")" = "$want" ]; then
		echo "agent-inputs PASS spec,client,params=rendered"
	else
		echo "agent-inputs FAIL agent-inputs-differ-from-rendered"
	fi

	# Launch form: setpriv --reuid=UID --regid=GID --init-groups gives four
	# equal UIDs, four GIDs at the declared primary, exactly the two groups and
	# no capability.
	l=$ag/launch.txt
	u4=$(awk '$1 == "Uid:" { print $2","$3","$4","$5 }' "$l" 2>/dev/null || true)
	g4=$(awk '$1 == "Gid:" { print $2","$3","$4","$5 }' "$l" 2>/dev/null || true)
	gs=$(awk '$1 == "Groups:" { for (i = 2; i <= NF; i++) print $i }' "$l" 2>/dev/null | sort -un | tr '\n' ',' | sed 's/,$//')
	want_gs=$(printf '%s\n%s\n' "$gid" "$sgid" | sort -un | tr '\n' ',' | sed 's/,$//')
	# Each of these lines stands exactly once: a missing or repeated line is
	# unknown evidence, never a zero. caps lists the three capability sets in
	# /proc order.
	once=1
	for k in Uid Gid Groups CapPrm CapEff CapAmb; do
		[ "$(grep -c "^$k:" "$l" 2>/dev/null)" = 1 ] || once=0
	done
	caps=$(awk '$1 ~ /^Cap(Prm|Eff|Amb):$/ { printf "%s%s=%s", s, substr($1, 1, 6), $2; s = "," }' "$l" 2>/dev/null || true)
	if [ "$once" = 1 ] && [ "$u4" = "$uid,$uid,$uid,$uid" ] && [ "$g4" = "$gid,$gid,$gid,$gid" ] && [ "$gs" = "$want_gs" ] && [ "$(echo "$want_gs" | tr ',' '\n' | wc -l)" = 2 ] &&
		[ "$caps" = CapPrm=0000000000000000,CapEff=0000000000000000,CapAmb=0000000000000000 ]; then
		echo "launch-form PASS uid=$u4 gid=$g4 groups=$gs caps=0"
	else
		echo "launch-form FAIL uid=$(printf '%s' "${u4:-none}" | tr '\n' ';') gid=$(printf '%s' "${g4:-none}" | tr '\n' ';') groups=${gs:-none} caps=${caps:-none} each_line_once=$once want_uid=$uid want_gid=$gid want_groups=$want_gs"
	fi

	ck=$(file_line "$ag/custody/credentials-check.txt")
	if [ "$ck" = "G2_AGENT_GROUPS_OK observed_gid=$gid declared_primary_gid=$gid socket_gid=$sgid" ] && [ "$ex" != credentials=refused ]; then
		echo "credentials PASS observed_gid=$gid groups=$want_gs check=G2_AGENT_GROUPS_OK"
	else
		echo "credentials FAIL $(file_line "$ag/custody/credentials.txt" | tr ' ' ',') check=$(echo "${ck:-none}" | tr ' ' ',')"
	fi

	reads=$(json_array "$spec" denied_reads) || reads=
	rpcs=$(json_array "$spec" denied_rpc) || rpcs=
	if [ -z "$reads" ] || [ -z "$rpcs" ]; then
		echo "custody-spec FAIL unreadable-or-unsupported-characters"
	fi
	# On a stand-in run every denied_reads path is a root-owned placeholder
	# (or not the production object), so a denial there is STAND_IN, never
	# PASS. A missing placeholder is still FAIL.
	# r10: on a live run a denial is PASS only when the root-side record
	# (OPDIR/denied-paths-stat.txt, denied-stat output) holds exactly one
	# `exists=yes` line for the path: a closed parent reads EACCES for a
	# missing object too, so the denial alone does not show the object.
	# A path the record lists as absent is FAIL reason=path-absent; a path it
	# does not list (or lists twice, or malformed) is FAIL
	# reason=path-not-in-stat-record. The stand-in run does not read the
	# record: its denials stay STAND_IN, never PASS.
	denied=PASS
	[ "$wallet" = stand-in ] && denied=STAND_IN
	statrec=$op/denied-paths-stat.txt
	status_seen=0
	for p in $reads; do
		o=$(probe_observed read "$p" "$cr") || o=
		why=
		case $o in
		EACCES | EPERM)
			dv=$denied ev=
			if [ "$wallet" = real ]; then
				sr=$(stat_rec "$p" "$statrec")
				case $sr in
				"exists=yes "*) ev=" $sr" ;;
				exists=no) dv=FAIL why=" reason=path-absent" ;;
				*) dv=FAIL why=" reason=path-not-in-stat-record" ;;
				esac
			fi
			echo "denied-read:$p $dv observed=$o$ev$why"
			;;
		*) echo "denied-read:$p FAIL observed=${o:-none}" ;;
		esac
		if [ "$p" = "$status_dir" ]; then
			status_seen=1
			case $o in
			EACCES | EPERM) echo "status-dir $dv path=$p observed=$o$why" ;;
			*) echo "status-dir FAIL path=$p observed=${o:-none}" ;;
			esac
		fi
	done
	[ "$status_seen" = 1 ] || echo "status-dir FAIL path=$status_dir not-in-denied_reads"
	# r9: denied RPC needs a live node. The product probe counts a refused
	# connection (REFUSED, ECONNREFUSED: nothing listens at the target) as a
	# denial; this report does not, because with no node, or a stopped one,
	# that observation proves nothing. A row is PASS only when both hold:
	#  - the credential-less call got an explicit authorization refusal,
	#    HTTP_401 or HTTP_403: a listener at the target answered it at probe
	#    time (step 5) and refused it;
	#  - node liveness in the same run: node-txindex is PASS, i.e. the node's
	#    saved getindexinfo answer (a node call, authenticated, made before the
	#    operator phase, so before the probe) shows a synced index.
	# A refusal without that liveness is FAIL reason=node-liveness-unproven.
	# REFUSED is FAIL reason=node-not-listening on a real run, and STAND_IN on
	# a stand-in run (whose station may run no node), never PASS. A timeout or
	# any other transport error aborts the product probe (no report), so the
	# row is FAIL observed=none; HTTP_OK is FAIL (the call was not refused).
	#
	# r10: liveness at probe time, on a live run (`real`). The pre-probe
	# capture (OPDIR/node-pre.txt, the node-txindex answer) and the post-probe
	# capture (OPDIR/node-post.txt, taken right after the agent phase) are
	# node calls made by node-capture against this row's target, each between
	# two UTC times; the agent phase recorded the probe window. The row is
	# PASS only when, beside the r9 rule:
	#  - all six times are present and well formed (else
	#    reason=capture-time-missing);
	#  - both captures name this row's target, host and port (else
	#    reason=capture-port-mismatch);
	#  - pre start <= pre end <= probe start <= probe end <= post start <=
	#    post end (else reason=window-not-bracketed): the pre-probe answer was
	#    given before the probe began and the post-probe answer after it
	#    ended, so the node answered at that address on both sides of the
	#    probe's whole window;
	#  - the post-probe call exited 0 with a synced answer (else
	#    reason=capture-not-synced); the pre-probe answer is node-txindex.
	# Stand-in runs read no capture: their rows are as in r9.
	pre=$op/node-pre.txt post=$op/node-post.txt win=$ag/probe-window.txt
	l_pr=$(cap_val "$pre" rpc) l_ps=$(cap_val "$pre" start) l_pe=$(cap_val "$pre" end)
	l_ws=$(kv_once probe_start "$win") l_we=$(kv_once probe_end "$win")
	l_qr=$(cap_val "$post" rpc) l_qs=$(cap_val "$post" start) l_qe=$(cap_val "$post" end)
	l_qx=$(cap_val "$post" exit) l_qa=$(cap_val "$post" answer)
	for rpc in $rpcs; do
		o=$(probe_observed rpc "$rpc" "$cr") || o=
		case $o in
		HTTP_401 | HTTP_403)
			if [ "$node_live" != 1 ]; then
				echo "denied-rpc:$rpc FAIL observed=$o reason=node-liveness-unproven"
			elif [ "$wallet" != real ]; then
				echo "denied-rpc:$rpc PASS observed=$o"
			else
				lv="pre_rpc=$(tok "$l_pr") pre_start=$(tok "$l_ps") pre_end=$(tok "$l_pe") probe_start=$(tok "$l_ws") probe_end=$(tok "$l_we") post_rpc=$(tok "$l_qr") post_start=$(tok "$l_qs") post_end=$(tok "$l_qe") post_getindexinfo=$(tok "$l_qa")"
				why=
				for x in "$l_ps" "$l_pe" "$l_ws" "$l_we" "$l_qs" "$l_qe"; do
					is_ts "$x" || why=capture-time-missing
				done
				if [ -z "$why" ] && { [ "$l_pr" != "$rpc" ] || [ "$l_qr" != "$rpc" ]; }; then
					why=capture-port-mismatch
				fi
				if [ -z "$why" ] && ! ordered "$l_ps" "$l_pe" "$l_ws" "$l_we" "$l_qs" "$l_qe"; then
					why=window-not-bracketed
				fi
				if [ -z "$why" ] && { [ "$l_qx" != 0 ] || ! printf '%s\n' "$l_qa" | grep -Eq "$synced_re"; }; then
					why=capture-not-synced
				fi
				if [ -z "$why" ]; then
					echo "denied-rpc:$rpc PASS observed=$o $lv"
				else
					echo "denied-rpc:$rpc FAIL observed=$o reason=$why $lv"
				fi
			fi
			;;
		REFUSED)
			if [ "$wallet" = stand-in ]; then
				echo "denied-rpc:$rpc STAND_IN observed=$o"
			else
				echo "denied-rpc:$rpc FAIL observed=$o reason=node-not-listening"
			fi
			;;
		*) echo "denied-rpc:$rpc FAIL observed=${o:-none}" ;;
		esac
	done

	# Precondition of the peer identity: perl, recorded by its first version
	# line as the agent ran it.
	pv=$(file_line "$ag/perl-version.txt")
	case $pv in
	"This is perl 5, version "[0-9]*", subversion "[0-9]*) echo "peer-precondition PASS perl_v=$(echo "$pv" | tr ' ' '_')" ;;
	*) echo "peer-precondition FAIL perl_v=$(echo "${pv:-none}" | tr ' ' '_')" ;;
	esac

	sock=$(json_member "$spec" allowed_socket)
	o=$(probe_observed socket "$sock" "$cr") || o=
	pl=$(file_line "$ag/peer.txt")
	puid=$(echo "$pl" | sed -n 's/^PEER connect=ok uid=\([0-9]*\) gid=[0-9]*$/\1/p')
	st=$(file_line "$ag/socket-stat.txt" | tr ' ' '_')
	ev="wallet=$wallet probe=${o:-none} peer_uid=${puid:-none} service_uid=$suid socket=$st socket_gid=$sgid"
	if [ "$wallet" = stand-in ]; then
		if [ "$o" = CONNECTED ] && [ -n "$puid" ]; then
			echo "allowed-socket STAND_IN $ev"
		else
			echo "allowed-socket FAIL $ev"
		fi
	elif [ "$o" = CONNECTED ] && [ -n "$puid" ] && [ "$puid" = "$suid" ] && [ "$st" = "socket|$suid|$sgid|660" ]; then
		echo "allowed-socket PASS $ev"
	else
		echo "allowed-socket FAIL $ev"
	fi

	vf=$(shown "$ag/custody/custody-verify.txt")
	case $ex in
	"uid=$uid probe_exit=0 positive_exit="*" verify_exit=0") ok=1 ;;
	*) ok=0 ;;
	esac
	# r8: the verifier's output file is compared byte for byte.
	if [ "$ok" = 1 ] && exact_line "T18_CUSTODY_VERIFIED $spec_sha" "$ag/custody/custody-verify.txt"; then
		echo "custody-verify PASS $(echo "$ex" | tr ' ' ',') verified=$spec_sha"
	else
		echo "custody-verify FAIL exits=$(echo "${ex:-none}" | tr ' ' ',') verify=${vf:-none}"
	fi

	# Launch layout (r7): verify's -launch=true result on this run, as its own
	# item. PASS only when that run exited 0 (one exit line) and its output
	# file is, byte for byte (r8), `T18_CUSTODY_VERIFIED <header spec_sha256>`
	# and one newline; FAIL otherwise. layout=refused when the same report
	# passed verify with -launch=false, its output exact too (the launch
	# layout check alone refused), layout=unknown otherwise. The FAIL evidence
	# shows the output with every byte outside printable ASCII as a comma.
	lt=$(agent_exit launch_true_exit "$ag/agent-exits.txt")
	lf=$(agent_exit launch_false_exit "$ag/agent-exits.txt")
	if [ "$lt" = 0 ] && exact_line "T18_CUSTODY_VERIFIED $spec_sha" "$ag/launch-layout-on.txt"; then
		echo "launch-layout PASS verify=g2-custody-verify launch=true verify_exit=0 verified=$spec_sha"
	else
		cause=unknown
		if [ "$lf" = 0 ] && exact_line "T18_CUSTODY_VERIFIED $spec_sha" "$ag/launch-layout-off.txt"; then cause=refused; fi
		lon=$(shown "$ag/launch-layout-on.txt")
		echo "launch-layout FAIL launch=true verify_exit=${lt:-none} verify=${lon:-none} launch_false_exit=${lf:-none} layout=$cause"
	fi

	# The positive own-agent request is never sent here; the hosted test is
	# its evidence, and the real-wallet positive path is the owner-authorized
	# mainnet smoke gate's. A host run whose evidence shows that the client
	# sent a frame (a receipt other than the marker, another exit, or any
	# client error output) fails this item.
	echo "$positive_note"
	# The receipt must be the marker line and nothing else, byte for byte: a
	# second line, unterminated trailing bytes or a missing newline is a
	# receipt this report cannot read as unsent. Client error output fails
	# the item in both branches.
	rc=0
	printf '%s\n' "$stub_marker" | cmp -s - "$ag/custody/positive-receipt.json" 2>/dev/null && rc=1
	if [ "$ex" = credentials=refused ] && [ ! -e "$ag/custody/positive-request.json" ] && [ ! -e "$ag/custody/positive-receipt.json" ] && [ ! -s "$ag/custody/positive.err" ]; then
		echo "positive-request COVERED_BY_HOSTED $positive_pin host=not-run positive_path=mainnet-smoke-gate"
	else
		case $ex in
		*" positive_exit=3 "*) pe=1 ;;
		*) pe=0 ;;
		esac
		if [ "$pe" = 1 ] && [ "$rc" = 1 ] && [ ! -s "$ag/custody/positive.err" ]; then
			echo "positive-request COVERED_BY_HOSTED $positive_pin host=not-sent positive_path=mainnet-smoke-gate"
		else
			echo "positive-request FAIL host=request-sent-or-unknown"
		fi
	fi

	covered_lines
}

# ---------------------------------------------------------------- check
# check_report FILE stored|composed SPEC: parse every line once, strictly,
# and print the recomputed OVERALL line. Exit 0 only when it is PASS and, for
# a stored report, the report ends with exactly that OVERALL line.
#
# The parser refuses instead of choosing: a line is the header, the one
# custody_spec_sha256 line, the literal no-op apply line, the literal
# positive-path statement, an item line or (in a stored report) the one last
# OVERALL line, single-space separated and newline-terminated; anything else
# is invalid. The report is bound to SPEC, the custody-spec.json file the run
# used: the custody_spec_sha256 line stands exactly once and equals the
# SHA-256 of SPEC, the render line's custody_spec_file_sha256 equals it too,
# the header's spec_sha256 equals the product's canonical hash of SPEC (r5:
# no spec hash in the report is a free field; r6: that hash comes only from
# `$DEPLOY_KIT g2-custody-hash`, and without it check refuses with
# canonical-hash-unavailable), and each denied_reads and denied_rpc
# entry of SPEC has
# exactly one row (any verdict), while a denied row for anything else is
# refused. An item line is
# `<id> <verdict> <field>...`, where a field is key=value (or a bare word)
# and each key stands once per line: a second occurrence is refused whether
# or not it agrees. A PASS, STAND_IN or COVERED_BY_HOSTED line carries exactly
# the fields of its item, in order, and every value is compared with the one
# value that verdict needs (from the header or the pin table), so a field
# that contradicts its verdict, the header or another item is refused.
check_report() {
	unterminated=0
	if [ -s "$1" ] && [ "$(tail -c 1 "$1" | wc -l)" -eq 0 ]; then
		unterminated=1
	fi
	spec_reads=$(json_array "$3" denied_reads) || spec_reads=
	spec_rpcs=$(json_array "$3" denied_rpc) || spec_rpcs=
	spec_file_sha=$(sha_of "$3")
	spec_canon_sha=$(product_spec_sha "$3") || spec_canon_sha=
	# r8: the identities of the spec the product accepted; the header's must
	# equal them. Read only when the product accepted the spec.
	spec_ids=
	[ -z "$spec_canon_sha" ] || spec_ids=$(spec_ids "$3")
	awk -v pins="$(covered_table; echo "$positive_row")" -v apply_line="$apply_noop_line" -v note="$positive_note" \
		-v pinned_commit="$pinned_commit" -v status_dir="$status_dir" -v unterminated="$unterminated" -v stored="$2" \
		-v spec_reads="$spec_reads" -v spec_rpcs="$spec_rpcs" -v spec_file_sha="$spec_file_sha" -v spec_canon_sha="$spec_canon_sha" -v spec_ids="$spec_ids" '
	function bad(why) { invalid++; reasons = reasons " " why }
	function num(s) { return s ~ /^(0|[1-9][0-9]*)$/ }
	function hex64(s) { return length(s) == 64 && s !~ /[^0-9a-f]/ }
	# r8: a group list is the exact set {a, b} of two distinct GIDs, in either
	# order (CheckG2AgentGroups); a third, missing or repeated GID is refused.
	function gset(l, a, b) { return a != b && (l == a "," b || l == b "," a) }
	function reserved(s) { return s == "0" || s == "65534" || s == "65535" || s == "4294967295" }
	# r10: a UTC time with nanoseconds, the one fixed-width form node-capture
	# and the agent phase write; two such times order as their text does.
	function ts(s) { return s ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z$/ }
	BEGIN {
		# r6: the canonical hash comes from the product or not at all.
		if (spec_canon_sha == "") bad("canonical-hash-unavailable")
		# r8: agent_uid and service_uid of the product-accepted spec.
		if (spec_canon_sha != "" && (split(spec_ids, sid, " ") != 2 || sid[1] !~ /^[1-9][0-9]*$/ || sid[2] !~ /^[1-9][0-9]*$/)) bad("spec-identity-unavailable")
		spec_agent = sid[1]; spec_service = sid[2]
		npin = split(pins, rows, "\n")
		for (i = 1; i <= npin; i++) {
			if (split(rows[i], f, " ") != 5) continue
			pin_test[f[1]] = f[2]; pin_commit[f[1]] = f[3]; pin_run[f[1]] = f[4]; pin_job[f[1]] = f[5]
			req_ids = req_ids " " f[1]
		}
		nreq = split("node-txindex render account agent-inputs launch-form credentials status-dir peer-precondition allowed-socket custody-verify launch-layout" req_ids, req, " ")
		nhk = split("wallet commit spec_sha256 agent_uid primary_gid socket_gid service_uid", hkey, " ")
		# The fields of each non-FAIL item line, in order.
		schema["node-txindex"] = "getindexinfo"
		schema["render"] = "files custody_spec_file_sha256"
		schema["account"] = "steps apply activation user real_account group_set"
		schema["agent-inputs"] = "spec,client,params"
		schema["launch-form"] = "uid gid groups caps"
		schema["credentials"] = "observed_gid groups check"
		schema["denied-read"] = "observed"
		schema["status-dir"] = "path observed"
		schema["denied-rpc"] = "observed"
		# r10: on a live run a denied-read PASS carries its root-side stat and
		# a denied-rpc PASS its two node captures and the probe window.
		schema["denied-read-live"] = "observed exists type owner mode"
		schema["denied-rpc-live"] = "observed pre_rpc pre_start pre_end probe_start probe_end post_rpc post_start post_end post_getindexinfo"
		schema["peer-precondition"] = "perl_v"
		schema["allowed-socket"] = "wallet probe peer_uid service_uid socket socket_gid"
		schema["custody-verify"] = "uid verified"
		schema["launch-layout"] = "verify launch verify_exit verified"
		schema["positive-request"] = "pin commit run job host positive_path"
		schema["covered"] = "pin commit run job"
		schema["custody-spec"] = ""
		# The rows the given spec requires, in spec order.
		nsread = split(spec_reads, sread, "\n")
		for (i = 1; i <= nsread; i++) {
			if (sread[i] in spec_read) bad("custody-spec-duplicate-entry:denied-read:" sread[i])
			spec_read[sread[i]] = 1
		}
		nsrpc = split(spec_rpcs, srpc, "\n")
		for (i = 1; i <= nsrpc; i++) {
			if (srpc[i] in spec_rpc) bad("custody-spec-duplicate-entry:denied-rpc:" srpc[i])
			spec_rpc[srpc[i]] = 1
		}
		if (nsread < 1 || nsrpc < 1) bad("custody-spec-unreadable")
	}
	NR == 1 {
		hok = ($1 == "T18-REAL-HOST" && $2 == "v1" && NF == nhk + 2)
		for (i = 3; i <= NF; i++) {
			p = index($i, "="); k = p ? substr($i, 1, p - 1) : $i
			if (k in hdr) { bad("duplicate-field:header:" k); hok = 0 }
			hdr[k] = p ? substr($i, p + 1) : ""
			if (k != hkey[i - 2]) hok = 0
		}
		if (hdr["wallet"] != "real" && hdr["wallet"] != "stand-in") hok = 0
		if (hdr["commit"] != pinned_commit || !hex64(hdr["spec_sha256"])) hok = 0
		if (!num(hdr["agent_uid"]) || !num(hdr["primary_gid"]) || !num(hdr["socket_gid"]) || !num(hdr["service_uid"])) hok = 0
		if (hdr["socket_gid"] == hdr["primary_gid"]) hok = 0
		if (!hok || $0 !~ /^[^ \t\r]+( [^ \t\r]+)*$/) { bad("header"); next }
		# The header names the canonical hash of the given spec (r5), as the
		# product computes it (r6); unavailable is refused in BEGIN.
		if (spec_canon_sha != "" && hdr["spec_sha256"] != spec_canon_sha) bad("header-spec-sha256:differs")
		# r8: no displayed identity is a reserved ID (root, nobody, -1), and the
		# header identities are those of the given spec: agent_uid and its own
		# primary GID (condition 9) are the agent_uid of the spec, service_uid
		# is its service_uid. Every item below is compared with these header
		# values, so the account, launch, credential, custody-verify, peer and
		# socket-owner identities are bound to the spec through them. The spec
		# carries no socket GID: socket_gid is bound to the items and must not
		# be reserved or the primary GID.
		for (i = 4; i <= nhk; i++) if (reserved(hdr[hkey[i]])) bad("header-reserved-id:" hkey[i])
		if (spec_agent != "" && hdr["agent_uid"] != spec_agent) bad("header-agent-uid-not-spec")
		if (spec_agent != "" && hdr["primary_gid"] != spec_agent) bad("header-primary-gid-not-spec")
		if (spec_service != "" && hdr["service_uid"] != spec_service) bad("header-service-uid-not-spec")
		wallet = hdr["wallet"]
		next
	}
	overall_seen { bad("trailing-after-overall:line" NR); next }
	$1 == "custody_spec_sha256" {
		nhash++
		if ($0 !~ /^custody_spec_sha256 [0-9a-f]+$/ || !hex64($2)) bad("custody-spec-sha256:malformed:line" NR)
		else stated_hash = $2
		next
	}
	$0 == apply_line { napply++; next }
	$0 == note { nnote++; next }
	/^OVERALL / && stored == "stored" { stated = $2; stated_line = $0; overall_seen = 1; next }
	$0 !~ /^[^# \t\r][^ \t\r]*( [^ \t\r]+)*$/ { bad("malformed-line:line" NR); next }
	{
		id = $1; v = $2
		if (NF < 3) bad("no-evidence:" id)
		if (seen[id]++) bad("duplicate:" id)
		if (v != "PASS" && v != "FAIL" && v != "STAND_IN" && v != "COVERED_BY_HOSTED") { bad("verdict:" id); next }
		# The fields, once each.
		split("", fv); keys = ""
		for (i = 3; i <= NF; i++) {
			p = index($i, "="); k = p ? substr($i, 1, p - 1) : $i
			if (k in fv) { bad("duplicate-field:" id ":" k); continue }
			fv[k] = p ? substr($i, p + 1) : ""
			keys = keys (keys == "" ? "" : " ") k
		}
		kind = id
		if (id ~ /^denied-read:./) kind = "denied-read"
		else if (id ~ /^denied-rpc:./) kind = "denied-rpc"
		else if ((id in pin_test) && id != "positive-request") kind = "covered"
		# Every denied row, whatever its verdict, is a row of the given spec.
		if (kind == "denied-read") { row_read[substr(id, 13)]++; if (!(substr(id, 13) in spec_read)) bad("extra-row:" id) }
		if (kind == "denied-rpc") { row_rpc[substr(id, 12)]++; if (!(substr(id, 12) in spec_rpc)) bad("extra-row:" id) }
		vv[id] = v
		count[v]++
		if (v == "FAIL") fail++
		placeholder = (kind == "allowed-socket" || kind == "status-dir" || kind == "denied-read")
		if (!(kind in schema)) { bad(v == "COVERED_BY_HOSTED" ? "covered-not-allowed:" id : "unknown-item:" id); next }
		if (v == "FAIL") next
		if (kind == "custody-spec") { bad("custody-spec-not-fail"); next }
		sk = kind
		if (wallet == "real" && v == "PASS" && (kind == "denied-read" || kind == "denied-rpc")) sk = kind "-live"
		if (keys != schema[sk]) bad("fields:" id)
		# r9: a denied-rpc row may be STAND_IN too, but only on a stand-in run
		# and only for REFUSED (checked below).
		if (v == "STAND_IN" && (!(placeholder || kind == "denied-rpc") || wallet != "stand-in")) bad("stand-in-misplaced:" id)
		if (v == "PASS" && placeholder && wallet == "stand-in") bad("stand-in-placeholder-pass:" id)
		if (v == "COVERED_BY_HOSTED" && !(id in pin_test)) bad("covered-not-allowed:" id)
		if (v != "COVERED_BY_HOSTED" && (id in pin_test)) bad("covered-item-verdict:" id)
		A = hdr["agent_uid"]; G = hdr["primary_gid"]; S = hdr["socket_gid"]; U = hdr["service_uid"]
		if (v == "COVERED_BY_HOSTED" && (id in pin_test)) {
			if (fv["pin"] != pin_test[id]) bad("no-pin:" id)
			if (fv["commit"] != pin_commit[id]) bad("no-commit:" id)
			if (fv["run"] != pin_run[id]) bad("no-run:" id)
			if (fv["job"] != pin_job[id]) bad("no-job:" id)
			if (id == "positive-request") {
				host = fv["host"]
				if (host != "not-sent" && host != "not-run") bad("request-not-shown-unsent")
				if (fv["positive_path"] != "mainnet-smoke-gate") bad("positive-path-not-stated")
			}
		}
		if (kind == "denied-read") {
			nread++
			if (fv["observed"] != "EACCES" && fv["observed"] != "EPERM") bad("read-pass-without-eacces:" id)
			read_o[substr(id, 13)] = fv["observed"]
			# r10: on a live run the denied path exists, by the root-side record.
			if (wallet == "real" && v == "PASS") {
				if (!("exists" in fv)) bad("read-pass-not-in-stat-record:" id)
				else if (fv["exists"] != "yes") bad("read-pass-path-absent:" id)
				else if (fv["type"] !~ /^[a-z][a-z_]*$/ || fv["owner"] !~ /^(0|[1-9][0-9]*):(0|[1-9][0-9]*)$/ || fv["mode"] !~ /^[0-7]+$/) bad("read-pass-stat-malformed:" id)
			}
		}
		if (kind == "status-dir") {
			if (fv["observed"] != "EACCES" && fv["observed"] != "EPERM") bad("status-pass-without-eacces")
			if (fv["path"] != status_dir) bad("status-pass-other-path")
			status_o = fv["observed"]
		}
		# r9: a PASS needs an explicit refusal (401, 403) from a live node: a
		# refused connection is node-not-listening, never PASS, and node-txindex
		# must be PASS in the same report (checked at the end). STAND_IN is
		# REFUSED on a stand-in run only.
		if (kind == "denied-rpc") {
			nrpc++
			o = fv["observed"]
			if (v == "PASS") {
				rpc_pass++
				if (o == "REFUSED") bad("rpc-pass-node-not-listening:" id)
				else if (o != "HTTP_401" && o != "HTTP_403") bad("rpc-pass-without-refusal:" id)
			}
			if (v == "STAND_IN" && o != "REFUSED") bad("rpc-stand-in-without-refused:" id)
			# r10: on a live run the node answered at this target on both
			# sides of the probe window, synced after it too.
			if (wallet == "real" && v == "PASS") {
				tgt = substr(id, 12)
				if (fv["pre_rpc"] != tgt || fv["post_rpc"] != tgt) bad("rpc-pass-capture-port-mismatch:" id)
				if (!ts(fv["pre_start"]) || !ts(fv["pre_end"]) || !ts(fv["probe_start"]) || !ts(fv["probe_end"]) || !ts(fv["post_start"]) || !ts(fv["post_end"])) bad("rpc-pass-capture-time-missing:" id)
				else if (!(fv["pre_start"] <= fv["pre_end"] && fv["pre_end"] <= fv["probe_start"] && fv["probe_start"] <= fv["probe_end"] && fv["probe_end"] <= fv["post_start"] && fv["post_start"] <= fv["post_end"])) bad("rpc-pass-window-not-bracketed:" id)
				if (fv["post_getindexinfo"] !~ /^\{"txindex":\{"synced":true,"best_block_height":[0-9]+\}\}$/) bad("rpc-pass-capture-not-synced:" id)
			}
		}
		if (id == "node-txindex" && fv["getindexinfo"] !~ /^\{"txindex":\{"synced":true,"best_block_height":[0-9]+\}\}$/) bad("txindex-pass-without-synced-index")
		if (id == "render" && (fv["files"] != "6" || !hex64(fv["custody_spec_file_sha256"]))) bad("render-pass-without-six-files")
		# The render line names the SHA-256 of the given spec file (r5).
		if (id == "render" && fv["custody_spec_file_sha256"] != spec_file_sha) bad("render-custody-spec-file-sha256:differs")
		if (id == "agent-inputs" && fv["spec,client,params"] != "rendered") bad("agent-inputs-pass-without-match")
		if (id == "peer-precondition" && fv["perl_v"] !~ /^This_is_perl_5,_version_[0-9]+,_subversion_[0-9]+/) bad("peer-precondition-without-perl-version")
		if (id == "account") {
			account_pass = 1
			if (fv["steps"] != "preflight,VerifyG2AgentAccount,group-set") bad("account-pass-without-steps")
			if (fv["apply"] != "noop" || fv["activation"] != "noop") bad("account-pass-without-noop-apply")
			if (fv["user"] !~ /^[a-z_][a-z0-9_-]*$/) bad("account-pass-without-user")
			if (fv["group_set"] != "G2_AGENT_GROUPS_OK") bad("account-pass-without-real-group-set")
			if (G != A) bad("account-own-gid-not-uid")
			ra = fv["real_account"]; rp = "uid=" A "_gid=" G "_groups="
			if (substr(ra, 1, length(rp)) != rp || !gset(substr(ra, length(rp) + 1), G, S)) bad("account-pass-without-real-account")
		}
		if (id == "launch-form") {
			if (fv["uid"] != A "," A "," A "," A) bad("launch-pass-other-uid")
			if (fv["gid"] != G "," G "," G "," G) bad("launch-pass-other-gid")
			if (!gset(fv["groups"], G, S)) bad("launch-pass-other-groups")
			if (fv["caps"] != "0") bad("launch-pass-with-capabilities")
		}
		if (id == "credentials" && (fv["observed_gid"] != G || !gset(fv["groups"], G, S) || fv["check"] != "G2_AGENT_GROUPS_OK")) bad("credentials-pass-contradicts-evidence")
		if (id == "custody-verify") {
			cv = fv["uid"]
			if (cv !~ /^[0-9]+,probe_exit=0,positive_exit=[0-9]+,verify_exit=0$/ || substr(cv, 1, index(cv, ",") - 1) != A) bad("custody-verify-pass-contradicts-exits")
			if (fv["verified"] != hdr["spec_sha256"]) bad("custody-verify-pass-other-spec")
		}
		# r7: the launch layout is checked per run by verify -launch=true.
		if (id == "launch-layout" && (fv["verify"] != "g2-custody-verify" || fv["launch"] != "true" || fv["verify_exit"] != "0" || fv["verified"] != hdr["spec_sha256"])) bad("launch-layout-pass-contradicts-verify")
		if (id == "allowed-socket") {
			if (v == "PASS") {
				if (wallet != "real" || fv["wallet"] != "real") bad("wallet-pass-on-stand-in")
				if (fv["probe"] != "CONNECTED") bad("wallet-pass-without-connect")
				if (fv["peer_uid"] != U || fv["service_uid"] != U) bad("wallet-pass-without-peer-identity")
				if (fv["socket"] != "socket|" U "|" S "|660" || fv["socket_gid"] != S) bad("wallet-pass-socket-metadata")
			} else if (v == "STAND_IN") {
				if (fv["wallet"] != "stand-in" || fv["probe"] != "CONNECTED" || !num(fv["peer_uid"]) || fv["service_uid"] != U || fv["socket_gid"] != S) bad("stand-in-socket-contradicts-evidence")
			}
		}
	}
	END {
		for (i = 1; i <= nreq; i++) if (req[i] != "" && !(req[i] in seen)) { missing++; reasons = reasons " missing:" req[i] }
		if (nread < 1) { missing++; reasons = reasons " missing:denied-read" }
		if (nrpc < 1) { missing++; reasons = reasons " missing:denied-rpc" }
		# Each entry of the given spec has its row.
		for (i = 1; i <= nsread; i++) if (!(sread[i] in row_read)) { missing++; reasons = reasons " missing:denied-read:" sread[i] }
		for (i = 1; i <= nsrpc; i++) if (!(srpc[i] in row_rpc)) { missing++; reasons = reasons " missing:denied-rpc:" srpc[i] }
		# The report names the exact spec file once.
		if (nhash == 0) bad("custody-spec-sha256:missing")
		else if (nhash > 1) bad("custody-spec-sha256:duplicate")
		else if (stated_hash != "" && stated_hash != spec_file_sha) bad("custody-spec-sha256:differs")
		if (wallet == "") { invalid++; reasons = reasons " header" }
		if (napply > 1 || (account_pass && napply != 1)) bad("apply-noop-line")
		if (nnote != 1) bad("positive-path-statement")
		# Contradictions between items.
		if (rpc_pass && vv["node-txindex"] != "PASS") bad("rpc-pass-without-live-node")
		if (vv["status-dir"] != "" && vv["status-dir"] != "FAIL" && (vv["denied-read:" status_dir] != vv["status-dir"] || read_o[status_dir] != status_o)) bad("status-dir-contradicts-denied-read")
		if (vv["positive-request"] == "COVERED_BY_HOSTED") {
			if (host == "not-run" && (vv["credentials"] == "PASS" || vv["custody-verify"] == "PASS")) bad("positive-not-run-contradicts-credentials")
			if (host == "not-sent" && vv["custody-verify"] == "PASS" && cv !~ /,positive_exit=3,/) bad("positive-not-sent-contradicts-exits")
		}
		if (unterminated) bad("unterminated-last-line")
		if (stored == "stored" && !overall_seen) bad("missing:OVERALL")
		run = (wallet == "stand-in") ? "run=stand-in valid-only-as-a-stand-in-run" : "run=" (wallet == "" ? "unknown" : wallet)
		# A stored OVERALL line must be the recomputed line, byte for byte;
		# one that disagrees is itself a contradiction.
		for (pass = 1; pass <= 2; pass++) {
			overall = (fail + invalid + missing == 0) ? "PASS" : "FAIL"
			line = sprintf("OVERALL %s pass=%d stand_in=%d covered=%d fail=%d invalid=%d missing=%d %s", overall, count["PASS"], count["STAND_IN"], count["COVERED_BY_HOSTED"], fail, invalid, missing, run)
			if (pass == 1 && stated_line != "" && stated_line != line) { disagree = 1; bad("stated-overall-disagrees") } else break
		}
		print line
		if (reasons != "") print "# reasons:" reasons
		if (disagree) print "# stated OVERALL " stated " disagrees"
		exit (overall == "PASS") ? 0 : 1
	}' "$1"
}

# ---------------------------------------------------------------- self-test
self_test() {
	[ "$#" -eq 0 ] || usage
	w=$(mktemp -d)
	trap 'rm -rf "$w"' EXIT
	r=$w/rendered op=$w/op ag=$w/ag
	mkdir "$r" "$op" "$op/render" "$ag" "$ag/custody"
	failures=0
	# r6: the real deploy-kit, built from this checkout, is the only source of
	# the canonical spec hash; DEPLOY_KIT from the caller is not used.
	src=$(cd "$(dirname "$(self_path)")" && pwd)
	if (cd "$src" && go build -mod=readonly -buildvcs=false -o "$w/deploy-kit" ./cmd/deploy-kit) >"$w/build.log" 2>&1; then
		echo "self-test build-deploy-kit ok exit=0"
	else
		echo "self-test build-deploy-kit WRONG: go build ./cmd/deploy-kit in $src"
		sed 's/^/  | /' "$w/build.log"
		echo "SELF_TEST FAIL failures=1"
		return 1
	fi
	deploy_kit=$w/deploy-kit
	DEPLOY_KIT=$deploy_kit
	export DEPLOY_KIT
	printf '{"agent_user":"g2-agent","agent_uid":210001}\n' >"$w/params.json"
	printf 'u swarma-wallet 210201\ng swarma-wallet-peer 210101\ng swarma-wallet-status 210301\nu g2-agent 210001\nm g2-agent swarma-wallet-peer\n' >"$r/sysusers.conf"
	printf '{"v":1,"agent_uid":210001,"service_uid":210201,"denied_reads":["/etc/swarma/wallet/wallet.json","%s"],"denied_rpc":["127.0.0.1:8336"],"allowed_socket":"/run/swarma-wallet/wallet.sock"}\n' "$status_dir" >"$r/custody-spec.json"
	for f in client.json namecoin-rpc.conf service.json tmpfiles.conf; do echo "$f" >"$r/$f"; done
	for f in $rendered_files; do cp "$r/$f" "$op/render/$f" && echo "same $f"; done >"$op/render-cmp.txt"
	printf 'render_exit=0\nhost_flow_exit=0\naccount_groups_exit=0\n' >"$op/exits.txt"
	echo G2_HOST_FLOW_ACTIVATED >"$op/host-flow.out"
	echo 'apply=noop activation=noop sysusers=true' >"$op/host-flow-mode.txt"
	echo 'uid=210001 gid=210001 groups=210001,210101' >"$op/account-real.txt"
	echo 'G2_AGENT_GROUPS_OK observed_gid=210001 declared_primary_gid=210001 socket_gid=210101' >"$op/account-groups.txt"
	echo '{"txindex":{"synced":true,"best_block_height":1}}' >"$op/txindex.json"
	sha256sum "$r/custody-spec.json" "$r/client.json" "$w/params.json" | cut -d ' ' -f 1 >"$ag/inputs.sha256"
	printf 'Uid:\t210001\t210001\t210001\t210001\nGid:\t210001\t210001\t210001\t210001\nGroups:\t210001 210101 \nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n' >"$ag/launch.txt"
	echo 'G2_AGENT_GROUPS_OK observed_gid=210001 declared_primary_gid=210001 socket_gid=210101' >"$ag/custody/credentials-check.txt"
	if ! spec_sha=$(product_spec_sha "$r/custody-spec.json"); then
		echo "self-test product-spec-hash WRONG: the built deploy-kit refused the synthetic spec"
		echo "SELF_TEST FAIL failures=1"
		return 1
	fi
	probes() { # FIRST-READ-OBSERVED [RPC-OBSERVED, default HTTP_401]
		printf '{"v":1,"spec_sha256":"%s","uid":210001,"gid":210001,"probes":[{"kind":"read","target":"/etc/swarma/wallet/wallet.json","expect":"denied","observed":"%s","pass":true},{"kind":"read","target":"%s","expect":"denied","observed":"EACCES","pass":true},{"kind":"rpc","target":"127.0.0.1:8336","expect":"denied","observed":"%s","pass":true},{"kind":"socket","target":"/run/swarma-wallet/wallet.sock","expect":"allowed","observed":"CONNECTED","pass":true}],"pass":true}\n' "$spec_sha" "$1" "$status_dir" "${2:-HTTP_401}" >"$ag/custody/custody-report.json"
	}
	probes EACCES
	echo "uid=210001 probe_exit=0 positive_exit=3 verify_exit=0" >"$ag/custody/exits.txt"
	echo "T18_CUSTODY_VERIFIED $spec_sha" >"$ag/custody/custody-verify.txt"
	exits_ok() { printf 'custody_check_exit=1\nlaunch_true_exit=0\nlaunch_false_exit=0\npeer_exit=0\n' >"$ag/agent-exits.txt"; }
	exits_ok
	echo "T18_CUSTODY_VERIFIED $spec_sha" >"$ag/launch-layout-on.txt"
	echo "T18_CUSTODY_VERIFIED $spec_sha" >"$ag/launch-layout-off.txt"
	echo "$stub_marker" >"$ag/custody/positive-receipt.json"
	: >"$ag/custody/positive-request.json"
	echo 'PEER connect=ok uid=210201 gid=210201' >"$ag/peer.txt"
	echo 'socket|210201|210101|660' >"$ag/socket-stat.txt"
	echo 'This is perl 5, version 34, subversion 0 (v5.34.0) built for x86_64-linux-gnu-thread-multi' >"$ag/perl-version.txt"
	# r10: the two node captures around the probe window, and the root-side
	# stat record of the two denied paths.
	capture() { # FILE RPC START END
		printf '%s\nrpc=%s\nstart=%s\nend=%s\nexit=0\nanswer={"txindex":{"synced":true,"best_block_height":1}}\n' "$capture_head" "$2" "$3" "$4" >"$1"
	}
	day=2026-01-01T00
	capture "$op/node-pre.txt" 127.0.0.1:8336 "$day:00:00.000000000Z" "$day:00:01.000000000Z"
	printf 'probe_start=%s\nprobe_end=%s\n' "$day:05:00.000000000Z" "$day:05:02.000000000Z" >"$ag/probe-window.txt"
	capture "$op/node-post.txt" 127.0.0.1:8336 "$day:06:00.000000000Z" "$day:06:01.000000000Z"
	stats_ok() { printf '/etc/swarma/wallet/wallet.json exists=yes type=regular_file owner=210201:210201 mode=600\n%s exists=yes type=directory owner=210201:210301 mode=750\n' "$status_dir" >"$op/denied-paths-stat.txt"; }
	stats_ok

	expect() { # NAME WANT-EXIT REPORT-MODE WANT-LINE (extended regex)
		sh "$(self_path)" report "$op" "$ag" "$r" "$w/params.json" "$3" >"$w/$1.txt" 2>&1 && got=0 || got=$?
		if [ "$got" = "$2" ] && grep -Eq "$4" "$w/$1.txt"; then
			echo "self-test $1 ok exit=$got"
		else
			echo "self-test $1 WRONG exit=$got want=$2"
			sed 's/^/  | /' "$w/$1.txt"
			failures=$((failures + 1))
		fi
	}
	expect real-wallet-all-pass 0 real '^OVERALL PASS pass=14 stand_in=0 covered=11 fail=0 invalid=0 missing=0 run=real$'
	expect apply-noop-line 0 real '^apply no-op: account pre-created by Infra$'
	expect stand-in-wallet 0 stand-in '^allowed-socket STAND_IN wallet=stand-in probe=CONNECTED '
	expect stand-in-placeholders 0 stand-in '^OVERALL PASS pass=10 stand_in=4 covered=11 fail=0 invalid=0 missing=0 run=stand-in valid-only-as-a-stand-in-run$'
	sed 's/^\(denied-read:[^ ]*\) STAND_IN /\1 PASS /' "$w/stand-in-placeholders.txt" >"$w/edited.txt"
	check_report "$w/edited.txt" stored "$r/custody-spec.json" >/dev/null && got=0 || got=$?
	if [ "$got" = 1 ]; then echo "self-test stand-in-placeholder-pass ok exit=1"; else echo "self-test stand-in-placeholder-pass WRONG exit=$got" && failures=$((failures + 1)); fi
	echo 'deploy: invalid policy' >"$op/account-groups.txt"
	expect account-real-group-set-refused 1 real '^account FAIL .* group_set=deploy:_invalid_policy$'
	echo 'G2_AGENT_GROUPS_OK observed_gid=210001 declared_primary_gid=210001 socket_gid=210101' >"$op/account-groups.txt"
	probes ENOENT
	expect enoent-denied-read 1 real '^denied-read:/etc/swarma/wallet/wallet.json FAIL observed=ENOENT$'
	probes EACCES
	echo 'PEER connect=ok uid=0 gid=210101' >"$ag/peer.txt"
	expect stand-in-declared-real 1 real '^allowed-socket FAIL wallet=real probe=CONNECTED peer_uid=0 '
	echo 'PEER connect=ok uid=210201 gid=210201' >"$ag/peer.txt"
	echo '{"receipt":{"verdict":"executed"}}' >"$ag/custody/positive-receipt.json"
	expect request-sent 1 real '^positive-request FAIL host=request-sent-or-unknown$'
	echo "$stub_marker" >"$ag/custody/positive-receipt.json"
	# r7: verify -launch=true refused the run's launch layout (the same report
	# passed with -launch=false): launch-layout FAIL, OVERALL FAIL.
	echo 'deploy: invalid policy' >"$ag/launch-layout-on.txt"
	printf 'custody_check_exit=1\nlaunch_true_exit=1\nlaunch_false_exit=0\npeer_exit=0\n' >"$ag/agent-exits.txt"
	expect launch-layout-refused 1 real '^launch-layout FAIL launch=true verify_exit=1 verify=deploy:,invalid,policy launch_false_exit=0 layout=refused$'
	if grep -q '^OVERALL PASS ' "$w/launch-layout-refused.txt"; then echo "self-test launch-layout-refused-overall WRONG" && failures=$((failures + 1)); fi
	echo "T18_CUSTODY_VERIFIED $spec_sha" >"$ag/launch-layout-on.txt"
	exits_ok
	sed 's/^allowed-socket PASS /allowed-socket STAND_IN /' "$w/real-wallet-all-pass.txt" >"$w/edited.txt"
	check_report "$w/edited.txt" stored "$r/custody-spec.json" >/dev/null && got=0 || got=$?
	if [ "$got" = 1 ]; then echo "self-test stand-in-on-real-wallet ok exit=1"; else echo "self-test stand-in-on-real-wallet WRONG exit=$got" && failures=$((failures + 1)); fi

	# check is bound to the spec file the run used (r4). The valid real report
	# passes with its spec; check refuses to run without one; and each planted
	# report fails with its named reason.
	checked() { # NAME WANT-EXIT REPORT SPEC|- WANT (fixed string in the output) [DEPLOY_KIT]
		kit=${6:-$deploy_kit}
		if [ "$4" = - ]; then
			DEPLOY_KIT=$kit sh "$(self_path)" check "$3" >"$w/$1.check" 2>&1 && got=0 || got=$?
		else
			DEPLOY_KIT=$kit sh "$(self_path)" check "$3" "$4" >"$w/$1.check" 2>&1 && got=0 || got=$?
		fi
		if [ "$got" = "$2" ] && grep -Fq -- "$5" "$w/$1.check"; then
			echo "self-test $1 ok exit=$got"
		else
			echo "self-test $1 WRONG exit=$got want=$2"
			sed 's/^/  | /' "$w/$1.check"
			failures=$((failures + 1))
		fi
	}
	valid=$w/real-wallet-all-pass.txt
	spec=$r/custody-spec.json
	checked spec-bound-valid 0 "$valid" "$spec" 'OVERALL PASS pass=14 stand_in=0 covered=11 fail=0 invalid=0 missing=0 run=real'
	checked spec-not-given 64 "$valid" - 'usage:'
	# The repro: a required row deleted and the OVERALL count edited to match.
	grep -v '^denied-read:/etc/swarma/wallet/wallet.json ' "$valid" | sed 's/^OVERALL PASS pass=14 /OVERALL PASS pass=13 /' >"$w/row-deleted.txt"
	checked row-deleted-overall-edited 1 "$w/row-deleted.txt" "$spec" 'missing:denied-read:/etc/swarma/wallet/wallet.json'
	# The same valid report against another spec: the rows agree, the file not.
	sed 's/"agent_uid":210001/"agent_uid":210002/' "$spec" >"$w/other-spec.json"
	checked other-spec 1 "$valid" "$w/other-spec.json" 'custody-spec-sha256:differs'
	grep -v '^custody_spec_sha256 ' "$valid" >"$w/no-hash.txt"
	checked missing-hash 1 "$w/no-hash.txt" "$spec" 'custody-spec-sha256:missing'
	awk '{ print } /^custody_spec_sha256 / { print }' "$valid" >"$w/two-hashes.txt"
	checked duplicate-hash 1 "$w/two-hashes.txt" "$spec" 'custody-spec-sha256:duplicate'
	# r5: each of the three spec hashes, changed alone, is refused by name.
	zero=0000000000000000000000000000000000000000000000000000000000000000
	sed "s/^custody_spec_sha256 [0-9a-f]*\$/custody_spec_sha256 $zero/" "$valid" >"$w/custody-hash.txt"
	checked custody-hash-differs 1 "$w/custody-hash.txt" "$spec" 'custody-spec-sha256:differs'
	sed "1s/ spec_sha256=[0-9a-f]* / spec_sha256=$zero /" "$valid" >"$w/header-hash.txt"
	checked header-hash-differs 1 "$w/header-hash.txt" "$spec" 'header-spec-sha256:differs'
	sed "s/^\(render PASS files=6 custody_spec_file_sha256=\)[0-9a-f]*\$/\1$zero/" "$valid" >"$w/render-hash.txt"
	checked render-hash-differs 1 "$w/render-hash.txt" "$spec" 'render-custody-spec-file-sha256:differs'
	awk '/^denied-rpc:/ { print "denied-read:/etc/swarma/wallet/extra.json PASS observed=EACCES" } { sub(/^OVERALL PASS pass=14 /, "OVERALL PASS pass=15 "); print }' "$valid" >"$w/extra-row.txt"
	checked extra-row 1 "$w/extra-row.txt" "$spec" 'extra-row:denied-read:/etc/swarma/wallet/extra.json'
	# r6: the canonical hash comes only from the product. Beside the valid
	# report, which passed above with the real deploy-kit: no deploy-kit, a
	# product that prints nothing, garbage or exits non-zero is refused as
	# canonical-hash-unavailable; one that prints another well-formed hash is
	# header-spec-sha256:differs.
	checked kit-missing 1 "$valid" "$spec" '# reasons: canonical-hash-unavailable ' "$w/absent/deploy-kit"
	fake() { # NAME BODY: a deploy-kit stand-in
		printf '#!/bin/sh\n%s\n' "$2" >"$w/$1" && chmod 700 "$w/$1"
	}
	fake kit-wrong "echo T18_CUSTODY_SPEC_SHA256 $zero"
	checked kit-wrong-hash 1 "$valid" "$spec" '# reasons: header-spec-sha256:differs ' "$w/kit-wrong"
	fake kit-garbage 'echo T18_CUSTODY_SPEC_SHA256 not-a-hash'
	checked kit-garbage 1 "$valid" "$spec" '# reasons: canonical-hash-unavailable ' "$w/kit-garbage"
	fake kit-empty 'exit 0'
	checked kit-empty 1 "$valid" "$spec" '# reasons: canonical-hash-unavailable ' "$w/kit-empty"
	fake kit-exit "echo T18_CUSTODY_SPEC_SHA256 $spec_sha; exit 1"
	checked kit-nonzero-exit 1 "$valid" "$spec" '# reasons: canonical-hash-unavailable ' "$w/kit-exit"
	# A spec with a leading space is the same spec to the product (and to
	# probe and verify): with its file hashes in the two file fields, the
	# valid report passes against it, header unchanged.
	printf ' ' >"$w/ws-spec.json" && cat "$spec" >>"$w/ws-spec.json"
	ws=$(sha_of "$w/ws-spec.json")
	sed -e "s/^custody_spec_sha256 [0-9a-f]*\$/custody_spec_sha256 $ws/" -e "s/^\(render PASS files=6 custody_spec_file_sha256=\)[0-9a-f]*\$/\1$ws/" "$valid" >"$w/ws-report.txt"
	checked whitespace-spec-agrees 0 "$w/ws-report.txt" "$w/ws-spec.json" 'OVERALL PASS pass=14 stand_in=0 covered=11 fail=0 invalid=0 missing=0 run=real'
	# r9: denied RPC needs a live node. A refused connection (nothing listens
	# at the RPC port) is FAIL node-not-listening on a real run and STAND_IN on
	# a stand-in run; check refuses that STAND_IN relabeled PASS by name; an
	# explicit 401 without node liveness (no getindexinfo answer) is FAIL.
	probes EACCES REFUSED
	expect rpc-node-not-listening 1 real '^denied-rpc:127\.0\.0\.1:8336 FAIL observed=REFUSED reason=node-not-listening$'
	expect rpc-refused-stand-in 0 stand-in '^denied-rpc:127\.0\.0\.1:8336 STAND_IN observed=REFUSED$'
	sed 's/^\(denied-rpc:[^ ]*\) STAND_IN observed=REFUSED$/\1 PASS observed=REFUSED/' "$w/rpc-refused-stand-in.txt" >"$w/rpc-refused-pass.txt"
	checked rpc-refused-as-pass 1 "$w/rpc-refused-pass.txt" "$spec" 'rpc-pass-node-not-listening:denied-rpc:127.0.0.1:8336'
	probes EACCES
	: >"$op/txindex.json"
	expect rpc-liveness-unproven 1 real '^denied-rpc:127\.0\.0\.1:8336 FAIL observed=HTTP_401 reason=node-liveness-unproven$'
	echo '{"txindex":{"synced":true,"best_block_height":1}}' >"$op/txindex.json"
	# r10: liveness at probe time and the existence of the denied paths, on a
	# live run. A post-probe capture on another port, one taken before the
	# probe ended, and a missing probe window are FAIL by name; a denied path
	# the root-side record lists as absent, or does not list, is FAIL by name;
	# and a stored live report without the r10 evidence (its denied-rpc row
	# as r9 wrote it) is refused by check.
	capture "$op/node-post.txt" 127.0.0.1:8337 "$day:06:00.000000000Z" "$day:06:01.000000000Z"
	expect rpc-post-capture-other-port 1 real '^denied-rpc:127\.0\.0\.1:8336 FAIL observed=HTTP_401 reason=capture-port-mismatch '
	capture "$op/node-post.txt" 127.0.0.1:8336 "$day:05:01.000000000Z" "$day:05:01.500000000Z"
	expect rpc-window-not-bracketed 1 real '^denied-rpc:127\.0\.0\.1:8336 FAIL observed=HTTP_401 reason=window-not-bracketed '
	capture "$op/node-post.txt" 127.0.0.1:8336 "$day:06:00.000000000Z" "$day:06:01.000000000Z"
	mv "$ag/probe-window.txt" "$w/probe-window.txt"
	expect rpc-capture-time-missing 1 real '^denied-rpc:127\.0\.0\.1:8336 FAIL observed=HTTP_401 reason=capture-time-missing .* probe_start=none probe_end=none '
	mv "$w/probe-window.txt" "$ag/probe-window.txt"
	sed 's#^/etc/swarma/wallet/wallet.json .*#/etc/swarma/wallet/wallet.json exists=no#' "$op/denied-paths-stat.txt" >"$w/stat.txt" && cp "$w/stat.txt" "$op/denied-paths-stat.txt"
	expect denied-path-absent 1 real '^denied-read:/etc/swarma/wallet/wallet\.json FAIL observed=EACCES reason=path-absent$'
	grep -v '^/etc/swarma/wallet/wallet.json ' "$w/stat.txt" >"$op/denied-paths-stat.txt"
	expect denied-path-not-in-record 1 real '^denied-read:/etc/swarma/wallet/wallet\.json FAIL observed=EACCES reason=path-not-in-stat-record$'
	stats_ok
	sed 's/^\(denied-rpc:[^ ]* PASS observed=HTTP_401\) .*$/\1/' "$valid" >"$w/r9-live.txt"
	checked stored-live-without-captures 1 "$w/r9-live.txt" "$spec" 'rpc-pass-capture-time-missing:denied-rpc:127.0.0.1:8336'
	if [ "$failures" = 0 ]; then
		echo "SELF_TEST PASS"
		return 0
	fi
	echo "SELF_TEST FAIL failures=$failures"
	return 1
}

case $mode in
operator) operator_phase "$@" ;;
agent) agent_phase "$@" ;;
node-capture) node_capture "$@" ;;
denied-stat) denied_stat "$@" ;;
peer) peer_phase "$@" ;;
items)
	[ "$#" -eq 0 ] || usage
	covered_lines
	;;
report)
	[ "$#" -eq 5 ] || usage
	case $5 in real | stand-in) ;; *) usage ;; esac
	[ -d "$1" ] && [ -d "$2" ] && [ -d "$3" ] && [ -f "$4" ] || usage
	[ -f "$3/custody-spec.json" ] && [ -f "$3/sysusers.conf" ] || usage
	# r6: the header's canonical hash comes from the product or the report is
	# not composed.
	if ! spec_canon=$(product_spec_sha "$3/custody-spec.json"); then
		echo "REFUSED canonical-hash-unavailable: $deploy_kit g2-custody-hash -spec $3/custody-spec.json" >&2
		exit 1
	fi
	report_tmp=$(mktemp)
	trap 'rm -f "$report_tmp"' EXIT
	report_items "$@" >"$report_tmp"
	cat "$report_tmp"
	check_report "$report_tmp" composed "$3/custody-spec.json"
	;;
check)
	# The spec is required: without it the rows cannot be bound to the run.
	[ "$#" -eq 2 ] && [ -f "$1" ] && [ -f "$2" ] || usage
	check_report "$1" stored "$2"
	;;
self-test) self_test "$@" ;;
*) usage ;;
esac
