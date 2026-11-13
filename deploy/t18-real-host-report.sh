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
#   t18-real-host-report.sh operator OPDIR PARAMS RENDERED TXINDEX_JSON
#       as the operator (no root needed): re-render, account checks, txindex
#   t18-real-host-report.sh agent AGDIR SPEC CLIENT GRANTEE PARAMS
#       as the agent, launched by root with setpriv exactly as SMOKE-G2.md §4
#   t18-real-host-report.sh report OPDIR AGDIR RENDERED PARAMS real|stand-in
#       reads both evidence directories and prints the report. The last
#       argument is the stand-in flag: `stand-in` marks a run on the stand-in
#       station, whose wallet files are root-owned placeholders and whose
#       socket is a planted listener; every placeholder-backed item (each
#       denied-read, status-dir, allowed-socket) is then STAND_IN, never PASS,
#       and the OVERALL line says the run is valid only as a stand-in run
#   t18-real-host-report.sh check REPORT
#       recomputes the OVERALL line of a stored report with one strict
#       parser: a duplicate field, a field that contradicts its verdict, the
#       header or another item, and a trailing, unterminated or unparsable
#       line are each refused with a named reason, and the report must end
#       with exactly the recomputed OVERALL line
#   t18-real-host-report.sh peer SOCKET
#       connects, reads SO_PEERCRED, sends nothing
#   t18-real-host-report.sh items
#       prints the COVERED_BY_HOSTED pin table
#   t18-real-host-report.sh self-test
#       dry run on synthetic evidence: no root, no station, no deploy-kit
#
# DEPLOY_KIT names the deploy-kit binary built from the reviewed head
# (default: deploy-kit on PATH).
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
	if [ -f "$txindex" ]; then
		tr -d ' \t\r\n' <"$txindex" >"$op/txindex.json"
	else
		: >"$op/txindex.json"
	fi
	echo "T18_REAL_HOST_OPERATOR_DONE $op"
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
	set +e
	T18_REAL_HOST_NO_REQUEST=1 DEPLOY_KIT=$deploy_kit AGENT_WALLET=$(self_path) \
		sh "$here/g2-custody-check.sh" "$spec" "$client" "$grantee" "$params" "$ag/custody" >"$ag/custody-check.out" 2>&1
	echo "custody_check_exit=$?" >"$ag/agent-exits.txt"

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
	spec_sha=$(printf '%s' "$(cat "$spec")" | sha256sum | cut -d ' ' -f 1)
	echo "T18-REAL-HOST v1 wallet=$wallet commit=$pinned_commit spec_sha256=$spec_sha agent_uid=$uid primary_gid=$gid socket_gid=$sgid service_uid=$suid"

	# Precondition: txindex=1 and the index synced.
	tx=$(cat "$op/txindex.json" 2>/dev/null || true)
	if printf '%s\n' "$tx" | grep -Eq '^\{"txindex":\{"synced":true,"best_block_height":[0-9]+\}\}$'; then
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
	if [ "$noop" = 1 ] && grep -qx host_flow_exit=0 "$op/exits.txt" 2>/dev/null && [ "$(cat "$op/host-flow.out" 2>/dev/null)" = G2_HOST_FLOW_ACTIVATED ] &&
		grep -qx account_groups_exit=0 "$op/exits.txt" 2>/dev/null && [ "$(cat "$op/account-groups.txt" 2>/dev/null)" = "$ag_ok" ] &&
		[ -n "$uid" ] && [ "$gid" = "$uid" ] && case $real in "$want_real"*) true ;; *) false ;; esac; then
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
	denied=PASS
	[ "$wallet" = stand-in ] && denied=STAND_IN
	status_seen=0
	for p in $reads; do
		o=$(probe_observed read "$p" "$cr") || o=
		case $o in
		EACCES | EPERM) echo "denied-read:$p $denied observed=$o" ;;
		*) echo "denied-read:$p FAIL observed=${o:-none}" ;;
		esac
		if [ "$p" = "$status_dir" ]; then
			status_seen=1
			case $o in
			EACCES | EPERM) echo "status-dir $denied path=$p observed=$o" ;;
			*) echo "status-dir FAIL path=$p observed=${o:-none}" ;;
			esac
		fi
	done
	[ "$status_seen" = 1 ] || echo "status-dir FAIL path=$status_dir not-in-denied_reads"
	for rpc in $rpcs; do
		o=$(probe_observed rpc "$rpc" "$cr") || o=
		case $o in
		HTTP_401 | HTTP_403 | REFUSED) echo "denied-rpc:$rpc PASS observed=$o" ;;
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

	vf=$(file_line "$ag/custody/custody-verify.txt")
	case $ex in
	"uid=$uid probe_exit=0 positive_exit="*" verify_exit=0") ok=1 ;;
	*) ok=0 ;;
	esac
	if [ "$ok" = 1 ] && [ "$vf" = "T18_CUSTODY_VERIFIED $spec_sha" ]; then
		echo "custody-verify PASS $(echo "$ex" | tr ' ' ',') verified=$spec_sha"
	else
		echo "custody-verify FAIL exits=$(echo "${ex:-none}" | tr ' ' ',') verify=$(echo "${vf:-none}" | tr ' ' ',')"
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
# check_report FILE stored|composed: parse every line once, strictly, and
# print the recomputed OVERALL line. Exit 0 only when it is PASS and, for a
# stored report, the report ends with exactly that OVERALL line.
#
# The parser refuses instead of choosing: a line is the header, the literal
# no-op apply line, the literal positive-path statement, an item line or (in
# a stored report) the one last OVERALL line, single-space separated and
# newline-terminated; anything else is invalid. An item line is
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
	awk -v pins="$(covered_table; echo "$positive_row")" -v apply_line="$apply_noop_line" -v note="$positive_note" \
		-v pinned_commit="$pinned_commit" -v status_dir="$status_dir" -v unterminated="$unterminated" -v stored="$2" '
	function bad(why) { invalid++; reasons = reasons " " why }
	function num(s) { return s ~ /^[0-9]+$/ }
	function hex64(s) { return length(s) == 64 && s !~ /[^0-9a-f]/ }
	function pair(a, b) { return (a + 0 < b + 0) ? a "," b : b "," a }
	BEGIN {
		npin = split(pins, rows, "\n")
		for (i = 1; i <= npin; i++) {
			if (split(rows[i], f, " ") != 5) continue
			pin_test[f[1]] = f[2]; pin_commit[f[1]] = f[3]; pin_run[f[1]] = f[4]; pin_job[f[1]] = f[5]
			req_ids = req_ids " " f[1]
		}
		nreq = split("node-txindex render account agent-inputs launch-form credentials status-dir peer-precondition allowed-socket custody-verify" req_ids, req, " ")
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
		schema["peer-precondition"] = "perl_v"
		schema["allowed-socket"] = "wallet probe peer_uid service_uid socket socket_gid"
		schema["custody-verify"] = "uid verified"
		schema["positive-request"] = "pin commit run job host positive_path"
		schema["covered"] = "pin commit run job"
		schema["custody-spec"] = ""
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
		wallet = hdr["wallet"]
		next
	}
	overall_seen { bad("trailing-after-overall:line" NR); next }
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
		vv[id] = v
		count[v]++
		if (v == "FAIL") fail++
		placeholder = (kind == "allowed-socket" || kind == "status-dir" || kind == "denied-read")
		if (!(kind in schema)) { bad(v == "COVERED_BY_HOSTED" ? "covered-not-allowed:" id : "unknown-item:" id); next }
		if (v == "FAIL") next
		if (kind == "custody-spec") { bad("custody-spec-not-fail"); next }
		if (keys != schema[kind]) bad("fields:" id)
		if (v == "STAND_IN" && (!placeholder || wallet != "stand-in")) bad("stand-in-misplaced:" id)
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
		}
		if (kind == "status-dir") {
			if (fv["observed"] != "EACCES" && fv["observed"] != "EPERM") bad("status-pass-without-eacces")
			if (fv["path"] != status_dir) bad("status-pass-other-path")
			status_o = fv["observed"]
		}
		if (kind == "denied-rpc") {
			nrpc++
			o = fv["observed"]
			if (o != "HTTP_401" && o != "HTTP_403" && o != "REFUSED") bad("rpc-pass-without-refusal:" id)
		}
		if (id == "node-txindex" && fv["getindexinfo"] !~ /^\{"txindex":\{"synced":true,"best_block_height":[0-9]+\}\}$/) bad("txindex-pass-without-synced-index")
		if (id == "render" && (fv["files"] != "6" || !hex64(fv["custody_spec_file_sha256"]))) bad("render-pass-without-six-files")
		if (id == "agent-inputs" && fv["spec,client,params"] != "rendered") bad("agent-inputs-pass-without-match")
		if (id == "peer-precondition" && fv["perl_v"] !~ /^This_is_perl_5,_version_[0-9]+,_subversion_[0-9]+/) bad("peer-precondition-without-perl-version")
		if (id == "account") {
			account_pass = 1
			if (fv["steps"] != "preflight,VerifyG2AgentAccount,group-set") bad("account-pass-without-steps")
			if (fv["apply"] != "noop" || fv["activation"] != "noop") bad("account-pass-without-noop-apply")
			if (fv["user"] !~ /^[a-z_][a-z0-9_-]*$/) bad("account-pass-without-user")
			if (fv["group_set"] != "G2_AGENT_GROUPS_OK") bad("account-pass-without-real-group-set")
			if (G != A) bad("account-own-gid-not-uid")
			if (fv["real_account"] != "uid=" A "_gid=" G "_groups=" pair(G, S)) bad("account-pass-without-real-account")
		}
		if (id == "launch-form") {
			if (fv["uid"] != A "," A "," A "," A) bad("launch-pass-other-uid")
			if (fv["gid"] != G "," G "," G "," G) bad("launch-pass-other-gid")
			if (fv["groups"] != pair(G, S)) bad("launch-pass-other-groups")
			if (fv["caps"] != "0") bad("launch-pass-with-capabilities")
		}
		if (id == "credentials" && (fv["observed_gid"] != G || fv["groups"] != pair(G, S) || fv["check"] != "G2_AGENT_GROUPS_OK")) bad("credentials-pass-contradicts-evidence")
		if (id == "custody-verify") {
			cv = fv["uid"]
			if (cv !~ /^[0-9]+,probe_exit=0,positive_exit=[0-9]+,verify_exit=0$/ || substr(cv, 1, index(cv, ",") - 1) != A) bad("custody-verify-pass-contradicts-exits")
			if (fv["verified"] != hdr["spec_sha256"]) bad("custody-verify-pass-other-spec")
		}
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
		if (wallet == "") { invalid++; reasons = reasons " header" }
		if (napply > 1 || (account_pass && napply != 1)) bad("apply-noop-line")
		if (nnote != 1) bad("positive-path-statement")
		# Contradictions between items.
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
	spec_sha=$(printf '%s' "$(cat "$r/custody-spec.json")" | sha256sum | cut -d ' ' -f 1)
	probes() {
		printf '{"v":1,"spec_sha256":"%s","uid":210001,"gid":210001,"probes":[{"kind":"read","target":"/etc/swarma/wallet/wallet.json","expect":"denied","observed":"%s","pass":true},{"kind":"read","target":"%s","expect":"denied","observed":"EACCES","pass":true},{"kind":"rpc","target":"127.0.0.1:8336","expect":"denied","observed":"HTTP_401","pass":true},{"kind":"socket","target":"/run/swarma-wallet/wallet.sock","expect":"allowed","observed":"CONNECTED","pass":true}],"pass":true}\n' "$spec_sha" "$1" "$status_dir" >"$ag/custody/custody-report.json"
	}
	probes EACCES
	echo "uid=210001 probe_exit=0 positive_exit=3 verify_exit=0" >"$ag/custody/exits.txt"
	echo "T18_CUSTODY_VERIFIED $spec_sha" >"$ag/custody/custody-verify.txt"
	echo "$stub_marker" >"$ag/custody/positive-receipt.json"
	: >"$ag/custody/positive-request.json"
	echo 'PEER connect=ok uid=210201 gid=210201' >"$ag/peer.txt"
	echo 'socket|210201|210101|660' >"$ag/socket-stat.txt"
	echo 'This is perl 5, version 34, subversion 0 (v5.34.0) built for x86_64-linux-gnu-thread-multi' >"$ag/perl-version.txt"

	failures=0
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
	expect real-wallet-all-pass 0 real '^OVERALL PASS pass=13 stand_in=0 covered=11 fail=0 invalid=0 missing=0 run=real$'
	expect apply-noop-line 0 real '^apply no-op: account pre-created by Infra$'
	expect stand-in-wallet 0 stand-in '^allowed-socket STAND_IN wallet=stand-in probe=CONNECTED '
	expect stand-in-placeholders 0 stand-in '^OVERALL PASS pass=9 stand_in=4 covered=11 fail=0 invalid=0 missing=0 run=stand-in valid-only-as-a-stand-in-run$'
	sed 's/^\(denied-read:[^ ]*\) STAND_IN /\1 PASS /' "$w/stand-in-placeholders.txt" >"$w/edited.txt"
	check_report "$w/edited.txt" stored >/dev/null && got=0 || got=$?
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
	sed 's/^allowed-socket PASS /allowed-socket STAND_IN /' "$w/real-wallet-all-pass.txt" >"$w/edited.txt"
	check_report "$w/edited.txt" stored >/dev/null && got=0 || got=$?
	if [ "$got" = 1 ]; then echo "self-test stand-in-on-real-wallet ok exit=1"; else echo "self-test stand-in-on-real-wallet WRONG exit=$got" && failures=$((failures + 1)); fi
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
	report_tmp=$(mktemp)
	trap 'rm -f "$report_tmp"' EXIT
	report_items "$@" >"$report_tmp"
	cat "$report_tmp"
	check_report "$report_tmp" composed
	;;
check)
	[ "$#" -eq 1 ] && [ -f "$1" ] || usage
	check_report "$1" stored
	;;
self-test) self_test "$@" ;;
*) usage ;;
esac
