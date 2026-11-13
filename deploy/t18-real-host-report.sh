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
# evidence, STAND_IN appears only for the wallet socket of a stand-in host, and
# every COVERED_BY_HOSTED item carries its pin (test name, commit, hosted run).
#
#   t18-real-host-report.sh operator OPDIR PARAMS RENDERED TXINDEX_JSON
#       as the operator (no root needed): re-render, account checks, txindex
#   t18-real-host-report.sh agent AGDIR SPEC CLIENT GRANTEE PARAMS
#       as the agent, launched by root with setpriv exactly as SMOKE-G2.md §4
#   t18-real-host-report.sh report OPDIR AGDIR RENDERED PARAMS real|stand-in
#       reads both evidence directories and prints the report
#   t18-real-host-report.sh check REPORT
#       recomputes the OVERALL line of a stored report
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
cov-enoent-not-denied TestPX1T18DeniedReadMustBeEACCES $run_deploy checks
cov-searchable-dir TestPX1T18SearchableDirectory $run_deploy checks
cov-rpc-not-refused TestPX1T18RPCClassification $run_deploy checks
cov-probe-uid-gate TestPX1T18ProbeUIDGate $run_deploy checks
cov-verify-refusals TestPX1T18VerifyRefusals $run_deploy checks
cov-host-flow-tripwire TestPX1S5HostFlowTripwire $run_deploy checks
cov-readback-refusals TestPX1T18CustodyScript $run_deploy checks
cov-wallet-foreign-peer TestPX1T5ServiceRefusals $run_wallet px1-core-gate
cov-positive-request-client TestCoreActionClient $run_wallet w2-core
EOF
}

# positive_pin is the pin of the positive own-agent request (T18 item 2),
# which this qualification never sends.
positive_pin="pin=TestPX1CoreServiceG2FailClosed commit=$pinned_commit run=$run_wallet job=px1-core-gate"

covered_lines() {
	covered_table | while read -r id test run job; do
		echo "$id COVERED_BY_HOSTED pin=$test commit=$pinned_commit run=$run job=$job"
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
	# provisioned by Infra, so the apply and the activation are no-ops: nothing
	# is applied and nothing is started.
	set +e
	"$deploy_kit" g2-host-flow -params "$params" -sysusers true -- true >"$op/host-flow.out" 2>&1
	echo "host_flow_exit=$?" >>"$op/exits.txt"
	set -e
	user=$(json_member "$params" agent_user)
	id -- "$user" >"$op/account-id.txt" 2>&1 || true

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

	# Peer identity of the wallet socket: connect, SO_PEERCRED, no frame.
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

	if grep -qx host_flow_exit=0 "$op/exits.txt" 2>/dev/null && [ "$(cat "$op/host-flow.out" 2>/dev/null)" = G2_HOST_FLOW_ACTIVATED ]; then
		echo "account PASS steps=preflight,VerifyG2AgentAccount,group-set apply=noop activation=noop user=$user"
	else
		echo "account FAIL host_flow=$(file_line "$op/host-flow.out" | tr ' ' '_')"
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
	caps=$(awk '$1 ~ /^Cap(Prm|Eff|Amb):$/ { print $2 }' "$l" 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
	if [ "$u4" = "$uid,$uid,$uid,$uid" ] && [ "$g4" = "$gid,$gid,$gid,$gid" ] && [ "$gs" = "$want_gs" ] && [ "$(echo "$want_gs" | tr ',' '\n' | wc -l)" = 2 ] && [ "$caps" = 0000000000000000 ]; then
		echo "launch-form PASS uid=$u4 gid=$g4 groups=$gs caps=0"
	else
		echo "launch-form FAIL uid=${u4:-none} gid=${g4:-none} groups=${gs:-none} caps=${caps:-none} want_uid=$uid want_gid=$gid want_groups=$want_gs"
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
	status_seen=0
	for p in $reads; do
		o=$(probe_observed read "$p" "$cr") || o=
		case $o in
		EACCES | EPERM) echo "denied-read:$p PASS observed=$o" ;;
		*) echo "denied-read:$p FAIL observed=${o:-none}" ;;
		esac
		if [ "$p" = "$status_dir" ]; then
			status_seen=1
			case $o in
			EACCES | EPERM) echo "status-dir PASS path=$p observed=$o" ;;
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
	*" probe_exit=0 "*" verify_exit=0") ok=1 ;;
	*) ok=0 ;;
	esac
	if [ "$ok" = 1 ] && [ "$vf" = "T18_CUSTODY_VERIFIED $spec_sha" ]; then
		echo "custody-verify PASS $(echo "$ex" | tr ' ' ',') verified=$spec_sha"
	else
		echo "custody-verify FAIL exits=$(echo "${ex:-none}" | tr ' ' ',') verify=$(echo "${vf:-none}" | tr ' ' ',')"
	fi

	# The positive own-agent request is never sent here; the hosted test is
	# its evidence. A host run that did send it fails this item.
	rc=$(file_line "$ag/custody/positive-receipt.json")
	if [ "$ex" = credentials=refused ] && [ ! -e "$ag/custody/positive-request.json" ]; then
		echo "positive-request COVERED_BY_HOSTED $positive_pin host=not-run"
	else
		case $ex in
		*" positive_exit=3 "*) pe=1 ;;
		*) pe=0 ;;
		esac
		if [ "$pe" = 1 ] && [ "$rc" = "$stub_marker" ] && [ "$(wc -l <"$ag/custody/positive-receipt.json")" = 1 ]; then
			echo "positive-request COVERED_BY_HOSTED $positive_pin host=not-sent"
		else
			echo "positive-request FAIL host=request-sent-or-unknown"
		fi
	fi

	covered_lines
}

# ---------------------------------------------------------------- check
# check_report FILE: validate every line and print the recomputed OVERALL
# line. Exit 0 only when it is PASS and agrees with a stated OVERALL line.
check_report() {
	awk -v commit="$pinned_commit" -v rd="$run_deploy" -v rw="$run_wallet" -v covered="$(covered_table | awk '{ print $1 }' | tr '\n' ' ')" '
	function bad(why) { invalid++; reasons = reasons " " why }
	BEGIN {
		nreq = split("node-txindex render account agent-inputs launch-form credentials status-dir allowed-socket custody-verify positive-request " covered, req, " ")
	}
	NR == 1 {
		if ($1 != "T18-REAL-HOST" || $2 != "v1" || ($3 != "wallet=real" && $3 != "wallet=stand-in")) { bad("header"); next }
		wallet = substr($3, 8)
		for (i = 4; i <= NF; i++) { split($i, kv, "="); hdr[kv[1]] = kv[2] }
		next
	}
	/^#/ { next }
	/^OVERALL / { stated = $2; next }
	{
		id = $1; v = $2; ev = " " $0 " "
		if (NF < 3) bad("no-evidence:" id)
		if (seen[id]++) bad("duplicate:" id)
		if (v != "PASS" && v != "FAIL" && v != "STAND_IN" && v != "COVERED_BY_HOSTED") { bad("verdict:" id); next }
		count[v]++
		if (v == "FAIL") fail++
		if (v == "STAND_IN" && (id != "allowed-socket" || wallet != "stand-in")) bad("stand-in-misplaced:" id)
		if (v == "COVERED_BY_HOSTED") {
			if (ev !~ / pin=Test[A-Za-z0-9_]+ /) bad("no-pin:" id)
			if (ev !~ (" commit=" commit " ")) bad("no-commit:" id)
			if (ev !~ (" run=(" rd "|" rw ") ")) bad("no-run:" id)
			if (id != "positive-request" && id !~ /^cov-/) bad("covered-not-allowed:" id)
			if (id == "positive-request" && ev !~ / host=not-(sent|run) /) bad("request-not-shown-unsent")
		} else if (id ~ /^cov-/ || id == "positive-request") {
			if (v != "FAIL") bad("covered-item-verdict:" id)
		}
		if (id ~ /^denied-read:/) { nread++; if (v == "PASS" && ev !~ / observed=(EACCES|EPERM) /) bad("read-pass-without-eacces:" id) }
		if (id == "status-dir" && v == "PASS" && ev !~ / observed=(EACCES|EPERM) /) bad("status-pass-without-eacces")
		if (id ~ /^denied-rpc:/) { nrpc++; if (v == "PASS" && ev !~ / observed=(HTTP_401|HTTP_403|REFUSED) /) bad("rpc-pass-without-refusal:" id) }
		if (id == "allowed-socket" && v == "PASS") {
			if (wallet != "real") bad("wallet-pass-on-stand-in")
			if (ev !~ / probe=CONNECTED /) bad("wallet-pass-without-connect")
			if (!match(ev, / peer_uid=[0-9]+ /) || substr(ev, RSTART + 10, RLENGTH - 11) != hdr["service_uid"]) bad("wallet-pass-without-peer-identity")
		}
	}
	END {
		for (i = 1; i <= nreq; i++) if (req[i] != "" && !(req[i] in seen)) { missing++; reasons = reasons " missing:" req[i] }
		if (nread < 1) { missing++; reasons = reasons " missing:denied-read" }
		if (nrpc < 1) { missing++; reasons = reasons " missing:denied-rpc" }
		if (wallet == "") { invalid++; reasons = reasons " header" }
		overall = (fail + invalid + missing == 0) ? "PASS" : "FAIL"
		printf "OVERALL %s pass=%d stand_in=%d covered=%d fail=%d invalid=%d missing=%d\n", overall, count["PASS"], count["STAND_IN"], count["COVERED_BY_HOSTED"], fail, invalid, missing
		if (reasons != "") print "# reasons:" reasons
		if (stated != "" && stated != overall) { print "# stated OVERALL " stated " disagrees"; exit 1 }
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
	printf 'render_exit=0\nhost_flow_exit=0\n' >"$op/exits.txt"
	echo G2_HOST_FLOW_ACTIVATED >"$op/host-flow.out"
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
	expect real-wallet-all-pass 0 real '^OVERALL PASS pass=12 stand_in=0 covered=10 fail=0 invalid=0 missing=0$'
	expect stand-in-wallet 0 stand-in '^allowed-socket STAND_IN wallet=stand-in probe=CONNECTED '
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
	check_report "$w/edited.txt" >/dev/null && got=0 || got=$?
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
	check_report "$report_tmp"
	;;
check)
	[ "$#" -eq 1 ] && [ -f "$1" ] || usage
	check_report "$1"
	;;
self-test) self_test "$@" ;;
*) usage ;;
esac
