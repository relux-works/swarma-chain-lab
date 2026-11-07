#!/bin/bash
# Reproduce admission and causal fixtures; this does not execute a node.
set -euo pipefail
umask 077
if [[ $# -ne 5 ]]; then
 echo 'usage: reproduce.sh ABS_PLAN ABS_ACCEPTANCE ABS_PUBLIC_INPUT_DIR ABS_PUBLIC_COMPONENTS_DIR ABS_NEW_STATE_DIR' >&2
 exit 2
fi
src=$(cd -- "$(dirname -- "$0")" && pwd)
plan=$(realpath -e -- "$1")
acceptance=$(realpath -e -- "$2")
inputs=$(realpath -e -- "$3")
components=$(realpath -e -- "$4")
state=$5
[[ "$state" = /* && ! -e "$state" ]]
mkdir -m 700 -- "$state"
mkdir -m 700 -- "$state/home" "$state/tmp" "$state/cache"
ulimit -t 120
ulimit -f 49152
ulimit -v 1048576
ulimit -n 128
common=(bwrap --unshare-all --clearenv --new-session --die-with-parent --cap-drop ALL
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64
 --proc /proc --dev /dev --tmpfs /etc --tmpfs /home --tmpfs /run
 --ro-bind "$src" /src --ro-bind "$inputs" /inputs --ro-bind "$components" /components
 --ro-bind "$plan" /plan.json --ro-bind "$acceptance" /acceptance.json --bind "$state" /private
 --setenv HOME /private/home --setenv TMPDIR /private/tmp --setenv XDG_CACHE_HOME /private/cache
 --setenv PATH /usr/bin:/bin --setenv LC_ALL C.UTF-8 --setenv PYTHONDONTWRITEBYTECODE 1 --chdir /private)
# Private static account files support OpenSSH's public signature verification.
printf 'lab:x:%s:%s:Lab:/private/home:/bin/false\n' "$(id -u)" "$(id -g)" > "$state/passwd"
printf 'lab:x:%s:\n' "$(id -g)" > "$state/group"
common+=(--ro-bind "$state/passwd" /etc/passwd --ro-bind "$state/group" /etc/group)
timeout --signal=TERM --kill-after=5s 180s "${common[@]}" /usr/bin/python3 -B /src/test_assembly.py
timeout --signal=TERM --kill-after=5s 180s "${common[@]}" /usr/bin/python3 -B /src/assembly.py --plan /plan.json --acceptance /acceptance.json
