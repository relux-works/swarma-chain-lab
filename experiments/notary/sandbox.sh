#!/bin/bash
set -euo pipefail
[[ $(id -u) = 1002 ]]
umask 077
b=$(/usr/bin/python3 -B -c 'import sys; sys.path.insert(0,sys.argv[1]); from lab_paths import lab_root; print(lab_root())' "$(dirname -- "$0")")
if [[ $# = 0 ]]; then set -- /usr/bin/python3 -B /source/lab.py; fi
exec /usr/bin/timeout --signal=TERM --kill-after=10s 2110s /usr/bin/bwrap --unshare-all --clearenv --die-with-parent --new-session --cap-drop ALL \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --proc /proc --dev /dev --tmpfs /tmp --dir /etc --dir /run --dir /home \
 --ro-bind "$b/source/lab.passwd" /etc/passwd --ro-bind "$b/source/lab.group" /etc/group \
 --ro-bind "$b/source" /source --ro-bind "$b/bin" /runtime \
 --bind "$b/private" /private --bind "$b/public" /public \
 --setenv HOME /private/home --setenv TMPDIR /private/tmp --setenv XDG_CACHE_HOME /private/cache \
 --setenv PATH /usr/bin:/bin --setenv LANG C.UTF-8 --setenv TZ UTC \
 --chdir /private /usr/bin/python3 -B /source/supervise.py "$@"
