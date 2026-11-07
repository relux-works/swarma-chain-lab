#!/bin/bash
set -euo pipefail
umask 077
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
ulimit -n 512
ulimit -f 65536
ulimit -t 1200
exec timeout --signal=TERM --kill-after=30s 1500s bwrap --unshare-all --clearenv --new-session --die-with-parent --cap-drop ALL \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --proc /proc --dev /dev --dir /etc --dir /home --ro-bind /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt \
 --ro-bind "$root/source" /src --ro-bind "$root/tools" /tools --ro-bind "$root/scratch/runtimepack" /runtime \
 --size 1610612736 --tmpfs /lab --chdir /lab \
 --setenv PATH /usr/bin:/bin --setenv HOME /lab/home --setenv TMPDIR /lab/tmp --setenv XDG_CACHE_HOME /lab/cache \
 --setenv PYTHONDONTWRITEBYTECODE 1 --setenv PYTHONPATH /runtime/site --setenv LD_LIBRARY_PATH /runtime/lib --setenv LC_ALL C.UTF-8 \
 python3 /tools/lab.py "$@"
