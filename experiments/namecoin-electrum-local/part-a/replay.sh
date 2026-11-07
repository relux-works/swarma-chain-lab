#!/bin/bash
set -euo pipefail
umask 077
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
ulimit -v 2097152
ulimit -f 65536
ulimit -t 120
exec timeout --signal=TERM --kill-after=10s 180s bwrap --unshare-all --clearenv --new-session --die-with-parent --cap-drop ALL \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --proc /proc --dev /dev --dir /etc --dir /home \
 --ro-bind "$root/inputs/proof-evidence.json" /inputs/proof-evidence.json --ro-bind "$root/tools" /tools \
 --ro-bind "$root/scratch/runtimepack/site" /runtime/site --ro-bind "$root/scratch/runtimepack/lib" /runtime/lib \
 --bind "$root/scratch/home" /scratch/home --bind "$root/scratch/tmp" /scratch/tmp --bind "$root/scratch/cache" /scratch/cache \
 --setenv PATH /usr/bin:/bin --setenv HOME /scratch/home --setenv TMPDIR /scratch/tmp --setenv XDG_CACHE_HOME /scratch/cache \
 --setenv PYTHONDONTWRITEBYTECODE 1 --setenv PYTHONPATH /runtime/site --setenv LD_LIBRARY_PATH /runtime/lib --setenv LC_ALL C.UTF-8 \
 --chdir /scratch python3 /tools/verify_protocol_evidence.py
