#!/bin/bash
# Only the sandbox launcher runs on the host. The generator runs offline below.
set -euo pipefail
umask 077
src=$(cd -- "$(dirname -- "$0")" && pwd)
out=${1:?supply an empty absolute task-owned output directory, mode 0700}
[[ "$out" = /* && -d "$out" && ! -L "$out" && -O "$out" ]]
[[ $(stat -c %a -- "$out") = 700 ]]
[[ -z $(find "$out" -mindepth 1 -maxdepth 1 -print -quit) ]]
ulimit -v 2097152
ulimit -f 32768
ulimit -t 60
exec timeout --signal=TERM --kill-after=10s 120s \
 bwrap --unshare-all --clearenv --new-session --die-with-parent --cap-drop ALL \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --proc /proc --dev /dev --dir /etc --dir /home \
 --ro-bind "$src" /src --bind "$out" /out --size 67108864 --tmpfs /work \
 --setenv PATH /usr/bin:/bin --setenv HOME /work/home --setenv TMPDIR /work/tmp \
 --setenv XDG_CACHE_HOME /work/cache --setenv PYTHONDONTWRITEBYTECODE 1 \
 --setenv LC_ALL C.UTF-8 --chdir /work \
 /bin/bash -c 'mkdir -m 700 /work/home /work/tmp /work/cache; exec python3 /src/design.py --output /out'
