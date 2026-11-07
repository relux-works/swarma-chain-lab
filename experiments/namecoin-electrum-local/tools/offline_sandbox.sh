#!/bin/bash
# Administrative wrapper: mount only explicit public inputs and private scratch.
set -euo pipefail
umask 077
if (( $# < 4 )); then
    printf 'usage: %s ABS_SOURCE ABS_ARTIFACTS ABS_PRIVATE_SCRATCH COMMAND [ARG...]\n' "$0" >&2
    exit 64
fi
for input in "$1" "$2" "$3"; do
    [[ $input == /* ]] || { printf 'absolute paths required\n' >&2; exit 64; }
done
source_dir=$(realpath -e -- "$1")
artifact_dir=$(realpath -e -- "$2")
scratch_dir=$(realpath -e -- "$3")
shift 3
[[ $scratch_dir != / && $scratch_dir != "$source_dir" && $scratch_dir != "$artifact_dir" ]]
[[ $(stat -c %a -- "$scratch_dir") == 700 ]]
[[ $(stat -c %u -- "$scratch_dir") == "$(id -u)" ]]
for name in home tmp cache; do
    [[ ! -L $scratch_dir/$name ]]
    mkdir -m700 -p -- "$scratch_dir/$name"
    [[ $(stat -c %a -- "$scratch_dir/$name") == 700 ]]
done
ulimit -v 2097152
ulimit -f 65536
ulimit -t 120
exec timeout --signal=TERM --kill-after=10s 180s \
 bwrap --unshare-all --clearenv --new-session --die-with-parent --cap-drop ALL \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --proc /proc --dev /dev --dir /etc --dir /home \
 --ro-bind /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt \
 --ro-bind "$source_dir" /src --ro-bind "$artifact_dir" /artifacts \
 --bind "$scratch_dir" /scratch --chdir /src \
 --setenv PATH /usr/bin:/bin --setenv HOME /scratch/home --setenv TMPDIR /scratch/tmp \
 --setenv XDG_CACHE_HOME /scratch/cache --setenv PIP_CACHE_DIR /scratch/cache/pip \
 --setenv PYTHONDONTWRITEBYTECODE 1 --setenv PYTHONPATH /scratch/runtime \
 --setenv LD_LIBRARY_PATH /scratch/prefix/lib --setenv LC_ALL C.UTF-8 \
 --setenv PIP_NO_INDEX 1 --setenv PIP_DISABLE_PIP_VERSION_CHECK 1 \
 "$@"
