#!/bin/bash
set -euo pipefail
umask 077
if [[ $# -lt 3 ]]; then
  echo 'usage: run.sh ABSOLUTE_CORE_BIN_DIR ABSOLUTE_EXECUTION_DEADLINE_UNIX NETWORK' >&2
  exit 2
fi
src=$(cd -- "$(dirname -- "$0")" && pwd)
core=$(realpath -e -- "$1")
[[ "$core" = /* && -f "$core/namecoind" ]]
ulimit -n 512
ulimit -f 65536
ulimit -t 1200
exec timeout --signal=TERM --kill-after=30s 1500s \
 /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C.UTF-8 \
 /usr/bin/python3 -B "$src/runner.py" "$core" "$2" "$3"
