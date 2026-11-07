#!/bin/bash
# Namespace/stdio launch plumbing only. All source, tests and the Go relay run
# inside separate offline namespaces. Never import a product module on the host.
set -euo pipefail
umask 077
source_root=${1:?source checkout}
python_root=${2:?Python toolchain root}
go_root=${3:?Go toolchain root}
scratch=${4:?fresh private scratch}
test "$source_root" = "${source_root#/}" && exit 64
test "$scratch" = "${scratch#/}" && exit 64
mkdir -m 700 "$scratch/channels" "$scratch/build" "$scratch/relay" "$scratch/tests"
for box in build relay tests; do
  mkdir -m 700 "$scratch/$box/home" "$scratch/$box/tmp" "$scratch/$box/cache"
done
for name in tests verifier-{0..3}; do
  mkfifo -m 600 "$scratch/channels/$name.in" "$scratch/channels/$name.out" "$scratch/channels/$name.exit"
done
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT
common=(/bin/bash -c 'for entry in /proc/self/fd/*; do fd=${entry##*/}; if ((fd > 2)); then eval "exec $fd>&-"; fi; done; exec "$@"' close-fds
  /usr/bin/bwrap --unshare-all --clearenv --new-session --die-with-parent --cap-drop ALL
  --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64
  --proc /proc --dev /dev --dir /etc --dir /home
  --setenv PATH /usr/bin:/bin --setenv LC_ALL C.UTF-8 --setenv PYTHONDONTWRITEBYTECODE 1)
private=(--setenv HOME /work/home --setenv TMPDIR /work/tmp --setenv XDG_CACHE_HOME /work/cache)
ulimit -t 240
ulimit -f 262144
ulimit -n 256
# No external modules. Build before execution, offline, with a new private cache.
"${common[@]}" --ro-bind "$source_root" /source --ro-bind "$go_root" "$go_root" \
  --bind "$scratch/build" /work "${private[@]}" --setenv GOROOT "$go_root" \
  --setenv GOCACHE /work/cache --setenv GOPATH /work/tmp/gopath --setenv GOPROXY off \
  --setenv GOSUMDB off --setenv GOTOOLCHAIN local --setenv CGO_ENABLED 0 \
  --chdir /source/experiments/fullnode-trusts /bin/bash -ec \
  'sha256sum -c test-inputs/SHA256SUMS; exec "$@"' pinned-inputs \
  "$go_root/bin/go" build -trimpath -o /work/relay /source/.github/scripts/fullnode-relay.go
(
  set +e
  "${common[@]}" --ro-bind "$source_root" /source --ro-bind "$python_root" /tools/python \
    --bind "$scratch/tests" /work "${private[@]}" \
    --setenv PATH /tools/python/bin:/usr/bin:/bin \
    --setenv LD_LIBRARY_PATH /tools/python/lib --chdir /source \
    /bin/bash /source/.github/scripts/offline-checks.sh fullnode-trusts \
    < "$scratch/channels/tests.in" > "$scratch/channels/tests.out"
  rc=$?
  printf '%s\n' "$rc" > "$scratch/channels/tests.exit"
  exit "$rc"
) &
pids+=("$!")
for n in {0..3}; do
  (
    set +e
    child_pids=()
    child_cleanup() {
      for pid in "${child_pids[@]}"; do kill "$pid" 2>/dev/null || true; done
      for pid in "${child_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    }
    trap child_cleanup EXIT
    trap 'exit 143' TERM INT
    exec 3< <(/bin/cat "$scratch/channels/verifier-$n.in")
    child_pids+=("$!")
    exec 4> >(/bin/cat > "$scratch/channels/verifier-$n.out")
    child_pids+=("$!")
    "${common[@]}" --dir /src \
      --ro-bind "$source_root/experiments/fullnode-trusts/protocol.py" /src/protocol.py \
      --ro-bind "$source_root/experiments/fullnode-trusts/pipe_verify.py" /src/pipe_verify.py \
      --size 16777216 --tmpfs /private \
      --dir /private/home --chmod 0700 /private/home \
      --dir /private/tmp --chmod 0700 /private/tmp \
      --dir /private/cache --chmod 0700 /private/cache \
      --setenv HOME /private/home --setenv TMPDIR /private/tmp --setenv XDG_CACHE_HOME /private/cache \
      --chdir /private /usr/bin/python3 -I -B -c '
import json, sys, traceback
sys.excepthook = lambda kind, value, tb: print(json.dumps({"type": "startup_error", "exception": kind.__name__, "frames": [[f.filename, f.lineno] for f in traceback.extract_tb(tb)]}), flush=True)
sys.path.insert(0,"/src")
import pipe_verify' \
      <&3 >&4 2>/dev/null &
    verifier_pid=$!
    child_pids+=("$verifier_pid")
    exec 3<&- 4>&-
    wait "$verifier_pid"
    rc=$?
    printf '%s\n' "$rc" > "$scratch/channels/verifier-$n.exit"
    exit "$rc"
  ) &
  pids+=("$!")
done
"${common[@]}" --ro-bind "$scratch/build/relay" /tools/relay \
  --bind "$scratch/relay" /work --bind "$scratch/channels" /channels "${private[@]}" \
  --chdir /work /tools/relay
