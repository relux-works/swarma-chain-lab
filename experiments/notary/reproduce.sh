#!/bin/bash
# Fresh separately admitted replay only; immutable records are never rewritten.
set -euo pipefail
umask 077
export NOTARY_LAB_ROOT=${NOTARY_LAB_ROOT:?set an absolute disposable root ending in notary-lab}
b=$(/usr/bin/python3 -B -c 'import sys; sys.path.insert(0,"source"); from lab_paths import lab_root; print(lab_root())')
python3 - <<'PY'
import datetime,json
from pathlib import Path
x=json.loads(Path('receipt/correction-acceptance.json').read_text())
old=json.loads(Path('receipt/original-acceptance.json').read_text())
assert x['at']=='2026-11-07T02:39:49.302713+00:00'
assert old['at']=='2026-11-07T01:48:54.605930+00:00'
assert datetime.datetime.now(datetime.timezone.utc)<datetime.datetime.fromisoformat('2026-11-07T03:16:00+00:00'),'NOT_RUN: immutable runtime cutoff expired'
assert x['deadline']=='2026-11-07T03:24:49.302713+00:00'
PY
mkdir -p input evidence
curl --fail --location --max-time 120 --max-filesize 60000000 --proto '=https' \
 https://www.namecoin.org/files/namecoin-core/namecoin-core-28.0/namecoin-28.0-x86_64-linux-gnu.tar.gz \
 --output input/namecoin-28.0-x86_64-linux-gnu.tar.gz
mkdir -m 700 input/replay-public-gnupg
env -i PATH=/usr/bin:/bin GNUPGHOME="$PWD/input/replay-public-gnupg" gpg --batch --no-autostart --no-auto-key-retrieve --import upstream/RoseTuring.asc
env -i PATH=/usr/bin:/bin GNUPGHOME="$PWD/input/replay-public-gnupg" gpg --batch --no-autostart --no-auto-key-retrieve --status-fd=1 --verify upstream/noncodesigned.SHA256SUMS.asc upstream/noncodesigned.SHA256SUMS > evidence/replay-signature.txt 2>&1
rg -q 'VALIDSIG FD8366A807A99FA27FD9CCEA9FE3BFDDA6C53495 ' evidence/replay-signature.txt
python3 source/phase-check.py replay-before-runtime
python3 source/prepare-lab.py
sudo -n -u lab -i env -i PATH=/usr/bin:/bin NOTARY_LAB_ROOT="$b" /bin/bash "$b/source/sandbox.sh" /usr/bin/python3 -B /source/offline-counterexamples.py /source/baseline-lab.py > evidence/replay-before.json
sudo -n -u lab -i env -i PATH=/usr/bin:/bin NOTARY_LAB_ROOT="$b" /bin/bash "$b/source/sandbox.sh" /usr/bin/python3 -B /source/offline-counterexamples.py /source/lab.py > evidence/replay-after.json
set +e
sudo -n -u lab -i env -i PATH=/usr/bin:/bin NOTARY_LAB_ROOT="$b" /bin/bash "$b/source/sandbox.sh" > evidence/replay.stdout 2> evidence/replay.stderr
rc=$?
set -e
# Preserve this controller receipt before export runs under a new supervisor.
sudo -n -u lab -i env -i PATH=/usr/bin:/bin /usr/bin/cp "$b/public/supervision.json" "$b/public/node-supervision.json"
sudo -n -u lab -i env -i PATH=/usr/bin:/bin NOTARY_LAB_ROOT="$b" /bin/bash "$b/source/sandbox.sh" /usr/bin/python3 -B /source/export.py
mkdir -p replay-public
sudo -n -u lab -i env -i PATH=/usr/bin:/bin /usr/bin/tar -c -C "$b/public/export" . | tar -x -C replay-public
if [[ $rc = 0 ]]; then
 sudo -n -u lab -i env -i PATH=/usr/bin:/bin NOTARY_LAB_ROOT="$b" /usr/bin/python3 -B "$b/source/cleanup.py" > evidence/replay-cleanup.json
fi
exit "$rc"
