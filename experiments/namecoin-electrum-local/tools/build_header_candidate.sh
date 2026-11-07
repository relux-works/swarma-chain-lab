#!/bin/bash
# Execute within offline_sandbox.sh; all output is private build scratch.
set -euo pipefail
umask 077
base=/src/experiments/namecoin-electrum-local
export SOURCE_DATE_EPOCH=1793808703
python3 "$base/tools/verify_inputs.py"
mkdir -m700 -p /scratch/header-buildsite /scratch/header-source /scratch/header-wheels /scratch/header-runtime /scratch/prefix/lib
export PYTHONPATH=/scratch/header-buildsite
python3 -m pip install --no-index --no-deps --no-compile --require-hashes \
 --find-links /artifacts/wheels --target /scratch/header-buildsite -r "$base/requirements-build.lock"
tar xzf /artifacts/wheels/e_x-2.0.1.tar.gz -C /scratch/header-source --strip-components=1
python3 "$base/tools/apply_header_patch.py" /scratch/header-source
python3 -m pip wheel --no-index --no-deps --no-build-isolation --wheel-dir /scratch/header-wheels /scratch/header-source
python3 -m pip install --no-index --no-deps --no-compile --target /scratch/header-runtime \
 /scratch/header-wheels/*.whl /artifacts/built/plyvel-1.5.1-cp314-cp314-linux_x86_64.whl \
 $(python3 "$base/tools/verify_inputs.py" --runtime-paths)
cp /artifacts/built/libleveldb.so.1.23.0 /scratch/prefix/lib/
ln -s libleveldb.so.1.23.0 /scratch/prefix/lib/libleveldb.so.1
export PYTHONPATH=/scratch/header-runtime LD_LIBRARY_PATH=/scratch/prefix/lib
python3 "$base/tools/check_dependencies.py"
python3 "$base/tools/reproduce_header_boundary.py"
python3 "$base/tools/test_header_offsets.py"
python3 "$base/tools/offline_fixture.py"
sha256sum /scratch/header-wheels/*.whl
