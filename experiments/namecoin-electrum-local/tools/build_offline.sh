#!/bin/bash
# Run only inside the documented offline sandbox, with fixed mount points.
set -euo pipefail
umask 077
export SOURCE_DATE_EPOCH=1793808703
export CXXFLAGS=-fno-rtti CFLAGS=-fno-rtti
base=/src/experiments/namecoin-electrum-local
# All mutable paths are private sandbox scratch, never source or system paths.
rm -rf /scratch/buildsite /scratch/runtime /scratch/build /scratch/prefix /scratch/wheelout
mkdir -m700 -p /scratch/buildsite /scratch/runtime /scratch/build /scratch/prefix /scratch/wheelout
export PYTHONPATH=/scratch/buildsite
python3 -m pip install --no-index --no-deps --no-compile --require-hashes --find-links /artifacts/wheels --target /scratch/buildsite -r "$base/requirements-build.lock"
python3 "$base/tools/verify_inputs.py"
mkdir /scratch/build/leveldb /scratch/build/plyvel /scratch/build/electrumx
tar xzf /artifacts/leveldb-1.23.tar.gz -C /scratch/build/leveldb --strip-components=1
cmake -S /scratch/build/leveldb -B /scratch/build/leveldb/build \
 -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
 -DLEVELDB_BUILD_TESTS=OFF -DLEVELDB_BUILD_BENCHMARKS=OFF \
 -DHAVE_SNAPPY=OFF -DHAVE_CRC32C=OFF \
 -DLEVELDB_INSTALL=ON -DCMAKE_INSTALL_PREFIX=/scratch/prefix -DCMAKE_INSTALL_LIBDIR=lib
cmake --build /scratch/build/leveldb/build --parallel 2
cmake --install /scratch/build/leveldb/build
tar xzf /artifacts/wheels/plyvel-1.5.1.tar.gz -C /scratch/build/plyvel --strip-components=1
export CPLUS_INCLUDE_PATH=/scratch/prefix/include LIBRARY_PATH=/scratch/prefix/lib LD_LIBRARY_PATH=/scratch/prefix/lib
python3 -m pip wheel --no-index --no-deps --no-build-isolation --wheel-dir /scratch/wheelout /scratch/build/plyvel
# Build the verified PyPI source; verify_inputs checks its Python source against
# the separately authenticated official Git tag archive.
tar xzf /artifacts/wheels/e_x-2.0.1.tar.gz -C /scratch/build/electrumx --strip-components=1
python3 "$base/tools/apply_header_patch.py" /scratch/build/electrumx
python3 -m pip wheel --no-index --no-deps --no-build-isolation --wheel-dir /scratch/wheelout /scratch/build/electrumx
python3 -m pip install --no-index --no-deps --no-compile --require-hashes --find-links /artifacts/wheels --target /scratch/runtime -r "$base/requirements-runtime-wheels.lock" --dry-run
# Install in one invocation so console entry points are not lost to target/bin collisions.
python3 -m pip install --no-index --no-deps --no-compile --target /scratch/runtime \
 /scratch/wheelout/*.whl \
 $(python3 "$base/tools/verify_inputs.py" --runtime-paths)
export PYTHONPATH=/scratch/runtime
python3 "$base/tools/check_dependencies.py"
python3 "$base/tools/offline_fixture.py"
python3 "$base/tools/reproduce_header_boundary.py"
python3 "$base/tools/test_header_offsets.py"
sha256sum /scratch/wheelout/*.whl /scratch/prefix/lib/libleveldb.so.1.23.0
