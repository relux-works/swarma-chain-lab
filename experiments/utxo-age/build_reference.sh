#!/bin/bash
# Invoke only inside an offline filesystem/network sandbox.
set -euo pipefail
umask 077
upstream=${1:?absolute pinned source directory required}
work=${2:?absolute private work directory required}
case "$upstream:$work" in /*:/*) ;; *) exit 2 ;; esac
src=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cmake -S "$upstream/src/secp256k1" -B "$work/native" \
  -DSECP256K1_BUILD_TESTS=OFF -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF \
  -DSECP256K1_BUILD_BENCHMARK=OFF -DBUILD_SHARED_LIBS=OFF \
  -DSECP256K1_ENABLE_MODULE_RECOVERY=ON
cmake --build "$work/native" -j 2
units=(compressor.cpp pubkey.cpp script/names.cpp script/script.cpp
  support/cleanse.cpp util/strencodings.cpp hash.cpp crypto/sha256.cpp
  crypto/hex_base.cpp uint256.cpp)
files=()
for unit in "${units[@]}"; do files+=("$upstream/src/$unit"); done
g++ -std=c++20 -O1 -ffunction-sections -fdata-sections -Wl,--gc-sections \
  -I"$src" -I"$upstream/src" -I"$upstream/src/secp256k1/include" \
  "$src/native_reference.cpp" "${files[@]}" "$work/native/src/libsecp256k1.a" \
  -o "$work/native-reference"
"$work/native-reference" > "$work/native.json"
