# Offline fixture reconstruction

Use only the exact archive named in FORMAT.md. Verify its SHA-256 and official
detached checksum signature before extraction. The signing fingerprint is
`FD8366A807A99FA27FD9CCEA9FE3BFDDA6C53495`; verifying a signature alone does
not establish OpenPGP ownertrust. The runtime analysis has no third-party
Python modules. The reference uses only the pinned bundled secp256k1, system
C/C++ compiler and CMake; do not download modules or upgrade dependencies.

Create dedicated absolute source, upstream, work and input paths. Make the
private work, HOME, TMPDIR and cache directories mode 0700; do not reuse a host
home or cache. Extract the pinned archive in an offline namespace into its own
directory. For subsequent checks mount source and extracted upstream read-only,
tools (/usr and required library trees) read-only, and only that private work
tree writable. Use bwrap `--unshare-all --clearenv --die-with-parent
--new-session`, private /proc and /dev, no `--share-net`, and no host home,
credentials, keys, agent sockets or foreign caches. Set HOME=/work/home,
TMPDIR=/work/tmp, XDG_CACHE_HOME=/work/cache, PATH=/usr/bin,
PYTHONDONTWRITEBYTECODE=1 and LC_ALL=C. Apply the limits in CONTRACT.md.

Mount this experiment directory (`experiments/utxo-age/`), rather than the
repository root, at /src. With pinned extracted source at
/upstream/namecoin-28.0 and private work at /work, run these **inside** that
sandbox:

```sh
bash /src/build_reference.sh /upstream/namecoin-28.0 /work
cmp /work/native.json /src/fixtures/native.json
python3 /src/make_fixtures.py /work/native.json /work/regenerated
cmp /work/regenerated/canonical.dat /src/fixtures/canonical.dat
cmp /work/regenerated/headers.bin /src/fixtures/headers.bin
cmp /work/regenerated/binding.json /src/fixtures/binding.json
python3 -m unittest discover -s /src -p test_canonical.py -v
python3 /src/canonical.py /src/fixtures/canonical.dat /src/fixtures/headers.bin /src/fixtures/binding.json
```

The native encoder calls pinned SnapshotMetadata, Coin, ScriptCompression,
AmountCompression, CompactSize/VARINT and CNameScript implementations; each
native Coin also decodes and reencodes byte-identically. Its full synthetic
container uses the grouped writer's serialization operations. Its serialized
UTXO hash uses native field serializers in the order of kernel/coinstats.cpp.
The standalone portable SHA256 config enables no node or consensus changes.
The CMake build compiles only the bundled crypto library and reference units,
not a daemon. CMake/compiler warnings must remain in check evidence.

The fixture pack replaces only the native reference metadata's artificial
base hash with the separately generated synthetic header tip; it verifies all
other container bytes against the full native-encoded container. Every
creation height is known, and exact age boundaries are independently asserted
from the fixture rows. Malformed tests mutate or truncate these tiny known
inputs, including every truncation offset. No real chain input is needed.
