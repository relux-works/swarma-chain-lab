# Dynamic header response correction

This candidate keeps ElectrumX **2.0.1**, official commit
`39d477f31727ff95ce99694f6d8cb4a4cd7bd633`, with one transparent local patch.
The chain-lab prerequisite base is
`97cce72f2915c9da24351690e6216c3d0e45f252`; the exact patch, original file and
patched file SHA256 values are in [local-patch.json](local-patch.json).
Dependencies and upstream version are unchanged. This is a source candidate
requiring fresh independent review, not operational qualification.

## Protocol behavior established from the exact source

The authority for this correction is the pinned implementation, not a newer
server or an assumed Bitcoin header layout:

* `DB.read_headers(start, count)` reads the concatenated file interval
  `[header_offset(start), header_offset(start + actual_count))`. Offsets are
  absolute; the resulting byte buffer starts at zero. The DB may return fewer
  headers at its tip, or zero past its tip.
* `DB.dynamic_header_offset` reads big-endian 64-bit file offsets. Namecoin
  inherits `STATIC_BLOCK_HEADERS=False` and `TRUNCATED_HEADER_SIZE=80` from
  `AuxPowMixin`; Bitcoin uses its fixed 80-byte offset calculation.
* `ElectrumX.phandle_block_headers` returns concatenated `hex` before protocol
  1.6 and a `headers` array from 1.6. The requested count is capped at 2016;
  `count` reports the actual returned headers and `max` remains 2016.
* A nonzero checkpoint must cover the **last returned header**, and be at or
  below the DB tip. A checkpoint inside the requested returned range is an
  error, not an instruction to truncate only the covered portion. A zero-count
  reply has no checkpoint proof. The proof is for the last returned header.
* `AuxPoWElectrumX` preserves full AuxPoW for protocol below 1.4.1, or when
  `cp_height=0`. At protocol 1.4.1 and later with a nonzero valid checkpoint it
  keeps the base 80 bytes of each Namecoin header. This strips the extension;
  it does not itself validate AuxPoW, work, difficulty or a checkpoint's trust.
* Single-header responses use their separate existing path. Their checkpoint
  truncation is unchanged by this patch.

See the pinned primary files:
[session.py](https://github.com/spesmilo/electrumx/blob/39d477f31727ff95ce99694f6d8cb4a4cd7bd633/src/electrumx/server/session.py),
[db.py](https://github.com/spesmilo/electrumx/blob/39d477f31727ff95ce99694f6d8cb4a4cd7bd633/src/electrumx/server/db.py),
[db_util.py](https://github.com/spesmilo/electrumx/blob/39d477f31727ff95ce99694f6d8cb4a4cd7bd633/src/electrumx/server/db_util.py),
[coins.py](https://github.com/spesmilo/electrumx/blob/39d477f31727ff95ce99694f6d8cb4a4cd7bd633/src/electrumx/lib/coins.py).
All are supplied in the exact archive. External protocol documentation is linked
by upstream but was not added as a new unpinned input in this correction.

## Defect, fix and bounded scope

Unmodified `block_headers_array` starts at height zero and slices with absolute
file offsets. With dynamic headers it can split at the wrong boundaries or
consume several headers as one array item. The Namecoin checkpoint path then
truncates the wrong items. The retained exact call
`phandle_block_headers(100, 2, 101)` returns 400 bytes with `count=2` instead of
160 bytes, because the first five 80-byte slices are A,A,B,B,B instead of A,B.
The original reproducer exits 1, and the same script exits 0 after the patch.

The correction uses `header_offset(height + 1) - header_offset(start_height)`
for each returned height. It iterates the actual returned count and requires
each boundary to advance within the available bytes, with no trailing bytes.
Inconsistent array-path DB data raises the existing `DB.DBError` rather than
returning a success with a false count. Empty responses avoid any past-tip
offset access. No exception is hidden and no verifier is disabled.

The change is confined to the shared array helper. The legacy concatenated
`cp_height=0` path and older AuxPoW protocol path are intentionally unchanged;
they are control cases, not newly added corruption checks. Existing input
integer conversion, request-cost charging, chunk cap, checkpoint proof rules,
wire shapes and protocol gates are preserved. Per-request cost uses the original
requested count even when the 2016-header response cap applies.

## Tests and reproduction

`tools/test_header_offsets.py` runs 228 named cases against the exact pinned
DB reader, dynamic/static offset functions and protocol handlers. In-memory file
contents and checkpoint tree leaves are synthetic. Proof formatting and bounds
use production code; the synthetic leaves are not trusted real checkpoints.

The same matrix passes **228/228** with the patch and **187/228** unmodified.
The 41 failures include the affected boundaries and absent inconsistency guards;
unchanged cases pass on both versions. The separate exact historical reproducer
preserves the original 400-byte failure. The existing 32 synthetic fixtures also
pass with the candidate, including AuxPoW parsing and a native DB reopen.

Coverage includes starts 0, 1 and 100; mixed plain/AuxPoW dynamic lengths;
checkpoint exactly at the last header, later, before it and above the tip;
protocol 1.4.0/1.4.1/1.4.3/1.6; fixed Bitcoin headers; partial tip reads;
zero count and past-tip reads; negative/malformed parameters; 2017 and one
billion requested headers capped to 2016; single-header controls; short/extra
DB bytes and mismatched actual counts. No public server or listener is used.

For the complete original native build, run `tools/build_offline.sh` using
`tools/offline_sandbox.sh`. For this Python-only correction, use
`tools/build_header_candidate.sh`: it verifies exact artifacts, applies the
patch only to the exact original file, builds the wheel and runs dependency,
reproducer, header matrix and existing fixture checks on the installed wheel.
Use a fresh private scratch directory for each build. The narrower build reuses
the exact sealed plyvel/LevelDB binaries and their ABI; it makes no new native
or cross-platform reproducibility claim. Full artifact hashes and actual
start/end/exit receipts travel with the candidate.

No live SPV chain, signed name transaction, server authentication, reorg,
index resource bound or notification latency is established by these tests.
