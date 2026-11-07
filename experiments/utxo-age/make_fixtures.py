"""Package explicitly synthetic native-encoded records; never generate chain data."""
import hashlib
import json
from pathlib import Path
import struct
import sys

import canonical as c


def compact(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def generate(reference, dest):
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    ref = 2_000_000_000
    dates = [ref - 10*c.YEAR, ref - 5*c.YEAR, ref - 2*c.YEAR,
             ref - c.YEAR, ref, ref]
    previous, headers = bytes(32), b""
    for date in dates:
        raw = struct.pack("<I", 1) + previous + bytes(32) + struct.pack("<III", date, 0, 0)
        previous = c.double_sha(raw)
        headers += raw
    base = previous[::-1].hex()
    # Metadata bytes originate in SnapshotMetadata::Serialize. Only bind the
    # synthetic header-chain tip in place of the native reference's 00..1f hash.
    header = bytes.fromhex(reference["header_hex"])
    assert header == c.MAGIC + bytes(range(32)) + struct.pack("<Q", len(reference["coins"]))
    dump = header[:11] + previous + header[43:]
    for i, row in enumerate(reference["coins"]):
        dump += bytes([i + 1]) + bytes(31) + compact(1) + compact(0) + bytes.fromhex(row["coin_hex"])
    native_container = bytes.fromhex(reference["snapshot_hex"])
    assert dump[:11] + bytes(range(32)) + dump[43:] == native_container
    rows = reference["coins"]
    ordinary = sum(r["value"] for r in rows if r["kind"] == "ordinary")
    names = sum(r["value"] for r in rows if r["kind"] != "ordinary")
    binding = {"schema": "namecoin-age-fixture/1", "fixture": True,
        "height": 5, "base_hash": base, "native_height": 5,
        "dump_sha256": hashlib.sha256(dump).hexdigest(),
        "dump_txoutset_hash": reference["stats_hash"],
        "headers_sha256": hashlib.sha256(headers).hexdigest(),
        "native_txouts": len(rows), "native_transactions": len(rows),
        "native_atoms": {"coins": ordinary, "names": names, "total": ordinary + names}}
    for field in ("tip_before", "tip_after", "chainstate_before", "chainstate_after", "native_bestblock"):
        binding[field] = base
    (dest / "canonical.dat").write_bytes(dump)
    (dest / "headers.bin").write_bytes(headers)
    (dest / "binding.json").write_text(json.dumps(binding, sort_keys=True, indent=2) + "\n")
    (dest / "README.txt").write_text(
        "SYNTHETIC ONLY. Native Namecoin encodings, fabricated zero-work headers.\n"
        "Not real UTXOs, addresses, proof of work, transactions or statistics.\n"
        "Six header dates deliberately exercise exactly 1/2/5/10 fixed-365-day-year boundaries.\n")


if __name__ == "__main__":
    with open(sys.argv[1]) as stream:
        generate(json.load(stream), Path(sys.argv[2]))
