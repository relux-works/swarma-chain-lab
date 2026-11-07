import copy
import hashlib
import io
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

import canonical as c
from make_fixtures import compact

ROOT = Path(__file__).parent / "fixtures"
NATIVE = json.loads((ROOT / "native.json").read_text())
BIND = json.loads((ROOT / "binding.json").read_text())
DUMP = (ROOT / "canonical.dat").read_bytes()
HEADERS = (ROOT / "headers.bin").read_bytes()
BASE = BIND["base_hash"]


def one(coin, count=1, index=0, group=None):
    return (c.MAGIC + bytes.fromhex(BASE)[::-1] + struct.pack("<Q", count) +
            b"\x01" + bytes(31) + (compact(count) if group is None else group) +
            compact(index) + coin)


def decode(data, height=5, budget=c.Budget()):
    return list(c.Decoder(io.BytesIO(data), BASE, height, budget))


class NativeParity(unittest.TestCase):
    def test_native_full_container_and_stats_hash(self):
        decoder = c.Decoder(io.BytesIO(bytes.fromhex(NATIVE["snapshot_hex"])),
                            bytes(range(32))[::-1].hex(), 5)
        self.assertEqual(len(list(decoder)), len(NATIVE["coins"]))
        self.assertEqual(decoder.coinstats_hash, NATIVE["stats_hash"])

    def test_native_metadata(self):
        self.assertEqual(bytes.fromhex(NATIVE["header_hex"]),
                         c.MAGIC + bytes(range(32)) + struct.pack("<Q", len(NATIVE["coins"])))

    def test_native_coins_and_name_classifier(self):
        for row in NATIVE["coins"]:
            with self.subTest(row=row):
                coin, = decode(one(bytes.fromhex(row["coin_hex"])))
                self.assertEqual((coin.height, coin.coinbase, coin.value, coin.script.hex(), coin.kind),
                                 (row["height"], row["coinbase"], row["value"], row["script_hex"], row["kind"]))

    def test_native_integer_encodings(self):
        for row in NATIVE["integers"]:
            v = row["value"]
            self.assertEqual(c.varint_bytes(v).hex(), row["varint"])
            self.assertEqual(compact(v).hex(), row["compact"])
            self.assertEqual(c.Reader(io.BytesIO(bytes.fromhex(row["varint"])), c.Budget()).varint(), v)
            self.assertEqual(c.Reader(io.BytesIO(bytes.fromhex(row["compact"])), c.Budget()).compact(c.U64), v)

    def test_all_compression_tags(self):
        # Each record has a single-byte height code and amount VARINT of varying width.
        tags = set()
        for row in NATIVE["coins"]:
            reader = c.Reader(io.BytesIO(bytes.fromhex(row["coin_hex"])), c.Budget())
            reader.varint(32); reader.varint()
            tags.add(reader.varint(32))
        self.assertTrue(set(range(6)) <= tags)

    def test_amount_known_primary_vectors(self):
        # src/test/compress_tests.cpp's TestPair values, independent of this decoder.
        for value, encoded in ((0,0), (1,1), (1000000,7), (100000000,9),
                               (5000000000,50), (2100000000000000,21000000)):
            self.assertEqual(c.compress_amount(value), encoded)
            self.assertEqual(c.decompress_amount(encoded), value)


class Refusals(unittest.TestCase):
    def test_every_truncation(self):
        for n in range(len(DUMP)):
            with self.subTest(offset=n), self.assertRaises(c.Refusal):
                decode(DUMP[:n])

    def test_trailing(self):
        for extra in (b"\x00", DUMP, b"junk"):
            with self.assertRaisesRegex(c.Refusal, "trailing"):
                decode(DUMP + extra)

    def test_header_magic_version_network_endian(self):
        for offset in (0,4,5,6,7,10):
            data = bytearray(DUMP); data[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(c.Refusal):
                decode(data)
        data = bytearray(DUMP); data[5:7] = b"\x00\x02"
        with self.assertRaises(c.Refusal): decode(data)
        data = bytearray(DUMP); data[11:43] = data[11:43][::-1]
        with self.assertRaises(c.Refusal): decode(data)

    def test_count_and_empty_group(self):
        for count in (0, 1, len(NATIVE["coins"]) + 1):
            data = DUMP[:43] + struct.pack("<Q", count) + DUMP[51:]
            with self.assertRaises(c.Refusal): decode(data)
        coin = bytes.fromhex(NATIVE["coins"][0]["coin_hex"])
        with self.assertRaisesRegex(c.Refusal, "empty"):
            decode(one(coin, group=b"\x00"))

    def test_compact_noncanonical_and_range(self):
        for raw in (b"\xfd\xfc\x00", b"\xfe\xff\xff\x00\x00", b"\xff"+struct.pack("<Q",0xffffffff), b"\xfe\x01\x00\x00\x02"):
            with self.assertRaises(c.Refusal):
                c.Reader(io.BytesIO(raw), c.Budget()).compact()

    def test_varint_overflow(self):
        for bits, data in ((32,b"\xff"*6),(64,b"\xff"*11), (32,c.varint_bytes(1<<32))):
            with self.assertRaises(c.Refusal): c.Reader(io.BytesIO(data), c.Budget()).varint(bits)

    def test_amount_overflow(self):
        with self.assertRaises(c.Refusal): c.decompress_amount(c.U64)
        with self.assertRaises(c.Refusal): c.decompress_amount(21000010)

    def test_unknown_height(self):
        with self.assertRaisesRegex(c.Refusal, "creation height"):
            decode(one(c.varint_bytes(12) + b"\x00\x06"))

    def test_duplicates_and_order(self):
        coin = bytes.fromhex(NATIVE["coins"][0]["coin_hex"])
        header = c.MAGIC + bytes.fromhex(BASE)[::-1] + struct.pack("<Q", 2)
        group = b"\x01" + bytes(31) + b"\x01\x00" + coin
        with self.assertRaisesRegex(c.Refusal, "transaction group"):
            decode(header + group + group)
        for indices in ((0,0),(2,1),(16511,16512)):
            data = header + b"\x01" + bytes(31) + b"\x02" + b"".join(compact(i)+coin for i in indices)
            with self.assertRaisesRegex(c.Refusal, "output DB key"):
                decode(data)
        # VARINT DB lexicographic ordering differs from integer sorting here.
        good = header + b"\x01" + bytes(31) + b"\x02" + compact(16512)+coin+compact(16511)+coin
        self.assertEqual([x.vout for x in decode(good)], [16512,16511])

    def test_script_oversize_raw_special_and_invalid_point(self):
        hval = b"\x00\x00"
        scripts = [c.varint_bytes(10007), b"\x1f\x76\xa9\x14"+bytes(20)+b"\x88\xac",
                   b"\x04"+b"\xff"*32, b"\x07\x6a"]
        for script in scripts:
            with self.subTest(script=script), self.assertRaises(c.Refusal): decode(one(hval+script))

    def test_budgets(self):
        for budget in (c.Budget(max_bytes=51), c.Budget(max_coins=0)):
            with self.assertRaises(c.Refusal): decode(DUMP, budget=budget)
        with self.assertRaises(c.Refusal): c.Budget(max_group=0)
        with patch("canonical.time.monotonic", side_effect=[0,31]):
            with self.assertRaisesRegex(c.Refusal, "time budget"):
                c.Decoder(io.BytesIO(DUMP), BASE, 5)
        with self.assertRaises(c.Refusal): c.integer(True, 0, 10, "integer")


class Analysis(unittest.TestCase):
    def run_analysis(self, binding=None, dump=DUMP, headers=HEADERS):
        return c.analyze_fixture(io.BytesIO(dump), io.BytesIO(headers), BIND if binding is None else binding)

    def test_exact_boundaries_shares_and_largest(self):
        result = self.run_analysis()
        self.assertEqual(result["status"], "SYNTHETIC_FIXTURE_ONLY")
        self.assertIsNone(result["global_statistics"])
        rows = NATIVE["coins"]
        expected_heights = {"ge10y": {0}, "5to10y": {1}, "2to5y": {2}, "1to2y": {3}, "lt1y": {4,5}}
        for label, heights in expected_heights.items():
            wanted = [r for r in rows if r["height"] in heights]
            self.assertEqual(result["age_bands"][label], {"count": len(wanted), "value_atoms": sum(r["value"] for r in wanted)})
        expected = sum(r["value"] for r in rows if r["height"] in (0,1))
        self.assertEqual(result["creation_age_at_least"]["ge5y"]["value_atoms"], expected)
        self.assertEqual(result["creation_age_at_least"]["ge5y"]["value_share"],
                         {"numerator": expected, "denominator": sum(r["value"] for r in rows)})
        self.assertEqual([x["value_atoms"] for x in result["largest_outputs"]], sorted([r["value"] for r in rows], reverse=True)[:10])
        self.assertEqual(sum(x["count"] for x in result["value_bands"].values()), len(rows))
        intervals = {"zero": lambda v: v == 0, "lt1nmc": lambda v: 0 < v < 10**8,
                     "1to10nmc": lambda v: 10**8 <= v < 10**9,
                     "10to100nmc": lambda v: 10**9 <= v < 10**10,
                     "100to1000nmc": lambda v: 10**10 <= v < 10**11,
                     "ge1000nmc": lambda v: v >= 10**11}
        for band, included in intervals.items():
            wanted = [r["value"] for r in rows if included(r["value"])]
            self.assertEqual(result["value_bands"][band], {"count": len(wanted), "value_atoms": sum(wanted)})

    def test_snapshot_bindings(self):
        for field in ("tip_before", "tip_after", "chainstate_before", "chainstate_after", "native_bestblock", "dump_sha256", "headers_sha256", "dump_txoutset_hash"):
            binding = copy.deepcopy(BIND); binding[field] = "0"*64
            with self.subTest(field=field), self.assertRaises(c.Refusal): self.run_analysis(binding)
        for field in ("native_height", "native_txouts", "native_transactions"):
            binding = copy.deepcopy(BIND); binding[field] += 1
            with self.assertRaises(c.Refusal): self.run_analysis(binding)
        for field in ("coins", "names", "total"):
            binding = copy.deepcopy(BIND); binding["native_atoms"][field] += 1
            with self.assertRaises(c.Refusal): self.run_analysis(binding)

    def test_real_data_gate(self):
        binding = copy.deepcopy(BIND); binding["fixture"] = False
        with self.assertRaisesRegex(c.Refusal, "fixture-only"): self.run_analysis(binding)
        with self.assertRaisesRegex(c.Refusal, "not qualified"):
            c.read_headers(io.BytesIO(HEADERS), 6, BASE)

    def test_header_integrity_unknown_and_future_dates(self):
        for data in (HEADERS[:-1], HEADERS+b"\x00", HEADERS[:80]+bytes(80)+HEADERS[160:]):
            with self.assertRaises(c.Refusal): self.run_analysis(headers=data)
        # Last header is earlier than an ancestor: keep actual dates and refuse negative age.
        data = bytearray(HEADERS)
        data[-12:-8] = struct.pack("<I", 1)
        base = c.double_sha(data[-80:])[::-1].hex()
        binding = copy.deepcopy(BIND)
        for field in ("base_hash", "tip_before", "tip_after", "chainstate_before", "chainstate_after", "native_bestblock"):
            binding[field] = base
        binding["headers_sha256"] = hashlib.sha256(data).hexdigest()
        dump = DUMP[:11] + bytes.fromhex(base)[::-1] + DUMP[43:]
        binding["dump_sha256"] = hashlib.sha256(dump).hexdigest()
        with self.assertRaisesRegex(c.Refusal, "timestamp after"):
            self.run_analysis(binding, dump=dump, headers=data)

    def test_nonmonotonic_dates_not_binary_searched(self):
        # Only hashes/links/date extraction are checked here: not consensus validation.
        dates = [100,90,200]
        previous, raw = bytes(32), b""
        for date in dates:
            header = struct.pack("<I",1)+previous+bytes(32)+struct.pack("<III",date,0,0)
            raw += header; previous = c.double_sha(header)
        got, _, regressions = c.read_headers(io.BytesIO(raw),3,previous[::-1].hex(),fixture=True)
        self.assertEqual(got, dates)
        self.assertEqual(regressions, 1)

    def test_zero_denominators_and_aggregate_overflow(self):
        self.assertIsNone(c.ratio(0,0))
        with self.assertRaisesRegex(c.Refusal, "aggregate overflow"):
            c.add({"count": 0, "value_atoms": c.I64}, 1)


if __name__ == "__main__":
    unittest.main()
