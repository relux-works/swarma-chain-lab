"""Strict Namecoin Core nc28.0 snapshot-v2 decoder. No node/RPC/database access.

Only fixture qualification is exposed by the command line. See CONTRACT.md for
the independent validation still required before analysing an actual snapshot.
"""
from dataclasses import dataclass
import hashlib
import heapq
import io
import json
import time

SOURCE_COMMIT = "a08218ef2d44b81c53d25c399898e59271f4b642"
SOURCE_SHA256 = "389b676e7aa74f6b96f235c77dacdf0dcca6a6ab2e32bd7c823efeb252ab8bd8"
GENESIS = "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770"
MAGIC = b"utxo\xff\x02\x00\xf9\xbe\xb4\xfe"
MAX_MONEY = 21_000_000 * 100_000_000
U64 = (1 << 64) - 1
I64 = (1 << 63) - 1
YEAR = 365 * 86400  # fixed duration, deliberately not calendar anniversaries
P = (1 << 256) - (1 << 32) - 977


class Refusal(ValueError):
    """Untrusted or unsupported input. No partial result may be published."""


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def integer(value, lo, hi, label):
    require(type(value) is int and lo <= value <= hi, label)
    return value


def varint_bytes(n):
    """Native subtract-one base-128 DB key ordering, not LEB128."""
    integer(n, 0, U64, "varint range")
    out = [n & 127]
    while n > 127:
        n = (n >> 7) - 1
        out.append((n & 127) | 128)
    return bytes(reversed(out))


def compact_bytes(n):
    integer(n, 0, U64, "CompactSize range")
    if n < 253:
        return bytes([n])
    width, tag = (2, 253) if n <= 65535 else (4, 254) if n <= 0xffffffff else (8, 255)
    return bytes([tag]) + n.to_bytes(width, "little")


def compress_amount(n):
    integer(n, 0, MAX_MONEY, "amount range")
    if n == 0:
        return 0
    e = 0
    while n % 10 == 0 and e < 9:
        n //= 10
        e += 1
    if e == 9:
        return 1 + 10 * (n - 1) + e
    return 1 + 10 * (9 * (n // 10) + n % 10 - 1) + e


def decompress_amount(x):
    integer(x, 0, U64, "compressed amount overflow")
    if x == 0:
        return 0
    original = x
    x -= 1
    e = x % 10
    x //= 10
    n = ((x // 9) * 10 + x % 9 + 1) if e < 9 else x + 1
    n *= 10 ** e  # arbitrary precision before explicit native range checks
    require(n <= MAX_MONEY and n <= I64, "decompressed amount overflow/range")
    require(compress_amount(n) == original, "noncanonical amount")
    return n


@dataclass(frozen=True)
class Budget:
    max_bytes: int = 64 * 1024 * 1024
    max_coins: int = 1_000_000
    max_group: int = 100_000
    max_group_bytes: int = 4 * 1024 * 1024
    max_seconds: int = 30

    def __post_init__(self):
        integer(self.max_bytes, 51, 1 << 34, "byte budget")
        integer(self.max_coins, 0, 100_000_000, "coin budget")
        integer(self.max_group, 1, 0x02000000, "group budget")
        integer(self.max_group_bytes, 10000, 16 * 1024 * 1024, "group memory budget")
        integer(self.max_seconds, 1, 3600, "time budget")


class Reader:
    def __init__(self, stream, budget):
        self.stream, self.budget = stream, budget
        self.offset = 0
        self.digest = hashlib.sha256()
        self.started = time.monotonic()

    def check_time(self):
        require(time.monotonic() - self.started <= self.budget.max_seconds,
                "time budget exceeded")

    def read(self, n):
        self.check_time()
        require(0 <= n <= 10000 and self.offset + n <= self.budget.max_bytes,
                "byte budget exceeded")
        data = self.stream.read(n)
        require(len(data) == n, "truncated at offset " + str(self.offset))
        self.offset += n
        self.digest.update(data)
        return data

    def uint(self, n):
        return int.from_bytes(self.read(n), "little")

    def compact(self, maximum=0x02000000):
        first = self.uint(1)
        if first < 253:
            n = first
        else:
            n = self.uint({253: 2, 254: 4, 255: 8}[first])
            require(n >= {253: 253, 254: 65536, 255: 1 << 32}[first],
                    "noncanonical CompactSize")
        require(n <= maximum, "CompactSize range/budget")
        return n

    def varint(self, bits=64):
        n = 0
        maximum = (1 << bits) - 1
        for _ in range((bits + 6) // 7):
            c = self.uint(1)
            require(n <= maximum >> 7, "VARINT overflow")
            n = (n << 7) | (c & 127)
            if c & 128:
                require(n < maximum, "VARINT overflow")
                n += 1
            else:
                require(n <= maximum, "VARINT overflow")
                return n
        raise Refusal("VARINT overflow/unterminated")

    def eof(self):
        self.check_time()
        require(self.stream.read(1) == b"", "trailing bytes")


def point_y(x, parity):
    require(x < P, "invalid compressed uncompressed-pubkey x")
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    require(y * y % P == y2, "invalid compressed uncompressed-pubkey point")
    return y if y % 2 == parity else P - y


def special_encoding(script):
    """Writer's exact CompressScript cases; no address or ownership decoding."""
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac":
        return b"\x00" + script[3:23]
    if len(script) == 23 and script[:2] == b"\xa9\x14" and script[-1:] == b"\x87":
        return b"\x01" + script[2:22]
    if len(script) == 35 and script[0] == 33 and script[1] in (2, 3) and script[-1] == 172:
        return script[1:34]
    if len(script) == 67 and script[:2] == b"\x41\x04" and script[-1] == 172:
        x, y = int.from_bytes(script[2:34], "big"), int.from_bytes(script[34:66], "big")
        if x < P and y < P and y * y % P == (x * x * x + 7) % P:
            return bytes([4 | (y & 1)]) + script[2:34]
    return None


def read_script(reader):
    size = reader.varint(32)
    if size < 6:
        payload = reader.read(20 if size < 2 else 32)
        if size == 0:
            return b"\x76\xa9\x14" + payload + b"\x88\xac"
        if size == 1:
            return b"\xa9\x14" + payload + b"\x87"
        if size < 4:
            return b"\x21" + bytes([size]) + payload + b"\xac"
        y = point_y(int.from_bytes(payload, "big"), size & 1)
        return b"\x41\x04" + payload + y.to_bytes(32, "big") + b"\xac"
    require(size - 6 <= 10000, "oversized raw script unsupported")
    script = reader.read(size - 6)
    require(special_encoding(script) is None, "noncanonical raw special script")
    require(not script.startswith(b"\x6a"), "OP_RETURN cannot be a native live coin")
    return script


def name_kind(script):
    """CNameScript constructor classification, including nonminimal pushes.

    Malformed prefixes are ordinary coins in the native totals. This is not
    name-consensus validation or an active-name database reconstruction.
    """
    if not script or script[0] not in (81, 82, 83):
        return "ordinary"
    pos, args = 1, 0
    while pos < len(script):
        opcode = script[pos]
        pos += 1
        if opcode in (0x75, 0x6d, 0x61):
            wanted = {81: 1, 82: 3, 83: 2}[script[0]]
            return {81: "name_new", 82: "name_firstupdate", 83: "name_update"}[script[0]] if args == wanted else "ordinary"
        if opcode > 78:
            return "ordinary"
        length = opcode
        if opcode >= 76:
            width = {76: 1, 77: 2, 78: 4}[opcode]
            if pos + width > len(script):
                return "ordinary"
            length = int.from_bytes(script[pos:pos + width], "little")
            pos += width
        if length > len(script) - pos:
            return "ordinary"
        pos += length
        args += 1
    return "ordinary"


@dataclass(frozen=True)
class Coin:
    txid_raw: bytes
    vout: int
    height: int
    coinbase: bool
    value: int
    kind: str
    script: bytes


class Decoder:
    def __init__(self, stream, base_hash, tip_height, budget=Budget()):
        self.reader = Reader(stream, budget)
        self.tip_height = integer(tip_height, 0, (1 << 31) - 1, "tip height")
        require(type(base_hash) is str and len(base_hash) == 64 and
                all(c in "0123456789abcdef" for c in base_hash), "base hash syntax")
        require(self.reader.read(11) == MAGIC, "unsupported snapshot magic/version/network")
        require(self.reader.read(32)[::-1].hex() == base_hash, "snapshot base hash mismatch")
        self.count = self.reader.uint(8)
        require(self.count <= budget.max_coins, "coin budget exceeded")
        self.transactions = 0
        self.coinstats_hasher = hashlib.sha256()
        self.coinstats_hash = None
        self.finished = False

    def __iter__(self):
        require(not self.finished, "decoder already consumed")
        self.finished = True
        left, previous_tx = self.count, None
        while left:
            tx = self.reader.read(32)
            require(previous_tx is None or tx > previous_tx, "duplicate/unordered transaction group")
            previous_tx = tx
            n = self.reader.compact(min(left, self.reader.budget.max_group))
            require(n > 0, "empty transaction group")
            self.transactions += 1
            previous_key = None
            serialized_outputs, group_bytes = [], 0
            for _ in range(n):
                index = self.reader.compact()
                require(index < 0xffffffff, "null/overflow outpoint")
                key = varint_bytes(index)
                require(previous_key is None or key > previous_key,
                        "duplicate/unordered output DB key")
                previous_key = key
                code = self.reader.varint(32)
                height = code >> 1
                require(height <= self.tip_height, "unknown/future creation height")
                value = decompress_amount(self.reader.varint())
                script = read_script(self.reader)
                # kernel/coinstats.cpp hashes uncompressed TxOutSer records,
                # in numeric-vout order within each raw-lexical txid group.
                record = (tx + index.to_bytes(4, "little") + code.to_bytes(4, "little") +
                          value.to_bytes(8, "little", signed=True) + compact_bytes(len(script)) + script)
                group_bytes += len(record)
                require(group_bytes <= self.reader.budget.max_group_bytes, "group memory budget exceeded")
                serialized_outputs.append((index, record))
                left -= 1
                yield Coin(tx, index, height, bool(code & 1), value, name_kind(script), script)
            for _, record in sorted(serialized_outputs):
                self.coinstats_hasher.update(record)
        self.reader.eof()
        self.coinstats_hash = hashlib.sha256(self.coinstats_hasher.digest()).digest()[::-1].hex()


def double_sha(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def read_headers(stream, count, expected_tip, *, fixture=False, max_bytes=160_000_000,
                 max_seconds=30):
    """Check fixed 80-byte pure-header ancestry/hash/date, NOT consensus/AuxPoW.

    A chain of header hashes does not prove local block validation. Deliberately
    fixture-only until an independently reviewed validation-custody adapter exists.
    """
    require(fixture is True, "real header validation adapter not qualified")
    integer(count, 1, 2_000_000, "header count")
    require(count * 80 <= max_bytes, "header byte budget")
    integer(max_seconds, 1, 3600, "header time budget")
    started = time.monotonic()
    dates, previous, regressions = [], bytes(32), 0
    digest = hashlib.sha256()
    for _ in range(count):
        require(time.monotonic() - started <= max_seconds, "header time budget exceeded")
        raw = stream.read(80)
        require(len(raw) == 80, "truncated header table")
        require(raw[4:36] == previous, "header ancestry mismatch")
        digest.update(raw)
        previous = double_sha(raw)
        timestamp = int.from_bytes(raw[68:72], "little")
        if dates and timestamp < dates[-1]:
            regressions += 1
        dates.append(timestamp)
    require(stream.read(1) == b"", "trailing header bytes")
    require(previous[::-1].hex() == expected_tip, "header tip mismatch")
    return dates, digest.hexdigest(), regressions


def bucket():
    return {"count": 0, "value_atoms": 0}


def add(target, value):
    target["count"] += 1
    target["value_atoms"] += value
    require(target["count"] <= U64 and target["value_atoms"] <= I64, "aggregate overflow")


def ratio(n, d):
    return None if d == 0 else {"numerator": n, "denominator": d}


def analyze_fixture(dump, headers, binding, budget=Budget(), largest=10):
    """All-or-nothing synthetic analysis. No real-data approval escape switch."""
    require(binding.get("fixture") is True, "fixture-only candidate; real data refused")
    require(binding.get("schema") == "namecoin-age-fixture/1", "binding schema")
    height = integer(binding.get("height"), 0, 1_999_999, "binding height")
    base = binding.get("base_hash")
    for field in ("tip_before", "tip_after", "chainstate_before", "chainstate_after", "native_bestblock"):
        require(binding.get(field) == base, "unstable/mismatched " + field)
    require(integer(binding.get("native_height"), 0, 1_999_999, "native height") == height,
            "native height mismatch")
    integer(largest, 0, 100, "largest bound")
    dates, headers_digest, regressions = read_headers(headers, height + 1, base, fixture=True)
    require(headers_digest == binding.get("headers_sha256"), "header digest mismatch")
    reference_time = dates[-1]
    groups = {k: bucket() for k in ("all", "ordinary", "names", "name_new", "name_firstupdate", "name_update")}
    ages = {k: bucket() for k in ("lt1y", "1to2y", "2to5y", "5to10y", "ge10y")}
    dormant = {k: bucket() for k in ("ge5y", "ge10y")}
    values = {k: bucket() for k in ("zero", "lt1nmc", "1to10nmc", "10to100nmc", "100to1000nmc", "ge1000nmc")}
    largest_heap = []
    decoder = Decoder(dump, base, height, budget)
    for coin in decoder:
        require(coin.height < len(dates), "missing creation header")
        age = reference_time - dates[coin.height]
        require(age >= 0, "creation header timestamp after reference tip; no clamping")
        add(groups["all"], coin.value)
        add(groups["ordinary" if coin.kind == "ordinary" else "names"], coin.value)
        if coin.kind != "ordinary":
            add(groups[coin.kind], coin.value)
        band = ("lt1y" if age < YEAR else "1to2y" if age < 2 * YEAR else
                "2to5y" if age < 5 * YEAR else "5to10y" if age < 10 * YEAR else "ge10y")
        add(ages[band], coin.value)
        for threshold, key in ((5 * YEAR, "ge5y"), (10 * YEAR, "ge10y")):
            if age >= threshold:
                add(dormant[key], coin.value)
        band = ("zero" if coin.value == 0 else "lt1nmc" if coin.value < 10**8 else
                "1to10nmc" if coin.value < 10**9 else "10to100nmc" if coin.value < 10**10 else
                "100to1000nmc" if coin.value < 10**11 else "ge1000nmc")
        add(values[band], coin.value)
        if largest:
            item = (coin.value, coin.txid_raw, coin.vout, coin.height, coin.kind)
            heapq.heappush(largest_heap, item)
            if len(largest_heap) > largest:
                heapq.heappop(largest_heap)
    require(decoder.reader.digest.hexdigest() == binding.get("dump_sha256"), "dump digest mismatch")
    require(decoder.coinstats_hash == binding.get("dump_txoutset_hash"), "native serialized UTXO hash mismatch")
    native = binding.get("native_atoms")
    require(type(native) is dict, "missing native exact-atom totals")
    require(integer(binding.get("native_txouts"), 0, U64, "native count") == groups["all"]["count"], "native count mismatch")
    require(integer(binding.get("native_transactions"), 0, U64, "native transactions") == decoder.transactions,
            "native transaction count mismatch")
    for label, key in (("coins", "ordinary"), ("names", "names"), ("total", "all")):
        require(integer(native.get(label), 0, I64, "native amount") == groups[key]["value_atoms"], "native amount mismatch: " + label)
    total = groups["all"]
    for item in dormant.values():
        item["count_share"] = ratio(item["count"], total["count"])
        item["value_share"] = ratio(item["value_atoms"], total["value_atoms"])
    return {"status": "SYNTHETIC_FIXTURE_ONLY", "global_statistics": None,
            "base_hash": base, "height": height, "reference_timestamp": reference_time,
            "header_timestamp_regressions": regressions, "dump_sha256": decoder.reader.digest.hexdigest(),
            "dump_bytes": decoder.reader.offset, "headers_sha256": headers_digest,
            "txoutset_hash": decoder.coinstats_hash,
            "bindings": {key: binding[key] for key in ("tip_before", "tip_after", "chainstate_before",
                         "chainstate_after", "native_bestblock", "native_height")},
            "transactions_with_unspent_outputs": decoder.transactions, "groups": groups,
            "age_bands": ages, "creation_age_at_least": dormant, "value_bands": values,
            "largest_outputs": [{"value_atoms": v, "creation_height": h, "kind": k}
                                for v, _, _, h, k in sorted(largest_heap, reverse=True)],
            "definition": "UTXO last-creation age; neither owner inactivity nor original coin age",
            "validation": "synthetic ancestry/hash checks; NOT consensus or AuxPoW validation",
            "budget": vars(budget)}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump")
    parser.add_argument("headers")
    parser.add_argument("binding")
    args = parser.parse_args()
    try:
        with open(args.binding, "rb") as f:
            raw = f.read(65537)
        require(len(raw) <= 65536, "binding byte budget")
        binding = json.loads(raw)
        require(type(binding) is dict, "binding object")
        with open(args.dump, "rb") as dump, open(args.headers, "rb") as headers:
            result = analyze_fixture(dump, headers, binding)
        print(json.dumps(result, sort_keys=True, indent=2))
    except (Refusal, OSError, ValueError, TypeError, KeyError) as exc:
        # No untrusted bytes, filenames, scripts or addresses in refusal output.
        print(json.dumps({"status": "REFUSED", "statistics": None, "error_type": type(exc).__name__}))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
