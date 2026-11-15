#!/usr/bin/env python3
"""Independent LIP-0021 draft sections 2-5 reader; Python plus system OpenSSL.

No Go code or Go-derived intermediate parsing is used. Expectations are read only
after the rule calculations. Compare every result with both the pinned vector
and the actual Go test output. This checks stated facts, never a node/signature.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

MODULE = Path(__file__).resolve().parents[1]
VECTOR_SHA256 = "67e45caabfa4599160e53bd95541db2b02ad8afdc21872776756881a85c97b4c"
TESTS = {"TestV4OwnerPin", "TestV4NameScript", "TestV4Writer", "TestV4LiveName"}


def hash160(data):
    # RIPEMD-160 is absent from some Python builds. Require the independent
    # OpenSSL 3.0.2 supplies it only in the legacy provider; select that
    # provider explicitly on every platform, without an alternate backend.
    run = subprocess.run(["openssl", "dgst", "-provider", "legacy", "-ripemd160", "-binary"],
                         input=hashlib.sha256(data).digest(), capture_output=True)
    if run.returncode != 0 or len(run.stdout) != 20:
        raise ValueError("OpenSSL RIPEMD-160 unavailable or malformed output")
    return run.stdout


def pin_result(text):
    if re.fullmatch(r"0[23][0-9a-f]{64}", text) is None:
        return "form"
    prime = 2**256 - 2**32 - 977
    x = int(text[2:], 16)
    square = (x**3 + 7) % prime
    y = pow(square, (prime + 1) // 4, prime)
    return "pin" if x < prime and y*y % prime == square else "point"


class Cursor:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        if self.pos + n > len(self.data):
            raise ValueError("truncated octets")
        result = self.data[self.pos:self.pos+n]
        self.pos += n
        return result

    def push(self):
        op = self.take(1)[0]
        if op <= 75:
            size = op
        elif op in (76, 77):
            size = int.from_bytes(self.take(op - 75), "little")
            if size < (76 if op == 76 else 256):
                raise ValueError("longer push than needed")
        else:
            raise ValueError("not a profile push")
        return self.take(size)

    def tail(self):
        return self.take(len(self.data) - self.pos)


def split_name(data):
    """O3.2: independently consume the literal grammar, with no node parser."""
    c = Cursor(data)
    try:
        op = c.take(1)[0]
        if op == 83:
            fields = {"prefix": "update", "name": c.push(), "value": c.push()}
            drops = b"\x6d\x75"
        elif op == 82:
            fields = {"prefix": "registration", "name": c.push(), "rand": c.push(), "value": c.push()}
            drops = b"\x6d\x6d"
        elif op == 81:
            fields = {"prefix": "reservation", "hash": c.push()}
            if len(fields["hash"]) != 20:
                return None
            drops = b"\x6d"
        else:
            return None
        if c.take(len(drops)) != drops:
            return None
        fields["address"] = c.tail()
        return fields
    except ValueError:
        return None


def address_kind(data, height, witness_from):
    if re.fullmatch(b"\x76\xa9\x14.{20}\x88\xac", data, re.DOTALL):
        return "key", data[3:23]
    if re.fullmatch(b"\x00\x14.{20}", data, re.DOTALL) and height is not None and height >= witness_from:
        return "witness", data[2:]
    return None, None


def read_script(data, pin, at, witness_from):
    ns = split_name(data)
    if ns is None:
        return {"prefix": "none", "reading": "unsupported"}
    result = {"prefix": ns["prefix"], "address_script_hex": ns["address"].hex()}
    for key in ("name", "value", "rand", "hash"):
        if key in ns:
            result[key if key in ("name", "value") else key+"_hex"] = ns[key].decode("ascii") if key in ("name", "value") else ns[key].hex()
    kind, keyhash = address_kind(ns["address"], at, witness_from)
    digest = hash160(bytes.fromhex(pin))
    result["reading"] = "unsupported" if kind is None else "controlled" if keyhash == digest else "another key"
    return result


def read_writer(row, witness_from):
    candidates = []
    for txin in row["inputs"]:
        ns = split_name(bytes.fromhex(txin["spent_script_hex"]))
        if ns is None:
            continue
        created = row["created"]
        if (created["operation"] == "registration" and ns["prefix"] == "reservation") or (
            created["operation"] == "update" and ns["prefix"] in ("update", "registration") and ns["name"] == created["name"].encode("ascii")
        ):
            candidates.append((txin, ns))
    if len(candidates) != 1:
        return "unsupported"
    txin, ns = candidates[0]
    at = txin.get("spent_confirmed_at")
    reading = read_script(bytes.fromhex(txin["spent_script_hex"]), row["pin"], at, witness_from)["reading"]
    if reading == "another key":
        return "written by another"
    if reading != "controlled":
        return "unsupported"
    kind, _ = address_kind(ns["address"], at, witness_from)
    unlocking = bytes.fromhex(txin["unlocking_script_hex"])
    witness = [bytes.fromhex(item) for item in txin.get("witness_hex", [])]
    if kind == "key" and not witness:
        try:
            c = Cursor(unlocking)
            signature, key = c.push(), c.push()
            if c.tail():
                return "unsupported"
        except ValueError:
            return "unsupported"
    elif kind == "witness" and not unlocking and len(witness) == 2:
        signature, key = witness
    else:
        return "unsupported"
    return "written by the owner" if signature and signature[-1] == 1 and key == bytes.fromhex(row["pin"]) else "unsupported"


def calculate(vectors):
    result = {}
    rows = vectors["pins"]["valid"] + vectors["pins"]["invalid"] + vectors["pins"]["comparisons"] + vectors["scripts"] + vectors["writers"] + vectors["live"]
    counts = [len(vectors["pins"][k]) for k in ("valid", "invalid", "comparisons")] + [len(vectors[k]) for k in ("scripts", "writers", "live")]
    if counts != [3, 9, 3, 39, 24, 6]:
        raise ValueError(f"wrong vector counts: {counts}")
    witness_from = vectors["parameters"]["witness_rules_from_height_main_chain"]
    for row in rows:
        key = row["id"]
        if key in result:
            raise ValueError(f"duplicate vector {key}")
        if key.startswith("pin-c-"):
            if pin_result(row["pin"]) != "pin" or pin_result("02" + row["signing_public_key"]) != "pin":
                raise ValueError(f"invalid comparison input {key}")
            actual = "same" if row["pin"][2:] == row["signing_public_key"] else "different"
        elif key.startswith("pin-"):
            actual = pin_result(row["value"])
        elif key.startswith("script-"):
            actual = read_script(bytes.fromhex(row["script_hex"]), row["pin"], row.get("confirmed_at"), witness_from)
        elif key.startswith("writer-"):
            actual = read_writer(row, witness_from)
        elif key.startswith("live-"):
            actual = "live" if row["height"] < row["confirmed_at"] + row["depth"] else "expired"
        else:
            raise ValueError(f"unknown vector {key}")
        result[key] = actual
        # Consult the expected answer only after evaluating the LIP rule.
        if actual != row["expect"]:
            raise ValueError(f"VECTOR_DISAGREEMENT {key}: independent={actual!r}, vector={row['expect']!r}")
    index = {row["id"]: row for row in rows}
    for row in rows:
        if neighbour := row.get("valid_neighbour"):
            if neighbour not in index or index[neighbour].get("valid_neighbour"):
                raise ValueError(f"invalid neighbour for {row['id']}")
    return result


def go_results(stream):
    results, passed, packages = {}, set(), 0
    for line in stream.splitlines():
        event = json.loads(line)
        if event.get("Action") in ("fail", "skip"):
            raise ValueError(f"Go test did not pass: {event.get('Test', 'package')}")
        if event.get("Action") == "pass" and event.get("Test") in TESTS:
            passed.add(event["Test"])
        if event.get("Action") == "pass" and "Test" not in event:
            packages += 1
        output = event.get("Output", "")
        if "SECOND_READER " in output:
            item = json.loads(output.split("SECOND_READER ", 1)[1])
            if item["id"] in results:
                raise ValueError(f"duplicate Go result {item['id']}")
            results[item["id"]] = item["result"]
    if passed != TESTS:
        raise ValueError(f"missing passing Go tests: {TESTS - passed}")
    if packages != 1:
        raise ValueError("missing complete Go package pass")
    return results


def agree(independent, go):
    if independent.keys() != go.keys():
        raise ValueError(f"Go result ids differ: missing={sorted(independent.keys()-go.keys())}, extra={sorted(go.keys()-independent.keys())}")
    for key in independent:
        if independent[key] != go[key]:
            raise ValueError(f"GO_DISAGREEMENT {key}: independent={independent[key]!r}, Go={go[key]!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-results", type=Path, help="reuse a complete go test -json stream")
    parser.add_argument("--output", type=Path, help="write independent decisions for audit")
    args = parser.parse_args()
    try:
        data = (MODULE / "testdata/name-vectors.json").read_bytes()
        if hashlib.sha256(data).hexdigest() != VECTOR_SHA256:
            raise ValueError("vector source hash differs")
        decisions = calculate(json.loads(data))
        if args.go_results:
            stream = args.go_results.read_text()
        else:
            run = subprocess.run(["go", "test", "-count=1", "-json", "-run", "^TestV4(OwnerPin|NameScript|Writer|LiveName)$", "./..."], cwd=MODULE, text=True, capture_output=True)
            if run.returncode != 0:
                raise ValueError(f"Go test exit {run.returncode}:\n{run.stdout}\n{run.stderr}")
            stream = run.stdout
        agree(decisions, go_results(stream))
        if args.output:
            args.output.write_text(json.dumps(decisions, indent=2, sort_keys=True) + "\n")
        print(f"AGREE {len(decisions)} vectors: independent Python = pinned vectors = Go; no walk or node reads")
        return 0
    except (ValueError, KeyError, OSError) as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
