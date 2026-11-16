#!/usr/bin/env python3
"""Independent v0.1.49 R1 draft calculations; no Go parsing/intermediates.

This reader reuses the existing Python O3/O4 primitives, independently of Go.
Expectations are consulted after decisions. No node or signature is qualified.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

spec = importlib.util.spec_from_file_location("name_reader", Path(__file__).with_name("second-reader.py"))
names = importlib.util.module_from_spec(spec)
spec.loader.exec_module(names)
ROOT = Path(__file__).resolve().parents[1]
HASHES = {"row-fit-vectors.json":"b92eb11c26432002daa51e8c463dbdfbaf27c5bc9b8b7c444ad51016c27f4ae8","groups-vectors.json":"ff0df0b7c859c27baa905be68237cc8453695d5f2bc6ec33d3b16d5445387f96","class-vectors.json":"749cb734fce306f8a5fd163414398c1fb4005216ebc810c350b25b11014278e8","holders-vectors.json":"2cbfe76a1dfe83f3ac09be8538ff159eb4ff609faf88444aa3f44c8d26f0fe12"}


class Pairs(list):
    """JSON object whose spelling/order/duplicates remain observable."""


def obj(pairs):
    if not isinstance(pairs, Pairs) or len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("not a unique-member object")
    return dict(pairs)


def plain(value):
    if isinstance(value, Pairs):
        return {k: plain(v) for k, v in obj(value).items()}
    if isinstance(value, list):
        return [plain(v) for v in value]
    return value


def signing_key(key):
    return isinstance(key, str) and len(key) == 64 and names.pin_result("02" + key) == "pin"


def channel(value):
    if signing_key(value):
        return value
    try:
        nk = obj(obj(value)["names"])["_"]
        return nk if signing_key(nk) else None
    except (ValueError, KeyError, TypeError):
        return None


def value_read(raw):
    if len(raw.encode("utf-8")) > 520:
        raise ValueError("size")
    decoder = json.JSONDecoder(object_pairs_hook=Pairs)
    top = decoder.decode(raw)
    if not isinstance(top, Pairs):
        raise ValueError("top")
    read = {}
    for key, val in top:
        if key.casefold() in ("swarma", "nostr"):
            if key not in ("swarma", "nostr") or key in read:
                raise ValueError("read alias/duplicate")
            read[key] = val
    swarma = obj(read["swarma"])
    if list(swarma) == ["agent"]:
        binding = obj(swarma["agent"])
        if list(binding) != ["landlord"] or not isinstance(binding["landlord"], str) or not binding["landlord"]:
            raise ValueError("agent binding")
        result = {"landlord": binding["landlord"]}
    elif list(swarma) == ["landlord"]:
        binding = obj(swarma["landlord"])
        if list(binding) not in (["grant"], ["grant", "holders"]) or not signing_key(binding["grant"]):
            raise ValueError("landlord binding")
        holders = binding.get("holders", [])
        if type(holders) is not list or any(not isinstance(p, str) or names.pin_result(p) != "pin" for p in holders):
            raise ValueError("holder pin")
        if any(a >= b for a, b in zip(holders, holders[1:])):
            raise ValueError("holder order")
        result = {"grant": binding["grant"], "holders": holders}
    else:
        raise ValueError("binding kind")
    # Locate the raw top-level swarma span independently of Go's RawMessage.
    pos = raw.index("{") + 1
    span = None
    for _ in top:
        pos = len(raw[:pos]) + len(raw[pos:]) - len(raw[pos:].lstrip())
        key, end = decoder.raw_decode(raw, pos)
        pos = end
        while raw[pos].isspace():
            pos += 1
        if raw[pos] != ":":
            raise ValueError("colon")
        pos += 1
        while raw[pos].isspace():
            pos += 1
        start = pos
        _, pos = decoder.raw_decode(raw, pos)
        if key == "swarma":
            span = raw[start:pos]
        while raw[pos].isspace():
            pos += 1
        if raw[pos] == ",":
            pos += 1
    canonical = json.dumps(plain(read["swarma"]), ensure_ascii=False, separators=(",", ":"))
    if span != canonical:
        raise ValueError("binding encoding")
    result["channel"] = channel(read.get("nostr"))
    return result


def limit_map(limits):
    amounts = {}
    for limit in limits:
        key = tuple(limit.get(k, "") for k in ("kind", "resource", "unit", "period"))
        if key in amounts or not all(key[:3]) or type(limit["amount"]) is not int or limit["amount"] < 0:
            raise ValueError("limit identity")
        amounts[key] = limit["amount"]
    return amounts


def group_decision(parent):
    groups = parent["groups"]
    if not 1 <= len(groups) <= 16 or any(not 1 <= len(g["ranges"]) <= 16 for g in groups):
        return {"outcome": "refused", "rule": "R8.4"}
    coins, sums, total = {}, {}, 0
    for group in groups:
        rows = 0
        for interval in group["ranges"]:
            first, count = interval["first"], interval["count"]
            if count > 4096:
                return {"outcome": "refused", "rule": "R8.4"}
            if count < 1 or first < 0 or first + count > 2**32 or re.fullmatch("0014[0-9a-f]{40}", interval["script_hex"]) is None:
                return {"outcome": "refused", "rule": "R8.2"}
            end = first + count
            txid = interval["txid"]
            if any(first < stop and start < end for start, stop in coins.get(txid, [])) or (
                    txid == parent["seal"]["txid"] and first <= parent["seal"]["vout"] < end):
                return {"outcome": "refused", "rule": "R8.6"}
            coins.setdefault(txid, []).append((first, end))
            rows += count
        total += rows
        for key, amount in limit_map(group["limits"]).items():
            sums[key] = sums.get(key, 0) + rows * amount
    pools = limit_map(parent["pools"])
    if pools.keys() != sums.keys() or any(amount > pools[key] for key, amount in sums.items()):
        return {"outcome": "refused", "rule": "R8.5"}
    return {"outcome": "valid", "rows": total}


def ordinal_decision(parent, ordinal):
    rows = sum(r["count"] for g in parent["groups"] for r in g["ranges"])
    if not 1 <= ordinal <= rows:
        return "CHILD_ORDINAL"
    before = 0
    for gi, group in enumerate(parent["groups"], 1):
        for ri, interval in enumerate(group["ranges"], 1):
            if ordinal <= before + interval["count"]:
                return {"group": gi, "range": ri, "coin": {"txid": interval["txid"], "vout": interval["first"] + ordinal - before - 1, "script_hex": interval["script_hex"]}}
            before += interval["count"]
    raise ValueError("unreachable ordinal")


def template_decision(template):
    r = template["recipient"]
    if sum(k in r for k in ("request_public_key", "name", "class")) != 1:
        return {"outcome": "refused", "rule": "R9.1"}
    if "class" in r and (not r["class"] or len({l["name"] for l in r["class"]}) != len(r["class"])):
        return {"outcome": "refused", "rule": "R9.1"}
    if template["certifier"] is not None:
        if template["certifier"] not in template["notaries"]:
            return {"outcome": "refused", "rule": "R10.1"}
    elif "request_public_key" in r or ("class" in r and r["class"] != [template["issuer"]]):
        return {"outcome": "refused", "rule": "R10.2"}
    return {"outcome": "valid"}


def landlord_decision(state, context, exact):
    history = state["history"]
    if not exact:
        if context["tip_height"] - history[0]["height"] >= 36000:
            return "CLASS_LANDLORD_CHANGED"
        if not state.get("transaction_index", True):
            return "CLASS_HISTORY_UNAVAILABLE"
        if not history or history[-1]["prefix"] != "registration":
            return "CLASS_HISTORY_UNAVAILABLE"
        if history[-1]["id"] != state["pinned_registration"]:
            return "CLASS_LANDLORD_CHANGED"
        if history[-1]["height"] > context["recent_block_height"]:
            return "CLASS_CHECKPOINT"
        for output in history:
            if output["reading"] == "another key":
                return "CLASS_LANDLORD_CHANGED"
            if output["reading"] != "controlled":
                return "CLASS_HISTORY_UNAVAILABLE"
            if output["height"] <= context["recent_block_height"]:
                break
    writer = history[0]["writer"]
    if writer == "written by another":
        return "CLASS_VALUE_UNAUTHORIZED"
    if writer != "written by the owner":
        return "CLASS_HISTORY_UNAVAILABLE"
    if state.get("pending_spend_of_current_output", False):
        return "CLASS_LANDLORD_PENDING"
    return None


def admission_decision(row):
    constraint = row["row"]["recipient"]
    child = row["child"]["recipient"]
    exact = "name" in constraint
    if "name" not in child or (exact and child != constraint):
        return {"outcome": "CHILD_GRANTEE_NOT_ALLOWED"}
    raw = bytes.fromhex(row["node"]["recipient_name"]["current_output_script_hex"])
    reading = names.read_script(raw, child["owner_public_key"], row["context"]["tip_height"], 0)
    if reading["reading"] == "unsupported":
        return {"outcome": "RECIPIENT_NAME_UNAVAILABLE"}
    if reading["reading"] == "another key":
        return {"outcome": "RECIPIENT_NAME_NOT_HELD"}
    if reading.get("name") != child["name"]:
        return {"outcome": "RECIPIENT_NAME_UNAVAILABLE"}
    if exact and row["row"]["certifier"] is not None:
        return {"outcome": "pass", "attestation": "required"}
    try:
        agent = value_read(reading["value"])
        landlord = agent["landlord"]
    except (ValueError, KeyError, TypeError):
        return {"outcome": "CLASS_LANDLORD"}
    pins = [row["issuer"]] if exact else constraint["class"]
    if landlord not in [p["name"] for p in pins]:
        return {"outcome": "CLASS_LANDLORD"}
    state = row["node"]["landlords"].get(landlord)
    if state is None:
        return {"outcome": "CLASS_HISTORY_UNAVAILABLE"}
    if error := landlord_decision(state, row["context"], exact):
        return {"outcome": error}
    try:
        holders = value_read(state["current_value"])["holders"]
    except (ValueError, KeyError, TypeError):
        return {"outcome": "CLASS_HOLDER"}
    if child["owner_public_key"] not in holders:
        return {"outcome": "CLASS_HOLDER"}
    operation = row["node"]["recipient_name"]["creating_operation"]
    writers = [names.read_writer({"inputs": [dict(txin, spent_confirmed_at=1) for txin in operation["inputs"]], "created": {"operation": operation["operation"], "name": child["name"]}, "pin": holder}, 0) for holder in holders]
    if "written by the owner" not in writers:
        return {"outcome": "CLASS_HISTORY_UNAVAILABLE" if "unsupported" in writers else "CLASS_WRITER"}
    if agent["channel"] is None:
        return {"outcome": "identity: unsupported channel or missing channel key"}
    return {"outcome": "pass", "attestation": "not read" if row["row"]["certifier"] is None else "required"}


def calculate(files):
    groups, classes, values = [files[name] for name in ("groups-vectors.json", "class-vectors.json", "holders-vectors.json")]
    decisions = {}

    def record(row, actual, expected):
        if row["id"] in decisions:
            raise ValueError("duplicate R1 id")
        decisions[row["id"]] = actual
        if actual != expected:
            raise ValueError(f"R1_VECTOR_DISAGREEMENT {row['id']}: {actual!r} != {expected!r}")

    parents = {r["id"]: r["parent"] for r in groups["parents"]}
    for row in groups["parents"]:
        actual = group_decision(row["parent"])
        record(row, actual, row["expect"])
    for row in groups["ordinals"]:
        actual = ordinal_decision(parents[row["parent_of"]], row["ordinal"])
        record(row, actual, row["expect"])
    for row in classes["templates"]:
        actual = template_decision(row["template"])
        record(row, actual, row["expect"])
    for row in classes["admissions"]:
        actual = admission_decision(row)
        record(row, actual, row["expect"])
    for row in values["values"]:
        try:
            result = value_read(row["value"])
            actual = {"outcome": "valid", "grant": result["grant"], "holders": result["holders"]}
        except (ValueError, KeyError, TypeError):
            actual = {"outcome": "refused"}
        expected = {k: v for k, v in row["expect"].items() if k != "rule"}
        record(row, actual, expected)
    for row in values["capacity"]:
        size = len(row["value_without_holders"].encode())
        most = (520 - size - 12) // 69
        actual = {"without": size, "most": most, "with": size + 12 + 69 * most, "more": size + 12 + 69 * (most + 1)}
        expected = dict(zip(("without", "most", "with", "more"), (row[k] for k in ("bytes_without_holders", "most_holders", "bytes_with_most", "bytes_with_one_more"))))
        record(row, actual, expected)
    fit = files["row-fit-vectors.json"]
    for row in fit["vectors"]:
        child, template = row["child"], fit["row"]
        if not 1 <= child["ordinal"] <= fit["row_count"]:
            code = "CHILD_ORDINAL"
        elif child["executor"] != template["executor"]:
            code = "CHILD_AGENT_NOT_ALLOWED"
        elif "name" not in child["recipient"]:
            code = "CHILD_GRANTEE_NOT_ALLOWED"
        else:
            caps = limit_map(template["limits"])
            amounts = limit_map(child["limits"])
            code = "CHILD_BUDGET_OVER" if any(key not in caps or value > caps[key] for key, value in amounts.items()) else "pass"
        record(row, {"outcome": code}, row["expect"])
    if len(decisions) != 151:
        raise ValueError("R1 inventory differs")
    return decisions


def go_results(stream):
    decisions, passed, package = {}, set(), False
    for line in stream.splitlines():
        event = json.loads(line)
        if event.get("Action") in ("fail", "skip", "build-fail"):
            raise ValueError("R1 Go failure or skip")
        if event.get("Action") == "pass":
            passed.add(event.get("Test"))
            package |= "Test" not in event
        if "R1_RESULT " in event.get("Output", ""):
            item = json.loads(event["Output"].split("R1_RESULT ", 1)[1])
            if item["id"] in decisions:
                raise ValueError("duplicate Go R1 result")
            decisions[item["id"]] = item["result"]
    if not {"TestR1Groups", "TestR1Class", "TestR1Holders", "TestR1RowFitVectors"} <= passed or not package:
        raise ValueError("R1 Go package or required tests missing")
    return decisions


def agree(independent, go):
    if independent != go:
        wrong = sorted(k for k in independent.keys() | go.keys() if independent.get(k) != go.get(k))
        raise ValueError(f"R1_GO_DISAGREEMENT {wrong}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go-results", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        files = {}
        for filename, checksum in HASHES.items():
            raw = (ROOT / "testdata" / filename).read_bytes()
            if hashlib.sha256(raw).hexdigest() != checksum:
                raise ValueError("R1 fixture hash differs")
            files[filename] = json.loads(raw)
        independent = calculate(files)
        agree(independent, go_results(args.go_results.read_text()))
        if args.output:
            args.output.write_text(json.dumps(independent, sort_keys=True, indent=2) + "\n")
        print("AGREE 151 R1 vectors: independent Python = pinned vectors = Go; no node reads")
        return 0
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
