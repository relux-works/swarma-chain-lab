#!/usr/bin/env python3
"""Independent v0.1.51 R1 profile calculations; no Go parsing/intermediates.

This reader reuses the existing Python O3/O4 primitives, independently of Go.
Expectations are consulted after decisions. No node or signature is qualified.
"""
import argparse
import copy
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
HASHES = {"row-fit-vectors.json":"b92eb11c26432002daa51e8c463dbdfbaf27c5bc9b8b7c444ad51016c27f4ae8","groups-vectors.json":"46ebd308bf71332c3026320d4978e44e96e14e57a1f88aab614c47934b566c5c","class-vectors.json":"46522ae03176f6891a83c6a834af24fb7c16dfd4825ac83a5163bfdcf872f994","holders-vectors.json":"d7bd9ecdcd826b13a743a85b1875b8fc976c587ae37aa89a847b37b9d4152ad8"}


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


def value_members(raw):
    """Strict LIP-0010 2.1 reading: object at byte zero, no byte after it."""
    if len(raw.encode("utf-8")) > 520:
        raise ValueError("size")
    decoder = json.JSONDecoder(object_pairs_hook=Pairs)
    if not raw.startswith("{"):
        raise ValueError("leading bytes")
    top, end = decoder.raw_decode(raw)
    if not isinstance(top, Pairs) or end != len(raw):
        raise ValueError("top or trailing bytes")
    read = {}
    for key, val in top:
        if key.casefold() in ("swarma", "nostr"):
            if key not in ("swarma", "nostr") or key in read:
                raise ValueError("read alias/duplicate")
            read[key] = val
    return decoder, top, read


def value_read(raw, profile="draft"):
    decoder, top, read = value_members(raw)
    swarma = obj(read["swarma"])
    if list(swarma) == ["agent"]:
        binding = obj(swarma["agent"])
        if list(binding) != ["landlord"] or not isinstance(binding["landlord"], str) or not binding["landlord"]:
            raise ValueError("agent binding")
        result = {"landlord": binding["landlord"]}
    elif list(swarma) == ["landlord"]:
        binding = obj(swarma["landlord"])
        # LIP-0010 0.1.53 M2: neither form supplies a holder when both occur.
        if "holders" in binding and any(key == "swarma-holders" for key, _ in top):
            raise ValueError("CLASS_HOLDER")
        if list(binding) not in (["grant"], ["grant", "holders"]) or not signing_key(binding["grant"]):
            raise ValueError("landlord binding")
        holders = binding.get("holders", [])
        if type(holders) is not list or any(not isinstance(p, str) or names.pin_result(p) != "pin" for p in holders):
            raise ValueError("holder pin")
        if profile == "draft" and any(a >= b for a, b in zip(holders, holders[1:])):
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



def holders_capacity(raw):
    """Product-equivalent capacity for a valid landlord with holders absent."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    value = value_read(raw, "in-force-051")
    _, _, members = value_members(raw)
    binding = obj(obj(members["swarma"])["landlord"])
    if "grant" not in value or list(binding) != ["grant"]:
        raise ValueError("capacity requires absent holders")
    size = len(raw.encode("utf-8"))
    most = max(0, (520 - size - 12) // 69)
    with_most = size if most == 0 else size + 12 + 69 * most
    return {"without": size, "most": most, "with": with_most,
            "more": size + 12 + 69 * (most + 1)}


def capacity_cases():
    """Every envelope size, plus invalid shapes and a UTF-8 byte control."""
    key = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    base = '{"swarma":{"landlord":{"grant":"' + key + '"}}}'
    for size in range(521):
        raw = "x" * size if size < len(base) else base[:-1] + " " * (size - len(base)) + "}"
        yield f"size/{size}", raw.encode()
    invalid = {
        "malformed": b"{", "agent": b'{"swarma":{"agent":{"landlord":"id/example"}}}',
        "empty-holders": base.replace('"}}}', '","holders":[]}}}').encode(),
        "present-holders": base.replace('"}}}', '","holders":["02' + key + '"]}}}').encode(),
        "oversize": (base[:-1] + " " * (521 - len(base)) + "}").encode(),
        "leading": (" " + base).encode(), "trailing": (base + " ").encode(),
        "alias": base.replace("swarma", "Swarma").encode(),
        "duplicate": ('{"swarma":{},' + base[1:]).encode(),
        "noncompact": base.replace('"grant":', '"grant": ').encode(),
        "bad-key": base.replace(key, "0" * 64).encode(),
        "missing-binding": b"{}", "not-object": b"[]",
        "extra-binding": base.replace('"}}}', '","other":0}}}').encode(),
        "invalid-utf8": b'{"unused":"\xff",' + base[1:].encode(),
    }
    for name, raw in invalid.items():
        yield "invalid/" + name, raw
    yield "utf8", ('{"padding":"é",' + base[1:]).encode()


def capacity_result(raw):
    try:
        return holders_capacity(raw)
    except (ValueError, KeyError, TypeError):
        return {"outcome": "refused", "most": 0, "with": 0, "more": 0}


def limit_map(limits):
    amounts = {}
    for limit in limits:
        key = tuple(limit.get(k, "") for k in ("kind", "resource", "unit", "period"))
        if key in amounts or not all(key[:3]) or type(limit["amount"]) is not int or limit["amount"] < 0:
            raise ValueError("limit identity")
        amounts[key] = limit["amount"]
    return amounts


def group_decision(parent, profile="draft"):
    groups = parent["groups"]
    if profile == "draft" and (not 1 <= len(groups) <= 16 or any(not 1 <= len(g["ranges"]) <= 16 for g in groups)):
        return {"outcome": "refused", "rule": "R8.4"}
    coins, sums, total = {}, {}, 0
    for group in groups:
        rows = 0
        for interval in group["ranges"]:
            first, count = interval["first"], interval["count"]
            if profile == "draft" and count > 4096:
                return {"outcome": "refused", "rule": "R8.4"}
            if count < 1 or first < 0 or first + count > 2**32 or (profile == "draft" and re.fullmatch("0014[0-9a-f]{40}", interval["script_hex"]) is None):
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


def fixture_template(template):
    # The upstream class fixtures omit executor facts. Match the Go fixture
    # adapter's explicitly synthetic valid executor, without changing fixtures.
    return dict(template, executor={"name": "service.example", "key": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"})


def template_decision(template):
    executor = template.get("executor", {})
    if not executor.get("name") or not signing_key(executor.get("key")):
        return {"outcome": "refused", "rule": "R8.1"}
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


def landlord_decision(state, context, exact, profile="draft"):
    if profile == "in-force-051":
        if "pinned_checkpoint" not in state:
            return "CLASS_HISTORY_UNAVAILABLE"
        context = dict(context, recent_block_height=state["pinned_checkpoint"])
        if context["recent_block_height"] > context["tip_height"]:
            return "CLASS_HISTORY_UNAVAILABLE"
        exact = False
    status = state.get("current_status", 1)
    if status == 2:
        return "CLASS_LANDLORD_CHANGED"
    if status != 1:
        return "CLASS_HISTORY_UNAVAILABLE"
    history = state["history"]
    if not history:
        return "CLASS_HISTORY_UNAVAILABLE"
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
    if profile == "draft":
        writer = history[0]["writer"]
        if writer == "written by another":
            return "CLASS_VALUE_UNAUTHORIZED"
        if writer != "written by the owner":
            return "CLASS_HISTORY_UNAVAILABLE"
    if state.get("pending_spend_of_current_output", False):
        return "CLASS_LANDLORD_PENDING"
    return None


def admission_decision(row, profile="draft"):
    constraint = row["row"]["recipient"]
    child = row["child"]["recipient"]
    exact = "name" in constraint
    if "name" not in child or (exact and child != constraint):
        return {"outcome": "CHILD_GRANTEE_NOT_ALLOWED"}
    status = row["node"]["recipient_name"].get("current_status", 1)
    if status == 2:
        return {"outcome": "RECIPIENT_NAME_NOT_HELD"}
    if status != 1:
        return {"outcome": "RECIPIENT_NAME_UNAVAILABLE"}
    raw = bytes.fromhex(row["node"]["recipient_name"]["current_output_script_hex"])
    reading = names.read_script(raw, child["owner_public_key"], row["context"]["tip_height"], 0)
    if reading["reading"] == "unsupported":
        return {"outcome": "RECIPIENT_NAME_UNAVAILABLE"}
    if reading["reading"] == "another key":
        return {"outcome": "RECIPIENT_NAME_NOT_HELD"}
    if reading.get("name") != child["name"]:
        return {"outcome": "RECIPIENT_NAME_UNAVAILABLE"}
    if exact and row["row"]["certifier"] is not None:
        try:
            _, _, members = value_members(reading["value"])
            key = channel(members.get("nostr"))
        except (ValueError, KeyError, TypeError):
            key = None
        if key is None:
            return {"outcome": "identity: unsupported channel or missing channel key"}
        return {"outcome": "pass", "attestation": "required"}
    try:
        agent = value_read(reading["value"], profile)
        landlord = agent["landlord"]
    except (ValueError, KeyError, TypeError):
        return {"outcome": "CLASS_LANDLORD"}
    pins = [row["issuer"]] if exact else constraint["class"]
    if landlord not in [p["name"] for p in pins]:
        return {"outcome": "CLASS_LANDLORD"}
    state = row["node"]["landlords"].get(landlord)
    if state is None:
        return {"outcome": "CLASS_HISTORY_UNAVAILABLE"}
    if error := landlord_decision(state, row["context"], exact, profile):
        return {"outcome": error}
    try:
        holders = value_read(state["current_value"], profile)["holders"]
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
    return {"outcome": "pass", "attestation": ("not read" if profile == "draft" else "not required") if row["row"]["certifier"] is None else "required"}


def revision_decisions(files):
    decisions = {}
    classes = files["class-vectors.json"]
    control = next(row for row in classes["admissions"] if row["id"] == "class-01")
    value = next(row["value"] for row in files["holders-vectors.json"]["values"] if row["id"] == "value-03")
    boundaries = [("suffix", item) for item in (" ", "\t", "\n", "\r\n", " {}")]
    boundaries += [("prefix", item) for item in (" ", "\t", "\n", "\r\n")]
    for side, extra in boundaries:
        tag = extra.encode().hex()
        value_id = "r2-value-" if side == "suffix" else "r3-value-prefix-"
        child_id = "r2-child-" if side == "suffix" else "r3-child-prefix-"
        # The canonical value is a positive beside each forbidden boundary byte.
        value_read(value)
        try:
            value_read(value + extra if side == "suffix" else extra + value)
            outcome = "valid"
        except (ValueError, KeyError, TypeError):
            outcome = "identity: invalid R1 name value"
        decisions[value_id + tag] = outcome
        for exact in (False, True):
            row = copy.deepcopy(control)
            if exact:
                row["row"]["recipient"] = row["child"]["recipient"]
            if admission_decision(row)["outcome"] != "pass":
                raise ValueError("revision positive control")
            # Replace only the name value in a minimal update script.
            raw = bytes.fromhex(row["node"]["recipient_name"]["current_output_script_hex"])
            parsed = names.read_script(raw, row["child"]["recipient"]["owner_public_key"], row["context"]["tip_height"], 0)
            def push(data):
                if len(data) <= 75:
                    return bytes([len(data)]) + data
                if len(data) <= 255:
                    return bytes([0x4c, len(data)]) + data
                return bytes([0x4d, len(data) & 255, len(data) >> 8]) + data
            address = bytes.fromhex(parsed["address_script_hex"])
            changed_value = parsed["value"] + extra if side == "suffix" else extra + parsed["value"]
            script = b"\x53" + push(row["child"]["recipient"]["name"].encode()) + push(changed_value.encode()) + b"\x6d\x75" + address
            row["node"]["recipient_name"]["current_output_script_hex"] = script.hex()
            decisions[f"{child_id}{str(exact).lower()}-{tag}"] = admission_decision(row)["outcome"]
    for status in (2, 0, 3, 99, 255):
        row = copy.deepcopy(control)
        parsed = names.read_script(bytes.fromhex(row["node"]["recipient_name"]["current_output_script_hex"]), row["child"]["recipient"]["owner_public_key"], row["context"]["tip_height"], 0)
        selected = value_read(parsed["value"])["landlord"]
        landlord = row["node"]["landlords"][selected]
        landlord["current_status"] = status
        landlord["history"] = []
        decisions[f"r2-landlord-{status}"] = admission_decision(row)["outcome"]
    for status in range(256):
        row = copy.deepcopy(control)
        row["node"]["recipient_name"]["current_status"] = status
        decisions[f"r2-recipient-{status}"] = admission_decision(row)["outcome"]
    absent = copy.deepcopy(control)
    absent["node"]["recipient_name"] = {"current_status": 2}
    decisions["r3-recipient-absence-cross-path"] = admission_decision(absent)["outcome"]
    return decisions



PROFILE_ERROR = "R1_PROFILE_UNAVAILABLE"
DRAFT_ERROR = "R1_DRAFT_RULE_UNAVAILABLE"


def rule_availability(profile, rule, catalog):
    if profile not in ("draft", "in-force-051"):
        return PROFILE_ERROR
    if rule not in catalog or (profile == "in-force-051" and catalog[rule] == "DRAFT"):
        return DRAFT_ERROR
    return "available"


def fit_decision(child, template, rows):
    if not 1 <= child["ordinal"] <= rows:
        code = "CHILD_ORDINAL"
    elif child["executor"] != template["executor"]:
        code = "CHILD_AGENT_NOT_ALLOWED"
    elif "name" not in child["recipient"]:
        code = "CHILD_GRANTEE_NOT_ALLOWED"
    else:
        caps, amounts = limit_map(template["limits"]), limit_map(child["limits"])
        code = "CHILD_BUDGET_OVER" if any(key not in caps or value > caps[key] for key, value in amounts.items()) else "pass"
    return {"outcome": code}


def profile_vectors(files, profile):
    """Apply a named profile to original fixture octets, never Go results."""
    result = {}
    closed = profile not in ("draft", "in-force-051")
    groups = files["groups-vectors.json"]
    parents = {row["id"]: row["parent"] for row in groups["parents"]}
    for row in groups["parents"]:
        result[row["id"]] = PROFILE_ERROR if closed else group_decision(row["parent"], profile)
    for row in groups["ordinals"]:
        result[row["id"]] = PROFILE_ERROR if closed else (DRAFT_ERROR if profile == "in-force-051" else ordinal_decision(parents[row["parent_of"]], row["ordinal"]))
    for row in files["class-vectors.json"]["templates"]:
        result[row["id"]] = PROFILE_ERROR if closed else template_decision(fixture_template(row["template"]))
    for original in files["class-vectors.json"]["admissions"]:
        row = copy.deepcopy(original)
        # Adapter convention: fixture checkpoint explicitly states 500, also
        # equal to its recent block. Separate controls break that equality.
        for state in row["node"]["landlords"].values():
            state["pinned_checkpoint"] = 500
        result[row["id"]] = PROFILE_ERROR if closed else admission_decision(row, profile)
    for row in files["holders-vectors.json"]["values"]:
        if closed:
            actual = PROFILE_ERROR
        else:
            try:
                value = value_read(row["value"], profile)
                actual = {"outcome": "valid", "grant": value["grant"], "holders": value["holders"]}
            except (ValueError, KeyError, TypeError):
                actual = {"outcome": "refused"}
        result[row["id"]] = actual
    for row in files["holders-vectors.json"]["capacity"]:
        result[row["id"]] = PROFILE_ERROR if closed else holders_capacity(row["value_without_holders"])
    fit = files["row-fit-vectors.json"]
    for row in fit["vectors"]:
        result[row["id"]] = PROFILE_ERROR if closed else fit_decision(row["child"],fit["row"],fit["row_count"])
    return result


def profile_calculate(files):
    config = json.loads((ROOT / "testdata" / "profile-vectors.json").read_text())
    if config["spec_tag"] != "v0.1.51" or config["spec_commit"] != "bd3bc80e5543d8a563343ec05abd1a5f3f67284c":
        raise ValueError("R1 profile specification pin differs")
    catalog = {row["rule"]: row["status"] for row in config["rules"]}
    if len(catalog) != 20 or len(config["profiles"]) != 5:
        raise ValueError("R1 profile inventory differs")
    output = {}
    base = profile_vectors(files, "draft")
    for profile in config["profiles"]:
        actual = profile_vectors(files, profile["name"])
        for identifier, value in actual.items():
            expected = base[identifier]
            if profile["name"] == "in-force-051":
                expected = config["in_force_overrides"].get(identifier, expected)
            elif profile["name"] != "draft":
                expected = PROFILE_ERROR
            if value != expected:
                raise ValueError(f"profile {profile['name']} {identifier}: {value!r} != {expected!r}")
            output[f"profile/{profile['name']}/{identifier}"] = value
        for rule in config["rules"]:
            output[f"profile/{profile['name']}/rule/{rule['rule']}"] = rule_availability(profile["name"], rule["rule"], catalog)
    return output



def executor_recipient_decisions(files):
    """Bounded template and parent-first composition on the valid A3 fixture.

    In-force parent/child entry points refuse before any template predicate.
    Child facts and fit stay valid here: only its parent's template is changed.
    """
    admission = files["class-vectors.json"]["admissions"][0]
    template = fixture_template(dict(admission["row"], issuer=admission["issuer"],
                                     notaries=[admission["row"]["certifier"]]))
    template["executor"]["key"] = admission["issuer"]["owner_public_key"][2:]
    output = {}
    for profile in ("draft", "in-force-051"):
        for path in ("template", "parent", "child"):
            for defect in ("valid", "executor", "recipient", "both"):
                candidate = copy.deepcopy(template)
                if defect in ("executor", "both"):
                    candidate["executor"]["name"] = ""
                if defect in ("recipient", "both"):
                    candidate["recipient"]["request_public_key"] = "request-key"
                if profile == "in-force-051" and path != "template":
                    actual = DRAFT_ERROR
                else:
                    result = template_decision(candidate)
                    actual = "valid" if result["outcome"] == "valid" else result["rule"]
                    if path == "child" and actual == "valid":
                        if admission_decision(admission, profile)["outcome"] != "pass":
                            raise ValueError("A4 composed positive fixture failed")
                output[f"a4-order/{profile}/{path}/{defect}"] = actual
    return output


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
        actual = template_decision(fixture_template(row["template"]))
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
        actual = holders_capacity(row["value_without_holders"])
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
    decisions.update(revision_decisions(files))
    decisions.update(profile_calculate(files))
    template = fixture_template(classes["templates"][0]["template"])
    # r1FullParent's A3 controls use the first admission's issuer key as the
    # executor key. Exercise those same key octets, including the short form.
    key = classes["admissions"][0]["issuer"]["owner_public_key"][2:]
    # R8.1 is decided in both profiles (LIP-0026 L510/L526). Expectations
    # follow that shape contract, independently of Go verdicts.
    for profile in ("draft", "in-force-051"):
        for identifier, name, candidate, expected in (
            ("valid", "service.example", key, "valid"),
            ("empty-name", "", key, "R8.1"),
            ("empty-key", "service.example", "", "R8.1"),
            ("short-key", "service.example", key[1:], "R8.1"),
            ("uppercase-key", "service.example", key.upper(), "R8.1"),
            ("off-curve-key", "service.example", "0"*64, "R8.1"),
            ("nonhex-key", "service.example", "g"*64, "R8.1"),
        ):
            row = dict(template, executor={"name": name, "key": candidate})
            actual = template_decision(row)
            verdict = "valid" if actual["outcome"] == "valid" else actual["rule"]
            record({"id": f"a3-executor/{profile}/{identifier}"}, verdict, expected)
    decisions.update(executor_recipient_decisions(files))
    for identifier, raw in capacity_cases():
        decisions["a4-capacity/" + identifier] = capacity_result(raw)
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
    if not {"TestR1Groups", "TestR1Class", "TestR1Holders", "TestR1RowFitVectors", "TestR1Profiles", "TestR1HoldersCapacityRange", "TestR1ExecutorRecipientOrder"} <= passed or not package:
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
        print(f"AGREE {len(independent)} R1 cases: independent Python = Go (pinned vectors and generated controls); no node reads")
        return 0
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(error, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
