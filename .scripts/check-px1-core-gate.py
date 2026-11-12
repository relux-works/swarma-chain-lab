#!/usr/bin/env python3
"""Fail a PX1 gate unless every required test passed, with no skip at all.

Input: a gate manifest (.scripts/px1-core-gate.json for T1-T17,
.scripts/px1-s5-consumer-gate.json for the S5 client consumer) and one or more
`go test -json` event files of that manifest's package.

A required test passes only when its last action is "pass". The gate fails on:
- a required test that skipped, failed or never ran;
- any skip anywhere in the streams (a Core test skips without W1_REGTEST, so a
  gate that admitted a skip would pass with no node at all);
- any failed test, a package or build failure;
- a line that is not a JSON event, an event of another package, or an empty
  stream.
A label (T-id) with no required test must carry an "open" reason; it is
reported as OPEN and never as a pass. The manifest must name exactly the labels
listed in "labels".

Usage:
  check-px1-core-gate.py check --manifest M EVENTS.json [EVENTS.json ...]
  check-px1-core-gate.py list --manifest M {core,unit}

Exit status: 0 gate passed, 1 gate failed, 2 usage, manifest or input error.
"""
import argparse
import json
import re
import sys

TEST_NAME = re.compile(r"^Test[A-Za-z0-9_]+(/[A-Za-z0-9_.+-]+)*$")
TERMINAL = ("pass", "fail", "skip")


class InputError(Exception):
    """The gate could not be evaluated; never reported as a pass."""


def load_manifest(path):
    try:
        with open(path, encoding="utf-8") as f:
            m = json.load(f)
    except (OSError, ValueError) as e:
        raise InputError(f"manifest {path}: {e}")
    if not isinstance(m, dict) or m.get("v") != 1 or not isinstance(m.get("package"), str) or not m["package"]:
        raise InputError("manifest: v must be 1 and package a non-empty string")
    labels, tids, core = m.get("labels"), m.get("tids"), m.get("core_tests", [])
    if not isinstance(labels, list) or not labels or not isinstance(tids, dict) or set(tids) != set(labels) or len(set(labels)) != len(labels):
        raise InputError("manifest: tids must name exactly the listed labels")
    if not isinstance(core, list) or any(not isinstance(n, str) or "/" in n or not TEST_NAME.match(n) for n in core):
        raise InputError("manifest: core_tests must be top-level test names")
    for label in labels:
        entry = tids[label]
        if not isinstance(entry, dict) or set(entry) - {"core", "unit", "open"}:
            raise InputError(f"manifest {label}: only core, unit and open are allowed")
        names = entry.get("core", []) + entry.get("unit", [])
        for n in names:
            if not isinstance(n, str) or not TEST_NAME.match(n):
                raise InputError(f"manifest {label}: malformed test name {n!r}")
        for n in entry.get("core", []):
            if n.split("/")[0] not in core:
                raise InputError(f"manifest {label}: core test {n} is not under core_tests")
        for n in entry.get("unit", []):
            if n.split("/")[0] in core:
                raise InputError(f"manifest {label}: unit test {n} is a core test")
        open_reason = entry.get("open")
        if open_reason is not None and (not isinstance(open_reason, str) or not open_reason.strip()):
            raise InputError(f"manifest {label}: open must be a non-empty reason")
        if not names and open_reason is None:
            raise InputError(f"manifest {label}: no required test and no open reason")
    return m


def read_events(paths, package):
    status, problems, events = {}, [], 0
    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                lines = f.read().splitlines()
        except OSError as e:
            raise InputError(f"events {path}: {e}")
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                problems.append(f"NOT_JSON {path}:{number}")
                continue
            if not isinstance(ev, dict) or not isinstance(ev.get("Action"), str):
                problems.append(f"NOT_EVENT {path}:{number}")
                continue
            events += 1
            action = ev["Action"]
            if action == "build-fail":
                problems.append(f"BUILD_FAILED {ev.get('ImportPath', '?')}")
                continue
            pkg = ev.get("Package")
            if pkg is not None and pkg != package:
                problems.append(f"OTHER_PACKAGE {pkg}")
                continue
            test = ev.get("Test")
            if action not in TERMINAL:
                continue
            if test is None:
                if action == "fail":
                    problems.append(f"PACKAGE_FAILED {path}")
                continue
            status[test] = action
    if events == 0:
        problems.append("EMPTY_STREAM")
    return status, problems


def check(manifest, paths):
    status, problems = read_events(paths, manifest["package"])
    lines, failed = [], bool(problems)
    lines.extend(problems)
    for test, action in sorted(status.items()):
        if action == "skip":
            failed = True
            lines.append(f"SKIPPED {test}")
        elif action == "fail":
            failed = True
            lines.append(f"FAILED {test}")
    passed = 0
    for label in manifest["labels"]:
        entry = manifest["tids"][label]
        names = entry.get("core", []) + entry.get("unit", [])
        row = []
        for n in names:
            got = status.get(n)
            if got == "pass":
                passed += 1
                row.append(f"pass {n}")
                continue
            failed = True
            code = {"skip": "REQUIRED_SKIPPED", "fail": "REQUIRED_FAILED"}.get(got, "REQUIRED_MISSING")
            lines.append(f"{code} {label} {n}")
            row.append(f"{got or 'missing'} {n}")
        state = "PASS" if names and all(r.startswith("pass ") for r in row) else ("FAIL" if names else "OPEN")
        detail = "; ".join(row)
        if "open" in entry:
            detail = (detail + "; " if detail else "") + "open: " + entry["open"]
        lines.append(f"{label} {state} {detail}")
    lines.append(f"PX1_GATE {'FAIL' if failed else 'PASS'} required_passed={passed}")
    return (1 if failed else 0), lines


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--manifest", required=True)
    c.add_argument("events", nargs="+")
    lst = sub.add_parser("list")
    lst.add_argument("--manifest", required=True)
    lst.add_argument("layer", choices=("core", "unit"))
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    try:
        manifest = load_manifest(args.manifest)
        if args.cmd == "list":
            # core: every Core test (each needs its own fresh W1_RUN_ROOT);
            # unit: the top-level names of the unit tests, in label order.
            tops = list(manifest.get("core_tests", [])) if args.layer == "core" else []
            if args.layer == "unit":
                for label in manifest["labels"]:
                    for n in manifest["tids"][label].get("unit", []):
                        if n.split("/")[0] not in tops:
                            tops.append(n.split("/")[0])
            print("\n".join(tops))
            return 0
        code, lines = check(manifest, args.events)
    except InputError as e:
        print(f"PX1_GATE INPUT_ERROR {e}", file=sys.stderr)
        return 2
    print("\n".join(lines))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
