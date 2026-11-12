#!/usr/bin/env python3
"""Fail a PX1 gate unless every required test passed, with no skip at all.

Input: a gate manifest (.scripts/px1-core-gate.json for T1-T17,
.scripts/px1-s5-consumer-gate.json for the S5 client consumer) and one or more
`go test -json` event files of that manifest's package.

Each label (T-id) declares its REQUIRED layers ("layers": unit and/or core,
as the PX1 test table says) and lists the tests of each layer. The checker
keeps, per test, the set of EVERY terminal action it reported across all input
files and all `-count` repetitions (never only the last one). A test passes
only when that set is exactly {pass}: a skip or a fail anywhere, before or
after a pass, in the same file or another, fails it. The gate fails on:
- a label that is OPEN (it carries an "open" reason): a missing test is never
  a pass;
- a required layer with no test listed (MISSING_LAYER);
- a listed test that skipped, failed or never ran;
- a Core test with a required repetition count ("core_runs") that passed
  fewer times than that count;
- any skip anywhere in the streams (a Core test skips without W1_REGTEST, so a
  gate that admitted a skip would pass with no node at all);
- any failed test, a package or build failure;
- a line that is not a JSON event, an event of another package, or an empty
  stream.
The manifest must name exactly the labels listed in "labels". The summary line
says PX1_GATE PASS only when every required layer of every label passed.

Usage:
  check-px1-core-gate.py check --manifest M EVENTS.json [EVENTS.json ...]
  check-px1-core-gate.py list --manifest M {core,unit}
    core: one line per Core test, "NAME FLAGS" (go test flags from core_runs,
    default -count=1); unit: the top-level unit test names.

Exit status: 0 gate passed, 1 gate failed, 2 usage, manifest or input error.
"""
import argparse
import json
import re
import sys

TEST_NAME = re.compile(r"^Test[A-Za-z0-9_]+(/[A-Za-z0-9_.+-]+)*$")
TERMINAL = ("pass", "fail", "skip")
LAYERS = ("unit", "core")


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
    runs = m.get("core_runs", {})
    if not isinstance(runs, dict):
        raise InputError("manifest: core_runs must be an object")
    for n, r in runs.items():
        if n not in core or not isinstance(r, dict) or set(r) - {"count", "race"} or type(r.get("count")) is not int or not 1 <= r["count"] <= 100 or type(r.get("race", False)) is not bool:
            raise InputError(f"manifest core_runs {n}: a core test with count 1..100 and an optional race flag")
    for label in labels:
        entry = tids[label]
        if not isinstance(entry, dict) or set(entry) - {"core", "unit", "open", "layers"}:
            raise InputError(f"manifest {label}: only layers, core, unit and open are allowed")
        layers = entry.get("layers")
        if not isinstance(layers, list) or not layers or len(set(layers)) != len(layers) or any(x not in LAYERS for x in layers):
            raise InputError(f"manifest {label}: layers must list the required layers (unit, core)")
        for layer in LAYERS:
            if not isinstance(entry.get(layer, []), list):
                raise InputError(f"manifest {label}: {layer} must be a list")
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
    return m


def read_events(paths, package):
    """history[test] is the set of every terminal action the test reported in
    any of paths; passes[test] counts its passes."""
    history, passes, problems, events = {}, {}, [], 0
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
            history.setdefault(test, set()).add(action)
            if action == "pass":
                passes[test] = passes.get(test, 0) + 1
    if events == 0:
        problems.append("EMPTY_STREAM")
    return history, passes, problems


def check(manifest, paths):
    history, passes, problems = read_events(paths, manifest["package"])
    lines, failed = [], bool(problems)
    lines.extend(problems)
    for test, actions in sorted(history.items()):
        if "skip" in actions:
            failed = True
            lines.append(f"SKIPPED {test}")
        if "fail" in actions:
            failed = True
            lines.append(f"FAILED {test}")
    for n, r in sorted(manifest.get("core_runs", {}).items()):
        if passes.get(n, 0) < r["count"]:
            failed = True
            lines.append(f"REQUIRED_RUNS {n} passed={passes.get(n, 0)} want={r['count']}")
    passed, labels_failed = 0, 0
    for label in manifest["labels"]:
        entry = manifest["tids"][label]
        row, ok = [], True
        for layer in LAYERS:
            names = entry.get(layer, [])
            if layer in entry["layers"] and not names:
                ok = False
                lines.append(f"MISSING_LAYER {label} {layer}")
                row.append(f"{layer}: missing")
            for n in names:
                got = history.get(n, set())
                if got == {"pass"}:
                    passed += 1
                    row.append(f"{layer}: pass {n}")
                    continue
                ok = False
                codes = [c for a, c in (("skip", "REQUIRED_SKIPPED"), ("fail", "REQUIRED_FAILED")) if a in got] or ["REQUIRED_MISSING"]
                for code in codes:
                    lines.append(f"{code} {label} {n}")
                row.append(f"{layer}: {'+'.join(sorted(got)) or 'missing'} {n}")
        state = "PASS" if ok else "FAIL"
        if "open" in entry:
            # OPEN is never a pass, whatever else the label lists.
            ok, state = False, "OPEN"
            lines.append(f"OPEN_TID {label}")
            row.append("open: " + entry["open"])
        if not ok:
            failed = True
            labels_failed += 1
        lines.append(f"{label} {state} layers={'+'.join(entry['layers'])} " + "; ".join(row))
    if failed:
        lines.append(f"PX1_GATE FAIL labels_failed={labels_failed} required_passed={passed}")
    else:
        lines.append(f"PX1_GATE PASS labels={len(manifest['labels'])} required_passed={passed}")
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
            # core: every Core test (each needs its own fresh W1_RUN_ROOT) with
            # its go test flags; unit: the top-level unit test names, in
            # label order.
            tops = []
            if args.layer == "core":
                runs = manifest.get("core_runs", {})
                for n in manifest.get("core_tests", []):
                    r = runs.get(n, {"count": 1})
                    tops.append(n + (" -race" if r.get("race") else "") + f" -count={r['count']}")
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
