#!/usr/bin/env python3
"""Known-bad controls for .scripts/check-px1-core-gate.py.

Run: python3 -B -m unittest discover -s .scripts -p 'test_check_px1_core_gate.py' -v
Each case writes a synthetic `go test -json` stream built from the real gate
manifest and runs the checker CLI exactly as CI does. PX1_GATE_CHECKER may
point at a mutated copy of the checker for gate-mutation runs.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import re

REPO = Path(__file__).resolve().parents[1]
CHECKER = Path(os.environ.get("PX1_GATE_CHECKER", REPO / ".scripts" / "check-px1-core-gate.py"))
MANIFEST = REPO / ".scripts" / "px1-core-gate.json"
CONSUMER = REPO / ".scripts" / "px1-s5-consumer-gate.json"
INTERFACES = REPO / "experiments" / "agent-wallet" / "PX1-INTERFACES.md"


def table_layers(path=INTERFACES):
    """The required layers of T1-T17 from the frozen test table ("Test ids"
    in PX1-INTERFACES.md): "unit" and/or "Core" in the Layer column; T10's
    "Core subprocess" is a Core layer. T18 (host script) is not a gate label."""
    out = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 5 and re.fullmatch(r"T([1-9]|1[0-7])", cells[0]):
            layer = cells[3]
            out[cells[0]] = [x for x, word in (("unit", "unit"), ("core", "Core")) if word in layer]
    return out


def layer_mismatches(manifest, table):
    """Labels whose declared layers differ from the table, or that the
    manifest and the table do not both name."""
    names = set(manifest["labels"]) | set(table)
    return sorted(n for n in names if sorted(manifest["tids"].get(n, {}).get("layers", [])) != sorted(table.get(n, [])))


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def required(manifest):
    names = []
    for label in manifest["labels"]:
        entry = manifest["tids"][label]
        for n in entry.get("core", []) + entry.get("unit", []):
            if n not in names:
                names.append(n)
    return names


def stream(manifest, override=None, extra=()):
    """A go test -json stream in which every required test (and each parent of
    a required subtest) runs and passes, except where override names another
    final action (None drops the test entirely)."""
    override = override or {}
    pkg = manifest["package"]
    tests = []
    for n in required(manifest):
        parts = n.split("/")
        for i in range(1, len(parts) + 1):
            t = "/".join(parts[:i])
            if t not in tests:
                tests.append(t)
    lines = []
    runs = manifest.get("core_runs", {})
    for t in tests:
        action = override.get(t, "pass")
        if action is None:
            continue
        # A Core test with a required count runs that many times (go test
        # -count=N reports each repetition).
        for _ in range(runs.get(t, {}).get("count", 1)):
            lines.append({"Action": "run", "Package": pkg, "Test": t})
            lines.append({"Action": "output", "Package": pkg, "Test": t, "Output": "=== RUN   " + t + "\n"})
            lines.append({"Action": action, "Package": pkg, "Test": t, "Elapsed": 0.01})
    lines.extend(extra)
    lines.append({"Action": "pass" if "fail" not in override.values() else "fail", "Package": pkg, "Elapsed": 0.5})
    return "\n".join(json.dumps(x) for x in lines) + "\n"


class Gate(unittest.TestCase):
    def run_checker(self, *texts, manifest=MANIFEST):
        with tempfile.TemporaryDirectory() as d:
            paths = []
            for i, text in enumerate(texts):
                p = Path(d) / f"events-{i}.json"
                p.write_text(text, encoding="utf-8")
                paths.append(str(p))
            r = subprocess.run([sys.executable, "-I", "-B", str(CHECKER), "check", "--manifest", str(manifest), *paths],
                               capture_output=True, text=True, timeout=60)
            return r.returncode, r.stdout + r.stderr

    def run_manifest(self, manifest, *texts):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "m.json"
            p.write_text(json.dumps(manifest), encoding="utf-8")
            return self.run_checker(*texts, manifest=p)

    # Claim: the valid neighbour passes: a complete run in which every listed
    # test of every required layer of T1-T17 passes (T9 50 times) gives exit 0
    # and PX1_GATE PASS, with every label reported PASS and none OPEN.
    def test_all_required_pass(self):
        m = load(MANIFEST)
        code, out = self.run_checker(stream(m))
        self.assertEqual(code, 0, out)
        self.assertIn("PX1_GATE PASS labels=17", out)
        for label in m["labels"]:
            self.assertRegex(out, rf"(?m)^{label} PASS layers=")
        self.assertNotIn("OPEN", out)

    # Claim: the gate manifest declares, for every T1-T17, exactly the
    # required layers of the frozen test table, and every required layer
    # lists at least one test. Control: the comparison reports a manifest
    # whose T3 drops its Core layer, and one that omits T9.
    def test_manifest_layers_match_table(self):
        m, table = load(MANIFEST), table_layers()
        self.assertEqual(sorted(table, key=lambda x: int(x[1:])), m["labels"])
        self.assertEqual(layer_mismatches(m, table), [])
        self.assertEqual(table["T9"], ["core"])
        self.assertEqual(table["T10"], ["core"])
        self.assertEqual(table["T3"], ["unit", "core"])
        for label in m["labels"]:
            for layer in m["tids"][label]["layers"]:
                self.assertTrue(m["tids"][label].get(layer), f"{label} {layer}")
        weak = json.loads(json.dumps(m))
        weak["tids"]["T3"]["layers"] = ["unit"]
        self.assertEqual(layer_mismatches(weak, table), ["T3"])
        gap = json.loads(json.dumps(m))
        gap["labels"].remove("T9")
        del gap["tids"]["T9"]
        self.assertEqual(layer_mismatches(gap, table), ["T9"])

    # Claim (known-bad control): a planted OPEN T-id fails the gate (exit 1,
    # OPEN_TID, never PX1_GATE PASS), both with no test at all and when its
    # listed tests pass; the passing neighbour is test_all_required_pass.
    def test_open_tid_fails(self):
        base = load(MANIFEST)
        for name, entry in [("no-test", {"layers": ["core"], "open": "not written"}),
                            ("tests-pass", dict(base["tids"]["T9"], open="still open"))]:
            with self.subTest(case=name):
                m = json.loads(json.dumps(base))
                m["tids"]["T9"] = entry
                code, out = self.run_manifest(m, stream(m))
                self.assertEqual(code, 1, out)
                self.assertIn("OPEN_TID T9", out)
                self.assertRegex(out, r"(?m)^T9 OPEN ")
                self.assertIn("PX1_GATE FAIL", out)
                self.assertNotIn("PX1_GATE PASS", out)

    # Claim (known-bad control): a T-id whose required Core layer lists no
    # test fails the gate with MISSING_LAYER even though its unit tests pass
    # (T3, T5), and so does a Core-only T-id with no test (T10).
    def test_missing_core_layer_fails(self):
        base = load(MANIFEST)
        for label in ("T3", "T5", "T10"):
            with self.subTest(label=label):
                m = json.loads(json.dumps(base))
                m["tids"][label].pop("core")
                if not m["tids"][label].get("unit"):
                    m["tids"][label]["unit"] = ["TestPX1T16ClockRollback"]
                code, out = self.run_manifest(m, stream(m))
                self.assertEqual(code, 1, out)
                self.assertIn(f"MISSING_LAYER {label} core", out)
                self.assertRegex(out, rf"(?m)^{label} FAIL ")
                self.assertNotIn("PX1_GATE PASS", out)

    # Claim (known-bad control): T9 must pass in every one of its 50 required
    # repetitions: 49 passes fail REQUIRED_RUNS, and a failing repetition
    # followed by passes fails although the last action is a pass.
    def test_required_runs(self):
        m = load(MANIFEST)
        pkg = m["package"]
        full = stream(m).splitlines()
        passes = [i for i, line in enumerate(full) if json.loads(line) == {"Action": "pass", "Package": pkg, "Test": "TestPX1CoreS2Race", "Elapsed": 0.01}]
        self.assertEqual(len(passes), 50)
        short = "\n".join(line for i, line in enumerate(full) if i != passes[0]) + "\n"
        code, out = self.run_checker(short)
        self.assertEqual(code, 1, out)
        self.assertIn("REQUIRED_RUNS TestPX1CoreS2Race passed=49 want=50", out)
        flaky = list(full)
        flaky[passes[0]] = json.dumps({"Action": "fail", "Package": pkg, "Test": "TestPX1CoreS2Race", "Elapsed": 0.01})
        flaky.append(json.dumps({"Action": "pass", "Package": pkg, "Test": "TestPX1CoreS2Race", "Elapsed": 0.01}))
        code, out = self.run_checker("\n".join(flaky) + "\n")
        self.assertEqual(code, 1, out)
        self.assertIn("REQUIRED_FAILED T9 TestPX1CoreS2Race", out)
        self.assertNotIn("PX1_GATE PASS", out)
        listed = subprocess.run([sys.executable, "-I", "-B", str(CHECKER), "list", "--manifest", str(MANIFEST), "core"], capture_output=True, text=True, timeout=60)
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn("TestPX1CoreS2Race -race -count=50", listed.stdout.splitlines())
        self.assertIn("TestPX1CoreS2 -count=1", listed.stdout.splitlines())

    # Claim (the brief's known-bad control): for EVERY T-id with a required
    # test, a skip of that test fails the gate with REQUIRED_SKIPPED naming the
    # T-id, so no T-id can pass by skipping.
    def test_required_skip_fails_each_tid(self):
        m = load(MANIFEST)
        for label in m["labels"]:
            entry = m["tids"][label]
            for n in entry.get("core", []) + entry.get("unit", []):
                with self.subTest(label=label, test=n):
                    code, out = self.run_checker(stream(m, {n: "skip"}))
                    self.assertEqual(code, 1, out)
                    self.assertIn(f"REQUIRED_SKIPPED {label} {n}", out)
                    self.assertIn("PX1_GATE FAIL", out)

    # Claim: a Core test that skipped as a whole (no W1_REGTEST: the parent
    # skips and its subtests never run) fails the gate.
    def test_core_parent_skipped(self):
        m = load(MANIFEST)
        override = {"TestPX1CoreS1": "skip"}
        for n in required(m):
            if n.startswith("TestPX1CoreS1/"):
                override[n] = None
        code, out = self.run_checker(stream(m, override))
        self.assertEqual(code, 1, out)
        self.assertIn("REQUIRED_MISSING T1 TestPX1CoreS1/T1-at-transfer-cap", out)
        self.assertIn("SKIPPED TestPX1CoreS1", out)

    # Claim: a skip of a test outside the required list also fails (no skip
    # anywhere), as do a failed required test and a missing required test.
    def test_other_skip_fail_missing(self):
        m = load(MANIFEST)
        pkg = m["package"]
        extra = [{"Action": "run", "Package": pkg, "Test": "TestPX1Other"}, {"Action": "skip", "Package": pkg, "Test": "TestPX1Other"}]
        code, out = self.run_checker(stream(m, extra=extra))
        self.assertEqual(code, 1, out)
        self.assertIn("SKIPPED TestPX1Other", out)
        code, out = self.run_checker(stream(m, {"TestPX1T17ReadLimiter": "fail"}))
        self.assertEqual(code, 1, out)
        self.assertIn("REQUIRED_FAILED T17 TestPX1T17ReadLimiter", out)
        code, out = self.run_checker(stream(m, {"TestPX1T16ClockRollback": None}))
        self.assertEqual(code, 1, out)
        self.assertIn("REQUIRED_MISSING T16 TestPX1T16ClockRollback", out)

    # Claim: a required test reported pass and then skip (in the same stream)
    # fails the gate: a later skip is never hidden by an earlier pass.
    def test_last_action_counts(self):
        m = load(MANIFEST)
        pkg = m["package"]
        extra = [{"Action": "skip", "Package": pkg, "Test": "TestPX1T3DayBuckets"}]
        code, out = self.run_checker(stream(m, extra=extra))
        self.assertEqual(code, 1, out)
        self.assertIn("REQUIRED_SKIPPED T3 TestPX1T3DayBuckets", out)

    # Claim (known-bad controls, review finding core-gate-forgets-earlier-skip):
    # a required test's skip or fail ANYWHERE in the input files fails the
    # gate (exit 1) even when another file later reports it passing, and the
    # report names it: skip-then-pass, pass-then-skip and fail-then-pass across
    # separate files, and a fail-then-skip test reported both FAILED and
    # SKIPPED (independent history, not last-action or worst-action only). The
    # valid neighbour, the same complete passing set split over the same
    # number of files with no skip or fail, exits 0.
    def test_history_across_files(self):
        m = load(MANIFEST)
        pkg = m["package"]
        complete = stream(m)
        name = "TestPX1CoreS1"

        def one(action, test=name):
            return "\n".join(json.dumps(x) for x in [
                {"Action": "run", "Package": pkg, "Test": test},
                {"Action": action, "Package": pkg, "Test": test, "Elapsed": 0.01},
                {"Action": "pass" if action != "fail" else "fail", "Package": pkg, "Elapsed": 0.02}]) + "\n"

        code, out = self.run_checker(one("pass"), complete)
        self.assertEqual(code, 0, out)
        self.assertIn("PX1_GATE PASS labels=17", out)
        for first, second, want in ((one("skip"), complete, ("SKIPPED " + name,)),
                                    (complete, one("skip"), ("SKIPPED " + name,)),
                                    (one("fail"), complete, ("FAILED " + name,))):
            code, out = self.run_checker(first, second)
            self.assertEqual(code, 1, out)
            self.assertIn("PX1_GATE FAIL", out)
            for w in want:
                self.assertIn(w, out)
        sub = "TestPX1CoreS1/T1-at-transfer-cap"
        code, out = self.run_checker(one("skip", sub), complete)
        self.assertEqual(code, 1, out)
        self.assertIn("REQUIRED_SKIPPED T1 " + sub, out)
        code, out = self.run_checker(one("fail", sub), one("skip", sub), complete)
        self.assertEqual(code, 1, out)
        for w in ("FAILED " + sub, "SKIPPED " + sub, "REQUIRED_FAILED T1 " + sub, "REQUIRED_SKIPPED T1 " + sub):
            self.assertIn(w, out)

    # Claim: streams split over several files (one per Core test, one for the
    # unit tests, as the workflow writes them) are read together; the same
    # split with one file missing fails.
    def test_split_streams(self):
        m = load(MANIFEST)
        full = stream(m).splitlines()
        half = len(full) // 2
        code, out = self.run_checker("\n".join(full[:half]) + "\n", "\n".join(full[half:]) + "\n")
        self.assertEqual(code, 0, out)
        code, out = self.run_checker("\n".join(full[:half]) + "\n")
        self.assertEqual(code, 1, out)

    # Claim: input the gate cannot trust fails (exit 1) with its own reason
    # beside the passing stream: a package failure, a build failure, a
    # non-JSON line, an event of another package and an empty stream.
    def test_untrusted_input(self):
        m = load(MANIFEST)
        good = stream(m)
        for name, text, reason in [
            ("package-fail", good + json.dumps({"Action": "fail", "Package": m["package"]}) + "\n", "PACKAGE_FAILED"),
            ("build-fail", good + json.dumps({"Action": "build-fail", "ImportPath": m["package"] + " [test]"}) + "\n", "BUILD_FAILED"),
            ("not-json", good + "FAIL\tgithub.com/x [build failed]\n", "NOT_JSON"),
            ("other-package", good + json.dumps({"Action": "pass", "Package": "example.com/other", "Test": "TestX"}) + "\n", "OTHER_PACKAGE"),
            ("empty", "", "EMPTY_STREAM"),
        ]:
            with self.subTest(case=name):
                code, out = self.run_checker(text)
                self.assertEqual(code, 1, out)
                self.assertIn("PX1_GATE FAIL", out)
                self.assertIn(reason, out)

    # Claim: a manifest that could hide a gap is refused (exit 2): a T-id
    # with no declared layers, an unknown layer, labels that differ from the
    # tids, a Core test listed as a unit test, and a repetition count for a
    # test that is not a Core test or out of range; the real manifest is
    # accepted (test_all_required_pass).
    def test_manifest_refusals(self):
        base = load(MANIFEST)
        bad = []
        m = json.loads(json.dumps(base)); m["tids"]["T9"] = {}; bad.append(("silent-gap", m))
        m = json.loads(json.dumps(base)); m["tids"]["T9"].pop("layers"); bad.append(("no-layers", m))
        m = json.loads(json.dumps(base)); m["tids"]["T9"]["layers"] = ["core", "host"]; bad.append(("unknown-layer", m))
        m = json.loads(json.dumps(base)); m["core_runs"] = {"TestPX1T16ClockRollback": {"count": 50}}; bad.append(("runs-not-core", m))
        m = json.loads(json.dumps(base)); m["core_runs"]["TestPX1CoreS2Race"]["count"] = 0; bad.append(("runs-zero", m))
        m = json.loads(json.dumps(base)); m["labels"] = m["labels"][:-1]; bad.append(("labels", m))
        m = json.loads(json.dumps(base)); m["tids"]["T1"]["unit"].append("TestPX1CoreS1/T1-at-transfer-cap"); bad.append(("core-as-unit", m))
        for name, m in bad:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as d:
                p = Path(d) / "m.json"
                p.write_text(json.dumps(m), encoding="utf-8")
                code, out = self.run_checker(stream(base), manifest=p)
                self.assertEqual(code, 2, out)
                self.assertIn("INPUT_ERROR", out)

    # Claim: the S5 client-consumer gate passes only when the consumer test
    # passed with no skip: a skipped consumer (the G2_CLIENT_CONSUMER_SKIP
    # path) or a skipped case fails it.
    def test_consumer_gate(self):
        m = load(CONSUMER)
        pkg = m["package"]
        case = [{"Action": "run", "Package": pkg, "Test": "TestPX1S5ClientConsumerResolved/resolved"}, {"Action": "pass", "Package": pkg, "Test": "TestPX1S5ClientConsumerResolved/resolved"}]
        code, out = self.run_checker(stream(m, extra=case), manifest=CONSUMER)
        self.assertEqual(code, 0, out)
        code, out = self.run_checker(stream(m, {"TestPX1S5ClientConsumerResolved": "skip"}), manifest=CONSUMER)
        self.assertEqual(code, 1, out)
        self.assertIn("REQUIRED_SKIPPED S5-client-consumer", out)
        skipped = [case[0], {"Action": "skip", "Package": pkg, "Test": "TestPX1S5ClientConsumerResolved/resolved"}]
        code, out = self.run_checker(stream(m, extra=skipped), manifest=CONSUMER)
        self.assertEqual(code, 1, out)


if __name__ == "__main__":
    unittest.main()
