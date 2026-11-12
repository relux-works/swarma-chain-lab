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

REPO = Path(__file__).resolve().parents[1]
CHECKER = Path(os.environ.get("PX1_GATE_CHECKER", REPO / ".scripts" / "check-px1-core-gate.py"))
MANIFEST = REPO / ".scripts" / "px1-core-gate.json"
CONSUMER = REPO / ".scripts" / "px1-s5-consumer-gate.json"


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
    for t in tests:
        action = override.get(t, "pass")
        if action is None:
            continue
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

    # Claim: the valid neighbour passes: every required test passing gives
    # exit 0 and PX1_GATE PASS, with T9/T10 reported OPEN, never PASS.
    def test_all_required_pass(self):
        code, out = self.run_checker(stream(load(MANIFEST)))
        self.assertEqual(code, 0, out)
        self.assertIn("PX1_GATE PASS", out)
        self.assertIn("T9 OPEN", out)
        self.assertIn("T10 OPEN", out)
        self.assertIn("T1 PASS", out)

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

    # Claim: the last terminal action of a test counts: a required test that
    # is reported pass and then skip fails the gate.
    def test_last_action_counts(self):
        m = load(MANIFEST)
        pkg = m["package"]
        extra = [{"Action": "skip", "Package": pkg, "Test": "TestPX1T3DayBuckets"}]
        code, out = self.run_checker(stream(m, extra=extra))
        self.assertEqual(code, 1, out)
        self.assertIn("REQUIRED_SKIPPED T3 TestPX1T3DayBuckets", out)

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

    # Claim: a manifest that could hide a gap is refused (exit 2): a T-id with
    # no test and no open reason, labels that differ from the tids, and a
    # Core test listed as a unit test; the real manifest is accepted.
    def test_manifest_refusals(self):
        base = load(MANIFEST)
        bad = []
        m = json.loads(json.dumps(base)); m["tids"]["T9"] = {}; bad.append(("silent-gap", m))
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
