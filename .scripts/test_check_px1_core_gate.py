#!/usr/bin/env python3
"""Known-bad controls for .scripts/check-px1-core-gate.py.

Run: python3 -B -m unittest discover -s .scripts -p 'test_check_px1_core_gate.py' -v
Each case writes a synthetic `go test -json` stream built from the real gate
manifest and runs the checker CLI exactly as CI does. PX1_GATE_CHECKER may
point at a mutated copy of the checker for gate-mutation runs. W2Gate holds
the controls of the w2-core job (.scripts/w2-core-gate.json, the legacy W2
Core tests); it finds the newCore users with the Go syntax-tree helper
.scripts/w2-newcore-users.go, run with the go on PATH (W2_NEWCORE_HELPER may
point at a mutated copy of the helper).
"""
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import re

REPO = Path(__file__).resolve().parents[1]
CHECKER = Path(os.environ.get("PX1_GATE_CHECKER", REPO / ".scripts" / "check-px1-core-gate.py"))
MANIFEST = REPO / ".scripts" / "px1-core-gate.json"
CONSUMER = REPO / ".scripts" / "px1-s5-consumer-gate.json"
W2 = REPO / ".scripts" / "w2-core-gate.json"
WALLET = REPO / "experiments" / "agent-wallet"
WORKFLOW = REPO / ".github" / "workflows" / "agent-wallet.yml"
INTERFACES = REPO / "experiments" / "agent-wallet" / "PX1-INTERFACES.md"
NEWCORE_HELPER = Path(os.environ.get("W2_NEWCORE_HELPER", REPO / ".scripts" / "w2-newcore-users.go"))


def newcore_users(directory=WALLET):
    """(tests, helpers) from the Go syntax tree of the package's *_test.go
    files (.scripts/w2-newcore-users.go): the Test functions whose body
    references the identifier newCore (the W2 grant fixture) in any form, and
    every other top-level declaration that references it (an indirect user
    the manifest could miss). Never a text match: comments and strings do not
    count, (newCore)(t) and f := newCore do. Raises if go is missing or the
    helper fails (no test file, a parse error, not exactly one func newCore)."""
    go = shutil.which("go")
    if go is None:
        raise RuntimeError("go is not on PATH")
    r = subprocess.run([go, "run", str(NEWCORE_HELPER), "-dir", str(directory)], cwd=REPO,
                       env=dict(os.environ, GOTOOLCHAIN="local"), capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise RuntimeError(f"w2-newcore-users exit {r.returncode}: {r.stderr.strip()}")
    out = json.loads(r.stdout)
    return out["tests"], out["helpers"]


def w2_manifest_errors(manifest, directory=WALLET):
    """Why the W2 manifest is not exactly the newCore tests of the tree, each
    once under its own core-only label; empty when it is."""
    tests, helpers = newcore_users(directory)
    core = manifest.get("core_tests", [])
    errors = [f"MISSING {n}" for n in sorted(set(tests) - set(core))]
    errors += [f"NOT_NEWCORE_USER {n}" for n in sorted(set(core) - set(tests))]
    errors += [f"INDIRECT_USER {n}" for n in helpers]
    if len(core) != len(set(core)):
        errors.append("DUPLICATE_TEST")
    labels = ["W2-" + n[len("Test"):] for n in core]
    if manifest.get("labels") != labels or set(manifest.get("tids", {})) != set(labels):
        errors.append("LABELS")
    errors += [f"TID {label}" for label, n in zip(labels, core)
               if manifest.get("tids", {}).get(label) != {"layers": ["core"], "core": [n]}]
    if "core_runs" in manifest:
        errors.append("CORE_RUNS")
    return errors


def with_tests(manifest, *names):
    """The manifest with core-only labels for extra tests appended."""
    m = json.loads(json.dumps(manifest))
    for n in names:
        label = "W2-" + n[len("Test"):]
        m["core_tests"].append(n)
        m["labels"].append(label)
        m["tids"][label] = {"layers": ["core"], "core": [n]}
    return m


def tree_with(directory, files):
    """A copy of the package's *_test.go files plus the given synthetic ones."""
    for path in WALLET.glob("*_test.go"):
        (Path(directory) / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    for name, text in files.items():
        (Path(directory) / name).write_text(text, encoding="utf-8")
    return directory


def job_block(text, job):
    """The lines of one job of the workflow (up to the next job key)."""
    lines, out, inside = text.splitlines(), [], False
    for line in lines:
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line):
            inside = line.strip() == job + ":"
            continue
        if inside:
            out.append(line)
    return out


def core_fetch(text, job):
    """The NMC_* pins and the Core fetch-and-verify step of one job."""
    block = job_block(text, job)
    pins = [x.strip() for x in block if re.match(r"^\s+NMC_[A-Z0-9_]+:", x)]
    step, inside = [], False
    for line in block:
        if line.startswith("      - "):
            inside = line.strip().startswith("- name: Fetch and verify Namecoin Core 28.0")
        if inside:
            step.append(line)
    return pins, step


def job_steps(text, job):
    """(working directory, step text) for each step of one job, comment lines
    dropped. The directory is repository-relative ("" for the root) or None
    when it lies outside the checkout (a ${{ ... }} expression)."""
    block = job_block(text, job)
    head = block[:block.index("    steps:")]
    default = next((m.group(1) for m in (re.match(r"^\s+working-directory:\s*(\S+)\s*$", x) for x in head) if m), ".")
    steps = []
    for line in block[len(head) + 1:]:
        if line.startswith("      - "):
            steps.append([])
        if steps and not line.strip().startswith("#"):
            steps[-1].append(line)
    out = []
    for lines in steps:
        wd = next((m.group(1) for m in (re.match(r"^        working-directory:\s*(\S+)\s*$", x) for x in lines) if m), default)
        wd = None if "${{" in wd else os.path.normpath(wd)
        out.append(("" if wd == "." else wd, "\n".join(lines)))
    return out


def repo_file(rel):
    """The repository-relative path of rel when it names a file of the
    checkout, else None."""
    rel = os.path.normpath(rel)
    if os.path.isabs(rel) or rel == ".." or rel.startswith("../"):
        return None
    return rel if (REPO / rel).is_file() else None


def script_inputs(rel):
    """The files a Python script of the checkout reads by a REPO / "..." path
    (its syntax tree, not a text match)."""
    out = set()
    for node in ast.walk(ast.parse((REPO / rel).read_text(encoding="utf-8"))):
        parts = []
        while isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) and isinstance(node.right, ast.Constant) and isinstance(node.right.value, str):
            parts.insert(0, node.right.value)
            node = node.left
        if parts and isinstance(node, ast.Name) and node.id == "REPO":
            found = repo_file("/".join(parts))
            if found:
                out.add(found)
    return out


def job_inputs(text, job):
    """The repository files one job of the workflow executes or reads as gate
    input, derived from its steps: every path token of a step that names a
    file of the checkout relative to the step's working directory, the
    modules a `unittest discover -s DIR -p PATTERN` step runs, and,
    transitively, every file such a Python script reads by a REPO / "..."
    path (for the checker controls: the manifests and the newCore helper)."""
    found = set()
    for wd, step in job_steps(text, job):
        if wd is None:
            continue
        for token in re.findall(r"[A-Za-z0-9_./-]+", step):
            rel = repo_file(os.path.join(wd, token))
            if rel:
                found.add(rel)
        for d, pattern in re.findall(r"unittest discover -s (\S+) -p '([^']+)'", step):
            found.update(str(p.relative_to(REPO)) for p in (REPO / wd / d).glob(pattern) if p.is_file())
    todo = sorted(p for p in found if p.endswith(".py"))
    while todo:
        for rel in script_inputs(todo.pop()) - found:
            found.add(rel)
            if rel.endswith(".py"):
                todo.append(rel)
    return found


def path_filters(text):
    """The `paths` lists of the triggers under `on:` ({event: [pattern]}).
    Raises on paths-ignore, which this check does not model."""
    out, on, event, inside = {}, False, None, False
    for line in text.splitlines():
        if re.match(r"^\S", line):
            on, event, inside = line.rstrip() == "on:", None, False
            continue
        if not on or not line.strip() or line.strip().startswith("#"):
            continue
        m = re.match(r"^  ([A-Za-z_]+):", line)
        if m:
            event, inside = m.group(1), False
            continue
        m = re.match(r"^    ([A-Za-z_-]+):", line)
        if m:
            if m.group(1) == "paths-ignore":
                raise ValueError(f"paths-ignore under {event}")
            inside = m.group(1) == "paths"
            if inside:
                out.setdefault(event, [])
            continue
        m = re.match(r"""^      - (['"]?)(.+)\1\s*$""", line)
        if inside and m:
            out[event].append(m.group(2))
    return out


def filter_matches(pattern, path):
    """GitHub path-filter semantics for the pattern subset this workflow uses:
    `**` crosses `/`, `*` does not, everything else literal. Any other glob
    character raises rather than guessing."""
    rx, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            rx, i = rx + ".*", i + 2
        elif pattern[i] == "*":
            rx, i = rx + "[^/]*", i + 1
        elif re.fullmatch(r"[A-Za-z0-9_./-]", pattern[i]):
            rx, i = rx + re.escape(pattern[i]), i + 1
        else:
            raise ValueError(f"unsupported path-filter pattern {pattern!r}")
    return re.fullmatch(rx, path) is not None


def filter_triggers(patterns, path):
    """Whether a change to path triggers a filter: patterns in order, a later
    `!` pattern excluding what an earlier one included."""
    hit = False
    for p in patterns:
        if p.startswith("!"):
            hit = hit and not filter_matches(p[1:], path)
        elif filter_matches(p, path):
            hit = True
    return hit


def filter_gaps(text, job):
    """Each (event, input) pair where a gate input of the job is not matched
    by the paths filter of pull_request or push; empty when both filters
    cover every input."""
    filters = path_filters(text)
    gaps = [f"NO_PATHS {e}" for e in ("pull_request", "push") if not filters.get(e)]
    for rel in sorted(job_inputs(text, job)):
        gaps += [f"{e} {rel}" for e in ("pull_request", "push") if not filter_triggers(filters.get(e, []), rel)]
    return gaps


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


class W2Gate(unittest.TestCase):
    """Controls for the w2-core job: the same checker with the W2 manifest."""

    run_checker = Gate.run_checker

    # Claim: the valid neighbour passes: every W2 Core test of the manifest
    # passing once gives exit 0, PX1_GATE PASS with 25 labels and 25 required
    # passes, and every label PASS.
    def test_w2_all_pass(self):
        m = load(W2)
        code, out = self.run_checker(stream(m), manifest=W2)
        self.assertEqual(code, 0, out)
        self.assertIn("PX1_GATE PASS labels=25 required_passed=25", out)
        for label, n in zip(m["labels"], m["core_tests"]):
            self.assertRegex(out, rf"(?m)^{label} PASS layers=core core: pass {n}$")

    # Claim: the manifest requires exactly the Test functions whose body
    # references newCore (the W2 grant fixture) in the Go syntax tree, each
    # once under its own core-only label, and no other declaration references
    # newCore (no indirect user is missed). Controls: a tree with an extra
    # direct-call test and a method that calls newCore is detected.
    def test_w2_manifest_is_newcore_users(self):
        m = load(W2)
        tests, helpers = newcore_users()
        self.assertEqual(len(tests), 25)
        self.assertEqual(helpers, [])
        self.assertEqual(sorted(m["core_tests"]), tests)
        self.assertEqual(w2_manifest_errors(m), [])
        with tempfile.TemporaryDirectory() as d:
            tree_with(d, {"extra_test.go":
                "package wallet\n\nfunc TestCoreExtra(t *testing.T) {\n\tl := newCore(t)\n\t_ = l\n}\n\n"
                "func (x *coreLab) relab(t *testing.T) *coreLab {\n\treturn newCore(t)\n}\n"})
            tests, helpers = newcore_users(d)
            self.assertEqual(sorted(set(tests) - set(m["core_tests"])), ["TestCoreExtra"])
            self.assertEqual(helpers, ["relab"])

    # Claim (known-bad controls beside passing neighbours): on a copy of the
    # real tree plus one synthetic test file, the current manifest FAILS when
    # the file adds a test that references newCore without the text
    # "newCore(" - a parenthesised call (newCore)(t), a call through a local
    # variable, newCore passed as an argument - and the same manifest
    # completed with that test passes. A package-level alias of newCore is an
    # indirect user that fails every manifest. A test that names newCore only
    # in a comment and a string is not a user: the current manifest passes and
    # a manifest naming that test FAILS. Each verdict is the exact error list.
    # Limit: the helper reads syntax, not types (a shadowing local named
    # newCore also counts: an over-count, never an under-count).
    def test_w2_manifest_ast_controls(self):
        m = load(W2)
        head = "package wallet\n\nimport \"testing\"\n\n"
        cases = [
            ("paren", "func TestCoreParenCall(t *testing.T) {\n\tl := (newCore)(t)\n\t_ = l\n}\n",
             ["MISSING TestCoreParenCall"], "TestCoreParenCall", []),
            ("local", "func TestCoreLocalCall(t *testing.T) {\n\tbuild := newCore\n\tl := build(t)\n\t_ = l\n}\n",
             ["MISSING TestCoreLocalCall"], "TestCoreLocalCall", []),
            ("argument", "func TestCoreFixtureArg(t *testing.T) {\n"
             "\tfunc(mk func(*testing.T) *coreLab) { _ = mk(t) }(newCore)\n}\n",
             ["MISSING TestCoreFixtureArg"], "TestCoreFixtureArg", []),
            ("alias", "var buildCore = newCore\n\nfunc TestCoreAliasCall(t *testing.T) {\n\tl := buildCore(t)\n\t_ = l\n}\n",
             ["INDIRECT_USER buildCore"], "TestCoreAliasCall",
             ["NOT_NEWCORE_USER TestCoreAliasCall", "INDIRECT_USER buildCore"]),
            ("mention", "func TestCoreMentionOnly(t *testing.T) {\n\t// newCore(t) is not called here.\n"
             "\tt.Log(\"newCore(t)\")\n}\n",
             [], "TestCoreMentionOnly", ["NOT_NEWCORE_USER TestCoreMentionOnly"]),
        ]
        self.assertEqual(w2_manifest_errors(m), [])
        for name, src, current, test, completed in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as d:
                tree_with(d, {"synthetic_test.go": head + src})
                self.assertEqual(w2_manifest_errors(m, d), current)
                self.assertEqual(w2_manifest_errors(with_tests(m, test), d), completed)

    # Claim (known-bad manifests on the real tree, beside the current one that
    # passes): a manifest naming a real test that does not reference newCore,
    # one naming a test that does not exist, and one that omits a newCore test
    # each FAIL with exactly that error.
    def test_w2_manifest_wrong_tests_fail(self):
        m = load(W2)
        self.assertEqual(w2_manifest_errors(m), [])
        self.assertEqual(w2_manifest_errors(with_tests(m, "TestDK5InstalledMode")),
                         ["NOT_NEWCORE_USER TestDK5InstalledMode"])
        self.assertEqual(w2_manifest_errors(with_tests(m, "TestCoreAbsent")), ["NOT_NEWCORE_USER TestCoreAbsent"])
        short = json.loads(json.dumps(m))
        short["core_tests"].remove("TestCoreRevocation")
        short["labels"].remove("W2-CoreRevocation")
        del short["tids"]["W2-CoreRevocation"]
        self.assertEqual(w2_manifest_errors(short), ["MISSING TestCoreRevocation"])

    # Claim: the helper fails closed instead of reporting no users: a tree
    # with a file that does not parse, a tree that does not declare func
    # newCore, and a directory without test files each raise, beside the real
    # tree copy that reads cleanly (the controls above).
    def test_w2_newcore_helper_fails_closed(self):
        bad = {
            "parse": ({"broken_test.go": "package wallet\n\nfunc TestCoreBroken(t *testing.T) {\n\tnewCore(t\n}\n"},
                      r"W2_NEWCORE_USERS_ERROR .*broken_test\.go:4:"),
            "no fixture": (None, r"W2_NEWCORE_USERS_ERROR 0 top-level func newCore declarations"),
            "empty": ({}, r"W2_NEWCORE_USERS_ERROR no \*_test\.go file"),
        }
        for name, (files, reason) in bad.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory() as d:
                if files is None:
                    (Path(d) / "unit_test.go").write_text("package wallet\n\nfunc TestUnit(t *testing.T) {}\n", encoding="utf-8")
                elif files:
                    tree_with(d, files)
                with self.assertRaisesRegex(RuntimeError, reason):
                    newcore_users(d)

    # Claim (known-bad controls): for EVERY W2 Core test, a skip, a failure or
    # a missing stream fails the gate (exit 1) with REQUIRED_SKIPPED,
    # REQUIRED_FAILED or REQUIRED_MISSING naming that test's label, and never
    # reports PX1_GATE PASS.
    def test_w2_each_test_skip_fail_missing(self):
        m = load(W2)
        for label, n in zip(m["labels"], m["core_tests"]):
            for action, code_name in (("skip", "REQUIRED_SKIPPED"), ("fail", "REQUIRED_FAILED"), (None, "REQUIRED_MISSING")):
                with self.subTest(test=n, action=action):
                    code, out = self.run_checker(stream(m, {n: action}), manifest=W2)
                    self.assertEqual(code, 1, out)
                    self.assertIn(f"{code_name} {label} {n}", out)
                    self.assertIn("PX1_GATE FAIL", out)
                    self.assertNotIn("PX1_GATE PASS", out)

    # Claim (recorded known-bad stream): the go test -json shape of the
    # action-final-authority plant (TestCoreActionFinalCheck failing at
    # "want refused/GRANT_SEAL_SPENT got executed/EXECUTED", then the package
    # failing), beside the passing streams of the other 24 tests, fails the
    # gate with FAILED, REQUIRED_FAILED and PACKAGE_FAILED and no missing or
    # skipped test, so the plant alone causes the failure. The hosted job
    # repeats this with a genuinely planted tree (agent-wallet.yml w2-core).
    def test_w2_recorded_plant_stream(self):
        m = load(W2)
        pkg, name = m["package"], "TestCoreActionFinalCheck"
        others = stream(m, {name: None}).splitlines()[:-1]
        planted = [
            {"Action": "start", "Package": pkg},
            {"Action": "run", "Package": pkg, "Test": name},
            {"Action": "output", "Package": pkg, "Test": name, "Output": "=== RUN   " + name + "\n"},
            {"Action": "output", "Package": pkg, "Test": name, "Output": "    service_crash_test.go:222: want refused/GRANT_SEAL_SPENT got executed/EXECUTED\n"},
            {"Action": "output", "Package": pkg, "Test": name, "Output": "--- FAIL: " + name + " (7.68s)\n"},
            {"Action": "fail", "Package": pkg, "Test": name, "Elapsed": 7.68},
            {"Action": "output", "Package": pkg, "Output": "FAIL\n"},
            {"Action": "fail", "Package": pkg, "Elapsed": 7.7},
        ]
        code, out = self.run_checker("\n".join(others) + "\n", "\n".join(json.dumps(x) for x in planted) + "\n", manifest=W2)
        self.assertEqual(code, 1, out)
        for want in ("FAILED " + name, "REQUIRED_FAILED W2-CoreActionFinalCheck " + name, "PACKAGE_FAILED", "PX1_GATE FAIL"):
            self.assertIn(want, out)
        self.assertNotRegex(out, r"(?m)^REQUIRED_(MISSING|SKIPPED) ")
        self.assertEqual(len(re.findall(r"(?m)^W2-\S+ PASS ", out)), 24)

    # Claim: a run without W1_REGTEST (every newCore test skips) fails the
    # gate with SKIPPED and REQUIRED_SKIPPED for each of the 25 tests.
    def test_w2_no_node_skips_all(self):
        m = load(W2)
        code, out = self.run_checker(stream(m, {n: "skip" for n in m["core_tests"]}), manifest=W2)
        self.assertEqual(code, 1, out)
        for label, n in zip(m["labels"], m["core_tests"]):
            self.assertIn(f"SKIPPED {n}", out)
            self.assertIn(f"REQUIRED_SKIPPED {label} {n}", out)

    # Claim: the w2-core job fetches the same Namecoin Core 28.0 archive with
    # the same pins and the same fetch-and-verify step as px1-core-gate, and
    # checks its streams with this checker and the W2 manifest under
    # W1_REGTEST=1. Control: a w2-core job whose archive pin or verify step
    # differs is detected.
    def test_w2_job_shares_core_fetch(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        pins, step = core_fetch(text, "px1-core-gate")
        self.assertEqual(len(pins), 6)
        self.assertGreater(len(step), 10)
        self.assertEqual(core_fetch(text, "w2-core"), (pins, step))
        w2 = "\n".join(job_block(text, "w2-core"))
        for want in ("check-px1-core-gate.py", "W1_REGTEST: '1'", "go test $flags -timeout 20m -json"):
            self.assertIn(want, w2)
        # Every checker call of the job uses the W2 manifest, never another.
        self.assertNotIn("px1-core-gate.json", w2)
        self.assertEqual(re.findall(r"manifest=(\S+)", w2), ["../../.scripts/w2-core-gate.json"] * 2)
        uses = re.findall(r"--manifest (\S+)", w2)
        self.assertGreaterEqual(len(uses), 6)
        self.assertEqual(set(uses), {'"$manifest"', "../../.scripts/w2-core-gate.json"})
        for old, new in (("NMC_ARCHIVE_SHA256: 6f12", "NMC_ARCHIVE_SHA256: 0f12"), ("sha256sum -c -", "true")):
            parts = text.split("\n  w2-core:\n")
            self.assertEqual(len(parts), 2)
            bad = parts[0] + "\n  w2-core:\n" + parts[1].replace(old, new, 1)
            self.assertNotEqual(core_fetch(bad, "w2-core"), core_fetch(bad, "px1-core-gate"), old)


class PathFilters(unittest.TestCase):
    """Both path filters of agent-wallet.yml cover the gate inputs of the
    w2-core and px1-core-gate jobs, so a change to one of them reruns the
    gate on the pull request and on main."""

    ANCHORS = {
        "w2-core": {".scripts/check-px1-core-gate.py", ".scripts/w2-core-gate.json",
                    ".scripts/test_check_px1_core_gate.py", ".scripts/w2-newcore-users.go"},
        "px1-core-gate": {".scripts/check-px1-core-gate.py", ".scripts/px1-core-gate.json",
                          ".scripts/test_check_px1_core_gate.py", ".scripts/px1-s5-consumer-gate.json"},
    }

    @staticmethod
    def drop_filter(text, event, path):
        """The workflow text with path removed from one event's filter only."""
        head, sep, rest = text.partition(f"\n  {event}:\n")
        body, sep2, tail = rest.partition("\n  workflow_dispatch:\n" if event == "push" else "\n  push:\n")
        return head + sep + body.replace(f"\n      - '{path}'", "", 1) + sep2 + tail

    # Claim: in the real workflow, every repository file each gate job runs
    # or reads as gate input (derived from its steps and, transitively, from
    # the REPO paths of the Python scripts it runs) is matched by both the
    # pull_request and the push filter. The anchors keep the derivation from
    # passing vacuously: the checker, the job's manifest, the checker
    # controls and (through them) the newCore helper must be derived.
    # Limit: Go module dependencies are not derived; the go test steps' own
    # package trees are covered only because their filters list them.
    def test_path_filters_cover_gate_inputs(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        filters = path_filters(text)
        self.assertEqual(set(filters), {"pull_request", "push"})
        for job, anchors in self.ANCHORS.items():
            inputs = job_inputs(text, job)
            self.assertLessEqual(anchors, inputs, job)
            self.assertEqual(filter_gaps(text, job), [], job)

    # Claim: known-bad workflow texts fail the check, each naming exactly the
    # dropped input and the event whose filter lost it: one executed script,
    # the job's manifest or the helper dropped from either filter; and a new
    # step running a repository script outside both filters (a future helper)
    # is caught for both events. The real text is the passing neighbour.
    def test_path_filters_known_bad(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        for job, path in (("w2-core", ".scripts/check-px1-core-gate.py"), ("w2-core", ".scripts/w2-newcore-users.go"),
                          ("w2-core", ".scripts/w2-core-gate.json"), ("px1-core-gate", ".scripts/px1-core-gate.json")):
            for event in ("pull_request", "push"):
                bad = self.drop_filter(text, event, path)
                self.assertEqual(len(bad), len(text) - len(f"\n      - '{path}'"), (event, path))
                self.assertEqual(filter_gaps(bad, job), [f"{event} {path}"], (job, event, path))
        self.assertTrue(text.endswith("\n"))
        future = text + "      - name: Future gate helper\n        run: python3 -B ../../.scripts/check-module-graph.py\n"
        self.assertEqual(filter_gaps(future, "w2-core"),
                         ["pull_request .scripts/check-module-graph.py", "push .scripts/check-module-graph.py"])
        self.assertEqual(filter_gaps(text, "w2-core"), [])

    # Claim: the filter matcher follows GitHub's semantics for the patterns
    # used here (`*` stops at `/`, `**` crosses it, a later `!` excludes) and
    # refuses glob syntax it does not model instead of guessing; paths-ignore
    # is refused too.
    def test_path_filter_matcher(self):
        deep = "experiments/agent-wallet/testdata/service-mutations.json"
        self.assertTrue(filter_triggers(["experiments/agent-wallet/**"], deep))
        self.assertFalse(filter_triggers(["experiments/agent-wallet/*"], deep))
        self.assertTrue(filter_triggers(["experiments/agent-wallet/*"], "experiments/agent-wallet/go.mod"))
        self.assertFalse(filter_triggers(["experiments/agent-wallet/**", "!experiments/agent-wallet/testdata/**"], deep))
        self.assertFalse(filter_triggers([".scripts/w2-core-gate.json"], ".scripts/w2-core-gate-json"))
        for bad in (".scripts/[a-z]*.go", ".scripts/w2-core-gate.json?", ".scripts/w2+.go"):
            with self.assertRaises(ValueError):
                filter_triggers([bad], ".scripts/w2-newcore-users.go")
        with self.assertRaises(ValueError):
            path_filters("on:\n  push:\n    paths-ignore:\n      - 'docs/**'\n")


if __name__ == "__main__":
    unittest.main()
