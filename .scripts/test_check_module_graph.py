#!/usr/bin/env python3
"""Regression and mutant controls for .scripts/check-module-graph.py.

Run: python3 -m unittest discover -s .scripts -p 'test_check_module_graph.py'
Each fixture copies the checkout's real go.mod files, the snapshot floor file
and MODULE-GRAPH.md into a scratch git tree, mutates one thing, and runs the
checker CLI exactly as CI does. MODULE_GRAPH_CHECKER may point at a mutated
copy of the checker for gate-mutation runs.
"""
import json
import importlib.util
from unittest import mock
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
CHECKER = Path(os.environ.get("MODULE_GRAPH_CHECKER", REPO / ".scripts" / "check-module-graph.py"))
PREFIX = "github.com/relux-works/swarma-chain-lab/"
SINGLE_USE = PREFIX + "experiments/single-use"
SNAPSHOT_FLOORS = json.loads((REPO / "experiments/module-graph-snapshot.json").read_text())["modules"]
SNAPSHOT_SINGLE_USE = SNAPSHOT_FLOORS[SINGLE_USE]
# Fixtures mutate the selected wallet edge, which may legitimately exceed the
# global semantic floor. Read it with Go's parser rather than assuming equality.
WALLET_SINGLE_USE = next(r["Version"] for r in json.loads(subprocess.run(
    ["go", "mod", "edit", "-json", str(REPO / "experiments/agent-wallet/go.mod")],
    check=True, capture_output=True, text=True).stdout)["Require"] if r["Path"] == SINGLE_USE)
STANDALONE = ("deploy/go.mod", "experiments/station-lifecycle/go.mod")


def tracked_manifests():
    out = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"], check=True,
                         capture_output=True, text=True).stdout
    return [p for p in out.split("\0") if p and Path(p).name == "go.mod"]


class Fixture:
    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="module-graph-fixture-"))
        for relative in tracked_manifests() + ["experiments/module-graph-snapshot.json",
                                               "experiments/MODULE-GRAPH.md"]:
            target = self.dir / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / relative, target)
        subprocess.run(["git", "init", "-q", str(self.dir)], check=True)
        # Borrow immutable history only; provenance must still pass real Git checks.
        objects = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--git-path", "objects"],
                                 check=True, capture_output=True, text=True).stdout.strip()
        (self.dir / ".git/objects/info/alternates").write_text(str((REPO / objects).resolve()) + "\n")
        main = subprocess.run(["git", "-C", str(REPO), "rev-parse", "origin/main"],
                              check=True, capture_output=True, text=True).stdout.strip()
        subprocess.run(["git", "-C", str(self.dir), "update-ref", "refs/remotes/origin/main", main], check=True)

    def substitute(self, relative, old, new):
        path = self.dir / relative
        text = path.read_text()
        if text.count(old) != 1:
            raise AssertionError(f"{relative}: expected exactly one {old!r}; manifest layout changed")
        path.write_text(text.replace(old, new))

    def stale_standalone(self, relative):
        # The F1 shape: a single-line `require path version`, not a block entry.
        text = (self.dir / relative).read_text()
        current = re.search(r"(?m)^require " + re.escape(SINGLE_USE) + r" (v[^\s]+)$", text)
        if current is None:
            raise AssertionError(f"{relative}: standalone single-use requirement missing")
        self.substitute(relative, f"\nrequire {SINGLE_USE} {current.group(1)}\n",
                        f"\nrequire {SINGLE_USE} v0.1.0\n")

    def run(self):
        proc = subprocess.run([sys.executable, str(CHECKER), "--root", str(self.dir)],
                              capture_output=True, text=True)
        violations = [line[len("VIOLATION "):] for line in proc.stdout.splitlines()
                      if line.startswith("VIOLATION ")]
        return proc.returncode, violations, proc.stdout + proc.stderr

    def close(self):
        shutil.rmtree(self.dir)


def stale_message(manifest, version="v0.1.0", path=SINGLE_USE, floor=SNAPSHOT_SINGLE_USE):
    return f"{manifest}: require {path} {version} is older than snapshot {floor}"


class ModuleGraphCheck(unittest.TestCase):
    def setUp(self):
        self.fixture = Fixture()

    def tearDown(self):
        self.fixture.close()

    # Claim: the checked-in graph passes with zero violations (positive control
    # for every negative case below, which differ from it by one mutation).
    def test_repository_graph_is_at_snapshot(self):
        code, violations, output = self.fixture.run()
        self.assertEqual((code, violations), (0, []), output)
        self.assertIn(f"{len(tracked_manifests())} manifests, 21 consumers, 103 internal require edges, 0 violations", output)

    # Claim (standalone-require regression, F1 at b516cc21): both standalone
    # single-use requires at v0.1.0 with every block edge current fail with
    # exactly those two edges named.
    def test_standalone_require_regression_b516(self):
        for manifest in STANDALONE:
            self.fixture.stale_standalone(manifest)
        code, violations, output = self.fixture.run()
        self.assertEqual(code, 1, output)
        self.assertEqual(sorted(violations), sorted(stale_message(m) for m in STANDALONE), output)

    # Claim (narrowing mutant): one standalone edge stale while all block edges,
    # including the same manifest's indirect sealwatch block edge, stay current
    # still fails, naming only that edge.
    def test_narrowing_mutant_single_stale_standalone_edge(self):
        for manifest in STANDALONE:
            with self.subTest(manifest=manifest):
                fixture = Fixture()
                try:
                    fixture.stale_standalone(manifest)
                    code, violations, output = fixture.run()
                    self.assertEqual((code, violations), (1, [stale_message(manifest)]), output)
                finally:
                    fixture.close()

    # Claim: the class is form-independent; a stale block entry and a stale
    # `// indirect` block entry each fail too.
    def test_stale_block_and_indirect_edges_fail(self):
        sealwatch = PREFIX + "experiments/sealwatch"
        floor = SNAPSHOT_FLOORS[sealwatch]
        self.fixture.substitute("experiments/agent-wallet/go.mod",
                                f"\t{SINGLE_USE} {WALLET_SINGLE_USE}\n", f"\t{SINGLE_USE} v0.1.0\n")
        self.fixture.substitute("deploy/go.mod", f"\t{sealwatch} {floor} // indirect\n",
                                f"\t{sealwatch} v0.1.0 // indirect\n")
        code, violations, output = self.fixture.run()
        self.assertEqual(code, 1, output)
        self.assertEqual(sorted(violations), sorted([
            stale_message("experiments/agent-wallet/go.mod"),
            stale_message("deploy/go.mod", path=sealwatch, floor=floor)]), output)

    # Claim: ordering is semantic-version precedence, not string order: v0.10.0
    # (above the floor) passes; v0.3.0 and an earlier pseudo-version fail.
    def test_semver_precedence(self):
        manifest = "experiments/agent-wallet/go.mod"
        cases = {"v0.10.0": [], "v0.3.1": [],
                 "v0.3.0": [stale_message(manifest, "v0.3.0")],
                 "v0.3.1-0.20261111181053-aaaaaaaaaaaa": [
                     stale_message(manifest, "v0.3.1-0.20261111181053-aaaaaaaaaaaa")]}
        for version, expected in cases.items():
            with self.subTest(version=version):
                fixture = Fixture()
                try:
                    fixture.substitute(manifest, f"\t{SINGLE_USE} {WALLET_SINGLE_USE}\n",
                                       f"\t{SINGLE_USE} {version}\n")
                    code, violations, output = fixture.run()
                    self.assertEqual((code, violations), (1 if expected else 0, expected), output)
                finally:
                    fixture.close()

    # Claim: an internal module without a recorded floor fails closed instead
    # of being skipped.
    def test_missing_snapshot_floor_fails(self):
        path = self.fixture.dir / "experiments/module-graph-snapshot.json"
        data = json.loads(path.read_text())
        del data["modules"][SINGLE_USE]
        path.write_text(json.dumps(data))
        code, violations, output = self.fixture.run()
        self.assertEqual(code, 1, output)
        self.assertTrue(violations, output)
        self.assertTrue(all(v.endswith(": no snapshot floor recorded") and SINGLE_USE in v
                            for v in violations), output)

    # Claim: the audit document cannot overclaim again; the old 96-edge prose
    # count fails against the current 103-edge inventory.
    def test_doc_edge_count_drift_fails(self):
        self.fixture.substitute("experiments/MODULE-GRAPH.md", "all 103 internal require edges",
                                "all 96 internal require edges")
        code, violations, output = self.fixture.run()
        self.assertEqual((code, violations),
                         (1, ["MODULE-GRAPH.md: claims 96 internal require edges; inventory has 103"]), output)

    # Claim: the generated per-manifest table cannot drift either; the old
    # `deploy/go.mod | 1` row (MODULE-GRAPH.md:39 at b516) fails.
    def test_doc_table_drift_fails(self):
        self.fixture.substitute("experiments/MODULE-GRAPH.md", "| `deploy/go.mod` | 2 |",
                                "| `deploy/go.mod` | 1 |")
        code, violations, output = self.fixture.run()
        self.assertEqual((code, violations),
                         (1, ["MODULE-GRAPH.md: inventory table is stale; rerun with --write-doc"]), output)

    # Control: a whitespace/block-only line filter, the parser class behind F1,
    # does not see the two standalone edges (101 block edges, 0 stale),
    # so the regression above discriminates syntax-aware parsing from it.
    def test_line_filter_misses_standalone_edges(self):
        for manifest in STANDALONE:
            self.fixture.stale_standalone(manifest)
        edges = stale = 0
        for relative in tracked_manifests():
            in_block = False
            for line in (self.fixture.dir / relative).read_text().splitlines():
                if line.strip() == "require (":
                    in_block = True
                elif line.strip() == ")":
                    in_block = False
                elif in_block and line.startswith("\t" + PREFIX):
                    edges += 1
                    stale += " v0.1.0" in line
        self.assertEqual((edges, stale), (101, 0))
        code, violations, _ = self.fixture.run()
        self.assertEqual((code, len(violations)), (1, 2))


class FloorProvenance(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("provenance_graph", CHECKER)
        self.graph = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.graph)
        self.temp = tempfile.TemporaryDirectory(prefix="floor-provenance-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-q")
        self.default = PREFIX + "experiments/fixture"
        self.later = PREFIX + "experiments/later"
        self.add_module(self.default)
        self.base = self.commit("1577934245")  # 20200102030405 UTC
        self.add_module(self.later)
        self.main = self.commit("1578020645", self.base)  # 20200103030405 UTC
        self.git("update-ref", "refs/remotes/origin/main", self.main)
        self.side = self.commit("1578107045", self.base)
        self.snapshot = {
            "snapshot_commit": self.base, "snapshot_time": "20200102030405",
            "modules": {self.default: "v0.0.0-20200102030405-" + self.base[:12],
                        self.later: "v0.0.0-20200103030405-" + self.main[:12]},
            "module_provenance": {self.later: {"commit": self.main, "time": "20200103030405"}},
        }

    def git(self, *args, input=None):
        return subprocess.run(["git", "-C", str(self.root), *args], input=input,
                              check=True, capture_output=True, text=True).stdout.strip()

    def add_module(self, module):
        target = self.root / module.removeprefix(PREFIX) / "go.mod"
        target.parent.mkdir(parents=True)
        target.write_text("module " + module + "\n\ngo 1.26.0\n")

    def commit(self, seconds, parent=None):
        # Synthetic immutable objects are fixture data, never delivery commits.
        self.git("add", ".")
        tree = self.git("write-tree")
        body = "tree " + tree + "\n" + ("parent " + parent + "\n" if parent else "")
        body += ("author Fixture <fixture@example.invalid> " + seconds + " +0000\n"
                 "committer Fixture <fixture@example.invalid> " + seconds + " +0000\n\nfixture\n")
        return self.git("hash-object", "-t", "commit", "-w", "--stdin", input=body)

    def check(self):
        return self.graph.floor_violations(self.root, self.snapshot)

    # Claim: one later module may use its own main floor while all undeclared
    # modules retain the default, with real Git history and no resolver mocks.
    def test_mixed_default_and_per_module_floor(self):
        self.assertEqual(self.check(), [])
        del self.snapshot["module_provenance"]
        self.assertEqual(self.check(), [
            f"snapshot: {self.later} floor {self.snapshot['modules'][self.later]} is not a pseudo-version of snapshot 20200102030405-{self.base[:12]}"])

    # Claim: non-object provenance, missing fields, wrong types, abbreviated
    # commits and invalid times receive the exact format refusal, beside a valid control.
    def test_malformed_provenance(self):
        prefix = f"snapshot: {self.later} provenance"
        cases = [(None, prefix + " must be an object with commit and time"),
                 ({}, prefix + " requires a full lowercase commit SHA and UTC time YYYYMMDDhhmmss"),
                 ({"commit": self.main[:12], "time": "20200103030405"}, prefix + " requires a full lowercase commit SHA and UTC time YYYYMMDDhhmmss"),
                 ({"commit": self.main, "time": 20200103030405}, prefix + " requires a full lowercase commit SHA and UTC time YYYYMMDDhhmmss"),
                 ({"commit": self.main, "time": "20201303030405"}, prefix + " has invalid UTC time 20201303030405")]
        for source, expected in cases:
            with self.subTest(source=source):
                self.snapshot["module_provenance"][self.later] = source
                self.assertEqual(self.check(), [expected])
        self.snapshot["module_provenance"] = []
        self.assertEqual(self.check(), ["snapshot: module_provenance must be an object"])

    # Claim: neither an unknown record member nor a module absent from floors
    # can introduce an unchecked provenance declaration.
    def test_unknown_provenance_key(self):
        source = self.snapshot["module_provenance"][self.later]
        source["extra"] = True
        self.assertEqual(self.check(), [f"snapshot: {self.later} provenance has unknown key extra"])
        del source["extra"]
        self.snapshot["module_provenance"]["unknown"] = source
        self.assertEqual(self.check(), ["snapshot: unknown module provenance key unknown"])

    # Claim: a syntactically valid but unavailable SHA fails as an unknown
    # commit, never as a successful ancestry or version check.
    def test_unknown_commit(self):
        self.snapshot["module_provenance"][self.later]["commit"] = "0" * 40
        self.assertEqual(self.check(), [f"snapshot: {self.later} provenance commit {'0' * 40} is not an available commit"])

    # Claim: an existing side-branch commit with the module and matching time
    # and hash is refused specifically because it is not on origin/main.
    def test_commit_not_on_main(self):
        self.snapshot["module_provenance"][self.later] = {"commit": self.side, "time": "20200104030405"}
        self.snapshot["modules"][self.later] = "v0.0.0-20200104030405-" + self.side[:12]
        self.assertEqual(self.check(), [f"snapshot: {self.later} provenance commit {self.side} is not on origin/main"])

    # Claim: a genuine main ancestor with matching pseudo-version is refused
    # when the module did not yet exist there; version syntax cannot invent it.
    def test_module_absent_at_commit(self):
        self.snapshot["module_provenance"][self.later] = {"commit": self.base, "time": "20200102030405"}
        self.snapshot["modules"][self.later] = "v0.0.0-20200102030405-" + self.base[:12]
        self.assertEqual(self.check(), [f"snapshot: {self.later} provenance commit {self.base} does not contain experiments/later/go.mod"])

    # Claim: declared time must be the actual commit time, even when the floor
    # repeats that false time and its hash is correct.
    def test_provenance_time_matches_commit(self):
        self.snapshot["module_provenance"][self.later]["time"] = "20200104030405"
        self.snapshot["modules"][self.later] = "v0.0.0-20200104030405-" + self.main[:12]
        self.assertEqual(self.check(), [f"snapshot: {self.later} provenance time 20200104030405 does not match commit time 20200103030405"])

    # Claim: either pseudo-version component differing from verified provenance
    # is refused exactly; valid provenance alone cannot authorize a different floor.
    def test_pseudo_version_time_or_hash_mismatch(self):
        for floor in ("v0.0.0-20200104030405-" + self.main[:12],
                      "v0.0.0-20200103030405-000000000000"):
            with self.subTest(floor=floor):
                self.snapshot["modules"][self.later] = floor
                self.assertEqual(self.check(), [f"snapshot: {self.later} floor {floor} is not a pseudo-version of snapshot 20200103030405-{self.main[:12]}"])


class SnapshotRegeneration(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("snapshot_graph", CHECKER)
        self.graph = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.graph)
        self.temp = tempfile.TemporaryDirectory(prefix="snapshot-regeneration-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "snapshot.json"
        # Fixed protocol fixture: future repository snapshot refreshes must
        # not require editing this generator control's expected timestamp.
        self.commit = "1" * 40
        self.snapshot = {
            "snapshot_commit": self.commit, "snapshot_time": "20200102030405",
            "module_provenance": {PREFIX + "experiments/rental": {
                "commit": "2" * 40, "time": "20190102030405"}},
            "modules": {
                PREFIX + "experiments/rental": "v0.5.1-0.20200102030405-111111111111",
                PREFIX + "experiments/grantcheck": "v0.1.2-0.20200102030405-111111111111",
            },
        }
        self.original = (json.dumps(self.snapshot, indent=2) + "\n").encode()
        self.path.write_bytes(self.original)

    def resolver(self, wrong_origin=False, failed_module=False):
        def run(argv, **kwargs):
            if argv[0] == "git":
                return subprocess.CompletedProcess(argv, 0, "1577934245\n", "")
            module, commit = argv[-1].split("@")
            if failed_module and module == sorted(self.snapshot["modules"])[-1]:
                return subprocess.CompletedProcess(argv, 1, "", "fixture proxy unavailable")
            info = {"Path": module, "Version": self.snapshot["modules"][module],
                    "Origin": {"Hash": "0" * 40 if wrong_origin else self.commit}}
            return subprocess.CompletedProcess(argv, 0, json.dumps(info), "")
        return run

    # Claim: generation records canonical module versions only after every
    # proxy response identifies the requested published Git commit.
    def test_proxy_verified_snapshot_regeneration(self):
        with mock.patch.object(self.graph.subprocess, "run", side_effect=self.resolver()) as calls:
            self.graph.refresh_snapshot(REPO, self.path, "go", self.commit)
        generated = json.loads(self.path.read_text())
        self.assertEqual(generated["modules"], self.snapshot["modules"])
        self.assertNotIn("module_provenance", generated)
        self.assertEqual(generated["snapshot_commit"], self.commit)
        self.assertEqual(generated["snapshot_time"], "20200102030405")
        self.assertEqual(calls.call_count, len(self.snapshot["modules"]) + 1)

    # Claim: wrong proxy origin and resolution failure cannot leave partial
    # snapshot writes, beside the successful generation control above.
    def test_failed_resolution_preserves_snapshot(self):
        for origin, unavailable, witness in [(True, False, "origin mismatch"),
                                              (False, True, "cannot resolve published snapshot")]:
            with self.subTest(witness=witness):
                with mock.patch.object(self.graph.subprocess, "run",
                                       side_effect=self.resolver(origin, unavailable)):
                    with self.assertRaisesRegex(self.graph.SetupError, witness):
                        self.graph.refresh_snapshot(REPO, self.path, "go", self.commit)
                self.assertEqual(self.path.read_bytes(), self.original)


if __name__ == "__main__":
    unittest.main()
