#!/usr/bin/env python3
"""Regression and mutant controls for .scripts/check-module-graph.py.

Run: python3 -m unittest discover -s .scripts -p 'test_check_module_graph.py'
Each fixture copies the checkout's real go.mod files, the snapshot floor file
and MODULE-GRAPH.md into a scratch git tree, mutates one thing, and runs the
checker CLI exactly as CI does. MODULE_GRAPH_CHECKER may point at a mutated
copy of the checker for gate-mutation runs.
"""
import json
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
        self.assertIn("20 manifests, 19 consumers, 98 internal require edges, 0 violations", output)

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
                                f"\t{SINGLE_USE} {SNAPSHOT_SINGLE_USE}\n", f"\t{SINGLE_USE} v0.1.0\n")
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
                    fixture.substitute(manifest, f"\t{SINGLE_USE} {SNAPSHOT_SINGLE_USE}\n",
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
    # count fails against the 98-edge inventory.
    def test_doc_edge_count_drift_fails(self):
        self.fixture.substitute("experiments/MODULE-GRAPH.md", "all 98 internal require edges",
                                "all 96 internal require edges")
        code, violations, output = self.fixture.run()
        self.assertEqual((code, violations),
                         (1, ["MODULE-GRAPH.md: claims 96 internal require edges; inventory has 98"]), output)

    # Claim: the generated per-manifest table cannot drift either; the old
    # `deploy/go.mod | 1` row (MODULE-GRAPH.md:39 at b516) fails.
    def test_doc_table_drift_fails(self):
        self.fixture.substitute("experiments/MODULE-GRAPH.md", "| `deploy/go.mod` | 2 |",
                                "| `deploy/go.mod` | 1 |")
        code, violations, output = self.fixture.run()
        self.assertEqual((code, violations),
                         (1, ["MODULE-GRAPH.md: inventory table is stale; rerun with --write-doc"]), output)

    # Control: a whitespace/block-only line filter, the parser class behind F1,
    # does not see the standalone edges in the b516 fixture (96 edges, 0 stale),
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
        self.assertEqual((edges, stale), (96, 0))
        code, violations, _ = self.fixture.run()
        self.assertEqual((code, len(violations)), (1, 2))


if __name__ == "__main__":
    unittest.main()
