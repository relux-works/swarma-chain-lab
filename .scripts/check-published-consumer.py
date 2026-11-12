#!/usr/bin/env python3
"""Qualify real published consumer graphs outside the repository, without replaces."""
import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

PREFIX = "github.com/relux-works/swarma-chain-lab/"
SINGLE_USE = PREFIX + "experiments/single-use"
STATION_MANAGER = PREFIX + "experiments/station-lifecycle/cmd/station-manager"
# Historical baselines are fixed, signed, published commits with a known defect.
SNAPSHOT_BASE = "288d63e191fefac885d6a39aa65f0a5fbb6ed7ee"  # single-use -> sealwatch v0.1.0
STANDALONE_STALE = "b516cc21ce2f0b91cbf3594ddf8db1b002a24717"  # PR 72 F1: single-use v0.1.0
MISSING_CONFIGGUARD = (r"cannot find module providing package "
                       + re.escape(SINGLE_USE + "/configguard") + r": module lookup disabled by GOPROXY=off")
SINGLE_USE_CONSUMER = '''package main

import (
    "github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"
    "github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadbootstrap"
    "github.com/relux-works/swarma-chain-lab/experiments/single-use/modelprofile"
)

var (
    _ = configguard.ValidateStagedSet
    _ = configguard.StagedSet{}
    _ = configguard.StagedPolicy{}
    _ = payloadbootstrap.DecodeBootstrap
    _ = payloadbootstrap.Bootstrap{}
    _ = modelprofile.ValidatePublicModelConfig
    _ = modelprofile.TypedProfile{}
)

func main() {}
'''
DEPLOY_CONSUMER = '''package main

import "github.com/relux-works/swarma-chain-lab/deploy"

var _ = deploy.RenderInstallAnchor

func main() {}
'''


@dataclass(frozen=True)
class Case:
    """One external entry point, consumed through its own module requirement only."""
    name: str
    module: str
    baseline: str
    witness: str        # regex the historical failure must match
    fails_at: tuple     # operations that must fail at the baseline
    source: str = ""    # consumer main.go, for library entry points
    tool: str = ""      # `tool` directive, for command entry points

    def targets(self):
        return [self.tool] if self.tool else ["./..."]


# Each case is its own consumer module: a shared module would let MVS take the
# highest single-use across cases and hide a stale edge in deploy/station-lifecycle.
CASES = (
    Case("single-use-api", SINGLE_USE, SNAPSHOT_BASE, r"undefined:?\s+sealwatch\.ValidateJSON",
         ("vet", "build"), source=SINGLE_USE_CONSUMER),
    Case("deploy", PREFIX + "deploy", STANDALONE_STALE, MISSING_CONFIGGUARD,
         ("resolve",), source=DEPLOY_CONSUMER),
    Case("station-manager", PREFIX + "experiments/station-lifecycle", STANDALONE_STALE,
         MISSING_CONFIGGUARD, ("resolve",), tool=STATION_MANAGER),
)


def objects(raw):
    decoder = json.JSONDecoder()
    while raw.strip():
        obj, end = decoder.raw_decode(raw.lstrip())
        raw = raw.lstrip()[end:]
        yield obj


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, help="published full commit SHA")
    parser.add_argument("--scratch-parent", required=True, type=Path)
    args = parser.parse_args()
    baselines = {case.baseline for case in CASES}
    if not re.fullmatch(r"[0-9a-f]{40}", args.candidate) or args.candidate in baselines:
        parser.error("candidate must be a full successor commit SHA")
    repo = Path(__file__).resolve().parents[1]
    parent = args.scratch_parent.resolve(strict=True)
    if parent == repo or repo in parent.parents:
        parser.error("scratch parent must be outside the repository")
    go = shutil.which("go")
    if go is None:
        raise RuntimeError("go is unavailable")
    root = Path(tempfile.mkdtemp(prefix="published-consumer-", dir=parent)).resolve()
    for name in ("home", "config", "cache", "go-build", "go-mod", "go-path", "tmp"):
        (root / name).mkdir()
    # Whitelist environment: no inherited GOFLAGS, GOWORK, Git overrides or caches.
    env = {
        "PATH": os.environ["PATH"], "HOME": str(root / "home"),
        "USERPROFILE": str(root / "home"), "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_CACHE_HOME": str(root / "cache"), "GOCACHE": str(root / "go-build"),
        "GOMODCACHE": str(root / "go-mod"), "GOPATH": str(root / "go-path"),
        "TMPDIR": str(root / "tmp"), "TMP": str(root / "tmp"), "TEMP": str(root / "tmp"),
        "GOENV": "off", "GOTOOLCHAIN": "local", "GOWORK": "off",
        "GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org",
        "CGO_ENABLED": "0", "GOMAXPROCS": "4", "GOFLAGS": "-p=2",
    }
    offline = dict(env, GOPROXY="off", GOSUMDB="off")
    print(f"evidence: {root}", flush=True)
    (root / "environment.json").write_text(json.dumps(env, indent=2) + "\n")
    records = []

    def run(cwd, name, argv, command_env=env, expected=0):
        log = root / (name + ".log")
        with log.open("w") as out:
            proc = subprocess.Popen([go, *argv], cwd=cwd, env=command_env,
                                    stdout=out, stderr=subprocess.STDOUT)
            record = {"name": name, "cwd": str(cwd), "argv": [go, *argv], "pid": proc.pid,
                      "expected": expected}
            try:
                record["exit"] = proc.wait(timeout=300)
            except subprocess.TimeoutExpired:
                proc.kill()
                record["exit"] = proc.wait()
                record["timeout"] = True
            records.append(record)
            (root / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
        output = log.read_text()
        print(f"{name}: exit {record['exit']} (expected {expected})", flush=True)
        if record.get("timeout") or record["exit"] != expected:
            print(output, flush=True)
            raise RuntimeError(f"{name}: unexpected exit {record['exit']}; see {log}")
        return output

    def step(case, label, cwd, operation, argv, command_env):
        # A historical failure must identify the actual defect, not any error.
        failing = label == "baseline" and operation in case.fails_at
        output = run(cwd, f"{case.name}-{label}-{operation}", argv, command_env, 1 if failing else 0)
        if failing:
            witness = re.search(case.witness, output)
            if not witness:
                raise RuntimeError(f"{case.name} baseline {operation}: intended witness absent")
            print(f"{case.name} baseline {operation}: witnessed {witness.group(0)!r}", flush=True)
        return output

    run(root, "toolchain", ["version"])
    summary = []
    for case in CASES:
        for label, commit in (("baseline", case.baseline), ("candidate", args.candidate)):
            cwd = root / f"{case.name}-{label}"
            cwd.mkdir()
            info = json.loads(run(cwd, f"{case.name}-{label}-origin",
                                  ["list", "-m", "-json", case.module + "@" + commit]))
            if info.get("Origin", {}).get("Hash") != commit:
                raise RuntimeError(f"{case.name} {label}: resolved revision mismatch")
            version = info["Version"]
            manifest = f"module example.invalid/{case.name}-consumer\n\ngo 1.26.0\n\nrequire {case.module} {version}\n"
            if case.tool:
                manifest += f"\ntool {case.tool}\n"
            (cwd / "go.mod").write_text(manifest)
            if case.source:
                (cwd / "main.go").write_text(case.source)
            # Online: fetch exactly the declared module graph with checksum-database
            # verification. `go mod download` never resolves imports, unlike an online
            # `go mod tidy`, which would query @latest for a missing package and could
            # silently add a newer sibling, masking a stale requirement.
            run(cwd, f"{case.name}-{label}-download", ["mod", "download", "all"])
            # Offline: imports must resolve from the published graph alone.
            step(case, label, cwd, "resolve", ["list", "-mod=mod", "-deps", *case.targets()], offline)
            if label == "baseline" and "resolve" in case.fails_at:
                summary.append(f"{case.name} baseline {case.baseline[:12]}: resolve refused (witness)")
                continue
            # Online again: resolution added indirect requirements; fetch the metadata
            # of the widened graph. This cannot change requirements.
            before = (cwd / "go.mod").read_bytes()
            run(cwd, f"{case.name}-{label}-download-resolved", ["mod", "download", "all"])
            if (cwd / "go.mod").read_bytes() != before:
                raise RuntimeError(f"{case.name} {label}: download changed go.mod")
            metadata = json.loads(run(cwd, f"{case.name}-{label}-manifest", ["mod", "edit", "-json"], offline))
            if metadata.get("Replace") or not any(r["Path"] == case.module and r["Version"] == version
                                                  for r in metadata["Require"]):
                raise RuntimeError(f"{case.name} {label}: consumer version changed or replace introduced")
            graph = list(objects(run(cwd, f"{case.name}-{label}-graph",
                                     ["list", "-mod=readonly", "-m", "-json", "all"], offline)))
            if any(m.get("Replace") for m in graph):
                raise RuntimeError(f"{case.name} {label}: replaced module in selected graph")
            run(cwd, f"{case.name}-{label}-verify", ["mod", "verify"], offline)
            step(case, label, cwd, "vet", ["vet", "-mod=readonly", *case.targets()], offline)
            step(case, label, cwd, "build", ["build", "-mod=readonly", "-o", str(cwd / "bin") + os.sep,
                                             *case.targets()], offline)
            summary.append(f"{case.name} {label} {version}: "
                           + ("vet/build refused (witness)" if label == "baseline" else "resolve/vet/build PASS"))
    print("\n".join(summary), flush=True)
    print("Scope: published API graph and static compilation only; no runtime/custody qualification.", flush=True)


if __name__ == "__main__":
    main()
