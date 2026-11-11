#!/usr/bin/env python3
"""Qualify real published consumer graphs outside the repository, without replaces."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

MODULE = "github.com/relux-works/swarma-chain-lab/experiments/single-use"
BASELINE = "288d63e191fefac885d6a39aa65f0a5fbb6ed7ee"
CONSUMER = '''package main

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
    if not re.fullmatch(r"[0-9a-f]{40}", args.candidate) or args.candidate == BASELINE:
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
    print(f"evidence: {root}", flush=True)
    (root / "environment.json").write_text(json.dumps(env, indent=2) + "\n")
    records = []

    def run(cwd, name, argv, command_env=env, expected=0):
        log = root / (name + ".log")
        with log.open("w") as out:
            proc = subprocess.Popen([go, *argv], cwd=cwd, env=command_env,
                                    stdout=out, stderr=subprocess.STDOUT)
            record = {"name": name, "cwd": str(cwd), "argv": [go, *argv], "pid": proc.pid}
            try:
                record["exit"] = proc.wait(timeout=300)
            except subprocess.TimeoutExpired:
                proc.kill()
                record["exit"] = proc.wait()
                record["timeout"] = True
            records.append(record)
            (root / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
        output = log.read_text()
        print(f"{name}: exit {record['exit']}", flush=True)
        if record.get("timeout") or record["exit"] != expected:
            print(output, flush=True)
            raise RuntimeError(f"{name}: unexpected exit {record['exit']}; see {log}")
        return output

    run(root, "toolchain", ["version"])
    cases = []
    for label, commit in (("baseline", BASELINE), ("candidate", args.candidate)):
        cwd = root / label
        cwd.mkdir()
        info = json.loads(run(cwd, label + "-resolve", ["list", "-m", "-json", MODULE + "@" + commit]))
        if info.get("Origin", {}).get("Hash") != commit:
            raise RuntimeError(f"{label}: resolved revision mismatch")
        version = info["Version"]
        (cwd / "go.mod").write_text(f"module example.invalid/published-consumer\n\ngo 1.26.0\n\nrequire {MODULE} {version}\n")
        (cwd / "main.go").write_text(CONSUMER)
        # Tidy only this throwaway consumer to populate checksummed dependencies.
        run(cwd, label + "-populate", ["mod", "tidy"])
        # Offline graph enumeration also needs lazy, non-imported dependency metadata.
        run(cwd, label + "-download", ["mod", "download", "all"])
        cases.append((label, cwd, version))

    offline = dict(env, GOPROXY="off", GOSUMDB="off")
    for label, cwd, version in cases:
        metadata = json.loads(run(cwd, label + "-manifest", ["mod", "edit", "-json"], offline))
        if metadata.get("Replace") or not any(r["Path"] == MODULE and r["Version"] == version
                                              for r in metadata["Require"]):
            raise RuntimeError(f"{label}: consumer version changed or replace introduced")
        graph = list(objects(run(cwd, label + "-graph", ["list", "-mod=readonly", "-m", "-json", "all"], offline)))
        if any(m.get("Replace") for m in graph):
            raise RuntimeError(f"{label}: replaced module in selected graph")
        run(cwd, label + "-verify", ["mod", "verify"], offline)
        for operation in ("vet", "build"):
            # Both old failures must identify the actual missing API, not any error.
            output = run(cwd, label + "-" + operation,
                         [operation, "-mod=readonly", "./..."], offline,
                         expected=1 if label == "baseline" else 0)
            if label == "baseline" and not re.search(r"undefined:?\s+sealwatch\.ValidateJSON", output):
                raise RuntimeError(f"baseline {operation}: intended missing-API witness absent")
            if label == "baseline":
                print(f"{operation}: witnessed undefined sealwatch.ValidateJSON", flush=True)
    print("baseline vet/build: intended missing-API refusal; candidate vet/build: PASS", flush=True)
    print("Scope: published API graph and static compilation only; no runtime/custody qualification.", flush=True)


if __name__ == "__main__":
    main()
