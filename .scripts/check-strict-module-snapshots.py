#!/usr/bin/env python3
"""Require strict-parser ancestry and call sites in selected published snapshots.

Version ordering cannot prove containment. Resolve each protected internal
require/replacement to its Git commit, require the recorded strict change as an
ancestor, then inspect that commit's source (including the shared parser bounds).
Unknown revisions fail closed; CI must fetch full history. No network is used.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "github.com/relux-works/swarma-chain-lab/"
STRICT = "28d4b9f1aba4f10e8d57ea486f73b52aeabe46ab"
# Only parser-bearing modules need a direct source policy. Grantcheck delegates
# to rental/gateway; its own snapshot must contain the same change as well.
POLICY = {
    "experiments/single-use": {"bip340/signature.go": [
        "if len(sig) != 64", "bytes.Compare(sig[:32], fieldPrime[:]) >= 0",
        "bytes.Compare(sig[32:], groupOrder[:]) >= 0", "return schnorr.ParseSignature(sig)"]},
    "experiments/rental": {"certificate.go": ["bip340.ParseBIP340Strict(sb)"]},
    "experiments/agent-wallet": {"wire.go": ["bip340.ParseBIP340Strict(sb)"]},
    "experiments/rental-booking": {"nostr.go": ["bip340.ParseBIP340Strict(s)"]},
    "experiments/rental-executor": {"event.go": ["bip340.ParseBIP340Strict(sb)"]},
    "experiments/rental-gateway": {
        "nostr/keys.go": ["bip340.ParseBIP340Strict(sigBytes)"],
        "kernel/presentation.go": ["bip340.ParseBIP340Strict(signature)"]},
    "experiments/grantcheck": {},
    "experiments/rental-gateway/kernelbind": {},
}


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)


def check_selection(root, module, version, policy=POLICY):
    relative = module.removeprefix(PREFIX)
    if relative not in policy:
        return []
    pseudo = re.search(r"-([0-9a-f]{12})$", version)
    revision = pseudo[1] if pseudo else f"refs/tags/{relative}/{version}"
    resolved = git(root, "rev-parse", "--verify", revision + "^{commit}")
    if resolved.returncode:
        return [f"{module} {version}: selected commit unavailable (full history required)"]
    commit = resolved.stdout.strip()
    ancestry = git(root, "merge-base", "--is-ancestor", STRICT, commit)
    if ancestry.returncode:
        return [f"{module} {version}: selected commit does not contain strict change {STRICT}"]
    errors = []
    for filename, markers in policy[relative].items():
        source = git(root, "show", f"{commit}:{relative}/{filename}")
        if source.returncode or any(marker not in source.stdout for marker in markers):
            errors.append(f"{module} {version}: selected source lacks strict call site {filename}")
        elif relative == "experiments/single-use":
            # Bounds must precede the permissive parser, not merely exist after it.
            if any(source.stdout.index(marker) > source.stdout.index(markers[-1]) for marker in markers[:-1]):
                errors.append(f"{module} {version}: strict bounds follow library parser")
    return errors


def check(root, go=None):
    spec = importlib.util.spec_from_file_location("module_graph", ROOT / ".scripts/check-module-graph.py")
    graph = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(graph)
    import shutil
    go = go or shutil.which("go")
    if not go:
        raise graph.SetupError("go is unavailable")
    selections = set()
    for manifest in graph.manifests(root):
        data, error = graph.parse(go, root, manifest)
        if error:
            raise graph.SetupError(error)
        selections.update((r["Path"], r["Version"]) for r in data.get("Require") or [])
        selections.update((r["New"]["Path"], r["New"]["Version"])
                          for r in data.get("Replace") or [] if r["New"].get("Version"))
    return [error for module, version in sorted(selections)
            for error in check_selection(root, module, version)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    errors = check(args.root.resolve())
    for error in errors:
        print("VIOLATION " + error)
    print(f"strict module snapshots: {len(errors)} violations")
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
