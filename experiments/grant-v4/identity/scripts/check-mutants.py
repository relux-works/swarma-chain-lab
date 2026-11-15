#!/usr/bin/env python3
"""Run narrowing LIP-0021 control plants through Go overlays, never source edits."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

MODULE = Path(__file__).resolve().parents[1]
PLANTS = [
    ("contains-key", "script.go", "\tns, ok := ParseNameScript(script)\n", "\tif p.ok && bytes.Contains(script, p.key[:]) {\n\t\tns, _ := ParseNameScript(script)\n\t\treturn Controlled, ns\n\t}\n\tns, ok := ParseNameScript(script)\n", "TestV4NameScript/script-21", "script-21: got"),
    ("inclusive-expiry", "live.go", "height-confirmedAt < depth", "height-confirmedAt <= depth", "TestV4LiveName/live-03", "live-03: got"),
    ("skip-witness-check", "writer.go", "ok = witnessSpendOK(in, p)", "ok = true", "TestV4Writer/writer-21", "writer-21: got"),
    ("omit-witness-branch", "writer.go", "ok = witnessSpendOK(in, p)", "ok = false", "TestV4Writer/writer-04", "writer-04: got"),
]


def run(scratch, name, command):
    proc = subprocess.run(command, cwd=MODULE, text=True, capture_output=True)
    (scratch / (name+".json")).write_text(proc.stdout)
    (scratch / (name+".stderr.log")).write_text(proc.stderr)
    events = [json.loads(line) for line in proc.stdout.splitlines()]
    return proc, events


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", type=Path, required=True)
    args = parser.parse_args()
    scratch = args.scratch.resolve()
    scratch.mkdir(parents=True, exist_ok=False)
    identities = {str(p.relative_to(MODULE)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(MODULE.rglob("*")) if p.is_file() and "__pycache__" not in p.parts}
    evidence = {"inputs": identities, "runs": []}
    try:
        command = ["go", "test", "-count=1", "-json", "./..."]
        proc, events = run(scratch, "control", command)
        roots = {e.get("Test") for e in events if e.get("Action") == "pass"}
        if proc.returncode != 0 or any(e.get("Action") in ("fail", "skip") for e in events) or not {"TestV4OwnerPin", "TestV4NameScript", "TestV4Writer", "TestV4LiveName"} <= roots:
            raise ValueError(f"unplanted control failed, exit {proc.returncode}")
        evidence["runs"].append({"name": "control", "command": command, "exit": proc.returncode})
        for name, file, old, new, required, diagnostic in PLANTS:
            source = MODULE / file
            original = source.read_text()
            if original.count(old) != 1:
                raise ValueError(f"{name}: plant not uniquely applicable")
            replacement = scratch / (name+".go")
            replacement.write_text(original.replace(old, new, 1))
            overlay = scratch / (name+"-overlay.json")
            overlay.write_text(json.dumps({"Replace": {str(source): str(replacement)}}) + "\n")
            command = ["go", "test", "-overlay", str(overlay), "-count=1", "-json", "-run", "^"+required.split("/")[0]+"$", "./..."]
            proc, events = run(scratch, name, command)
            failed = {e.get("Test") for e in events if e.get("Action") == "fail"}
            outputs = "".join(e.get("Output", "") for e in events if e.get("Test") == required)
            killed = proc.returncode == 1 and required in failed and diagnostic in outputs and not any(e.get("Action") in ("skip", "build-fail") for e in events)
            evidence["runs"].append({"name": name, "command": command, "exit": proc.returncode, "required_failure": required, "diagnostic": diagnostic, "killed": killed})
            print(f"{name}: exit {proc.returncode}; {'KILLED '+required if killed else 'NOT KILLED'}")
            if not killed:
                raise ValueError(f"{name}: intended test failure not demonstrated")
        return 0
    except (ValueError, OSError) as error:
        print(error, file=sys.stderr)
        return 1
    finally:
        (scratch / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    sys.exit(main())
