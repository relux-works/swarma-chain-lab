#!/usr/bin/env python3
"""Run eight wire-layer control plants through isolated Go overlays.

Requires a green candidate first. A plant is killed only by its named failing
subtest and diagnostic; compiler/setup failures and surviving plants fail this
runner. Overlays never edit source; complete JSON streams and an evidence index remain.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


PLANTS = (
    ("domain-binding", "crypto.go", "h.Write(t[:])", "_ = t", 2,
     "TestV4TypedDomains", "TestV4TypedDomains/swarma-grant/4", "hash ="),
    ("integer-float", "canonical.go", "return n, nil\n}\n\n// EncodeDocument", "return uint64(float64(n)), nil\n}\n\n// EncodeDocument", 1,
     "TestV4CanonicalVectors", "TestV4CanonicalVectors/int-v-05", "integer did not round-trip exactly"),
    ("scalar-range", "crypto.go",
     "\tif bytes.Compare(raw[32:], groupOrder[:]) >= 0 {\n\t\treturn nil, WireSignature\n\t}\n", "", 1,
     "TestV4StrictBIP340", "TestV4StrictBIP340/s=n", 'refusal = "", want "WIRE_SIGNATURE"'),
    ("unknown-member", "objects.go", "if !allowed[m.name] {", "if false && !allowed[m.name] {", 1,
     "TestV4CanonicalVectors", "TestV4CanonicalVectors/assent-i-01", 'refusal = "", want "WIRE_MEMBER"'),
    ("key-order-relaxed", "canonical.go", "if !bytes.Equal(b, serialize(v)) {", "if false && !bytes.Equal(b, serialize(v)) {", 1,
     "TestV4CanonicalVectors", "TestV4CanonicalVectors/canon-i-01", 'refusal = "", want "WIRE_NOT_CANONICAL"'),
    ("vout-bound-plus-one", "objects.go", "ParseInteger(x.text, 4294967295)", "ParseInteger(x.text, 4294967296)", 1,
     "TestV4CanonicalVectors", "TestV4CanonicalVectors/issuance-s-03", 'refusal = "", want "WIRE_INTEGER"'),
    ("snapshot-post-return", "consent.go", "\treturn nil\n}\n",
     "\tdefer func() { if snapshot != nil { snapshot.Name.Height++ } }()\n\treturn nil\n}\n", 1,
     "TestV4ConsentSnapshotPostReturn", "TestV4ConsentSnapshotPostReturn/issuer-c-07",
     "issuer check mutated live snapshot or context after return"),
    ("signature-byte-alias", "crypto.go", "return bytes.Clone(s.raw[:])", "return s.raw[:]", 1,
     "TestV4ReturnedBytesIsolation", "TestV4ReturnedBytesIsolation/Signature.Bytes",
     "returned bytes alias retained state"),
)


def run(command, cwd, path):
    with path.open("wb") as stream:
        return subprocess.run(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT,
                              env=dict(os.environ, GOPROXY="off", GOTOOLCHAIN="local", GOWORK="off")).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    module = Path(__file__).resolve().parents[1]
    scratch = args.scratch.resolve()
    if scratch.is_relative_to(module):
        parser.error("scratch must be outside the module")
    scratch.mkdir(parents=True, exist_ok=True)
    # Pin all product and test inputs, including the fixture and this runner.
    inputs = {str(p.relative_to(module)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(module.rglob("*")) if p.is_file() and "__pycache__" not in p.parts}
    evidence = {"inputs": inputs, "plants": []}
    baseline = [args.go, "test", "-json", "-count=1", "./..."]
    code = run(baseline, module, scratch / "baseline.json")
    evidence["baseline"] = {"command": baseline, "exit": code}
    if code:
        (scratch / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print("baseline failed; no mutation evidence")
        return 1
    failed = False
    for name, file, old, new, count, test, witness, diagnostic in PLANTS:
        target = scratch / name
        target.mkdir()  # Refuse reuse of a previous invocation's plant directory.
        text = (module / file).read_text()
        if text.count(old) != count:
            raise ValueError(f"{name}: expected exactly {count} plant sites")
        replacement = target / file
        replacement.write_text(text.replace(old, new))
        overlay = target / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {str(module / file): str(replacement)}}) + "\n")
        command = [args.go, "test", "-overlay", str(overlay), "-json", "-count=1", "-run", "^" + test + "$", "./..."]
        log = scratch / (name + ".json")
        code = run(command, module, log)
        events = []
        for line in log.read_text().splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass  # Non-JSON setup diagnostics cannot supply a kill.
        killed = code == 1 and any(e.get("Action") == "fail" and e.get("Test") == witness for e in events)
        killed = killed and any(e.get("Test") == witness and diagnostic in e.get("Output", "") for e in events)
        evidence["plants"].append({"name": name, "file": file, "before": old, "after": new,
                                   "command": command, "exit": code, "witness": witness,
                                   "diagnostic": diagnostic, "killed": killed})
        print(f"{name}: {'killed by ' + witness if killed else 'SURVIVED or unrelated failure'} (exit {code})")
        failed |= not killed
    (scratch / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
