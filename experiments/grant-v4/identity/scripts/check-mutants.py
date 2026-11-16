#!/usr/bin/env python3
"""Run narrowing LIP-0021 control plants through Go overlays and isolated Python copies."""

import argparse
import hashlib
import json
import shutil
from pathlib import Path
import subprocess
import sys

MODULE = Path(__file__).resolve().parents[1]
PLANTS = [
    ('r2-holder-reject-all', 'r1_value.go', 'swarma, nostr, err := r1ValueMembers(raw)', 'return fail(); swarma, nostr, err := r1ValueMembers(raw)', 'TestR1Holders/value-10', 'neighbour value-03: R1 got'),
    ('r2-group-reject-all', 'r1_groups.go', 'if len(p.Groups) < 1', 'if true { return 0, R1RuleError("R8.4") }; if len(p.Groups) < 1', 'TestR1Groups/group-11', 'neighbour group-02: R1 got'),
    ('r2-template-reject-all', 'r1_class.go', 'if t.Certifier != "" {', 'if true { return R1RuleError("R9.1") }; if t.Certifier != "" {', 'TestR1Class/template-07', 'neighbour template-01: R1 got'),
    ('r2-landlord-absence-verdict', 'r1_class.go', 'case NoLiveOutput:\n\t\treturn ClassLandlordChanged', 'case NoLiveOutput:\n\t\treturn ClassHistoryUnavailable', 'TestRev375LandlordNoLiveOutput/proved_absent', 'R9.5 first step:'),
    ('r2-trailing-json-whitespace', 'r1_value.go', 'if d.InputOffset() != int64(len(raw)) {', 'if d.InputOffset() != int64(len(bytes.TrimRight(raw, " \\t\\r\\n"))) {', 'TestRev375TopLevelSuffix/suffix_20', 'bytes after object must refuse'),
    ("current-owner-only", "verdict.go", "if inView {", "if inView && out.ID == s.Outputs[0].ID {", "TestV4IssuerHistory/walk-issuer-04", "walk-issuer-04: got"),
    ("require-id-recipient", "recipient.go", "if state == nil ||", 'if !bytes.HasPrefix(r.ByName.Name, []byte("id/")) || state == nil ||', "TestV4RecipientUnion/any-namespace", "current selected channel key:"),
    ("shared-history-cache-key", "walk.go", "rule: p.Rule,", "rule: IssuerHistory,", "TestV4NotaryHistoryPredicate/cache-rule-separation", "issuer and notary cache keys collide"),
    ("contains-key", "script.go", "\tns, ok := ParseNameScript(script)\n", "\tif p.ok && bytes.Contains(script, p.key[:]) {\n\t\tns, _ := ParseNameScript(script)\n\t\treturn Controlled, ns\n\t}\n\tns, ok := ParseNameScript(script)\n", "TestV4NameScript/script-21", "script-21: got"),
    ("inclusive-expiry", "live.go", "height-confirmedAt < depth", "height-confirmedAt <= depth", "TestV4LiveName/live-03", "live-03: got"),
    ("skip-witness-check", "writer.go", "ok = witnessSpendOK(in, p)", "ok = true", "TestV4Writer/writer-21", "writer-21: got"),
    ("omit-witness-branch", "writer.go", "ok = witnessSpendOK(in, p)", "ok = false", "TestV4Writer/writer-04", "writer-04: got"),
    ('r1-enable-in-force', 'r1_value.go', 'if profile != R1DraftLab {', 'if profile != R1DraftLab && false {', 'TestR1ProfileGate/0', 'R1 profile admitted a value'),
    ('r1-unweighted-pool', 'r1_groups.go', 'new(big.Int).Mul(amount, new(big.Int).SetUint64(rows))', 'new(big.Int).Set(amount)', 'TestR1Groups/group-19', 'group-19: R1 got'),
    ('r1-wrapped-pool', 'r1_groups.go', 'for key, sum := range sums {', 'for key, sum := range sums {\n sum.SetUint64(sum.Uint64())', 'TestR1Groups/group-22', 'group-22: R1 got'),
    ('r1-overlapping-ranges', 'r1_groups.go', 'if r.TxID == prior.TxID && r.First <= prior.First+prior.Count-1 && prior.First <= end {', 'if false && r.TxID == prior.TxID && r.First <= prior.First+prior.Count-1 && prior.First <= end {', 'TestR1Groups/group-24', 'group-24: R1 got'),
    ('r1-zero-based-ordinal', 'r1_groups.go', 'remaining := ordinal - 1', 'remaining := ordinal', 'TestR1Groups/ordinal-01', 'ordinal-01: R1 got'),
    ('r1-unordered-holders', 'r1_value.go', 'e != nil || (i > 0 && pins[i-1] >= p)', 'e != nil || (i > 0 && pins[i-1] >= p && false)', 'TestR1Holders/value-24', 'value-24: R1 got'),
    ('r1-cross-owner-no-certifier', 'r1_class.go', 'len(t.Recipient.Class) != 1 || !sameLandlord(t.Recipient.Class[0], issuer)', 'false', 'TestR1Class/template-12', 'template-12: R1 got'),
    ('r1-same-name-issuer-pin', 'r1_class.go', 'return a.Name == b.Name && a.Registration == b.Registration && a.Owner == b.Owner', 'return a.Name == b.Name', 'TestR1Class/template-13', 'template-13: R1 got'),
    ('r1-drop-certifier-requirement', 'r1_class.go', 'return RowRecipientResult{value.ChannelKey, t.Certifier != ""}, nil', 'return RowRecipientResult{value.ChannelKey, false}, nil', 'TestR1Class/class-01', 'class-01: R1 got'),
    ('r1-no-certifier-stop-coin', 'r1_class.go', 'if t.StopCoin != nil {', 'if t.StopCoin != nil && false {', 'TestR1CertifierBoundary', 'R1 stop coin admitted'),
    ('r1-current-owner-only', 'r1_class.go', 'if out.Reading == AnotherKey {', 'if out.ID == s.Outputs[0].ID && out.Reading == AnotherKey {', 'TestR1Class/class-14', 'class-14: R1 got'),
    ('r1-check-writer-before-history', 'r1_class.go', 'if reg.Height.h > o.Recent.h {', 'if s.Outputs[0].Writer == WrittenByAnother { return ClassValueUnauthorized }; if reg.Height.h > o.Recent.h {', 'TestR1Class/class-14', 'class-14: R1 got'),
    ('r1-ignore-landlord-writer', 'r1_class.go', 'case WrittenByAnother:\n\t\treturn ClassValueUnauthorized', 'case WrittenByAnother:', 'TestR1Class/certifier-10', 'certifier-10: R1 got'),
    ('r1-ignore-pending', 'r1_class.go', 'if e.Pending {', 'if e.Pending && false {', 'TestR1Class/class-31', 'class-31: R1 got'),
    ('r1-ignore-holder', 'r1_class.go', 'if !held {', 'if !held && false {', 'TestR1Class/class-37', 'class-37: R1 got'),
    ('r1-ignore-value-writer', 'r1_class.go', 'if !written {', 'if !written && false {', 'TestR1Class/class-25', 'class-25: R1 got'),
    ('r1-only-current-holder-writes', 'r1_class.go', 'switch CheckWriter(operation, ns.Name, e.Inputs, h, o.Chain) {', 'if h != child.ByName.Owner { continue }; switch CheckWriter(operation, ns.Name, e.Inputs, h, o.Chain) {', 'TestR1Class/class-02', 'class-02: R1 got'),
    ('r1-ignore-unsupported-writer', 'r1_class.go', 'if unsupported {', 'if unsupported && false {', 'TestR1Class/class-28', 'class-28: R1 got'),
    ('r1-ignore-recipient-owner', 'r1_class.go', 'if reading == AnotherKey {', 'if reading == AnotherKey { reading = Controlled }; if reading == AnotherKey {', 'TestR1Class/class-34', 'class-34: R1 got'),
    ('r1-executor-after-recipient', 'r1_class.go', 'if c.Executor != t.Executor {', 'if c.Executor != t.Executor && c.Recipient.ByName != nil {', 'TestR1ChildOrder/executor-before-recipient', 'R1 order got'),
    ('r1-budget-before-recipient', 'r1_class.go', '// Structural R2.3 precedes the limit ceiling, but proof-by-name comes later.', '// Control plant: improperly prefer the budget.\n plantedRow, _ := limitMap(t.Limits); plantedChild, _ := limitMap(c.Limits); for k,a := range plantedChild { if plantedRow[k] == nil || a.Cmp(plantedRow[k]) > 0 { return fail(ChildBudgetOver) } }', 'TestR1ChildOrder/recipient-before-budget', 'R1 order got'),
    ('r1-union-class-holders', 'r1_class.go', 'held := false', 'for _, other := range o.Landlords { if other.Binding.Name != value.Landlord { v, _ := ReadR1Value(profile, other.Value); lv.Holders = append(lv.Holders, v.Holders...) } }; held := false', 'TestR1Class/class-36', 'class-36: R1 got'),
    ('r1-prefix-class-holders', 'r1_class.go', 'held := false', 'for _, prior := range t.Recipient.Class { if prior.Name == value.Landlord { break }; for _, other := range o.Landlords { if other.Binding.Name == prior.Name { v, _ := ReadR1Value(profile, other.Value); lv.Holders = append(lv.Holders, v.Holders...) } } }; held := false', 'TestR1Class/class-38', 'class-38: R1 got'),
    ('r1-partial-parent', 'r1_class.go', 'for _, g := range p.Rows.Groups {', 'for _, g := range p.Rows.Groups[:1] {', 'TestR1ParentAtomic/later-template', 'R1 parent partial acceptance'),
]


def run(scratch, name, command):
    proc = subprocess.run(command, cwd=MODULE, text=True, capture_output=True)
    (scratch / (name+".json")).write_text(proc.stdout)
    (scratch / (name+".stderr.log")).write_text(proc.stderr)
    events = [json.loads(line) for line in proc.stdout.splitlines()]
    return proc, events


def python_round_control(scratch, evidence):
    """Require an assertion failure in the published-vector test, not a setup error."""
    required = "test_second_reader.Ripemd160Vectors.test_published_vectors"
    command = [sys.executable, "-B", "-m", "unittest", "-v", required]
    scripts = MODULE / "scripts"
    mutant = scratch / "python-broken-round"
    shutil.copytree(scripts, mutant / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
    (mutant / "testdata").mkdir()
    shutil.copy2(MODULE / "testdata/ripemd160-vectors.json", mutant / "testdata")
    source = mutant / "scripts/ripemd160.py"
    original = source.read_text()
    old, new = "return x ^ y ^ z", "return x ^ y ^ z ^ 1"
    if original.count(old) != 1:
        raise ValueError("python-broken-round: plant not uniquely applicable")
    source.write_text(original.replace(old, new, 1))
    for name, cwd in [("python-control", scripts), ("python-broken-round", mutant / "scripts")]:
        proc = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
        (scratch / (name + ".stdout.log")).write_text(proc.stdout)
        (scratch / (name + ".stderr.log")).write_text(proc.stderr)
        record = {"name": name, "command": command, "exit": proc.returncode}
        evidence["runs"].append(record)
        if name == "python-control":
            if proc.returncode != 0 or "Ran 1 test" not in proc.stderr or "OK" not in proc.stderr:
                raise ValueError(f"Python unplanted control failed, exit {proc.returncode}")
        else:
            killed = (proc.returncode == 1 and
                      f"FAIL: test_published_vectors ({required})" in proc.stderr and
                      "AssertionError:" in proc.stderr and
                      "published RIPEMD-160 vector" in proc.stderr and
                      "ERROR:" not in proc.stderr)
            record.update(required_failure=required, killed=killed)
            print(f"{name}: exit {proc.returncode}; {'KILLED ' + required if killed else 'NOT KILLED'}")
            if not killed:
                raise ValueError("python-broken-round: intended assertion failure not demonstrated")


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
        if proc.returncode != 0 or any(e.get("Action") in ("fail", "skip") for e in events) or not {"TestV4OwnerPin", "TestV4NameScript", "TestV4Writer", "TestV4LiveName", "TestV4IssuerHistory", "TestV4RecipientUnion", "TestV4NotaryHistoryPredicate", "TestV4ConsentHistory", "TestV4RecipientHistory"} <= roots:
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
        python_round_control(scratch, evidence)
        return 0
    except (ValueError, OSError) as error:
        print(error, file=sys.stderr)
        return 1
    finally:
        (scratch / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")


if __name__ == "__main__":
    sys.exit(main())
