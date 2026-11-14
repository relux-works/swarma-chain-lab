#!/usr/bin/env python3
"""Run wire-layer control plants through isolated Go overlays.

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
    ("key-order-relaxed", "canonical.go", "if !bytes.Equal(b, serialize(v)) {", "if !bytes.Equal(b, serializeMemberOrder(v)) {", 1,
     "TestV4CanonicalVectors", "TestV4CanonicalVectors/canon-i-04", 'refusal = "", want "WIRE_NOT_CANONICAL"'),
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


# This serializer changes ONLY member order. The parsed tree retains input
# order; all strings, integers, whitespace and other syntax retain the normal
# canonical spelling, and the original byte-for-byte comparison remains.
ORDER_ONLY_SERIALIZER = r"""
func serializeMemberOrder(v *value) []byte {
    var encode func([]byte, *value) []byte
    encode = func(b []byte, v *value) []byte {
        switch v.kind {
        case '{':
            b = append(b, '{')
            for i, m := range v.members {
                if i > 0 { b = append(b, ',') }
                b = appendString(b, m.name)
                b = append(b, ':')
                b = encode(b, m.value)
            }
            return append(b, '}')
        case '[':
            b = append(b, '[')
            for i, x := range v.elements {
                if i > 0 { b = append(b, ',') }
                b = encode(b, x)
            }
            return append(b, ']')
        default:
            return appendValue(b, v)
        }
    }
    return encode(nil, v)
}
"""

# Independent stage probes let a plant report the transposed first refusal
# even when a refused reader correctly returns no object. They add no product
# API. The commitment probe uses the supplied parts, not an admitted grant;
# malformed parts defer to their own stage. The untransposed probe is also
# required to pass the complete suite before any order plant is counted.
ORDER_PROBES = r"""
func CheckIssuance(in IssuanceInput) (*Preparation, error) {
    if in.Grant == nil { return originalCheckIssuance(in) }
    g := *in.Grant
    mode := func() error {
        if g.Mode != ByKey && g.Mode != ByName || g.Mode == ByKey && in.NameOutput != nil || g.Mode == ByName && in.NameOutput == nil { return IssuanceMode }
        return nil
    }
    assent := func() error {
        _, err := ReadAssent(in.IssuerAssent, AssentContext{g.Genesis, g.Contract, g.PartyPublicKey})
        return err
    }
    consent := func() error {
        _, err := ReadConsent(in.RecipientConsent, ConsentContext{
            Mode:g.Mode, Genesis:g.Genesis, Contract:g.Contract,
            IssuerPublicKey:g.IssuerPublicKey, RequestPublicKey:g.RequestPublicKey,
            RecipientName:g.RecipientName, RecentBlockHeight:g.RecentBlockHeight,
            Now:in.Now, Evidence:in.Evidence})
        return err
    }
    frame := func() error {
        expected, err := EncodeIssuanceFrame([32]byte{}, g.ContentAddress)
        f := in.Frame
        if err != nil || f.Value != 0 || f.OpReturnCount != 1 || len(f.Script) != 72 { return IssuanceFrame }
        if string(f.Script[:7]) != string(expected[:7]) || f.Script[39] != 1 || string(f.Script[40:]) != string(expected[40:]) { return IssuanceFrame }
        return nil
    }
    commitment := func() error {
        if len(in.Frame.Script) != 72 { return nil }
        a, err := ReadSigned(in.IssuerAssent, ContractAssent)
        if err != nil { return nil }
        c, err := parseConsent(in.RecipientConsent)
        if err != nil { return nil }
        // The encoding has no mode member; select the shape actually supplied
        // so the mode probe alone decides presence while this probe hashes it.
        shape := ByKey
        if in.NameOutput != nil { shape = ByName }
        p, err := BuildPreparation(PreparationParts{
            Mode:shape, Genesis:g.Genesis, Contract:g.Contract, GrantID:g.ID, GrantSignature:g.Signature,
            AssentParty:a.payload.root.get("party").text, AssentSignature:a.Signature(),
            ConsentID:c.ID(), ConsentSignature:c.Signature(), NameOutput:in.NameOutput})
        if err != nil { return err }
        digest := p.Commitment()
        if string(in.Frame.Script[7:39]) != string(digest[:]) { return IssuanceCommitment }
        return nil
    }
    for _, check := range []func() error{CHECK_ORDER} {
        if err := check(); err != nil { return nil, err }
    }
    return originalCheckIssuance(in)
}
"""

STEPS = ("mode", "assent", "consent", "frame", "commitment")
CODES = ("ISSUANCE_MODE", "ASSENT_PARTY", "CONSENT_TIME", "ISSUANCE_FRAME", "ISSUANCE_COMMITMENT")
ORDER_PLANTS = []
for earlier in range(len(STEPS)):
    for later in range(earlier + 1, len(STEPS)):
        name = f"{STEPS[earlier]}-before-{STEPS[later]}"
        ORDER_PLANTS.append(("swap-" + name, "composed.go", "func CheckIssuance(",
                             "func originalCheckIssuance(", 1,
                             "TestV4IssuanceFirstRefusalPairs",
                             "TestV4IssuanceFirstRefusalPairs/" + name,
                             f'refusal = "{CODES[later]}", want "{CODES[earlier]}"'))

PLANTS += (
    ("skip-consent-check", "composed.go",
     """ReadConsent(in.RecipientConsent, ConsentContext{
		Mode: g.Mode, Genesis: g.Genesis, Contract: g.Contract,
		IssuerPublicKey: g.IssuerPublicKey, RequestPublicKey: g.RequestPublicKey,
		RecipientName: g.RecipientName, RecentBlockHeight: g.RecentBlockHeight,
		Now: in.Now, Evidence: in.Evidence,
	})""", "parseConsent(in.RecipientConsent)", 1,
     "TestV4CanonicalVectors", "TestV4CanonicalVectors/composed-i-05",
     'refusal = "ISSUANCE_COMMITMENT", want "CONSENT_KEY"'),
    ("skip-assent-binding", "composed.go",
     "ReadAssent(in.IssuerAssent, AssentContext{g.Genesis, g.Contract, g.PartyPublicKey})",
     "ReadSigned(in.IssuerAssent, ContractAssent)", 1,
     "TestV4CanonicalVectors", "TestV4CanonicalVectors/composed-i-04",
     'refusal = "ISSUANCE_COMMITMENT", want "ASSENT_PARTY"'),
) + tuple(ORDER_PLANTS)


def planted_source(name, text, old, new):
    result = text.replace(old, new)
    if name == "key-order-relaxed":
        result += ORDER_ONLY_SERIALIZER
    elif name.startswith("swap-") or name == "order-probe-control":
        order = list(STEPS)
        if name.startswith("swap-"):
            early, late = name.removeprefix("swap-").split("-before-")
            a, b = order.index(early), order.index(late)
            order[a], order[b] = order[b], order[a]
        result += ORDER_PROBES.replace("CHECK_ORDER", ", ".join(order))
    return result


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
    # The independently evaluated stage probes must preserve the untransposed
    # candidate's entire tested contract before transpositions can be evidence.
    control = scratch / "order-probe-control"
    control.mkdir()
    module_source = module / "composed.go"
    probe_source = control / "composed.go"
    probe_source.write_text(planted_source("order-probe-control", module_source.read_text(),
                                          "func CheckIssuance(", "func originalCheckIssuance("))
    probe_overlay = control / "overlay.json"
    probe_overlay.write_text(json.dumps({"Replace": {str(module_source): str(probe_source)}}) + "\n")
    probe_command = [args.go, "test", "-overlay", str(probe_overlay), "-json", "-count=1", "./..."]
    probe_exit = run(probe_command, module, scratch / "order-probe-control.json")
    evidence["order_probe_control"] = {"command": probe_command, "exit": probe_exit}
    if probe_exit:
        (scratch / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
        print("untransposed order probes failed; no order mutation evidence")
        return 1
    failed = False
    for name, file, old, new, count, test, witness, diagnostic in PLANTS:
        target = scratch / name
        target.mkdir()  # Refuse reuse of a previous invocation's plant directory.
        text = (module / file).read_text()
        if text.count(old) != count:
            raise ValueError(f"{name}: expected exactly {count} plant sites")
        replacement = target / file
        replacement.write_text(planted_source(name, text, old, new))
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
        retained = []
        if name == "key-order-relaxed":
            # Every non-order invalid canonical vector must still pass under
            # the plant, including whitespace, escapes, duplicates and bounds.
            retained = [f"TestV4CanonicalVectors/canon-i-{i:02d}" for i in range(1, 31) if i not in (4, 5)]
            retained += ["TestV4CanonicalVectors/canon-v-03", "TestV4CanonicalVectors/canon-v-05"]
            killed = killed and all(any(e.get("Action") == "pass" and e.get("Test") == test for e in events)
                                    for test in retained)
        evidence["plants"].append({"name": name, "file": file, "before": old, "after": new,
                                   "command": command, "exit": code, "witness": witness,
                                   "diagnostic": diagnostic, "retained_controls": retained, "killed": killed})
        print(f"{name}: {'killed by ' + witness if killed else 'SURVIVED or unrelated failure'} (exit {code})")
        failed |= not killed
    (scratch / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
