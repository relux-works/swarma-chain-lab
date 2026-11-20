#!/usr/bin/env python3
"""Run lab-only source overlays; a compile error is not a killed gate mutant."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True, type=Path)
arguments = parser.parse_args()
if not arguments.output.is_absolute() or arguments.output.exists():
    raise SystemExit("output must be a new absolute task-owned directory")
output = arguments.output.resolve()
output.mkdir(parents=True)
root = Path(__file__).resolve().parents[1]
mutants = [
    ("A02", "duplicate-json-member", "lab_contract_linux.go", "if _, exists := object[name]; exists {", "if _, exists := object[name]; exists && false {", "TestLabBodyDuplicateMembers", "duplicate body fields cannot overwrite earlier values"),
    ("A02", "cache-placement-pinned", "lab_contract_linux.go", 'len(object) < 1 || len(object) > 2 || object["type"] != "ephemeral"', 'len(object) < 1 || len(object) > 2 || object["type"] != "ephemeral" || !reflect.DeepEqual(object, expected)', "TestLabBodyCachePositions", "the cache profile is a multiset, not a placement claim"),
    ("A02", "header-case-control", "lab_contract_linux.go", "lower[index] += 'a' - 'A'", "_ = lower[index]", "TestLabHeaderCatalogue", "ASCII header case controls must remain admitted"),
    ("A02", "body-number-rounding", "lab_contract_linux.go", "parsed, err := actual.Int64()\n\t\t\texpectedNumber, _ := expected.Int64()", "parsed, err := actual.Float64()\n\t\t\texpectedNumber, _ := expected.Float64()", "TestLabBodyNumberAliases", "fixed output bounds cannot use lossy rounding"),
    ("A08", "no-cross-read-retention", "lab_intake_linux.go", "safe := len(pending) - retained", "safe := len(pending)", "TestLabLeakPaths", "a split whole needle must not escape"),
    ("A02", "sse-buffer-until-eof", "lab_intake_linux.go", "safe := len(pending) - retained", "safe := 0", "TestLabSSEIncremental", "safe complete SSE events flush before EOF"),
    ("A09", "no-body-idle-timeout", "lab_intake_linux.go", "time.AfterFunc(gateway.idleTimeout, cancel)", "time.AfterFunc(time.Hour, cancel)", "TestLabReadStall", "stalled bodies retain the independent idle budget"),
    ("A01", "untag-source", "lab_source_linux.go", "linux && gateway_lab", "linux", "TestLabBuildTagIsolation", "lab source must be excluded from default builds"),
    ("A01", "open-object", "lab_contract_linux.go", "len(object) != len(shape.Fields)", "len(object) < len(shape.Fields)", "TestLabFrozenRecordCatalogue", "extra nested fields must refuse"),
    ("A01", "noncanonical-record", "internal/wire/canonical.go", "!bytes.Equal(b, canonical)", "!bytes.Equal(canonical, canonical)", "TestLabFrozenRecordCatalogue", "CCJ framing is byte exact"),
    ("A01", "payload-overflow", "lab_contract_linux.go", "len(raw) <= maximum", "len(raw) <= maximum+1", "TestLabPayloadBoundaries", "preflight rejects the next byte"),
    ("A02", "missing-beta", "lab_contract_linux.go", "len(seen) == len(wanted)", "len(seen) <= len(wanted)", "TestLabFrozenWirePairs", "all eleven flags are required"),
    ("A02", "duplicate-beta-field", "lab_intake_linux.go", "len(values) != 1", "len(values) < 1", "TestLabAPIKeyDuplicateBetaFields", "two beta header fields refuse"),
    ("A02", "oauth-scheme", "lab_intake_linux.go", 'scheme != "api-key"', 'scheme != "api-key" && scheme != "oauth-bearer"', "TestLabAPIKeyForwarding", "OAuth is not an API-key source"),
    ("A02", "extra-body-field", "lab_contract_linux.go", "len(object) != len(expected)", "len(object) < len(expected)", "TestLabFrozenWirePairs", "unobserved body aliases cannot be admitted"),
    ("A02", "policy-key-injection", "lab_intake_linux.go", 'if request.Method == http.MethodPost {\n\t\tout.Header.Set', 'if request.Method == http.MethodPost || request.Method == http.MethodGet {\n\t\tout.Header.Set', "TestLabAPIKeyForwarding", "policy GET must stay credential free"),
    ("A03", "uid-truncation", "lab_source_linux.go", 'gateway["uid"].(int64) > 4294967295 || worker["uid"].(int64) > 4294967295 || ', '', "TestLabPrincipalWidth", "C0 UIDs cannot truncate into kernel UIDs"),
    ("A09", "null-current-sequence", "lab_source_linux.go", 'if result.Verdict != "not_revoked"', 'if result.Sequence == nil { zero := uint64(0); result.Sequence = &zero }\n\tif result.Verdict != "not_revoked"', "TestLabCurrentSequence", "a nullable decoded sequence cannot refresh authority"),
    ("A03", "caller-retarget", "lab_source_linux.go", '!labEqual(record["caller"], pins.worker)', 'false', "TestLabLeaseBounds", "a lease cannot retarget the protected caller"),
    ("A03", "wrong-peer", "lab_intake_linux.go", "!ok || peer.uid != gateway.mapping.Caller.UID", "!ok && peer.uid != gateway.mapping.Caller.UID", "TestLabKernelCallerRefusal", "a kernel UID mismatch cannot lease"),
    ("A07", "selector-mismatch", "lab_source_linux.go", "cfg.MaxLifetime != pins.lifetime", "cfg.MaxLifetime > pins.lifetime", "TestLabCeilingAndPrincipalMismatch", "a lower independent ceiling is still a mismatch"),
    ("A07", "ignore-caller-deadline", "lab_source_linux.go", '"authority_until", "caller_until", "qualification_until", "time_until"', '"authority_until", "qualification_until", "time_until"', "TestLabLeaseBounds", "earliest caller bound remains exclusive"),
    ("A07", "renew-ended", "lab_source_linux.go", 'if oldID != "" {', 'if oldID == "never" {', "TestLabLeaseExpiredRenewal", "ended handles cannot be renewed back into life"),
    ("A07", "half-second-renewal", "lab_source_linux.go", "time.Now().Add(time.Until(until) * 2 / 3)", "time.Now().Add(500 * time.Millisecond)", "TestLabDeadlineRenewal", "long leases must not churn every half-second"),
    ("A08", "new-hold-operation", "lab_source_linux.go", "ctx, cancel := context.WithTimeout(source.recovery, LabRPCTimeout)", 'params["operation_id"], _ = OperationID()\n\t\tctx, cancel := context.WithTimeout(source.recovery, LabRPCTimeout)', "TestLabHoldAckLoss", "lost acknowledgments reconcile the same ID"),
    ("A08", "unknown-hold-success", "lab_source_linux.go", 'record["result"] == "committed"', '(record["result"] == "committed" || record["result"] == "unknown")', "TestLabHoldUnknownResult", "UNKNOWN is never a committed hold"),
    ("A08", "local-only-response", "lab_intake_linux.go", "hold()\n\t\t\treturn ErrInactive", "return ErrInactive", "TestLabLeakPaths", "response matches must enter the hold bridge"),
    ("A09", "one-second-watchdog", "lab_source_linux.go", "const LabWatchdog = 500 * time.Millisecond", "const LabWatchdog = time.Second", "TestLabWatchdogIndependent", "the watchdog cannot share a one-second budget"),
    ("A09", "no-listener-teardown", "lab_source_linux.go", "source.onClose()", "_ = source.onClose", "TestLabPollTeardown", "authority loss retires the listener and streams"),
    ("A09", "broker-left-open", "lab_source_linux.go", "_ = source.client.Close()", "_ = source.client", "TestLabPollTeardown", "the stale broker connection closes too"),
]
results = []
for row, name, source, before, after, test, claim in mutants:
    path = root / source
    original = path.read_text()
    if original.count(before) != 1:
        raise SystemExit(f"{name}: overlay target is not unique")
    planted = output / (name + ".go")
    planted.write_text(original.replace(before, after, 1))
    overlay = output / (name + ".json")
    overlay.write_text(json.dumps({"Replace": {str(path): str(planted)}}))
    environment = os.environ.copy()
    environment["LAB_TEST_OVERLAY"] = str(overlay)
    command = ["go", "test", "-tags", "gateway_lab", "-overlay", str(overlay), "-count=1", "-timeout=45s", "-run", "^" + test + "$", "."]
    log = output / (name + ".log")
    with log.open("w") as handle:
        process = subprocess.Popen(command, cwd=root, env=environment, stdout=handle, stderr=subprocess.STDOUT)
        process.wait()
    text = log.read_text()
    killed = process.returncode != 0 and ("--- FAIL: " + test) in text and "[build failed]" not in text and "panic:" not in text
    results.append({"row": row, "mutant": name, "claim": claim, "test": test, "pid": process.pid, "exit": process.returncode, "killed": killed, "log": str(log), "command": command})
    print(f"{row} {name}: exit={process.returncode} killed={str(killed).lower()}", flush=True)
(output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
sys.exit(0 if all(result["killed"] for result in results) else 1)
