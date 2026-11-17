#!/usr/bin/env python3
"""Bounded controls for B3a-CHILD. An intended named failure is mandatory.

No source is modified. Go overlays are isolated in --scratch. Full JSON test
streams, exact process exits and a summary are retained. Public-API plants
bound refusals/OPEN preservation; private-template plants do not prove public
acceptance through the unresolved ordinal row.
"""
import argparse
import json
from pathlib import Path
import subprocess

PLANTS = (
    ('accept-everything', 'func CheckChildAttenuationV4(parent, child *SignedGrant) error {',
     'func CheckChildAttenuationV4(parent, child *SignedGrant) error {\n return nil',
     'TestChildV4Prefix', 'TestChildV4Prefix/contract', 'want CHILD_CONTRACT_DIFFERS'),
    ('reject-everything', 'func checkChildTemplateV4(p, c, template *value) error {',
     'func checkChildTemplateV4(p, c, template *value) error {\n return childRefusalV4(14, ChildAgentNotAllowed)',
     'TestChildV4Template', 'TestChildV4Template/template-valid', 'comparison refused valid neighbour'),
    ('public-reject-everything', 'func CheckChildAttenuationV4(parent, child *SignedGrant) error {',
     'func CheckChildAttenuationV4(parent, child *SignedGrant) error {\n return childRefusalV4(13, ChildOrdinal)',
     'TestChildV4Prefix', 'TestChildV4Prefix/prefix-open', 'OPEN must refuse without inventing a protocol code'),
    ('parity-blind-seal', 'if c.get("seal").get("key").text != seal.text {',
     'if childKeyXV4(c.get("seal").get("key").text) != childKeyXV4(seal.text) {',
     'TestChildV4Prefix', 'TestChildV4Prefix/seal-parity', 'want CHILD_SEAL_KEY at F12'),
    ('executor-name-only', 'if !bytes.Equal(serialize(c.get("executor")), serialize(template.get("executor"))) {',
     'if c.get("executor").get("name").text != template.get("executor").get("name").text {',
     'TestChildV4Template', 'TestChildV4Template/executor-key', 'want CHILD_AGENT_NOT_ALLOWED'),
    ('unknown-kind-as-absent', 'if len(c.get("limits").elements) != 0 || len(template.get("limits").elements) != 0 {',
     'if false {', 'TestChildV4Template', 'TestChildV4Template/limit-5', 'want LIMIT_KIND_UNDEFINED'),
    ('missing-key-ignored', 'if !keys[grantLimitKey(limit)] {', 'if false && !keys[grantLimitKey(limit)] {',
     'TestChildV4Template', 'TestChildV4Template/new-key-zero', 'want exact code CHILD_BUDGET_OVER'),
    ('equal-window-rejected', 'grantNumber(c.get("not_before_height")) < grantNumber(p.get("not_before_height"))',
     'grantNumber(c.get("not_before_height")) <= grantNumber(p.get("not_before_height"))',
     'TestChildV4Template', 'TestChildV4Template/window-10-20', 'comparison refused valid neighbour'),
    ('ordinal-equality-rejected', 'ordinal == 0 || ordinal > count', 'ordinal == 0 || ordinal >= count',
     'TestChildV4Ordinal', 'TestChildV4Ordinal/ordinal-2', 'OPEN must refuse without inventing a protocol code'),
    ('ordinal-count-last-range-only', 'count += grantNumber(rng.get("count"))', 'count = grantNumber(rng.get("count"))',
     'TestChildV4Ordinal', 'TestChildV4Ordinal/ordinal-groups-ranges-9', 'OPEN must refuse without inventing a protocol code'),
    ('ordinal-open-bypassed', 'return childOpenV4(13, "ordinal count order:',
     'return nil\n // return childOpenV4(13, "ordinal count order:',
     'TestChildV4Prefix', 'TestChildV4Prefix/prefix-open', 'want OPEN'),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', required=True, type=Path)
    args = parser.parse_args()
    scratch = args.scratch.resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    module = Path(__file__).resolve().parents[1]
    source = module / 'child_v4.go'
    original = source.read_text()
    results = []

    def run(name, command):
        with (scratch / (name+'.json')).open('wb') as log:
            proc = subprocess.Popen(command, cwd=module, stdout=log, stderr=subprocess.STDOUT)
            (scratch / (name+'.pid')).write_text(str(proc.pid))
            code = proc.wait()
        (scratch / (name+'.exit')).write_text(str(code)+'\n')
        return code, (scratch / (name+'.json')).read_text()

    code, _ = run('baseline', ['go', 'test', '-count=1', '-json', '-run', '^TestChildV4', '.'])
    if code != 0:
        raise SystemExit('baseline did not pass: exit '+str(code))
    for name, old, new, group, witness, diagnostic in PLANTS:
        if original.count(old) != 1:
            raise SystemExit('non-unique plant anchor: '+name)
        planted = scratch / (name+'.go')
        planted.write_text(original.replace(old, new))
        overlay = scratch / (name+'-overlay.json')
        overlay.write_text(json.dumps({'Replace': {str(source): str(planted)}}))
        code, output = run(name, ['go', 'test', '-overlay='+str(overlay), '-count=1', '-json', '-run', '^'+group+'$', '.'])
        events = []
        for line in output.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        failed = any(e.get('Action') == 'fail' and e.get('Test') == witness for e in events)
        killed = code == 1 and failed and diagnostic in output
        results.append(dict(plant=name, exit=code, test=witness, diagnostic=diagnostic, killed=killed))
        print(name, 'exit', code, 'killed', killed, flush=True)
    (scratch/'results.json').write_text(json.dumps(results, indent=2)+'\n')
    if not all(r['killed'] for r in results):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
