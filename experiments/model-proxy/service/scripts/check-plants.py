#!/usr/bin/env python3
"""Bounded source overlays: require the named behavioral assertion to fail."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

MODULE = Path(__file__).resolve().parents[1]


def run(out, label, args):
    load = Path('/proc/loadavg').read_text()
    (out / (label + '-load.log')).write_text(load)
    if float(load.split()[0]) >= 10:
        raise RuntimeError('load gate blocked')
    proc = subprocess.Popen(args, cwd=MODULE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=os.environ.copy())
    stdout, stderr = proc.communicate()
    (out / (label + '-process.json')).write_text(json.dumps({'argv': args, 'cwd': str(MODULE), 'pid': proc.pid, 'exit': proc.returncode}, indent=2) + '\n')
    (out / (label + '.log')).write_bytes(stdout + stderr)
    events = []
    for line in stdout.splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            pass
    return proc.returncode, events


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise RuntimeError('plant did not apply exactly once')
    return source.replace(before, after, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    out = Path(args.out)
    if not out.is_absolute() or out.exists():
        raise RuntimeError('output must be a new absolute directory')
    out.mkdir(parents=True)
    adapter = MODULE / 'adapter_linux.go'
    client = MODULE / 'client_linux.go'
    unit = MODULE / 'unit_linux.go'
    source_api = MODULE / 'source_linux.go'
    original = {p: p.read_text() for p in (adapter, client, unit, source_api)}
    source = original[adapter]
    start = source.index('\tid, e := OperationID()\n')
    end = source.index('\tfail := func(', start)
    block = source[start:end]
    ordered = source[:start] + source[end:]
    point = ordered.index('\tif e = guard.Validate(ctx, m, op, "intake")')
    early_material = ordered[:point] + block + ordered[point:]
    plants = [
        ('material-before-admission', adapter, early_material,
         'TestPrepareRefusalsBeforeMaterial', 'TestPrepareRefusalsBeforeMaterial/intake',
         'No lease acquisition before intake, scan and dequeue acceptance.'),
        ('placeholder-instead-of-material', adapter,
         replace_once(source, '"Bearer "+string(l.value)', '"Bearer "+"placeholder-current"'),
         'TestPrepareOrderingAndMapping', 'TestPrepareOrderingAndMapping',
         'The qualified slot maps to the leased value, not the placeholder.'),
        ('unchecked-broker-uid', client,
         replace_once(original[client], 'uid != cfg.BrokerUID', 'uid != uid'),
         'TestIdentityAndRole', 'TestIdentityAndRole/server-uid',
         'Kernel broker UID is verified before hello.'),
        ('ordinary-refusal-closes-all', client,
         replace_once(original[client], 'err := refusal(r.Code)',
                      'c.invalidate()\n\t\terr := refusal(r.Code)'),
         'TestRefusalScope', 'TestRefusalScope/request-lease_unbound',
         'An ordinary refusal preserves unrelated leases and the connection epoch.'),
        ('dot-generation-admitted', unit,
         replace_once(original[unit], '!generationName.MatchString(in.Generation)',
                      '!valid(in.Generation)'),
         'TestInstallTemplateRefusals', 'TestInstallTemplateRefusals/dot-generation',
         'Listener generations cannot collapse to the parent directory.'),
        ('source-rejects-broker-label', source_api,
         replace_once(original[source_api], '!validCaller(caller)',
                      '!valid(caller.Account) || !valid(caller.Generation) || !valid(caller.LaunchID)'),
         'TestSourceLifecycle', 'TestSourceLifecycle',
         'Source accepts the pinned broker slash-label control.'),
        ('opaque-classification-error', adapter,
         replace_once(source, 'op, body, e := adapter.Classify(in)\n\tif e != nil {\n\t\treturn nil, nil, sanitized(e)',
                      'op, body, e := adapter.Classify(in)\n\tif e != nil {\n\t\treturn nil, nil, e'),
         'TestPrepareErrorSanitization', 'TestPrepareErrorSanitization/classify',
         'Adapter errors cross only the closed diagnostic seam.'),
        ('unchecked-hello-generation', client,
         replace_once(original[client], 'h.Principal.Generation != cfg.Generation', 'false'),
         'TestIdentityAndRole', 'TestIdentityAndRole/generation',
         'Hello must match the protected service generation.'),
    ]
    report = []
    code, _ = run(out, 'baseline', ['go', 'test', '-json', '-count=1', './...'])
    report.append({'plant': 'baseline', 'exit': code})
    if code:
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        raise RuntimeError('baseline failed')
    for name, path, mutated, test, witness, claim in plants:
        fixture = out / (name + '.go')
        fixture.write_text(mutated)
        overlay = out / (name + '.json')
        overlay.write_text(json.dumps({'Replace': {str(path): str(fixture)}}))
        code, events = run(out, name, ['go', 'test', '-vet=off', '-json', '-count=1',
                                      '-overlay=' + str(overlay), '-run=^' + test + '$', '.'])
        killed = code == 1 and any(e.get('Action') == 'fail' and e.get('Test') == witness for e in events)
        report.append({'plant': name, 'claim': claim, 'test': witness, 'exit': code,
                       'killed': killed,
                       'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        if not killed:
            (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
            raise RuntimeError('plant survived or failed outside its named test')
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    if any(p.read_text() != s for p, s in original.items()):
        raise RuntimeError('source changed during plants')
    print('baseline passed; all ' + str(len(plants)) + ' named plants killed')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
