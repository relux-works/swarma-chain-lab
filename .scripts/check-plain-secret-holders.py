#!/usr/bin/env python3
"""Calibrate the four plain-secret output tests with isolated Go overlays.

Run from a task-owned checkout with isolated HOME/caches/TMPDIR:
  python3 -I .scripts/check-plain-secret-holders.py OUTPUT NEW_SCRATCH
No node is contacted. Only the requested scratch and output paths are written.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    if not sys.flags.isolated or len(sys.argv) != 3:
        raise SystemExit('usage: python3 -I .scripts/check-plain-secret-holders.py OUTPUT NEW_SCRATCH')
    out, scratch = (Path(p).resolve() for p in sys.argv[1:])
    out.mkdir(parents=True, exist_ok=True)
    scratch.mkdir(parents=True, exist_ok=False)
    rows = []
    cases = [
        ('single-use-password', 'single-use', '.', 'rpc_password.go',
         'func (p RPCPassword) MarshalJSON() ([]byte, error)',
         'return json.Marshal(p.RevealForBasicAuth())', 'TestRPCPasswordHolderRedaction'),
        ('payment-password', 'payment-chain', '.', 'rpc_password.go',
         'func (p RPCPassword) MarshalJSON() ([]byte, error)',
         'return json.Marshal(p.RevealForBasicAuth())', 'TestRPCPasswordHolderRedaction'),
        ('journal-channel-secret', 'rental-gateway', './journal',
         '../single-use/payloadbootstrap/codec/secret.go',
         'func (s Secret[T]) MarshalJSON() ([]byte, error)',
         'return json.Marshal(s.Reveal())', 'TestSlotPrivateHolderRedaction'),
        ('socket-bootstrap', 'station-lifecycle', './slotd', 'slotd/bootstrap.go',
         'func (Bootstrap) MarshalJSON() ([]byte, error)',
         'if b.value == nil { return json.Marshal("") }; return json.Marshal(*b.value)',
         'TestBootstrapHolderRedaction'),
    ]

    def run(name, command, cwd, test, assertion=None):
        log = out / (name + '.log')
        with log.open('w') as stream:
            process = subprocess.Popen(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT)
            row = dict(control=name, command=command, cwd=str(cwd), pid=process.pid,
                       test=test, log=str(log))
            rows.append(row)
            (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            try:
                code = process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=15)
                row['exit'] = 124
                (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                raise AssertionError(name + ': timeout is unverified')
        row['exit'] = code
        (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
        text = log.read_text()
        if assertion is not None:
            # Require the intended disclosure assertion, never a build/setup error.
            row['killed'] = code == 1 and ('--- FAIL: ' + test) in text and assertion in text
            if not row['killed']:
                raise AssertionError(name + ': surviving or unrelated failure')
        elif code != 0:
            raise AssertionError(name + ': baseline refused')
        (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')

    for name, module, package, relative, signature, replacement, test in cases:
        cwd = ROOT / 'experiments' / module
        source = (cwd / relative).resolve()
        raw = source.read_text()
        pattern = re.escape(signature) + r'\s*\{'
        match = re.search(pattern, raw)
        if not match:
            raise AssertionError(name + ': method anchor missing')
        start = match.end()
        end, depth = start, 1
        while depth:
            if raw[end] == '{':
                depth += 1
            elif raw[end] == '}':
                depth -= 1
            end += 1
        mutated = raw[:start] + '\n' + replacement + '\n' + raw[end-1:]
        if name == 'socket-bootstrap':
            mutated = mutated.replace('func (Bootstrap) MarshalJSON()', 'func (b Bootstrap) MarshalJSON()', 1)
        command = ['go', 'test', '-count=1', '-run', '^' + test + '$', package]
        run(name + '-baseline', command, cwd, test)
        # Revert only storage and its mechanical accesses. Keep redacting output
        # methods intact: this calibrates reflection through real fmt containers.
        inline = raw.replace('value *string', 'value string')
        inline = inline.replace('value: &value', 'value: value').replace('value: &copy', 'value: copy')
        for receiver in ('p', 'b', 's'):
            inline = inline.replace(receiver + '.value == nil', receiver + '.value == ""')
            inline = inline.replace(receiver + '.value != nil', receiver + '.value != ""')
            inline = inline.replace('*' + receiver + '.value', receiver + '.value')
        if inline == raw or 'value *string' in inline:
            raise AssertionError(name + ': inline storage anchor missing')
        for kind, content, assertion, bound in (
                ('json', mutated, 'generic JSON disclosed private bytes',
                 'generic JSON credential disclosure'),
                ('inline', inline, 'fmt disclosed private bytes for',
                 'inline scalar storage reflected by fmt through real holders/containers')):
            mutant = scratch / (name + '-' + kind + '.go')
            mutant.write_text(content)
            overlay = scratch / (name + '-' + kind + '.json')
            overlay.write_text(json.dumps({'Replace': {str(source): str(mutant)}}) + '\n')
            run(name + '-' + kind + '-mutant',
                command[:2] + ['-overlay', str(overlay)] + command[2:],
                cwd, test, assertion)
            rows[-1].update(source_sha256=hashlib.sha256(raw.encode()).hexdigest(),
                            mutant_sha256=hashlib.sha256(content.encode()).hexdigest(),
                            assertion=assertion, bound=bound)
            (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    print('four green baselines; four JSON and four inline-storage mutants killed by named output tests')



if __name__ == '__main__':
    main()
