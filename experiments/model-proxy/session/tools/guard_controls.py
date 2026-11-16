#!/usr/bin/env python3
"""Copied-tree Reveal accessor controls; run with -I and owned output/work dirs.

The positive control pins 14 carriers and the unchanged 17 plain-Reveal sites
(23 calls), plus an empty RevealForOpen set. Each negative requires its exact
accessor, source-owner-call witness, count, and inventory-refusal diagnostic.
Only synthetic call sites are planted; candidate source is never edited.
"""
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
DIAGNOSTIC = 'credential storage/reveal inventory changed; re-audit required'


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    require(sys.flags.isolated and len(sys.argv) == 3,
            'usage: python3 -I session/tools/guard_controls.py <output> <empty-work-dir>')
    out, fixture = (Path(p).resolve() for p in sys.argv[1:])
    out.mkdir(parents=True, exist_ok=True)
    require(not fixture.exists(), 'fixture path must not exist')
    shutil.copytree(ROOT, fixture, ignore=shutil.ignore_patterns('.git', '.temp', '.tmp', '__pycache__'))
    rows = []

    def run(name):
        command = ['go', 'run', '.scripts/check-credential-output-boundaries.go']
        with (out / (name + '.log')).open('w') as log:
            process = subprocess.Popen(command, cwd=fixture, stdout=log, stderr=subprocess.STDOUT)
            rows.append(dict(control=name, command=command, cwd=str(fixture), pid=process.pid))
            (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            try:
                code = process.wait(timeout=180)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=15)
                rows[-1]['exit'] = 124
                (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                raise AssertionError(name + ': timed out; control is unverified')
        rows[-1]['exit'] = code
        text = (out / (name + '.log')).read_text()
        inventory = json.loads(next(line for line in text.splitlines() if line.startswith('{')))
        return code, text, inventory

    code, _, inventory = run('positive')
    require(code == 0, 'positive tree must pass')
    require(len(inventory['carrier_fields']) == 14, 'positive carrier count')
    require(set(inventory['explicit_reveals']) == {'Reveal', 'RevealForOpen'}, 'positive accessor set')
    rows_inventory_fields = inventory['carrier_fields']
    plain = inventory['explicit_reveals']['Reveal']
    require(len(plain) == 17 and sum(plain.values()) == 23, 'plain Reveal counts changed')
    require(inventory['explicit_reveals']['RevealForOpen'] == {}, 'RevealForOpen must have no callers')
    rows[-1]['witness'] = '14 carriers; Reveal 17 sites/23 calls; RevealForOpen empty'

    controls = [
        ('reveal-for-open', 'experiments/model-proxy/session/custody_control.go',
         'package session\nfunc custodyControl(t Token) { _ = t.RevealForOpen() }\n',
         'RevealForOpen', 'experiments/model-proxy/session/custody_control.go:custodyControl:t.RevealForOpen()'),
        ('new-reveal-method', 'experiments/model-proxy/session/custody_control.go',
         'package session\nfunc (t Token) RevealX() [32]byte { return [32]byte(t) }\nfunc custodyControl(t Token) { _ = t.RevealX() }\n',
         'RevealX', 'experiments/model-proxy/session/custody_control.go:custodyControl:t.RevealX()'),
        ('plain-reveal', 'experiments/model-proxy/custody_control.go',
         'package proxy\nfunc custodyControl(c Config) { _ = c.APIKey.Reveal() }\n',
         'Reveal', 'experiments/model-proxy/custody_control.go:custodyControl:c.APIKey.Reveal()'),
    ]
    for name, relative, plant, accessor, witness in controls:
        path = fixture / relative
        path.write_text(plant)
        try:
            code, text, inventory = run(name)
            require(code == 1 and DIAGNOSTIC in text, name + ': intended inventory refusal required')
            require(inventory['reveals'][accessor].get(witness) == 1, name + ': exact call witness required')
            require(inventory['fields'] == rows_inventory_fields, name + ': unrelated carrier drift')
            rows[-1]['witness'] = witness
        finally:
            path.unlink()
    (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    for row in rows:
        print(f"{row['control']}: expected exit={row['exit']} witness={row['witness']}")


if __name__ == '__main__':
    main()
