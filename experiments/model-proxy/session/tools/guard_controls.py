#!/usr/bin/env python3
"""Exact-inventory and copied-tree controls for the credential source guard.

Run with -I, owned output/fixture paths and optional legacy Go guard sources.
Each refusal must exit 1, print the inventory diagnostic, and match the entire
expected inventory delta. Source witnesses contain synthetic expressions only.
"""
import copy
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
DIAGNOSTIC = 'credential storage/reveal inventory changed; re-audit required'


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    require(sys.flags.isolated and len(sys.argv) >= 3,
            'usage: python3 -I experiments/model-proxy/session/tools/guard_controls.py <output> <new-fixture> [legacy-guard.go ...]')
    out, fixture = (Path(p).resolve() for p in sys.argv[1:3])
    out.mkdir(parents=True, exist_ok=True)
    require(not fixture.exists(), 'fixture must not exist')
    shutil.copytree(ROOT, fixture, ignore=shutil.ignore_patterns('.git', '.temp', '.tmp', '__pycache__'))
    expected = json.loads((ROOT / '.scripts/credential-output-inventory.json').read_text())
    rows = []

    def run(name, command):
        with (out / (name + '.log')).open('w') as log:
            p = subprocess.Popen(command, cwd=fixture, stdout=log, stderr=subprocess.STDOUT)
            row = dict(control=name, command=command, cwd=str(fixture), pid=p.pid)
            rows.append(row)
            (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
            try:
                code = p.wait(timeout=180)
            except subprocess.TimeoutExpired:
                p.terminate()
                p.wait(timeout=15)
                row['exit'] = 124
                (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
                raise AssertionError(name + ': timed out; unverified')
        row['exit'] = code
        text = (out / (name + '.log')).read_text()
        (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
        return code, text

    def inventory(text):
        return json.loads(next(line for line in text.splitlines() if line.startswith('{')))

    candidate = fixture.parent / 'credential-guard'
    code, _ = run('build-candidate', ['go', 'build', '-o', str(candidate), '.scripts/check-credential-output-boundaries.go'])
    require(code == 0, 'candidate guard must compile')
    code, text = run('positive', [str(candidate)])
    positive = inventory(text)
    require(code == 0, 'positive tree must pass')
    require({key: positive[key] for key in expected} == expected, 'exact listed positive inventory')
    require(len(expected['carrier_fields']) == 14, 'carrier count')
    require(set(expected['explicit_reveals']) == {'Reveal', 'RevealForOpen'}, 'accessor keys')
    require(len(expected['explicit_reveals']['Reveal']) == 53 and
            sum(expected['explicit_reveals']['Reveal'].values()) == 67, 'call counts')
    require(expected['explicit_reveals']['RevealForOpen'] == {}, 'no production opening reveal')
    rows[-1]['witness'] = expected

    # Each control changes precisely the named field/accessor/site; matching the
    # full delta proves no unrelated carrier drift or doubled direct-call count.
    session = 'experiments/model-proxy/session/custody_control.go'
    proxy = 'experiments/model-proxy/custody_control.go'
    controls = []

    def reveal(name, path, plant, accessor, owner, expression, legacy=False):
        controls.append(dict(name=name, path=path, plant=plant, accessor=accessor,
                             witness=path + ':' + owner + ':' + expression, legacy=legacy))

    reveal('reveal-for-open', session, 'package session\nfunc custodyControl(t Token) { _ = t.RevealForOpen() }\n',
           'RevealForOpen', 'custodyControl', 't.RevealForOpen()')
    reveal('new-reveal-method', session,
           'package session\nfunc (t Token) RevealX() [32]byte { return [32]byte(t) }\nfunc custodyControl(t Token) { _ = t.RevealX() }\n',
           'RevealX', 'custodyControl', 't.RevealX()')
    reveal('plain-reveal', proxy, 'package proxy\nfunc custodyControl(c Config) { _ = c.APIKey.Reveal() }\n',
           'Reveal', 'custodyControl', 'c.APIKey.Reveal()', legacy=True)
    reveal('package-var', session, 'package session\nvar leaked = Token{}.RevealForOpen()\n',
           'RevealForOpen', 'var', 'Token{}.RevealForOpen()')
    reveal('package-func-literal', session, 'package session\nvar f = func(t Token) { _ = t.RevealForOpen() }\n',
           'RevealForOpen', 'var', 't.RevealForOpen()')
    reveal('method-value', session, 'package session\nfunc custodyControl(t Token) { g := t.RevealForOpen; _ = g() }\n',
           'RevealForOpen', 'custodyControl', 't.RevealForOpen')
    reveal('plain-method-value-any-receiver', proxy,
           'package proxy\nfunc custodyControl(t Other) { g := t.Reveal; _ = g() }\n',
           'Reveal', 'custodyControl', 't.Reveal')
    reveal('method-expression-value', session, 'package session\nfunc custodyControl() { g := Token.RevealForOpen; _ = g }\n',
           'RevealForOpen', 'custodyControl', 'Token.RevealForOpen')
    reveal('method-expression', session, 'package session\nfunc custodyControl(t Token) { _ = Token.RevealForOpen(t) }\n',
           'RevealForOpen', 'custodyControl', 'Token.RevealForOpen(t)')
    reveal('tagged-source', session, '//go:build ignore\n\npackage session\nfunc custodyControl(t Token) { _ = t.RevealForOpen() }\n',
           'RevealForOpen', 'custodyControl', 't.RevealForOpen()')
    for name, expr in [('trackb-keyword', 'c.TrackBToken.Reveal()'), ('token-keyword', 'c.Token.Reveal()')]:
        reveal(name, proxy, 'package proxy\nfunc custodyControl(c Other) { _ = ' + expr + ' }\n',
               'Reveal', 'custodyControl', expr, legacy=True)
    reveal('go-txt', 'experiments/m5-rehearsal/fixtures/custody_control.go.txt',
           'package fixtures\nfunc custodyControl(c Other) { _ = c.APIKey.Reveal() }\n',
           'Reveal', 'custodyControl', 'c.APIKey.Reveal()', legacy=True)
    for name, path, plant, accessor in [
        ('unused-carrier-method', session, 'package session\nfunc (t Token) RevealX() {}\n', 'RevealX'),
        ('unused-noncarrier-method', 'experiments/single-use/payloadbootstrap/codec/custody_control.go',
         'package codec\nfunc (s Secret[T]) RevealBytes() []byte { return nil }\n', 'RevealBytes'),
    ]:
        controls.append(dict(name=name, path=path, plant=plant, accessor=accessor,
                             witness=None, legacy=False))
    for name, plant, owner in [
        ('extra-carrier', 'package proxy\ntype CustodyControl struct { APIKey string }\n', 'CustodyControl'),
        ('package-anonymous-carrier', 'package proxy\nvar holder = struct { Token string }{}\n', 'var'),
    ]:
        field = 'APIKey' if name == 'extra-carrier' else 'Token'
        controls.append(dict(name=name, path=proxy, plant=plant,
                             field=proxy + ':' + owner + '.' + field, value='string',
                             legacy=name == 'extra-carrier'))
    controls.append(dict(name='nested-carrier', path=proxy,
                         plant='package proxy\ntype CustodyControl struct { Nested struct { APIKey string } }\n',
                         field=proxy + ':CustodyControl.APIKey', value='string', legacy=True))
    types = 'experiments/model-proxy/types.go'
    raw = (fixture / types).read_text()
    replaced, count = re.subn(r'(\bAPIKey\s+)UpstreamKey\b', r'\1string', raw)
    require(count == 1, 'raw field control anchor')
    controls.append(dict(name='raw-retained-field', path=types, plant=replaced,
                         field=types + ':Config.APIKey', value='string', legacy=True))
    registry = 'experiments/model-proxy/registry.go'
    raw = (fixture / registry).read_text()
    for name, before, after, witness, delta in [
        ('approved-scope', 'static := len(c.APIKey.Reveal()) > 0',
         '_ = unrelated.Reveal()\n\tstatic := len(c.APIKey.Reveal()) > 0', 'unrelated.Reveal()', 1),
        ('call-multiplicity', 'static := len(c.APIKey.Reveal()) > 0',
         '_ = c.APIKey.Reveal()\n\tstatic := len(c.APIKey.Reveal()) > 0', 'c.APIKey.Reveal()', 1),
        ('missing-call', 'static := len(c.APIKey.Reveal()) > 0',
         'static := false', 'c.APIKey.Reveal()', -1),
    ]:
        require(raw.count(before) == 1, name + ': anchor')
        controls.append(dict(name=name, path=registry, plant=raw.replace(before, after),
                             accessor='Reveal', witness=registry + ':newService:' + witness,
                             delta=delta, legacy=True))

    def check_control(control, executable, baseline, prefix=''):
        path = fixture / control['path']
        original = path.read_bytes() if path.exists() else None
        path.write_text(control['plant'])
        want = copy.deepcopy(baseline)
        if 'field' in control:
            want['carrier_fields'][control['field']] = control['value']
            witness = control['field'] + '=' + control['value']
        else:
            sites = want['explicit_reveals'].setdefault(control['accessor'], {})
            key = control['witness']
            if key is not None:
                sites[key] = sites.get(key, 0) + control.get('delta', 1)
            witness = {control['accessor']: sites if key is None else {key: sites[key]}}
        try:
            code, text = run(prefix + control['name'], [str(executable)])
            require(code == 1 and DIAGNOSTIC in text, control['name'] + ': exact inventory refusal required')
            got = inventory(text)
            actual = got['reveals']
            if actual and all(isinstance(value, int) for value in actual.values()):
                actual = {'Reveal': actual}
            require(dict(carrier_fields=got['fields'], explicit_reveals=actual) == want,
                    control['name'] + ': exact whole-inventory witness required')
            rows[-1]['witness'] = witness
            print(prefix + control['name'] + ': exit=1 exact witness=' + json.dumps(witness, sort_keys=True))
        finally:
            if original is None:
                path.unlink()
            else:
                path.write_bytes(original)

    for control in controls:
        check_control(control, candidate, expected)

    # Excluded test files and name-free conversions/reflection remain accepted;
    # this documents the detector's boundary, not the safety of those operations.
    excluded = fixture / session.replace('.go', '_test.go')
    excluded.write_text('package session\nvar leaked = Token{}.RevealForOpen()\n')
    limit = fixture / session
    limit.write_text('package session\nfunc limits(t Token) { _ = [32]byte(t); _ = t[:]; _ = reflect.ValueOf(t).MethodByName("RevealForOpen") }\n')
    try:
        code, text = run('explicit-limits', [str(candidate)])
        require(code == 0 and inventory(text) == positive, 'explicit limits must leave inventory unchanged')
    finally:
        excluded.unlink()
        limit.unlink()

    for i, source in enumerate(sys.argv[3:]):
        executable = fixture.parent / ('legacy-guard-' + str(i))
        prefix = 'legacy-' + str(i) + '-'
        code, _ = run(prefix + 'build', ['go', 'build', '-o', str(executable), str(Path(source).resolve())])
        require(code == 0, 'legacy guard must compile')
        code, text = run(prefix + 'positive', [str(executable)])
        require(code == 0, 'legacy positive')
        old = inventory(text)
        old_reveals = old['explicit_reveals']
        if old_reveals and all(isinstance(value, int) for value in old_reveals.values()):
            old_reveals = {'Reveal': old_reveals}
        baseline = dict(carrier_fields=old['carrier_fields'], explicit_reveals=old_reveals)
        require(baseline['carrier_fields'] == expected['carrier_fields'], 'carrier inventory unchanged')
        for accessor, sites in old_reveals.items():
            require(accessor in expected['explicit_reveals'], 'legacy accessor retained')
            require(all(expected['explicit_reveals'][accessor].get(k) == v for k, v in sites.items()),
                    'all legacy sites and multiplicities unchanged')
        require(len(old_reveals['Reveal']) == 17 and sum(old_reveals['Reveal'].values()) == 23,
                'legacy 17-site/23-call set')
        for control in controls:
            # Landed main retains prefix calls and carrier declarations too.
            if control['legacy'] or ('RevealForOpen' in old_reveals and
                                     control['name'] in {'reveal-for-open', 'new-reveal-method', 'unused-carrier-method', 'method-expression', 'tagged-source'}):
                check_control(control, executable, baseline, prefix)
        rows[-1]['legacy_positive_inventory'] = baseline
    (out / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    print('positive: exit=0; exact 14 carriers; Reveal 53 sites/67 calls; RevealForOpen {}; all controls passed')


if __name__ == '__main__':
    main()
