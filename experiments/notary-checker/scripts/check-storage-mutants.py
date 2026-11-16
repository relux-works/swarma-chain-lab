#!/usr/bin/env python3
"""Calibrate holder-shape and diagnostic tests against unsafe storage.

Each control must fail BOTH its named shape assertion and its named full
diagnostic test. Panics, compilation errors, timeouts and non-applied edits
are never kills. Only disposable module copies are changed.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def replacement(source, old, new):
    if source.count(old) != 1:
        raise RuntimeError('storage mutation did not apply exactly once')
    return source.replace(old, new)


def mutate(source, name):
    if name.startswith('signing-key-'):
        if name == 'signing-key-struct-pointer':
            source = replacement(source, 'value **btcec.PrivateKey', 'value *btcec.PrivateKey')
            source = replacement(source, 'value: &key', 'value: key')
            return replacement(source, 'return *k.value', 'return k.value')
        source = replacement(source, 'value **btcec.PrivateKey', 'value btcec.PrivateKey')
        source = replacement(source, 'return &signingKey{value: &key}',
                             'if key == nil { return &signingKey{} }; return &signingKey{value: *key}')
        source = replacement(source, 'if k == nil || k.value == nil {', 'if k == nil {')
        return replacement(source, 'return *k.value', 'return &k.value')
    if name == 'password-inline':
        source = replacement(source, 'value *string', 'value string')
        source = replacement(source, 'value: &value', 'value: value')
        return replacement(source, 'if p.value == nil {\n\t\treturn ""\n\t}\n\treturn *p.value', 'return p.value')
    if name == 'password-byte-pointer':
        source = replacement(source, 'value *string', 'value *[]byte')
        source = replacement(source, 'value := string(b)', 'value := append([]byte(nil), b...)')
        return replacement(source, 'return *p.value', 'return string(*p.value)')
    if name == 'password-struct-pointer':
        source = replacement(source, 'value *string', 'value *struct{ text string }')
        source = replacement(source, 'value := string(b)', 'value := struct{ text string }{string(b)}')
        return replacement(source, 'return *p.value', 'return p.value.text')
    raise RuntimeError('unknown mutant')


def service_storage(copy, inline):
    """Restore raw Service storage, adapting only test fixture field access.

    The same shape assertion and diagnostic assertions remain intact. These
    adapters let the real old field type compile, instead of mistaking an API
    mismatch for detection. The *struct row exactly restores the base holder.
    """
    path = copy / 'internal/service/service.go'
    source = path.read_text()
    source = replacement(source, '"github.com/btcsuite/btcd/btcec/v2/schnorr"',
                         '"github.com/btcsuite/btcd/btcec/v2"\n"github.com/btcsuite/btcd/btcec/v2/schnorr"')
    source = replacement(source, 'key          *signingKey',
                         'key          btcec.PrivateKey' if inline else 'key          *btcec.PrivateKey')
    source = replacement(source, 'key: newSigningKey(k)', 'key: *k' if inline else 'key: k')
    source = replacement(source, 'schnorr.Sign(s.key.privateKey(), digest)',
                         'schnorr.Sign(&s.key, digest)' if inline else 'schnorr.Sign(s.key, digest)')
    if inline:
        source = replacement(source, 'if s.key != nil {', 'if !s.key.Key.IsZero() {')
    path.write_text(source)
    path = copy / 'internal/service/signing_key_test.go'
    source = path.read_text()
    assert source.count('key: holder') == 4, 'Service fixture adapter shape changed'
    source = source.replace('key: holder', 'key: *key' if inline else 'key: key')
    source = replacement(source, 'holder := newSigningKey(key)\n\tout :=', 'out :=')
    source = replacement(source, 'loaded.key.privateKey().PubKey()',
                         '(&loaded.key).PubKey()' if inline else 'loaded.key.PubKey()')
    path.write_text(source)
    path = copy / 'internal/service/rev374_test.go'
    source = path.read_text()
    assert source.count('s.key.privateKey().Key') == 2, 'key clearing adapter shape changed'
    path.write_text(source.replace('s.key.privateKey().Key', 's.key.Key'))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--work-dir', type=Path, required=True)
    work = ap.parse_args().work_dir.resolve()
    work.mkdir(parents=True, exist_ok=False)
    rows = []
    cases = [
        ('service-key-inline', None, './internal/service', 'TestSigningKeyStorage', 'TestSigningKeyServiceContainer', 'Service cannot store an inline private scalar'),
        ('service-key-struct-pointer', None, './internal/service', 'TestSigningKeyStorage', 'TestSigningKeyServiceContainer', 'exact base Service *PrivateKey exposure is detected'),
        ('signing-key-inline', 'internal/service/signing_key.go', './internal/service', 'TestSigningKeyStorage', 'TestSigningKeyServiceContainer', 'inline scalar never enters diagnostics'),
        ('signing-key-struct-pointer', 'internal/service/signing_key.go', './internal/service', 'TestSigningKeyStorage', 'TestSigningKeyServiceContainer', 'a pointer to a struct is unsafe under badVerb'),
        ('password-inline', 'password.go', '.', 'TestRPCPasswordStorage', 'TestRPCPasswordDiagnostics', 'inline string never enters diagnostics'),
        ('password-byte-pointer', 'password.go', '.', 'TestRPCPasswordStorage', 'TestRPCPasswordDiagnostics', 'decimal-byte output is detected, not just plaintext'),
        ('password-struct-pointer', 'password.go', '.', 'TestRPCPasswordStorage', 'TestRPCPasswordDiagnostics', 'a pointer to a struct is unsafe under badVerb'),
    ]
    env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOPROXY='off', GOSUMDB='off')
    for name, file, package, shape, diagnostic, bound in cases:
        copy = work / name
        shutil.copytree(ROOT, copy, ignore=shutil.ignore_patterns('.temp', '.tmp', '__pycache__'))
        if file is None:
            service_storage(copy, inline=name == 'service-key-inline')
        else:
            path = copy / file
            path.write_text(mutate(path.read_text(), name))
        command = [env.get('GO', 'go'), 'test', '-count=1', '-timeout', '60s', '-run', '^(' + shape + '|' + diagnostic + ')$', package]
        with (work / (name + '.log')).open('wb') as log:
            proc = subprocess.Popen(command, cwd=copy, env=env, stdout=log, stderr=subprocess.STDOUT)
            (work / (name + '.pid')).write_text(str(proc.pid) + '\n')
            try:
                rc = proc.wait(timeout=90)
            except subprocess.TimeoutExpired:
                proc.kill()  # This script's own exact child only.
                rc = proc.wait()
        out = (work / (name + '.log')).read_text()
        named = all('--- FAIL: ' + test + ' ' in out for test in (shape, diagnostic))
        invalid = any(s in out for s in ('panic:', '[build failed]', '[setup failed]', 'WARNING: DATA RACE', 'diagnostic sink unexpectedly panicked'))
        killed = rc == 1 and named and not invalid
        row = dict(mutant=name, bound=bound, command=command, exit=rc,
                   result='KILLED' if killed else 'SURVIVOR',
                   failing_tests=[shape, diagnostic] if killed else [], invalid_execution=invalid)
        rows.append(row)
        print(name, row['result'], rc, flush=True)
        shutil.rmtree(copy)
    (work / 'results.json').write_text(json.dumps(rows, indent=2) + '\n')
    table = ['| Mutant | Narrows gate to | Named failing tests | Result / surviving bound |', '| --- | --- | --- | --- |']
    for row in rows:
        table.append('| ' + ' | '.join([row['mutant'], row['bound'], ', '.join(row['failing_tests']) or 'none', row['result'] + ('; no established bound' if row['result'] != 'KILLED' else '; exit 1, no panic/build failure')]) + ' |')
    (work / 'mutation-results.md').write_text('\n'.join(table) + '\n')
    killed = sum(r['result'] == 'KILLED' for r in rows)
    print(f'{killed}/{len(rows)} storage controls killed; {len(rows)-killed} survivors')
    return 0 if killed == len(rows) else 1


if __name__ == '__main__':
    raise SystemExit(main())
