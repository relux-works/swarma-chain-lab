#!/usr/bin/env python3
"""Run the vectors CI gate in isolated sibling-module copies, with drift controls.

--plant-drift plants a single ASCII byte before the ordinary gate: the gate
must then fail. Normal runs prove both detectors reject that same plant and
return to green after restoring the owned copy.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def plant(path):
    original = path.read_bytes()
    data = json.loads(original)
    row = next(r for r in data['vectors'] if r['id'] == 'arithmetic-0')
    before = row['output']['payload_id']
    after = ('1' if before[0] == '0' else '0') + before[1:]
    needle = ('"payload_id": "' + before + '"').encode()
    replacement = ('"payload_id": "' + after + '"').encode()
    # Locate the arithmetic row specifically; other operations share this hash.
    offset = original.index(b'"id": "arithmetic-0"')
    prefix, tail = original[:offset], original[offset:]
    changed = prefix + tail.replace(needle, replacement, 1)
    if len(original) != len(changed) or sum(a != b for a, b in zip(original, changed)) != 1:
        raise ValueError('plant must change exactly one byte')
    path.write_bytes(changed)
    return original


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--plant-drift', action='store_true')
    args = parser.parse_args()
    parent = args.scratch.resolve()
    parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='v.', dir=parent)).resolve()
    results = []
    try:
        source = Path(__file__).resolve().parents[2]
        work = root / 'work'
        for name in ('wire', 'vectors'):
            shutil.copytree(source / name, work / name, ignore=shutil.ignore_patterns('__pycache__', '.temp'))
        env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOFLAGS='')
        for name, relative in {'HOME':'h', 'USERPROFILE':'h', 'XDG_CONFIG_HOME':'cfg',
                               'XDG_CACHE_HOME':'c', 'GOCACHE':'gc', 'GOMODCACHE':'gm',
                               'GOPATH':'gp', 'TMPDIR':'t', 'TMP':'t', 'TEMP':'t'}.items():
            directory = root / relative
            directory.mkdir(exist_ok=True)
            env[name] = str(directory)
        env.pop('GOTELEMETRYDIR', None)
        vectors = work / 'vectors'
        checker = vectors / 'scripts/check-vectors.py'

        def run(label, argv, expected=0, witness=None):
            proc = subprocess.run(argv, cwd=vectors, env=env, text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            (parent / (label + '.log')).write_text(proc.stdout)
            results.append({'command': argv, 'label': label, 'exit_code': proc.returncode,
                            'expected_exit_code': expected})
            print(f'{label}: exit {proc.returncode} (expected {expected})', flush=True)
            if proc.returncode != expected or (witness and witness not in proc.stdout):
                print(proc.stdout, file=sys.stderr)
                raise RuntimeError(label)

        run('download', ['go', 'mod', 'download'])
        run('verify', ['go', 'mod', 'verify'])
        env['GOPROXY'] = 'off'
        formatted = subprocess.run(['gofmt', '-l', *map(str, sorted(vectors.rglob('*.go')))],
                                   cwd=vectors, env=env, text=True, capture_output=True)
        results.append({'label':'format', 'exit_code': formatted.returncode,
                        'unformatted': formatted.stdout.splitlines()})
        if formatted.returncode or formatted.stdout:
            raise RuntimeError('format')
        if args.plant_drift:
            plant(vectors / 'vectors.json')
        run('vet', ['go', 'vet', './...'])
        run('test', ['go', 'test', '-count=1', './...'])
        run('build', ['go', 'build', './...'])
        run('python', [sys.executable, '-I', str(checker)])
        run('checker-tests', [sys.executable, '-I', str(vectors / 'scripts/test-check-vectors.py')])
        original = plant(vectors / 'vectors.json')
        run('plant-go', ['go', 'test', '-run', '^TestVectorsDrift$', '-count=1', './...'],
            expected=1, witness='first differing vector arithmetic-0')
        run('plant-python', [sys.executable, '-I', str(checker)], expected=1,
            witness='FINDING arithmetic-0')
        (vectors / 'vectors.json').write_bytes(original)
        run('restore-go', ['go', 'test', '-run', '^TestVectorsDrift$', '-count=1', './...'])
        run('restore-python', [sys.executable, '-I', str(checker)])
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f'vectors CI gate failed: {exc}', file=sys.stderr)
        return 1
    finally:
        (parent / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
        # Go module caches are read-only. Remove only this invocation's root.
        for path in root.rglob('*'):
            if path.is_dir():
                path.chmod(path.stat().st_mode | 0o700)
        shutil.rmtree(root)


if __name__ == '__main__':
    raise SystemExit(main())
