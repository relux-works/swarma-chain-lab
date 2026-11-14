#!/usr/bin/env python3
"""Resolve grantcheck outside the checkout and require the real Core capacity test.

The positive consumes grantcheck's own single-use requirement. The negative
excludes that exact single-use version and pins the pre-budget snapshot, without
replaces. Only the missing bounded-writer API is an accepted negative witness.
Proxy selection is explicit; a file proxy is local artifact evidence, not proof
that unpublished commits are available from the public Go proxy.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

PREFIX = 'github.com/relux-works/swarma-chain-lab/experiments/'
GRANTCHECK, SINGLE_USE = PREFIX + 'grantcheck', PREFIX + 'single-use'
TEST = 'TestCoreProvisioning/CombinedCapacity'


def boundary_passed(output):
    events = []
    for line in output.splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    passed = any(e.get('Test') == TEST and e.get('Action') == 'pass' for e in events)
    skipped = any(e.get('Action') in ('skip', 'fail') for e in events)
    sizes = [int(n) for n in re.findall(r'max_state_bytes=(\d+)', output)]
    return passed and not skipped and bool(sizes) and max(sizes) > 65536


def bounded_api_witness(output):
    # The old dependency must fail for the changed API, not setup/RPC/permission
    # errors. Go emits these specific diagnostics before any Core process starts.
    decoded = []
    for line in output.splitlines():
        try:
            decoded.append(json.loads(line).get('Output', ''))
        except (json.JSONDecodeError, AttributeError):
            decoded.append(line + '\n')
    diagnostics = re.findall(r'[^\n]*\.go:\d+:\d+: ([^\n]+)', ''.join(decoded))
    return bool(diagnostics) and all(
        re.fullmatch(r's\.WriteBounded undefined \(type \*durable\.Store has no field or method WriteBounded\)', d)
        or re.fullmatch(r'undefined: durable\.MaxWriteBytes', d)
        for d in diagnostics) and any('WriteBounded' in d for d in diagnostics)


def graph_valid(items, grantcheck, single_use):
    selected = {item['Path']: item for item in items}
    return (not any(item.get('Replace') for item in items)
            and selected.get(GRANTCHECK, {}).get('Version') == grantcheck
            and selected.get(SINGLE_USE, {}).get('Version') == single_use)


def objects(raw):
    decoder = json.JSONDecoder()
    while raw.strip():
        item, end = decoder.raw_decode(raw.lstrip())
        raw = raw.lstrip()[end:]
        yield item


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--grantcheck', required=True)
    parser.add_argument('--single-use', required=True)
    parser.add_argument('--old-single-use', required=True)
    parser.add_argument('--scratch-parent', type=Path, required=True)
    parser.add_argument('--proxy', default='https://proxy.golang.org')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    parent = args.scratch_parent.resolve(strict=True)
    if parent == repo or repo in parent.parents or args.single_use == args.old_single_use:
        parser.error('use an external scratch parent and distinct dependency versions')
    go = shutil.which('go')
    if not go:
        parser.error('go is unavailable')
    root = Path(tempfile.mkdtemp(prefix='capacity-', dir=parent))
    env = {key: os.environ[key] for key in ('PATH', 'CG1_CORE_DAEMON', 'CG1_CORE_CLI') if key in os.environ}
    env.update(GOTOOLCHAIN='local', GOWORK='off', GOENV='off', GOFLAGS='-p=2',
               GOPROXY=args.proxy, GOSUMDB='sum.golang.org', GONOSUMDB=PREFIX + '*',
               GOMAXPROCS='2', CG1_REGTEST='1', GORACE='atexit_sleep_ms=0')
    for key, name in [('HOME', 'home'), ('GOCACHE', 'build'), ('GOMODCACHE', 'modules'),
                      ('GOPATH', 'gopath'), ('TMPDIR', 'tmp')]:
        (root / name).mkdir()
        env[key] = str(root / name)
    results = []
    for name in ('positive', 'old-writer-witness'):
        case = root / name
        case.mkdir()
        old = name != 'positive'
        manifest = f'module example.invalid/published-capacity\n\ngo 1.26.0\n\nrequire {GRANTCHECK} {args.grantcheck}\n'
        if old:
            manifest += f'require {SINGLE_USE} {args.old_single_use}\nexclude {SINGLE_USE} {args.single_use}\n'
        (case / 'go.mod').write_text(manifest)
        selected = args.old_single_use if old else args.single_use
        for label, command in [('graph', [go, 'list', '-mod=mod', '-m', '-json', 'all']),
                               ('regression', [go, 'test', '-mod=mod', '-race', '-p', '1', '-count=1',
                                               '-timeout', '15m', '-json', '-run', '^TestCoreProvisioning$/^CombinedCapacity$', GRANTCHECK])]:
            case_env = dict(env, CG1_RUN_ROOT=str(root / ('nodes-' + name)))
            with (case / (label + '.log')).open('w') as out, (case / (label + '.stderr')).open('w') as err:
                process = subprocess.Popen(command, cwd=case, env=case_env, stdout=out, stderr=err)
                (case / (label + '.pid')).write_text(str(process.pid) + '\n')
                code = process.wait()
            output = (case / (label + '.log')).read_text()
            stderr = (case / (label + '.stderr')).read_text()
            if label == 'graph':
                valid = code == 0 and graph_valid(list(objects(output)), args.grantcheck, selected)
            else:
                valid = (code != 0 and bounded_api_witness(output + stderr)) if old else (code == 0 and boundary_passed(output))
            record = dict(case=name, gate=label, command=command, pid=process.pid, exit=code,
                          valid=valid, selected_single_use=selected, proxy=args.proxy)
            results.append(record)
            (root / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
            print(json.dumps(record), flush=True)
            if not valid:
                print('EVIDENCE ' + str(root), flush=True)
                return 1
    print('PublishedGrantcheckCombinedCapacity: positive and specific old-writer witness verified')
    print('EVIDENCE ' + str(root))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
