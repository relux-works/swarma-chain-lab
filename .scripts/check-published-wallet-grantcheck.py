#!/usr/bin/env python3
"""Check r4/r5 against the wallet's external module graph, without replacements.

An external test package supplies identical public-API Core tests to both
checker snapshots. Production source comes from the resolved module ZIP. The
historical selection must fail the named behavioral assertion, not compilation,
setup, a skip, or an absent test. A file proxy qualifies local ZIPs only; it does
not attest that unpublished commits are available from the public proxy.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

PREFIX = 'github.com/relux-works/swarma-chain-lab/experiments/'
WALLET, CHECKER = PREFIX + 'agent-wallet', PREFIX + 'grantcheck'
CASES = (
    ('r4-final-sample', 'TestPublishedFinalSampleFreshness',
     '^TestPublishedFinalSampleFreshness$', 'published final-sample stale admitted'),
    ('r5-atomic-commit', 'TestPublishedAggregateAtomic',
     '^TestPublishedAggregateAtomic$', 'published aggregate wrote before final acceptance'),
)


def behavior_verified(output, test, negative, witness):
    events = [json.loads(line) for line in output.splitlines() if line.strip()]
    actions = [e.get('Action') for e in events if e.get('Test') == test]
    text = ''.join(e.get('Output', '') for e in events)
    return (actions.count('run') == 1
            and actions.count('fail' if negative else 'pass') == 1
            and not any(e.get('Action') == 'skip' for e in events)
            and (not negative or witness in text))


def objects(raw):
    decoder = json.JSONDecoder()
    while raw.strip():
        value, end = decoder.raw_decode(raw.lstrip())
        raw = raw.lstrip()[end:]
        yield value


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--wallet', required=True)
    p.add_argument('--grantcheck', required=True)
    p.add_argument('--single-use', required=True)
    p.add_argument('--old-grantcheck', required=True)
    p.add_argument('--scratch-parent', type=Path, required=True)
    p.add_argument('--proxy', default='https://proxy.golang.org')
    args = p.parse_args()
    repo = Path(__file__).resolve().parents[1]
    parent = args.scratch_parent.resolve(strict=True)
    if parent == repo or repo in parent.parents or args.grantcheck == args.old_grantcheck:
        p.error('external scratch parent and distinct checker versions required')
    root = Path(tempfile.mkdtemp(prefix='wallet-checker-', dir=parent))
    go = shutil.which('go')
    env = {k: os.environ[k] for k in ('PATH', 'CG1_CORE_DAEMON', 'CG1_CORE_CLI') if k in os.environ}
    env.update(GOTOOLCHAIN='local', GOWORK='off', GOENV='off', GOFLAGS='-p=2',
               GOPROXY=args.proxy, GOSUMDB='sum.golang.org', GONOSUMDB=PREFIX + '*',
               GOMAXPROCS='2', CG1_REGTEST='1', GORACE='atexit_sleep_ms=0')
    for key, name in [('HOME', 'home'), ('GOCACHE', 'build'), ('GOMODCACHE', 'modules'),
                      ('GOPATH', 'gopath'), ('TMPDIR', 'tmp')]:
        (root / name).mkdir()
        env[key] = str(root / name)
    records = []

    def run(case, label, command, changes=None):
        with (case / (label + '.log')).open('w') as out, (case / (label + '.stderr')).open('w') as err:
            proc = subprocess.Popen(command, cwd=case, env=dict(env, **(changes or {})), stdout=out, stderr=err)
            (case / (label + '.pid')).write_text(str(proc.pid) + '\n')
            code = proc.wait()
        record = dict(case=case.name, gate=label, command=command, pid=proc.pid, exit=code)
        records.append(record)
        (root / 'results.json').write_text(json.dumps(records, indent=2) + '\n')
        print(json.dumps(record), flush=True)
        return code, (case / (label + '.log')).read_text()

    print('EVIDENCE ' + str(root), flush=True)
    for negative in (False, True):
        case = root / ('old-wallet-selection' if negative else 'wallet-selection')
        case.mkdir()
        module = CHECKER if negative else WALLET
        version = args.old_grantcheck if negative else args.wallet
        (case / 'go.mod').write_text(f'module example.invalid/wallet-checker\n\ngo 1.26.0\n\nrequire {module} {version}\n')
        code, raw = run(case, 'graph', [go, 'list', '-mod=mod', '-m', '-json', 'all'])
        if code:
            return 1
        graph = list(objects(raw))
        selected = {m['Path']: m for m in graph}
        expected = args.old_grantcheck if negative else args.grantcheck
        if (any(m.get('Replace') for m in graph) or selected[CHECKER]['Version'] != expected
                or (not negative and selected[PREFIX + 'single-use']['Version'] != args.single_use)):
            raise RuntimeError('unexpected graph or replacement')
        # Reuse laboratory helpers only. The fixture terms helper's final
        # private cachedGrant helper is excluded; all exercised APIs are public.
        helpers = repo / 'experiments/grantcheck'
        (case / 'core_helpers_test.go').write_text(
            (helpers / 'core_helpers_test.go').read_text().replace('package grantcheck', 'package published', 1))
        terms = (helpers / 'fixture_helpers_test.go').read_text().split('func cachedBytes(', 1)[0]
        terms = terms.replace('package grantcheck', 'package published', 1).replace(
            'import (', 'import (\n . "' + CHECKER + '"', 1)
        (case / 'fixture_helpers_test.go').write_text(terms)
        shutil.copyfile(repo / '.scripts/testdata/published_wallet_grantcheck_test.go',
                        case / 'published_test.go')
        for label, test, pattern, witness in CASES:
            code, output = run(case, label,
                [go, 'test', '-mod=mod', '-race', '-p', '1',
                 '-count=1', '-timeout=10m', '-json', '-run', pattern, '.'],
                {'CG1_RUN_ROOT': str(root / ('nodes-' + case.name + '-' + label))})
            valid = code == (1 if negative else 0) and behavior_verified(output, test, negative, witness)
            records[-1]['valid'] = valid
            (root / 'results.json').write_text(json.dumps(records, indent=2) + '\n')
            if not valid:
                return 1
    print('PublishedWalletR4R5: positive and named historical behavioral witnesses verified')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
