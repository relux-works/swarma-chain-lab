#!/usr/bin/env python3
"""Run grantcheck policy-removal controls on genuine Core using Go overlays.

A kill requires exit 1 and the named verdict assertion; setup failures, skips,
build errors and unrelated failures do not count. Source is never modified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'experiments/grantcheck'
CG = 'experiments/grantcheck/checker.go'
FRESH = 'experiments/grantcheck/freshness.go'
GRANT = 'experiments/rental/grant_kernel.go'
PLANTS = [
    ('aggregate-final-freshness', 'TestCoreFinalSampleFreshness/Transport2/OutboundFromAggregate/OverA1ns', 'experiments/grantcheck/sender.go',
     'if code := observation.node.freshAt(sample); code != CodeLive {',
     'if code := observation.node.freshAt(sample); false {',
     'every aggregate observation must satisfy the complete freshness rule at the final precise sample'),
    ('aggregate-last-only', 'TestCoreAggregateEveryObservation/Transport2/OverA1ns', 'experiments/grantcheck/sender.go',
     'for _, observation := range observations {',
     'for _, observation := range observations[len(observations)-1:] {',
     'checking only the newest recipient cannot cover an earlier stale observation'),
    ('single-final-freshness', 'TestCoreFinalSampleFreshness/Transport2/Provision/OverA1ns', CG,
     'if code := c.node.freshAt(lastTime); code != CodeLive {',
     'if code := c.node.freshAt(lastTime); false {',
     'the common inbound/outbound/provision final sample must refuse stale state before cache or audit persistence'),
    ('executor', 'TestCoreFreshness/ExecutorPin', CG,
     'if pay.ExecutorKey != c.config.ExecutorKey {',
     'if false && pay.ExecutorKey != c.config.ExecutorKey {',
     'canonical hash-bound executor must equal the consumer pin before state changes'),
    ('headers', 'TestCoreFreshness/HeadersEqualBlocks', FRESH,
     'if info.IBD || info.Headers != info.Blocks {', 'if info.IBD {',
     'both headers-ahead and headers-behind observations refuse as not-synced'),
    ('age', 'TestCoreFreshness/FrozenOldView', FRESH,
     'if n.tipTime.Before(now.Add(-n.policy.MaxTipAge)) {', 'if false {',
     'consistent old Core observations refuse at A+1 even above the floor'),
    ('future', 'TestCoreFreshness/FutureSkew', FRESH,
     'if n.tipTime.After(now.Add(*n.policy.MaxFutureSkew)) {', 'if false {',
     'actual Core tips at F+1 and two hours ahead refuse non-retryably'),
    ('floor', 'TestCoreFreshness/HeightFloor', FRESH,
     'if info.Blocks < *n.policy.MinimumHeight {', 'if false {',
     'an otherwise live view below the configured minimum height refuses'),
    ('provision-hash', 'TestCoreProvisioning/UncommittedHash', GRANT,
     'if returns != 1 || matches != 1 {', 'if false && (returns != 1 || matches != 1) {',
     'a canonical signed grant hash must match its on-chain issuance commitment'),
    ('combined-budget', 'TestCombinedStateBudget', 'experiments/grantcheck/cache.go',
     ' || len(raw) > maxStateBytes', '',
     'complete encoded state must be refused before writer failure can poison the checker',
     'combined overflow was not a non-poisoning preflight refusal'),
    ('cancellation', 'TestCoreProvisioning/FinalSampleCancellation/Sample3', CG,
     'if ctx.Err() != nil {', 'if false && ctx.Err() != nil {',
     'cancellation during the final clock callback must preserve cache and audit'),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--private-root', type=Path, required=True)
    args = parser.parse_args()
    if not args.private_root.is_absolute():
        parser.error('--private-root must be absolute')
    out = args.out.resolve()
    out.mkdir(mode=0o700)
    args.private_root.mkdir(mode=0o700)
    go = shutil.which('go')
    if not go:
        parser.error('go unavailable')
    records = []
    for plant in PLANTS:
        name, test, relative, old, new, bound, *marker = plant
        assertion = marker[0] if marker else 'verdict contract want '

        source = ROOT / relative
        original = source.read_text()
        matches = original.count(old)
        # The cancellation control removes the overlapping wrapper checks as a
        # group; removing just one is deliberately covered by the other guards.
        if matches != (9 if name == 'cancellation' else 1):
            raise RuntimeError(f'{name}: unexpected guard count {matches}')
        case = out / name
        case.mkdir(mode=0o700)
        mutant = case / source.name
        mutant.write_text(original.replace(old, new, matches))
        overlay = case / 'overlay.json'
        overlay.write_text(json.dumps({'Replace': {str(source): str(mutant)}}) + '\n')
        record = {'mutant': name, 'test': test, 'bound': bound, 'source': relative,
                  'source_sha256': hashlib.sha256(original.encode()).hexdigest(),
                  'mutant_sha256': hashlib.sha256(mutant.read_bytes()).hexdigest()}
        for mutated in (False, True):
            label = 'mutant' if mutated else 'baseline'
            selector = '/'.join('^' + part + '$' for part in test.split('/'))
            command = [go, 'test', '-race', '-count=1', '-timeout=3m', '-json',
                       '-run=' + selector, '.']
            if mutated:
                command.insert(2, '-overlay=' + str(overlay))
            env = dict(os.environ, CG1_REGTEST='1', GOTOOLCHAIN='local', GOWORK='off',
                       CG1_RUN_ROOT=str(args.private_root / (name + '-' + label)))
            with (case / (label + '.json')).open('w') as stdout, (case / (label + '.stderr')).open('w') as stderr:
                proc = subprocess.Popen(command, cwd=MODULE, env=env, stdout=stdout, stderr=stderr)
                pid = proc.pid
                code = proc.wait()
            events = [json.loads(line) for line in (case / (label + '.json')).read_text().splitlines()]
            actions = [e.get('Action') for e in events if e.get('Test') == test]
            output = ''.join(e.get('Output', '') for e in events if e.get('Test') == test)
            invalid = any(e.get('Action') in ('skip', 'build-fail') for e in events)
            failures = [e.get('Test') for e in events if e.get('Action') == 'fail' and e.get('Test')]
            unrelated = any(t != test and not test.startswith(t + '/') for t in failures)
            ok = code == 0 and actions.count('run') == 1 and actions.count('pass') == 1 and not invalid
            if mutated:
                ok = (code == 1 and actions.count('run') == 1 and actions.count('fail') == 1
                      and assertion in output and not invalid and not unrelated)
            record[label + '_run'] = {'pid': pid, 'command': command, 'exit': code,
                             'actions': actions, 'intended_result': ok}
            print(f'{name} {label}: exit={code} intended={ok} {test}', flush=True)
            if not ok:
                record['verdict'] = 'SURVIVED_OR_INVALID'
                records.append(record)
                (out / 'results.json').write_text(json.dumps(records, indent=2) + '\n')
                return 1
        record['verdict'] = 'KILLED'
        records.append(record)
        (out / 'results.json').write_text(json.dumps(records, indent=2) + '\n')
    print(f'GRANTCHECK_POLICY_GUARDS: {len(PLANTS)}/{len(PLANTS)} KILLED', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
