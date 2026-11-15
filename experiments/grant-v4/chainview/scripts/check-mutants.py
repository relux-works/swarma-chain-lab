#!/usr/bin/env python3
"""Narrowing overlays for three draft LIP-0022 decision defects.

Each plant must fail a named test with exit 1 after the unchanged control passes.
A compiler/setup failure, unrelated failure, skip or missing test is not a kill.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

MODULE = Path(__file__).resolve().parents[1]
MUTANTS = [
    ('minimum-depth', 'depth.go', [('max(signedMinimum, operatorFloor)', 'min(signedMinimum, operatorFloor)')], 'TestV4DepthMaximum'),
    ('clock-rollback', 'clock.go', [('if in.Now < state.KeptMark {', 'if false {'), ('now < keptMark ||', 'false ||')], 'TestV4ClockRollback'),
    ('lower-finding', 'order.go', [('for _, candidate := range refusalOrder {\n\t\tfor _, code := range findings {',
                                 'for i := len(refusalOrder) - 1; i >= 0; i-- {\n\t\tcandidate := refusalOrder[i]\n\t\tfor _, code := range findings {')], 'TestV4FirstRefusal'),
]


def run(command, cwd, logfile, env):
    with logfile.open('w') as output:
        child = subprocess.Popen(command, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT)
        pid = child.pid
        code = child.wait()
    return {'command': command, 'pid': pid, 'exit': code, 'log': logfile.name}


def test_result(log, name, passing):
    events = []
    for line in log.read_text().splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            return False
    action = 'pass' if passing else 'fail'
    return (any(e.get('Action') == action and e.get('Test') == name for e in events)
            and not any(e.get('Action') == 'skip' for e in events)
            and not any(e.get('Action') == 'fail' and e.get('Test') not in (None, name) for e in events))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch', required=True, type=Path)
    args = parser.parse_args()
    scratch = args.scratch.resolve()
    scratch.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOPROXY='off', GOSUMDB='off')
    evidence = []
    for name, filename, replacements, test in MUTANTS:
        baseline_log = scratch / (name + '-baseline.json')
        baseline = run(['go', 'test', '-count=1', '-json', '-run', '^' + test + '$', '.'], MODULE, baseline_log, env)
        if baseline['exit'] != 0 or not test_result(baseline_log, test, True):
            print(f'{name}: baseline did not pass {test}', file=sys.stderr)
            return 1
        original = MODULE / filename
        text = original.read_text()
        for old, new in replacements:
            if text.count(old) != 1:
                print(f'{name}: plant not applied exactly once', file=sys.stderr)
                return 1
            text = text.replace(old, new)
        changed = scratch / (name + '.go')
        changed.write_text(text)
        overlay = scratch / (name + '-overlay.json')
        overlay.write_text(json.dumps({'Replace': {str(original): str(changed)}}))
        logfile = scratch / (name + '-test.json')
        mutant = run(['go', 'test', '-overlay', str(overlay), '-count=1', '-json', '-run', '^' + test + '$', '.'], MODULE, logfile, env)
        killed = mutant['exit'] == 1 and test_result(logfile, test, False)
        evidence.append({'mutant': name, 'test': test, 'baseline': baseline, 'plant': mutant, 'killed': killed})
        (scratch / 'results.json').write_text(json.dumps(evidence, indent=2) + '\n')
        print(f'{name}: baseline exit {baseline["exit"]}; mutant exit {mutant["exit"]}; {test}; killed={killed}')
        if not killed:
            return 1
    # Calibrate the independent reader against a fabricated passing S+1 result.
    # The same pinned vector and all other Go results remain unchanged.
    result_path = scratch / 'go-results.json'
    go_env = dict(env, CHAINVIEW_VECTOR_RESULTS=str(result_path))
    base = run(['go', 'test', '-count=1', '-json', '-run', '^TestV4ObservationVectors$', '.'], MODULE, scratch / 'vectors-control.json', go_env)
    if base['exit'] != 0:
        return 1
    checker = MODULE / 'scripts/check-vectors.py'
    valid = run([sys.executable, '-B', str(checker), '--go-results', str(result_path)], MODULE, scratch / 'reader-baseline.log', env)
    results = json.loads(result_path.read_text())
    results['clock-10']['verdict'] = 'ok'
    bad = scratch / 'go-results-incorrect.json'
    bad.write_text(json.dumps(results))
    invalid = run([sys.executable, '-B', str(checker), '--go-results', str(bad)], MODULE, scratch / 'reader-control.log', env)
    detected = valid['exit'] == 0 and invalid['exit'] == 1 and 'clock-10:' in (scratch / 'reader-control.log').read_text()
    (scratch / 'reader-control.json').write_text(json.dumps({'go': base, 'baseline': valid, 'plant': invalid, 'detected': detected}, indent=2) + '\n')
    print(f'second-reader control: baseline exit {valid["exit"]}; wrong S+1 result exit {invalid["exit"]}; detected={detected}')
    return 0 if detected else 1


if __name__ == '__main__':
    raise SystemExit(main())
