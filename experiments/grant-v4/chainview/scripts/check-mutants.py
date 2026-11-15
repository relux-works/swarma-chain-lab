#!/usr/bin/env python3
"""Narrowing overlays for draft decisions and durable store refusals.

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
    ('same-tip-source-collapse', 'health.go', [('independent := n.SourceLabel != reading.SourceLabel', 'independent := n.SourceLabel != reading.SourceLabel && n.Tip != reading.Tip')], 'TestV4NodeSources'),
    ('inclusive-age', 'clock.go', [('if age >= cutoff {', 'if age > cutoff {')], 'TestV4DualTimeAndRisk'),
    ('skip-directory-sync', 'store.go', [('s.perform(kind+".directory-sync", func() error { return syncDirectory(dir) })', 'error(nil)')], 'TestReviewDirectorySyncRetry'),
    ('uncertain-no-op', 'store.go', [('disk, err := s.load()', 'raw, rawErr := readSnapshot(s.path)\n\t\tif rawErr == nil {\n\t\t\tstate := ClockState{*raw.KeptMark, raw.FirstSights}\n\t\t\tnext := cloneState(state)\n\t\t\tif change(&next) == nil && reflect.DeepEqual(state, next) { return nil }\n\t\t}\n\t\tdisk, err := s.load()')], 'TestV4UncertainNoOp'),
    ('skip-sentinel-comparison', 'store.go', [('if snapshot.Generation == sentinel.Generation && *snapshot.KeptMark == *sentinel.KeptMark {', 'if true {')], 'TestReviewRolledBackStoreRefused'),
    ('missing-sentinel-fresh', 'store.go', [('sentinel, err := readSentinel(s.sentinel)\n\tif err != nil {', 'sentinel, err := readSentinel(s.sentinel)\n\tif errors.Is(err, os.ErrNotExist) {\n\t\tsentinel = sentinelState{2, snapshot.Generation, snapshot.KeptMark}\n\t\terr = s.writeSentinel(snapshot.Generation, *snapshot.KeptMark)\n\t}\n\tif err != nil {')], 'TestV4MissingSentinelRefused'),
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
            and not any(e.get('Action') == 'fail' and e.get('Test') not in (None, name)
                        and not e.get('Test', '').startswith(name + '/') for e in events))


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
        if name in ('same-tip-source-collapse', 'inclusive-age'):
            vector_path = scratch / (name + '-vectors.json')
            vector_env = dict(env, CHAINVIEW_VECTOR_RESULTS=str(vector_path))
            vector_log = scratch / (name + '-vector-tests.json')
            vectors = run(['go', 'test', '-overlay', str(overlay), '-count=1', '-json',
                           '-run', '^TestV4ObservationVectors$', '.'], MODULE, vector_log, vector_env)
            reader_log = scratch / (name + '-reader.log')
            reader = run([sys.executable, '-B', str(MODULE / 'scripts/check-vectors.py'),
                          '--go-results', str(vector_path)], MODULE, reader_log, env)
            detected = (vectors['exit'] == 1 and test_result(vector_log, 'TestV4ObservationVectors', False)
                        and reader['exit'] == 1 and 'Go result=' in reader_log.read_text())
            evidence[-1].update(vector_plant=vectors, reader=reader, reader_detected=detected)
            (scratch / 'results.json').write_text(json.dumps(evidence, indent=2) + '\n')
            if not detected:
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
