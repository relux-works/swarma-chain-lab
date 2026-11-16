#!/usr/bin/env python3
"""Require named tests to detect enumeration and signer-role guard removal.

The unchanged test_all_good must still pass in the disposable mutant. Setup
errors, crashes, timeouts and unrelated failures do not count as detection.
"""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve().parent
    before = (source / 'verify-release.sh').read_text()
    controls = [
        ('release-directory-enumeration-removed', 'RELEASE_DIRECTORY_CHECK',
         'test_extra_file', 'exact release directory membership'),
        ('signer-role-separation-removed', 'SIGNER_ROLE_SEPARATION',
         'test_merged_signer_roles', 'actual signature key role disjointness'),
    ]
    rows = []
    all_killed = True
    for label, marker, negative, claim in controls:
        control = work / label
        control.mkdir()
        for name in ('verify-release.sh', 'test-verify-release.py'):
            shutil.copy2(source / name, control / name)
        start = '# BEGIN ' + marker + '\n'
        end = '# END ' + marker + '\n'
        assert before.count(start) == before.count(end) == 1, 'control not applied exactly once'
        first = before.index(start)
        last = before.index(end, first) + len(end)
        (control / 'verify-release.sh').write_text(before[:first] + before[last:])
        results = {}
        for name in ('test_all_good', negative):
            command = [sys.executable, '-B', str(control / 'test-verify-release.py'),
                       'ReleaseVerification.' + name]
            with (control / (name + '.log')).open('w') as log:
                process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
                (control / (name + '.pid')).write_text(str(process.pid) + '\n')
                try:
                    code = process.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise RuntimeError('control timeout') from None
            results[name] = (code, (control / (name + '.log')).read_text())
        code, output = results[negative]
        killed = (results['test_all_good'][0] == 0 and code == 1
                  and 'FAIL: ' + negative + ' (' in output
                  and 'AssertionError: 0 != 1' in output
                  and 'FAILED (failures=1)' in output)
        all_killed = all_killed and killed
        rows.append('| ' + label + ' | ' + claim + ' | '
                    + ('ReleaseVerification.' + negative if killed else 'none')
                    + ' | ' + ('Killed; mutant exit 1; positive exit 0; no survivors'
                               if killed else 'SURVIVOR: no demonstrated ' + claim) + ' |\n')
    report = ('| Mutant | Narrows gate to | Named failing test | Result / surviving bound |\n'
              '| --- | --- | --- | --- |\n' + ''.join(rows))
    (work / 'mutation-results.md').write_text(report)
    print(report, end='')
    return 0 if all_killed else 1


if __name__ == '__main__':
    sys.exit(main())
