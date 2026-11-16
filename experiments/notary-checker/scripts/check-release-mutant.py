#!/usr/bin/env python3
"""Require test_extra_file to detect removal of release-directory enumeration.

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
    for name in ('verify-release.sh', 'test-verify-release.py'):
        shutil.copy2(source / name, work / name)
    script = work / 'verify-release.sh'
    before = script.read_text()
    start = '# BEGIN RELEASE_DIRECTORY_CHECK\n'
    end = '# END RELEASE_DIRECTORY_CHECK\n'
    assert before.count(start) == before.count(end) == 1, 'control not applied exactly once'
    first = before.index(start)
    last = before.index(end, first) + len(end)
    script.write_text(before[:first] + before[last:])
    results = {}
    for name in ('test_all_good', 'test_extra_file'):
        command = [sys.executable, '-B', str(work / 'test-verify-release.py'),
                   'ReleaseVerification.' + name]
        with (work / (name + '.log')).open('w') as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            (work / (name + '.pid')).write_text(str(process.pid) + '\n')
            try:
                code = process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise RuntimeError('control timeout') from None
        results[name] = (code, (work / (name + '.log')).read_text())
    code, output = results['test_extra_file']
    killed = (results['test_all_good'][0] == 0 and code == 1
              and 'FAIL: test_extra_file (' in output
              and 'AssertionError: 0 != 1' in output
              and 'FAILED (failures=1)' in output)
    report = ('| Mutant | Narrows gate to | Named failing test | Result / surviving bound |\n'
              '| --- | --- | --- | --- |\n'
              '| release-directory-enumeration-removed | exact release directory membership | '
              + ('ReleaseVerification.test_extra_file' if killed else 'none')
              + ' | ' + ('Killed; mutant exit 1; positive exit 0; no survivors'
                         if killed else 'SURVIVOR: no demonstrated membership rejection') + ' |\n')
    (work / 'mutation-results.md').write_text(report)
    print(report, end='')
    return 0 if killed else 1


if __name__ == '__main__':
    sys.exit(main())
