#!/usr/bin/env python3
"""Require the named refusal test to detect even an attempted refusal signature.

Copies only this module into a new disposable directory; never mutates the
candidate. Compilation errors, crashes, timeouts and unrelated failures fail
this control instead of counting as a kill.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=False)
    source = work / 'source'
    shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns('.temp', '.tmp', '__pycache__'))
    path = source / 'internal/service/service.go'
    before = path.read_text()
    needle = 'if err != nil {\n\t\treturn Response{}, err\n\t}'
    assert before.count(needle) == 1, 'control not applied exactly once'
    after = before.replace(needle, 'if err != nil {\n\t\t_, _ = s.sign(make([]byte, 32))\n\t\treturn Response{}, err\n\t}')
    path.write_text(after)
    command = ['go', 'test', '-count=1', '-run', '^TestRefusalNeverSigns$', './internal/service']
    environment = dict(os.environ, GOPROXY='off', GOSUMDB='off', GOTOOLCHAIN='local')
    process = subprocess.Popen(command, cwd=source, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (work/'mutant.pid').write_text(str(process.pid)+'\n')
    try:
        output = process.communicate(timeout=60)[0].decode(errors='replace')
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise RuntimeError('control timeout') from None
    (work/'mutant.log').write_text(output)
    killed = process.returncode == 1 and '--- FAIL: TestRefusalNeverSigns ' in output and 'GRANT_ENCODING signs=1' in output and 'panic:' not in output and '[build failed]' not in output
    report = ('| Mutant | Narrows gate to | Named failing test | Result / surviving bound |\n'
              '| --- | --- | --- | --- |\n'
              '| signing-on-refusal | no signer invocation after checker refusal | ' + ('TestRefusalNeverSigns' if killed else 'none') + ' | ' + ('killed; exit 1, GRANT_ENCODING signs=1' if killed else 'SURVIVOR: no demonstrated rejection of refusal signing') + ' |\n')
    (work/'mutation-results.md').write_text(report)
    print(report, end='')
    shutil.rmtree(source)
    return 0 if killed else 1


if __name__ == '__main__':
    sys.exit(main())
