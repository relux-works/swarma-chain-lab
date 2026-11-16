#!/usr/bin/env python3
"""Require named tests to detect enumeration, role and tag-header guard removal.

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

    def remove_block(marker):
        start = '# BEGIN ' + marker + '\n'
        end = '# END ' + marker + '\n'
        assert before.count(start) == before.count(end) == 1, 'control not applied exactly once'
        first = before.index(start)
        last = before.index(end, first) + len(end)
        return before[:first] + before[last:]

    def replace_once(old, new):
        assert before.count(old) == 1, 'control not applied exactly once'
        return before.replace(old, new, 1)

    # Each negative must fail by verdict acceptance, beside a passing valid control.
    controls = [
        ('release-directory-enumeration-removed', remove_block('RELEASE_DIRECTORY_CHECK'),
         'test_extra_file', 'exact release directory membership'),
        ('signer-role-separation-removed', remove_block('SIGNER_ROLE_SEPARATION'),
         'test_merged_signer_roles', 'actual signature key role disjointness'),
        ('manifest-key-in-tag-role-removed', remove_block('MANIFEST_KEY_IN_TAG_ROLE'),
         'test_manifest_key_in_tag_role', 'manifest key absent from tag trust'),
        ('tag-key-in-manifest-role-removed', remove_block('TAG_KEY_IN_MANIFEST_ROLE'),
         'test_tag_key_in_manifest_role', 'tag key absent from manifest trust'),
        ('duplicate-tag-membership-accepted',
         replace_once('if names != [sys.argv[2].encode()]:',
                      'if sys.argv[2].encode() not in names:'),
         'test_duplicate_tag_headers', 'exactly one byte-exact tag name'),
        ('duplicate-object-count-removed',
         replace_once('len(objects) != 1', 'not objects'),
         'test_duplicate_object_headers', 'exactly one signed object header'),
        ('duplicate-type-membership-accepted',
         replace_once("types != [b'commit']", "b'commit' not in types"),
         'test_duplicate_type_headers', 'exactly one signed type header'),
        ('direct-commit-type-removed',
         replace_once(" or types != [b'commit']", ''),
         'test_signed_non_commit_type', 'exactly one signed commit type'),
    ]
    rows = []
    all_killed = True
    for label, mutated, negative, claim in controls:
        control = work / label
        control.mkdir()
        for name in ('verify-release.sh', 'test-verify-release.py'):
            shutil.copy2(source / name, control / name)
        (control / 'verify-release.sh').write_text(mutated)
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
            (control / (name + '.exit')).write_text(str(code) + '\n')
            results[name] = (code, (control / (name + '.log')).read_text())
        code, output = results[negative]
        killed = (results['test_all_good'][0] == 0 and code == 1
                  and 'FAIL: ' + negative + ' (' in output
                  and 'AssertionError: 0 != 1' in output
                  and 'FAILED (failures=' in output
                  and '\nERROR:' not in output and 'Traceback (most recent call last):' in output)
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
