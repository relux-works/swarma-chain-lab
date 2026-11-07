"""Verify exact acquisition bytes and Git/PyPI source equivalence offline."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

BASE = Path(__file__).resolve().parent.parent

def tar_members(path):
    with tarfile.open(path, 'r:gz') as archive:
        result = {}
        for member in archive.getmembers():
            relative = member.name.partition('/')[2]
            if member.isfile() and (relative.startswith('src/') or relative in ('LICENCE', 'pyproject.toml')):
                result[relative] = archive.extractfile(member).read()
        return result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime-paths', action='store_true')
    args = parser.parse_args()
    deps = json.loads(BASE.joinpath('dependencies.json').read_text())
    for entry in deps:
        path = Path('/artifacts/wheels', entry['filename'])
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
            raise SystemExit('dependency SHA256 mismatch: ' + path.name)
        if path.stat().st_size != entry['bytes']:
            raise SystemExit('dependency length mismatch: ' + path.name)
    pins = json.loads(BASE.joinpath('sources.json').read_text())
    for entry in pins['archives']:
        path = Path('/artifacts', entry['filename'])
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
            raise SystemExit('source SHA256 mismatch: ' + path.name)
    git = tar_members('/artifacts/electrumx-2.0.1-git.tar.gz')
    pypi = tar_members('/artifacts/wheels/e_x-2.0.1.tar.gz')
    # sdists add generated metadata under src/*.egg-info; compare exact code set.
    code = lambda d: {k:v for k,v in d.items() if k.endswith('.py') or k in ('LICENCE','pyproject.toml')}
    if code(git) != code(pypi):
        raise SystemExit('Git and PyPI ElectrumX source mismatch')
    if args.runtime_paths:
        for entry in deps:
            if entry['role'] == 'runtime' and entry['filename'].endswith('.whl'):
                print(Path('/artifacts/wheels', entry['filename']))
    else:
        print(json.dumps({'dependencies_verified': len(deps), 'git_pypi_source_files_equal': len(code(git)), 'source_archives_verified': len(pins['archives'])}))

if __name__ == '__main__':
    main()
