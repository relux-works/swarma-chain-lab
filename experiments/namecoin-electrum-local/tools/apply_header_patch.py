"""Apply only the exact local patch to an exact, freshly extracted upstream tree."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
BASE = Path(__file__).resolve().parent.parent

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_absolute():
        raise SystemExit('one absolute private build-source directory is required')
    tree = Path(sys.argv[1]).resolve(strict=True)
    pin = json.loads((BASE / 'local-patch.json').read_text())
    patch = BASE / pin['patch_file']
    source = tree / pin['source_file']
    if digest(patch) != pin['patch_sha256']:
        raise SystemExit('local patch SHA256 mismatch')
    if digest(source) != pin['original_source_sha256']:
        raise SystemExit('unpatched upstream source SHA256 mismatch')
    subprocess.run(['patch','--fuzz=0','--batch','-p1','-i',str(patch)],cwd=tree,check=True)
    if digest(source) != pin['patched_source_sha256']:
        raise SystemExit('patched source SHA256 mismatch')
    print(json.dumps({'upstream_commit':pin['upstream_commit'],
                      'local_patch_sha256':pin['patch_sha256'],
                      'patched_source_sha256':pin['patched_source_sha256']}))

if __name__ == '__main__':
    main()
