"""Check installed direct/transitive requirements in the private runtime."""
from importlib import metadata
from pathlib import Path
import json
import sys
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

base = Path(__file__).resolve().parent.parent
lock = json.loads((base / 'dependencies.json').read_text())
expected = {canonicalize_name(x['name']): x['version'] for x in lock if x['role'] == 'runtime'}
expected['e-x'] = '2.0.1'
for name, version in expected.items():
    actual = metadata.version(name)
    assert actual == version, (name, actual, version)
    dist = metadata.distribution(name)
    for text in dist.requires or []:
        requirement = Requirement(text)
        # The server explicitly requests aiorpcx[ws]. Other extras are absent.
        extra = 'ws' if name == 'aiorpcx' else ''
        if requirement.marker and not requirement.marker.evaluate({'extra': extra}):
            continue
        dep = canonicalize_name(requirement.name)
        assert dep in expected, (name, 'unlocked transitive dependency', dep)
        assert expected[dep] in requirement.specifier, (name, text, expected[dep])
print(json.dumps({'runtime_distributions_verified': len(expected), 'requires_dist_satisfied': True, 'python': sys.version}))
