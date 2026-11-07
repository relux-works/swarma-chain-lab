#!/usr/bin/env python3
"""Public-input verifier in an independent offline namespace, no credentials."""
import json
import os
import sys
import resource
import gc
from pathlib import Path
from protocol import PipeRPC, verify

os.umask(0o077)
# Bound this process independently of the enclosing admitted controller.
resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))
for name in ('/private/home', '/private/tmp', '/private/cache'):
    Path(name).mkdir(mode=0o700, exist_ok=True)
    assert Path(name).stat().st_mode & 0o777 == 0o700
assert not Path('/lab').exists() and not Path('/runtime').exists()
assert not list(Path('/home').iterdir()) and 'SSH_AUTH_SOCK' not in os.environ
environment = {'HOME', 'TMPDIR', 'XDG_CACHE_HOME', 'PATH', 'LC_ALL', 'PYTHONDONTWRITEBYTECODE', 'PWD'}
assert set(os.environ) <= environment, sorted(os.environ)
assert os.environ.get('PWD', '/private') == '/private'
assert {k: os.environ.get(k) for k in ('HOME', 'TMPDIR', 'XDG_CACHE_HOME')} == {
    'HOME': '/private/home', 'TMPDIR': '/private/tmp', 'XDG_CACHE_HOME': '/private/cache'}
descriptors = {}
for entry in Path('/proc/self/fd').iterdir():
    try:
        target = os.readlink(entry)
    except FileNotFoundError:  # closed directory enumeration descriptor
        continue
    descriptors[int(entry.name)] = 'pipe' if target.startswith('pipe:[') else target
assert set(descriptors) == {0, 1, 2}
assert descriptors[0] == descriptors[1] == 'pipe'
assert descriptors[2] in ('pipe', '/dev/null')
assert not {'mainnet', 'mainnet_t1', 'lab', 'verifier_process'} & set(sys.modules)
source_files = sorted(p.name for p in Path('/src').iterdir())
assert source_files == ['pipe_verify.py', 'protocol.py']
forbidden_objects = sorted({type(obj).__name__ for obj in gc.get_objects()
                           if type(obj).__name__ in ('Collector', 'Capability', 'SyntheticSigner')})
assert not forbidden_objects
process_boundary = {'pid': os.getpid(), 'fds': descriptors,
    'environment_keys': sorted(os.environ), 'foreign_home_empty': True,
    'collector_signer_broadcaster_gate_modules_present': False,
    'source_files': source_files, 'forbidden_capability_object_types': forbidden_objects,
    'pid_namespace': os.readlink('/proc/self/ns/pid'),
    'net_namespace': os.readlink('/proc/self/ns/net')}
local_denials = []
for method in ('signmessage', 'sendrawtransaction', 'getnewaddress', 'createwallet', 'stop'):
    try:
        PipeRPC('regtest').call(method)
    except ValueError:
        local_denials.append(method)
    else:
        raise RuntimeError('read-only transport guard failed')
try:
    raw = sys.stdin.buffer.readline(262145)
    if len(raw) > 262144:
        raise ValueError('input bound')
    obj = json.loads(raw)
    result = verify(PipeRPC(obj['network']), obj['fixture'], obj['request'], obj['signature'],
                    obj['pins']['issuer'], obj['pins']['grantee'])
except (ValueError, TypeError, KeyError, OSError):
    result = {'decision': 'refuse', 'reason': 'MALFORMED_INPUT'}
result['isolation'] = {'wallet_mount': False, 'node_mount': False, 'credentials_present': False,
                       'network': 'unshare-all; no interface to full node except restricted stdio pipe',
                       'home_tmp_cache_mode': '0700'}
result['read_only_methods_rejected_before_pipe'] = local_denials
result['process_boundary'] = process_boundary
print(json.dumps({'type': 'decision', 'result': result}), flush=True)
raise SystemExit(0 if result['decision'] == 'admit' else 1)
