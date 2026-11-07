#!/usr/bin/env python3
"""Public-input verifier in an independent offline namespace, no credentials."""
import json
import os
import sys
from pathlib import Path
from protocol import PipeRPC, verify

os.umask(0o077)
for name in ('/private/home', '/private/tmp', '/private/cache'):
    Path(name).mkdir(mode=0o700, exist_ok=True)
    assert Path(name).stat().st_mode & 0o777 == 0o700
assert not Path('/lab').exists() and not Path('/runtime').exists()
assert not list(Path('/home').iterdir()) and 'SSH_AUTH_SOCK' not in os.environ
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
print(json.dumps({'type': 'decision', 'result': result}), flush=True)
raise SystemExit(0 if result['decision'] == 'admit' else 1)
