"""Original public stdio broker for a separately isolated verifier process.

The admitted host controller implements the existing runner.py verify/rpc/
rpc_result/verdict protocol and execs pipe_verify.py in a sibling offline bwrap.
No verifier runs in this process. Only public JSON crosses its restricted pipe;
the read callback and all Collector references remain on this side of exec.
"""
import json
import math
import os
import select
import sys
import time
from decimal import Decimal

from protocol import READ_METHODS, canon

MAX_LINE = 8 * 1024 * 1024


def _readline(deadline):
    data = bytearray()
    fd = sys.stdin.fileno()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise ValueError('VERIFIER_PIPE_DEADLINE')
        byte = os.read(fd, 1)
        if not byte:
            raise ValueError('VERIFIER_PIPE_CLOSED')
        if byte == b'\n':
            return json.loads(data)
        data.extend(byte)
        if len(data) > MAX_LINE:
            raise ValueError('VERIFIER_PIPE_BYTES')


def _send(value, deadline):
    def public_number(item):
        if isinstance(item, Decimal) and item.is_finite():
            return str(item)
        raise TypeError('non-JSON public value')
    data = json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, default=public_number).encode() + b'\n'
    if len(data) > MAX_LINE:
        raise ValueError('VERIFIER_REPLY_BYTES')
    fd = sys.stdout.fileno()
    os.set_blocking(fd, False)
    try:
        while data:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
                raise ValueError('VERIFIER_PIPE_DEADLINE')
            try:
                count = os.write(fd, data)
            except BlockingIOError:
                continue
            data = data[count:]
    finally:
        os.set_blocking(fd, True)


def _dispatch(item, read):
    if (set(item) != {'type', 'method', 'params'} or item['type'] != 'rpc'
            or item['method'] not in READ_METHODS or type(item['params']) is not list):
        raise ValueError('VERIFIER_READ_METHOD_DENIED')
    try:
        return {'type': 'rpc_result', 'result': read(item['method'], *item['params'])}
    except Exception:
        # Preserve the original pipe's refusal semantics; transport exception
        # text is never serialized. The caller rechecks immutable bounds.
        return {'type': 'rpc_result', 'error': 'unavailable'}


def verify_public(public, read, *, timeout_s):
    if (type(timeout_s) not in (int, float) or not math.isfinite(timeout_s)
            or not 0 < timeout_s <= 21600):
        raise ValueError('VERIFIER_TIME_BOUND')
    if type(public) is not dict or set(public) != {'network', 'fixture', 'request', 'signature', 'pins'}:
        raise ValueError('VERIFIER_PUBLIC_SCHEMA')
    raw = canon(public)  # no pickle, executable serializer or object references
    if len(raw) + 1 > 262144:
        raise ValueError('VERIFIER_PUBLIC_BYTES')
    deadline = time.monotonic() + timeout_s
    _send({'type': 'verify', 'input': json.loads(raw)}, deadline)
    for _ in range(2101):
        item = _readline(deadline)
        if item.get('type') == 'verdict':
            result = item['result']
            if (set(item) != {'type', 'result', 'exit'} or
                    result.get('decision') not in ('admit', 'refuse') or
                    item['exit'] != (0 if result['decision'] == 'admit' else 1)):
                raise ValueError('VERIFIER_EXIT_MISMATCH')
            return result
        _send(_dispatch(item, read), deadline)
    raise ValueError('VERIFIER_REQUEST_BOUND')
