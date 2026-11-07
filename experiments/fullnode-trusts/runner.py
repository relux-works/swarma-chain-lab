#!/usr/bin/env python3
"""Host launch/pipe plumbing only. All protocol code runs inside bwrap.

This controller reads no home, credentials, caches, wallets or node files and
opens no network connection. Inherited environment is NOT given to children.
All children share the enclosing bounded systemd cgroup. Do not run outside the
documented cgroup admission; the controller verifies the actual current limits.
"""
import argparse
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

os.umask(0o077)
SOURCE = Path(__file__).resolve().parent
CHILDREN = []
MAX_LINE = 8 * 1024 * 1024


def cgroup_limits():
    group = next(line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
                 if line.startswith('0::'))
    root = Path('/sys/fs/cgroup') / group.lstrip('/')
    values = {name: (root/name).read_text().strip() for name in
              ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max')}
    assert values['memory.max'] != 'max' and int(values['memory.max']) <= 3221225472
    assert values['memory.swap.max'] == '0'
    assert values['pids.max'] != 'max' and int(values['pids.max']) <= 64
    quota, period = values['cpu.max'].split()
    assert quota != 'max' and int(quota) <= 2 * int(period)
    return values


def resource_stats():
    group = next(line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
                 if line.startswith('0::'))
    root = Path('/sys/fs/cgroup') / group.lstrip('/')
    return {name: (root/name).read_text().strip() for name in
            ('memory.peak', 'memory.events', 'cpu.stat', 'pids.current')}


def sandbox(kind, core=None, deadline=None, network=None):
    args = ['/usr/bin/bwrap', '--unshare-all', '--clearenv', '--new-session',
            '--die-with-parent', '--cap-drop', 'ALL', '--ro-bind', '/usr', '/usr',
            '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev',
            '--dir', '/etc', '--dir', '/home',
            '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
            '--setenv', 'LC_ALL', 'C.UTF-8']
    if kind == 'node':
        args += ['--ro-bind', str(SOURCE), '/src',
                 '--ro-bind', str(core), '/runtime', '--size', str(1520*1024*1024),
                 '--tmpfs', '/lab', '--dir', '/lab/home', '--chmod', '0700', '/lab/home',
                 '--dir', '/lab/tmp', '--chmod', '0700', '/lab/tmp',
                 '--dir', '/lab/cache', '--chmod', '0700', '/lab/cache',
                 '--chdir', '/lab', '--setenv', 'HOME', '/lab/home',
                 '--setenv', 'TMPDIR', '/lab/tmp', '--setenv', 'XDG_CACHE_HOME', '/lab/cache',
                 '/usr/bin/python3', '-B', '/src/lab.py', '--deadline', str(deadline), '--network', network]
    else:
        args += ['--dir', '/src',
                 '--ro-bind', str(SOURCE/'protocol.py'), '/src/protocol.py',
                 '--ro-bind', str(SOURCE/'pipe_verify.py'), '/src/pipe_verify.py',
                 '--size', str(16*1024*1024), '--tmpfs', '/private',
                 '--dir', '/private/home', '--chmod', '0700', '/private/home',
                 '--dir', '/private/tmp', '--chmod', '0700', '/private/tmp',
                 '--dir', '/private/cache', '--chmod', '0700', '/private/cache', '--chdir', '/private',
                 '--setenv', 'HOME', '/private/home', '--setenv', 'TMPDIR', '/private/tmp',
                 '--setenv', 'XDG_CACHE_HOME', '/private/cache',
                 '/usr/bin/python3', '-B', '/src/pipe_verify.py']
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         env={}, close_fds=True, pass_fds=(), bufsize=0, start_new_session=True)
    CHILDREN.append(p)
    return p


def readline(process, deadline):
    # Bound the whole line, including slow/partial producers, without blocking
    # the host controller beyond the immutable wall-time admission.
    data = bytearray()
    fd = process.stdout.fileno()
    while b'\n' not in data:
        remaining = deadline - time.time()
        if remaining <= 0 or not select.select([fd], [], [], min(remaining, 5))[0]:
            if remaining <= 0:
                raise RuntimeError('absolute wall deadline')
            continue
        byte = os.read(fd, 1)
        if not byte:
            raise RuntimeError('child pipe closed')
        data.extend(byte)
        if len(data) > MAX_LINE:
            raise RuntimeError('public pipe line bound')
    return json.loads(data)


def send(process, obj):
    data = json.dumps(obj).encode() + b'\n'
    process.stdin.write(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('core_dir', type=Path)
    parser.add_argument('deadline', type=float)
    parser.add_argument('network', choices=('regtest', 'main'))
    args = parser.parse_args()
    limits = cgroup_limits()
    cutoff = min(args.deadline, time.time()+1500)
    if time.time() >= cutoff:
        raise RuntimeError('admission expired before child creation')
    core = args.core_dir.resolve(strict=True)
    node = sandbox('node', core, cutoff, args.network)
    while True:
        event = readline(node, cutoff)
        if event.get('type') == 'verify':
            verifier = sandbox('verifier')
            send(verifier, event['input'])
            for _ in range(4096):
                request = readline(verifier, min(cutoff, time.time()+20))
                if request.get('type') == 'decision':
                    code = verifier.wait(timeout=5)
                    send(node, {'type': 'verdict', 'result': request['result'], 'exit': code})
                    break
                if request.get('type') != 'rpc':
                    raise RuntimeError('verifier pipe message type')
                send(node, request)
                reply = readline(node, cutoff)
                if reply.get('type') != 'rpc_result':
                    raise RuntimeError('node pipe message type')
                send(verifier, reply)
            else:
                raise RuntimeError('verifier request-count bound')
        else:
            node.stdin.close()
            code = node.wait(timeout=15)
            event['controller'] = {'actual_cgroup_limits': limits, 'node_namespace_exit': code,
                                    'all_children_reaped': all(p.poll() is not None for p in CHILDREN),
                                    'total_tmpfs_cap_mib': 1536,
                                    'verifier_transport': 'dedicated restricted public RPC pipe; separate offline bwrap',
                                    'resource_stats_after_child_exit': resource_stats()}
            print(json.dumps(event), flush=True)
            return code


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    finally:
        for child in CHILDREN:
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                    child.wait(timeout=5)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=5)
