#!/usr/bin/env python3
"""Emit finite public script fixtures and schedule; no transaction/runtime execution."""
import argparse
import hashlib
import json
from pathlib import Path


def compact_size(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b'\xfd' + n.to_bytes(2, 'little')
    return b'\xfe' + n.to_bytes(4, 'little')


def push(data):
    n = len(data)
    if n <= 75:
        prefix = bytes([n])
    elif n <= 255:
        prefix = b'\x4c' + bytes([n])
    elif n <= 65535:
        prefix = b'\x4d' + n.to_bytes(2, 'little')
    else:
        prefix = b'\x4e' + n.to_bytes(4, 'little')
    return prefix + data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not args.output.is_absolute():
        parser.error('output must be an absolute private task path')
    spec = json.loads(Path(__file__).with_name('design.json').read_text())
    sizes = spec['opreturn_single_push_payload_bytes']
    if len(sizes) > 32 or any(type(n) is not int or not 0 <= n <= 1000000 for n in sizes):
        raise ValueError('finite script fixture bounds exceeded')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    rows = []

    def emit(case_id, scripts, payloads, shape=True):
        paths = []
        for i, script in enumerate(scripts):
            name = f'{case_id}-{i}.bin'
            target = args.output / name
            with target.open('xb') as f:
                f.write(script)
            target.chmod(0o600)
            paths.append({'path': name, 'bytes': len(script),
                          'sha256': hashlib.sha256(script).hexdigest()})
        rows.append({
            'case_id': case_id, 'scripts': paths,
            'payload_bytes': payloads,
            'script_bytes': [len(s) for s in scripts],
            'push_framing_bytes': [len(s) - 1 - n for s, n in zip(scripts, payloads)] if shape else None,
            'serialized_output_bytes': [8 + len(compact_size(len(s))) + len(s) for s in scripts],
            'output_weight_units': [4 * (8 + len(compact_size(len(s))) + len(s)) for s in scripts],
            'standard_script_size_candidate': shape and len(scripts) == 1 and len(scripts[0]) <= 83,
            'expectation_scope': 'source shape/size predicate only; excludes full transaction, fees, weight and contextual checks',
            'local_testmempoolaccept': 'NOT_RUN', 'local_admission': 'NOT_RUN',
            'peer_to_peer_relay': 'NOT_RUN', 'default_template_membership': 'NOT_RUN',
            'default_mined_inclusion': 'NOT_RUN', 'forced_block_validity': 'NOT_RUN',
        })

    for n in sizes:
        emit(f'single-{n}', [b'\x6a' + push(b'B' * n)], [n])
    emit('split-40-40', [b'\x6a' + push(b'B' * 40) + push(b'C' * 40)], [80])
    emit('split-76-4', [b'\x6a' + push(b'B' * 76) + push(b'C' * 4)], [80])
    emit('two-outputs', [b'\x6a' + push(b'B'), b'\x6a' + push(b'C')], [1, 1])
    emit('nonpush', [b'\x6a\x76'], [0], shape=False)
    emit('truncated-pushdata1', [b'\x6a\x4c\x02\x42'], [1], shape=False)
    result = {'status': 'OFFLINE_PUBLIC_SCRIPT_FIXTURES_ONLY', 'case_count': len(rows),
              'cases': rows, 'schedule': spec['steps'],
              'runtime_prerequisites': spec['runtime_prerequisites']}
    (args.output / 'cases.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'case_count': len(rows),
                      'script_bytes': sum(s['bytes'] for row in rows for s in row['scripts'])}))


if __name__ == '__main__':
    main()
