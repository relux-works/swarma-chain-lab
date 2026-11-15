#!/usr/bin/env python3
"""Independent second reading of draft LIP-0022, with no Go code imports.

Evaluate all 97 cases from stated inputs, then compare computed results to both
published expectations and actual exported Go results. No node reads or clocks.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

VECTOR_HASH = '5f6b4c735b6e519c892518e0ade689f4055e211aa4693f2b6ca93858e756518c'
ORDER = ('OBSERVATION_CHAIN', 'OBSERVATION_VOID', 'NODE_UNHEALTHY',
         'NODE_DISAGREEMENT', 'OBSERVATION_CLOCK', 'TIP_AGE', 'RECENT_BLOCK',
         'RECENT_BLOCK_WINDOW', 'CONFIRMATIONS')


def priority(findings):
    if set(findings) - set(ORDER) - {'', 'ok'}:
        raise ValueError('unrecognized finding')
    return next((code for code in ORDER if code in findings), 'ok')


def clock_observation(state, row, parameters):
    """B3.2/B3.7 update eligibility differs from the admission verdict."""
    now = row['now']
    finding = row.get('finding', 'ok')
    if finding in ORDER[:2]:
        return finding
    if now < state['kept_mark']:
        return priority([finding, 'OBSERVATION_CLOCK'])
    tip = row['tip']
    if tip['hash'] not in state['first_sights']:
        state['first_sights'][tip['hash']] = now
        state['kept_mark'] = now
    first_sight = state['first_sights'][tip['hash']]
    cutoff = parameters['cutoff_other_privileged_seconds'] if row.get('class') == 'other privileged' else parameters['cutoff_money_or_irreversible_seconds']
    # Refuse if either age reaches the cutoff, without computing Go's max age.
    if tip['header_time'] > now + parameters['s_seconds']:
        verdict = 'OBSERVATION_CLOCK'
    elif tip['header_time'] <= now - cutoff or first_sight <= now - cutoff:
        verdict = 'TIP_AGE'
    else:
        verdict = 'ok'
    verdict = priority([finding, verdict])
    if verdict == 'ok':
        state['kept_mark'] = now
    return verdict


def on_chain(row, height, block_hash):
    return (height is not None and 0 <= height <= row['tip_height']
            and bool(block_hash) and row['active_chain'].get(str(height)) == block_hash)


def evaluate(group, row, parameters):
    p = dict(parameters)
    if group == 'readings':
        if row['genesis_hash'] != row['pinned_genesis_hash']:
            result = 'OBSERVATION_CHAIN'
        elif row['first_tip'] != row['last_tip'] or row.get('tip_before_effect', row['last_tip']) != row['last_tip']:
            result = 'OBSERVATION_VOID'
        else:
            result = 'ok'
    elif group == 'facts':
        result = 'belongs' if row['block_holds_transaction'] and on_chain(row, row['block_height'], row['block_hash']) else 'does not belong'
    elif group == 'nodes':
        def healthy(node):
            return (node['answers'] and node['genesis_hash'] == p['pinned_genesis_hash']
                    and not node['initial_block_download'] and node['headers_above_tip'] <= row['lag'])
        own = row['reading_node']
        good = [n for n in row['comparison_nodes'] if healthy(n)]
        distinct = [n for n in good if n['source_label'] != own['source_label']]
        same_branch = lambda n: n['tip_height'] <= own['tip_height'] and own['active_chain'].get(str(n['tip_height'])) == n['tip_hash']
        if own['genesis_hash'] != p['pinned_genesis_hash']:
            result = 'OBSERVATION_CHAIN'
        elif not healthy(own) or not distinct:
            result = 'NODE_UNHEALTHY'
        elif any(not same_branch(n) for n in good) or not any(same_branch(n) and own['tip_height'] <= n['tip_height'] + row['lag'] for n in distinct):
            result = 'NODE_DISAGREEMENT'
        else:
            result = 'ok'
    elif group == 'clock':
        p['s_seconds'] = row['s']
        state = {'kept_mark': row['kept_mark'], 'first_sights': {}}
        if 'first_sight' in row:
            state['first_sights']['tip'] = row['first_sight']
        step = {'now': row['now'], 'tip': {'hash': 'tip', 'header_time': row['tip_header_time']}, 'class': row.get('class')}
        result = clock_observation(state, step, p)
        if result == 'ok' and 'now_before_effect' in row:
            step['now'] = row['now_before_effect']
            result = clock_observation(state, step, p)
    elif group == 'sequences':
        p['s_seconds'] = row['s']
        state = json.loads(json.dumps(row['start']))
        steps = ['restart' if step.get('restart') else clock_observation(state, step, p) for step in row['steps']]
        return {'steps': steps, 'end': state}
    elif group == 'blocks':
        height = row.get('committed_block_height')
        if not on_chain(row, height, row['committed_block_hash']):
            result = 'RECENT_BLOCK'
        elif row['anchor_height'] not in range(height + 1, height + row['k'] + 1):
            result = 'RECENT_BLOCK_WINDOW'
        else:
            result = 'ok'
    elif group == 'windows':
        r, start, end, h = (row[k] for k in ('recent_block_height', 'not_before_height', 'not_after_height', 'tip_height'))
        result = 'admit' if 0 <= r <= start <= h < end else 'refuse'
    elif group == 'depth':
        evidence = row['evidence']
        h = evidence.get('block_height')
        enough = (h is not None and 0 <= h <= row['tip_height']
                  and evidence['chain'] == row['chain'])
        if enough:
            depth = row['tip_height'] + 1 - h
            enough = depth >= row['signed_minimum'] and depth >= row['operator_floor']
        result = 'ok' if enough else 'CONFIRMATIONS'
    elif group == 'order':
        result = priority(row['findings'])
    else:
        raise ValueError('unhandled group ' + group)
    return {'verdict': result}


def groups(document):
    return [('readings', document['observations']['readings']), ('facts', document['observations']['facts']),
            ('nodes', document['nodes']), ('clock', document['clock']), ('sequences', document['sequences']),
            ('blocks', document['recent']['blocks']), ('windows', document['recent']['windows']),
            ('depth', document['depth']), ('order', document['order'])]


def expected(group, row):
    if group == 'sequences':
        return {'steps': ['restart' if s.get('restart') else s['expect'] for s in row['steps']], 'end': row['end']}
    return {'verdict': row['expect']}


def check(document, go_results):
    rows = [(group, row) for group, cases in groups(document) for row in cases]
    ids = [row['id'] for _, row in rows]
    if len(ids) != 97 or len(set(ids)) != 97 or set(ids) != set(go_results):
        raise ValueError('missing, duplicate or extra vector results')
    by_id = {row['id']: row for _, row in rows}
    errors = []
    for group, row in rows:
        if 'valid_neighbour' in row:
            neighbour = by_id[row['valid_neighbour']]
            if neighbour['expect'] not in ('ok', 'belongs', 'admit'):
                raise ValueError('neighbour is not a passing control')
        elif group != 'sequences' and not row.get('compound') and row['expect'] not in ('ok', 'belongs', 'admit'):
            raise ValueError('refusal has no passing neighbour')
        if 'control' in row and 'steps' not in by_id[row['control']]:
            raise ValueError('missing sequence control')
        actual = evaluate(group, row, document['parameters'])
        for source, want in [('draft vector', expected(group, row)), ('Go result', go_results[row['id']])]:
            if actual != want:
                errors.append(f"{row['id']}: independent={actual!r}; {source}={want!r}")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go-results', required=True, type=Path)
    args = parser.parse_args()
    try:
        data = (Path(__file__).resolve().parents[1] / 'testdata/observation-vectors.json').read_bytes()
        if hashlib.sha256(data).hexdigest() != VECTOR_HASH:
            raise ValueError('pinned vector bytes changed')
        document = json.loads(data)
        errors = check(document, json.loads(args.go_results.read_text()))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'second reader could not run: {exc}', file=sys.stderr)
        return 2
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print('Independent second reader: all 97 vectors agree with draft expectations and Go; 10 sequences and 6 order vectors, zero skips.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
