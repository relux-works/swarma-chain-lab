#!/usr/bin/env python3
"""Independent, stdlib-only reader of logical lifecycle fixtures; run with -I.

This reader imports no implementation code and invokes no Go program. Expected
verdicts come from the fixtures' cited requirements, not from either reducer.
"""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import sys

DRAFT = 'DRAFT-LIP-0028-v0.1.49'
OK = 'ADMITTED'
MAX = (1 << 64) - 1


def state(executor):
    return dict(executor=executor, sessions={}, seen=set(), closed=set(),
                accounts={}, reservations=set(), serial=0, ready=True,
                fence=None, mark=None)


def binding(b):
    if b.get('Kind') == 'uid':
        return not b.get('Address', '')
    if b.get('Kind') != 'address' or b.get('UID', 0):
        return False
    text = b.get('Address', '')
    try:
        return '%' not in text and str(ipaddress.ip_address(text)) == text
    except ValueError:
        return False


def same_binding(a, b):
    return (a.get('Kind'), a.get('UID', 0), a.get('Address', '')) == (
        b.get('Kind'), b.get('UID', 0), b.get('Address', ''))


def channel(f):
    return f['Channel'] in ('local', 'private-authenticated')


def peer(f, record):
    b = record['binding']
    transport = 'local' if b['Kind'] == 'uid' else 'private-authenticated'
    return (f['PeerVerified'] and binding(f['Peer'])
            and same_binding(f['Peer'], b) and f['Channel'] == transport)


def hour(now, end):
    # Python has arbitrary precision: this arithmetic does not share Go overflow.
    return 0 < end - now <= 3600


def closure(s, grant):
    s['closed'].add(grant)
    for r in s['sessions'].values():
        if grant in r['path']:
            r['ended'] = True


def closed(s, path):
    return not s['closed'].isdisjoint(path)


def upstream(f, stage, fallback):
    c = f.get('Checks', {}).get(stage, {})
    return OK if c.get('OK', False) else c.get('Refusal') or fallback


def verify(s, f, record=None, signed=False):
    # Stage order is taken directly from LIP-0008 §4, with the session
    # replacement of recipient authentication from LIP-0028 T4.5.
    stages = [('Names', 'NAME_FACTS'), ('Recipient', 'KEY_FACTS')]
    for stage, fallback in stages:
        code = upstream(f, stage, fallback)
        if code != OK:
            return code
    if not f['Key'] or (record and f['Key'] != record['key']):
        return 'KEY_FACTS'
    if signed and (not f['RequestID'] or not f['Iat'] <= f['Now'] < f['Exp']):
        return 'INVOCATION_TIME'
    code = upstream(f, 'Observation', 'OBSERVATION_FACTS')
    if code != OK:
        return code
    if s['mark'] is not None and f['Now'] < s['mark']:
        return 'OBSERVATION_CLOCK'
    if not f['FinalObservation']:
        return 'OBSERVATION_VOID'
    for c in f.get('Closures', []):
        if c.get('Validated') and c.get('Grant'):
            closure(s, c['Grant'])
    path = f['Path']
    if (not 1 <= len(path) <= 2 or any(not g for g in path)
            or len(set(path)) != len(path) or f['Executor'] != s['executor']
            or not all(f['Executor'].values())):
        return 'AUTHORITY_FACTS'
    if record and (record['path'] != path or record['executor'] != f['Executor']):
        return 'AUTHORITY_FACTS'
    if closed(s, path):
        return 'GRANT_CLOSED'
    for stage, fallback in [('Path', 'AUTHORITY_FACTS'), ('Resources', 'RESOURCE_FACTS')]:
        code = upstream(f, stage, fallback)
        if code != OK:
            return code
    return OK


def expire(s, sid, now):
    r = s['sessions'][sid]
    r['ended'] = r['ended'] or now >= r['end']
    return r['ended']


def mark(s, now):
    s['mark'] = max(now, s['mark'] or 0)


def gate(profile, s):
    tests = [(profile == DRAFT, 'PROFILE_DISABLED'),
             (s['ready'], 'JOURNAL_UNAVAILABLE')]
    return next((code for passed, code in tests if not passed), OK)


def write_boundary(transition):
    def committed(profile, original, *args):
        f = args[-1]
        outcome = transition(profile, original, *args)
        if f['WriteOK']:
            return outcome
        # A refusal never loses its pipeline code to a failed write. Discard
        # all staged state, including an observed expiry or validated closure.
        code = 'JOURNAL_WRITE' if outcome[1] == OK else outcome[1]
        return (original, code, *([None] if len(outcome) == 3 else []))
    return committed


@write_boundary
def check_use(profile, original, f):
    return prepare_use(profile, original, f)


def prepare_use(profile, original, f):
    s = copy.deepcopy(original)
    code = gate(profile, s)
    if code != OK:
        return s, code, None
    if not channel(f):
        return s, 'SESSION_CHANNEL', None
    digest = hashlib.sha256(f['token']).digest()
    matches = [sid for sid, r in s['sessions'].items() if r['digest'] == digest]
    if not matches:
        return s, 'SESSION_TOKEN', None
    sid = matches[0]
    r = s['sessions'][sid]
    if not peer(f, r):
        return s, 'SESSION_PEER', None
    if expire(s, sid, f['Now']):
        return s, 'SESSION_ENDED', None
    if f['Action'] in ('open', 'extend', 'close'):
        return s, 'SESSION_COMMAND', None
    if f['Op'] != 'use':
        return s, 'OPERATION_UNSUPPORTED', None
    code = verify(s, f, r)
    if code != OK:
        return s, code, None
    if s['serial'] == MAX:
        return s, 'IDENTITY_EXHAUSTED', None
    plan = dict(serial=s['serial'], sid=sid, digest=digest, key=r['key'],
                now=f['Now'], spend=copy.deepcopy(f['Spend']))
    s['serial'] += 1
    return s, OK, plan


@write_boundary
def reserve(profile, original, plan, f):
    s = copy.deepcopy(original)
    code = gate(profile, s)
    if code != OK:
        return s, code
    if (plan is None or plan['serial'] in s['reservations']
            or plan['serial'] >= s['serial']):
        return s, 'REQUEST_REPLAY'
    r = s['sessions'].get(plan['sid'])
    if r is None or r['digest'] != plan['digest']:
        return s, 'SESSION_TOKEN'
    if not f['FinalObservation']:
        return s, 'OBSERVATION_VOID'
    if f['Now'] < max(plan['now'], s['mark'] or 0):
        return s, 'OBSERVATION_CLOCK'
    if expire(s, plan['sid'], f['Now']):
        return s, 'SESSION_ENDED'
    if closed(s, r['path']):
        return s, 'GRANT_CLOSED'
    if r['key'] != plan['key']:
        return s, 'KEY_FACTS'
    # Build a transaction as a list of account operations. All constraints are
    # tested in order against a temporary ledger; publish it only on success.
    ledger = copy.deepcopy(s['accounts'])
    usage = dict(r['used'])
    for item in plan['spend']:
        key, amount = item['Key'], item['Amount']
        if not key or item['Kind'] != 'cumulative':
            return s, 'RESOURCE_FACTS'
        operations = [(('own', r['path'][-1], 0, key), r['grant'].get(key, 0), 'OWN_LIMIT_OVER')]
        if r['row']:
            operations.append((('row', r['row']['Parent'], r['row']['Ordinal'], key),
                               r['row_caps'].get(key, 0), 'ROW_CAP_OVER'))
        for aid, ceiling, refusal in operations:
            total = ledger.get(aid, 0) + amount
            if total > ceiling:
                return s, refusal
            ledger[aid] = total
        total = usage.get(key, 0) + amount
        if total > r['caps'].get(key, 0):
            return s, 'SESSION_LIMIT_OVER'
        usage[key] = total
    s['accounts'] = ledger
    r['used'] = usage
    s['reservations'].add(plan['serial'])
    mark(s, f['Now'])
    return s, OK


@write_boundary
def apply(profile, original, f):
    s = copy.deepcopy(original)
    code = gate(profile, s)
    if code != OK:
        return s, code, None
    if f['Op'] == 'use':
        s, code, plan = prepare_use(profile, s, f)
        if code == OK:
            s, code = reserve(profile, s, plan, f)
        return s, code, None
    if f['Op'] == 'closure':
        cs = f.get('Closures', [])
        if not cs or any(not c.get('Validated') or not c.get('Grant') for c in cs):
            return s, 'SEAL_UNVALIDATED', None
        for c in cs:
            closure(s, c['Grant'])
        return s, OK, None
    if f['Op'] not in ('open', 'extend', 'close'):
        return s, 'OPERATION_UNSUPPORTED', None
    if f['Op'] == 'open' and not channel(f):
        return s, 'SESSION_CHANNEL', None
    code = verify(s, f, signed=True)
    if code != OK:
        return s, code, None
    if (f['RequestID'] in s['seen']
            or (s['fence'] is not None and f['Iat'] <= s['fence'])):
        return s, 'SESSION_REPLAY', None
    if f['Op'] == 'open':
        if not binding(f['Binding']):
            return s, 'SESSION_BINDING', None
        if not hour(f['Now'], f['End']):
            return s, 'SESSION_WINDOW', None
        keys = [x['Key'] for x in f['Limits']]
        invalid = len(keys) != len(set(keys))
        for x in f['Limits']:
            key, amount = x['Key'], x['Amount']
            invalid |= (not key or x['Kind'] != 'cumulative' or key not in f['GrantLimits']
                        or amount > f['GrantLimits'].get(key, 0)
                        or amount > f['OperatorLimits'].get(key, MAX))
        if invalid:
            return s, 'SESSION_LIMITS', None
        row = f.get('Row')
        if ((row and (len(f['Path']) != 2 or row['Parent'] != f['Path'][0]))
                or (len(f['Path']) == 2 and not row)):
            return s, 'AUTHORITY_FACTS', None
        if not f['RandomReady']:
            return s, 'ENTROPY_UNAVAILABLE', None
        digest = hashlib.sha256(f['random']).digest()
        if any(r['digest'] == digest for r in s['sessions'].values()):
            return s, 'ENTROPY_COLLISION', None
        s['sessions'][f['RequestID']] = dict(
            path=list(f['Path']), executor=dict(f['Executor']), row=copy.deepcopy(row),
            binding=dict(f['Binding']), end=f['End'], ended=False, key=f['Key'],
            digest=digest, caps={x['Key']:x['Amount'] for x in f['Limits']},
            grant=dict(f['GrantLimits']), row_caps=dict(f.get('RowLimits') or {}), used={})
        token = f['random']
    else:
        r = s['sessions'].get(f['SessionID'])
        if not r or r['path'] != f['Path'] or r['executor'] != f['Executor']:
            return s, 'SESSION_UNKNOWN', None
        if f['Op'] == 'extend':
            if expire(s, f['SessionID'], f['Now']):
                return s, 'SESSION_ENDED', None
            if not hour(f['Now'], f['End']):
                return s, 'SESSION_WINDOW', None
            r['end'] = max(r['end'], f['End'])
            r['key'] = f['Key']
        else:
            r['ended'] = True
        token = None
    s['seen'].add(f['RequestID'])
    mark(s, f['Now'])
    return s, OK, token


def require(test, message):
    if not test:
        raise AssertionError(message)


def run(path):
    vectors = json.loads(path.read_text())
    require(vectors['schema'] == 'session-lifecycle-facts/1', 'fixture schema')
    count = 0
    histogram = {}
    for sc in vectors['scenarios']:
        s = state(vectors['executor'])
        tokens, plan = {}, None
        for number, step in enumerate(sc['steps'], 1):
            label = f"{sc['id']}/step-{number:02d}"
            f = copy.deepcopy(vectors['base_facts'])
            f.update(copy.deepcopy(step['facts']))
            f['random'] = bytes.fromhex(step.get('entropy', '00' * 32))
            require(len(f['random']) == 32, label + ': entropy length')
            f['token'] = tokens[step['token_from']] if step.get('token_from') else f['random']
            p = step.get('profile', vectors['profile'])
            before = copy.deepcopy(s)
            token, code = None, OK
            op = step['op']
            if op == 'apply':
                s, code, token = apply(p, s, f)
            elif op == 'check':
                s, code, plan = check_use(p, s, f)
            elif op == 'reserve':
                s, code = reserve(p, s, plan, f)
            elif op == 'restart':
                s = copy.deepcopy(s)
            elif op == 'lost':
                s['ready'] = False
            elif op == 'recover':
                s['ready'], s['sessions'], s['seen'] = True, {}, set()
                s['fence'] = max(s['fence'] or 0, f['Now'])
                mark(s, s['fence'])
            elif op == 'other_service':
                s = state(dict(Name='service-b', Key='executor-b'))
            else:
                raise AssertionError(label + ': unknown fixture operation')
            e = step['expect']
            require(code == e['code'], label + f": verdict {code}, expected {e['code']}")
            require((token is not None) == e['token'], label + ': token presence')
            if token is not None:
                require(op == 'apply' and f['Op'] == 'open', label + ': token outside open')
                require(token == f['random'], label + ': token differs from draw')
                require(s['sessions'][f['RequestID']]['digest'] == hashlib.sha256(token).digest(), label + ': token digest')
                if not step.get('discard_reply'):
                    tokens[f['RequestID']] = token
            if not f['WriteOK']:
                require(s == before, label + ': uncompleted write changed state')
            if code != OK:
                require(len(s['sessions']) == len(before['sessions']) and s['seen'] == before['seen'], label + ': refusal allocated session/identity')
                require(s['accounts'] == before['accounts'], label + ': refusal debited accounts')
                for sid in before['sessions']:
                    require(s['sessions'][sid]['used'] == before['sessions'][sid]['used'], label + ': refusal debited session')
            for field, actual in [('sessions', len(s['sessions'])), ('seen', len(s['seen']))]:
                if field in e:
                    require(actual == e[field], label + ': ' + field)
            for field, attr in [('end', 'end'), ('ended', 'ended'), ('last_key', 'key'), ('used', 'used')]:
                for sid, expected in e.get(field, {}).items():
                    require(s['sessions'][sid][attr] == expected, label + ': ' + field)
            if 'accounts' in e:
                view = {':'.join(map(str, k)):v for k,v in s['accounts'].items()}
                require(view == e['accounts'], label + ': accounts')
            count += 1
            histogram[code] = histogram.get(code, 0) + 1
    print(json.dumps(dict(reader='independent-python-stdlib', scenarios=len(vectors['scenarios']),
                          transitions=count, verdicts=histogram), sort_keys=True))


if __name__ == '__main__':
    require(sys.flags.isolated == 1, 'run this reader with python3 -I')
    require(len(sys.argv) <= 2, 'usage: python3 -I second_reader.py [vectors.json]')
    run(Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).resolve().parents[1] / 'testdata' / 'lifecycle.json')
