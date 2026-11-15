#!/usr/bin/env python3
"""Independent stdlib reader; affine BIP-340 verification, no Go calls or network.

Fixtures are synthetic. Success is an unsigned offline candidate, never proof of
live authority, name history, a durable row record, or ownership affiliations.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
MAX_TIME = 253402300799
MAX_MONEY = 2100000000000000
MAX_ATTESTATION_BYTES = 8192
CONTRACT = 'profile network landlord_name agent_name grantee_key actions repos spend_budget not_before not_after scope_text_sha256 parent_grant_id ordinal delegate note'.split()
DELEGATE = 'depth actions budget slots notaries checkpoint'.split()
GRANT = 'version network genesis agent_name landlord_name issuer_key grantee_key contract_sha256 scope not_before not_after seal consent'.split()
EVENT = 'id pubkey created_at kind tags content sig'.split()
NETWORKS = {'main': '000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770',
            'regtest': '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'}


class Refused(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Refused(code)


class Object(dict):
    def __init__(self, pairs):
        super().__init__(pairs)
        self.members = [k for k, _ in pairs]
        self.pairs = pairs


def encode(x):
    if isinstance(x, Object):
        return '{' + ','.join(encode(k) + ':' + encode(v) for k, v in x.pairs) + '}'
    if isinstance(x, dict):
        return '{' + ','.join(encode(k) + ':' + encode(v) for k, v in x.items()) + '}'
    if isinstance(x, list):
        return '[' + ','.join(map(encode, x)) + ']'
    return json.dumps(x, ensure_ascii=False, separators=(',', ':'))


def octets(x):
    return encode(x).encode('ascii')


def sha(x):
    return hashlib.sha256(x).hexdigest()


def lexical(x):
    if isinstance(x, str):
        return all(32 <= ord(c) <= 126 for c in x)
    if type(x) is int:
        return 0 <= x <= 2**63-1
    if isinstance(x, Object):
        return all(lexical(k) and lexical(v) for k, v in x.pairs)
    if type(x) is list:
        return all(map(lexical, x))
    return False


def load(raw, limit, code):
    try:
        x = json.loads(raw, object_pairs_hook=Object)
        need(0 < len(raw) <= limit and lexical(x) and octets(x) == raw, code)
        return x
    except (ValueError, UnicodeError, RecursionError):
        raise Refused(code) from None


def shape(x, names):
    return isinstance(x, Object) and x.members == names


def hx(x, size):
    return isinstance(x, str) and re.fullmatch('[0-9a-f]{' + str(size) + '}', x) is not None


def lift(x):
    if not 0 <= x < P:
        return None
    y = pow((x*x*x+7) % P, (P+1)//4, P)
    return (x, y if y % 2 == 0 else P-y) if y*y % P == (x*x*x+7) % P else None


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u:
        if y != v or y == 0:
            return None
        m = 3*x*x*pow(2*y, -1, P) % P
    else:
        m = (v-y)*pow(u-x, -1, P) % P
    z = (m*m-x-u) % P
    return z, (m*(x-z)-y) % P


def mul(n, a=G):
    r = None
    while n:
        if n & 1:
            r = add(r, a)
        a = add(a, a)
        n >>= 1
    return r


def tagged(tag, data):
    h = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(h+h+data).digest()


def key(x):
    return hx(x, 64) and lift(int(x, 16)) is not None


def owner(x):
    return hx(x, 66) and x[:2] in ('02', '03') and lift(int(x[2:], 16)) is not None


def verify(public, digest, signature):
    if not (key(public) and hx(digest, 64) and hx(signature, 128)):
        return False
    r, s = int(signature[:64], 16), int(signature[64:], 16)
    if r >= P or s >= N:
        return False
    e = int.from_bytes(tagged('BIP0340/challenge', bytes.fromhex(signature[:64]+public+digest)), 'big') % N
    a = lift(int(public, 16))
    result = add(mul(s), mul(N-e, a))
    return result is not None and result[1] % 2 == 0 and result[0] == r


def name(x):
    return isinstance(x, str) and re.fullmatch(r'id/[a-z0-9_.-]{1,252}', x) is not None


def ordered(x):
    return type(x) is list and all(type(s) is str for s in x) and x == sorted(set(x))


def repo(x):
    if not isinstance(x, str) or len(x) > 200 or not x.startswith('https://'):
        return False
    parts = x[8:].split('/')
    labels = parts[0].split('.')
    return (len(labels) >= 2 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', a) for a in labels)
            and len(parts) >= 2 and all(a not in ('', '.', '..') and re.fullmatch(r'[A-Za-z0-9_.-]+', a) for a in parts[1:]))


def contract(raw):
    c = load(raw, 8192, 'CONTRACT_ENCODING')
    need(shape(c, CONTRACT), 'CONTRACT_ENCODING')
    types = [str, str, str, str, str, list, list, int, int, int, str, str, int, None, str]
    need(all(t is None or type(c[k]) is t for k, t in zip(CONTRACT, types)), 'CONTRACT_ENCODING')
    need(all(type(a) is str for a in c['actions']+c['repos']), 'CONTRACT_ENCODING')
    need(c['profile'] == 'swarma-trust-contract/2', 'CONTRACT_PROFILE')
    need(c['network'] in NETWORKS and name(c['landlord_name']) and name(c['agent_name'])
         and c['landlord_name'] != c['agent_name'] and key(c['grantee_key'])
         and c['not_before'] < c['not_after'] <= MAX_TIME
         and (c['scope_text_sha256'] == '' or hx(c['scope_text_sha256'], 64)), 'CONTRACT_FIELD')
    need(ordered(c['actions']) and c['actions'] and set(c['actions']) <= {'instruct', 'land', 'review', 'spend'}, 'CONTRACT_ACTIONS')
    need(ordered(c['repos']) and len(c['repos']) <= 16 and bool(c['repos']) == ('land' in c['actions']) and all(map(repo, c['repos'])), 'CONTRACT_REPOS')
    need(c['spend_budget'] <= MAX_MONEY and (c['spend_budget'] > 0) == ('spend' in c['actions']), 'CONTRACT_BUDGET')
    need(len(c['note']) <= 280, 'CONTRACT_NOTE')
    need(c['ordinal'] <= 16 and (c['parent_grant_id'] == '' or hx(c['parent_grant_id'], 64))
         and (c['parent_grant_id'] == '') == (c['ordinal'] == 0), 'CONTRACT_PARENT')
    d = c['delegate']
    if isinstance(d, Object) and d.members and d.members[0] == 'depth' and type(d.pairs[0][1]) is int and c['parent_grant_id']:
        need(d.pairs[0][1] == 0, 'CONTRACT_PARENT')
    need(shape(d, DELEGATE), 'CONTRACT_DELEGATE')
    need(all(type(d[k]) is t for k, t in zip(DELEGATE, [int, list, int, list, list, str])), 'CONTRACT_DELEGATE')
    if d['depth'] == 1:
        need(d['notaries'], 'DELEGATE_NO_NOTARY')
    need(ordered(d['actions']), 'CONTRACT_DELEGATE')
    if d['depth'] == 0:
        need(not (d['actions'] or d['budget'] or d['slots'] or d['notaries'] or d['checkpoint']), 'CONTRACT_DELEGATE')
        return c
    need(d['depth'] == 1 and d['actions'] and set(d['actions']) <= set(c['actions']) and 'spend' not in d['actions']
         and d['budget'] == 0 and 1 <= len(d['slots']) <= 16 and 1 <= len(d['notaries']) <= 4 and hx(d['checkpoint'], 64), 'CONTRACT_DELEGATE')
    names = []
    for n in d['notaries']:
        need(shape(n, ['name', 'registration', 'owner']) and name(n['name']) and owner(n['owner'])
             and shape(n['registration'], ['txid', 'vout']) and hx(n['registration']['txid'], 64)
             and type(n['registration']['vout']) is int and 0 <= n['registration']['vout'] <= 2**32-1, 'CONTRACT_DELEGATE')
        names.append(n['name'])
    need(ordered(names), 'CONTRACT_DELEGATE')
    for r in d['slots']:
        need(shape(r, ['executor', 'grantee', 'cap', 'notary']) and name(r['executor']) and r['executor'] != c['landlord_name']
             and key(r['grantee']) and type(r['cap']) is int and r['cap'] == 0 and r['notary'] in names, 'CONTRACT_DELEGATE')
    return c


def event_id(e):
    return sha(octets([0, e['pubkey'], e['created_at'], e['kind'], e['tags'], e['content']]))


def event(e, at):
    return (shape(e, EVENT) and type(e['created_at']) is int and 1 <= e['created_at'] <= min(at, MAX_TIME)
            and type(e['kind']) is int and type(e['tags']) is list and all(type(a) is list and all(type(s) is str for s in a) for a in e['tags'])
            and type(e['content']) is str and event_id(e) == e['id'] and verify(e['pubkey'], e['id'], e['sig']))


def grant(raw, at):
    p = load(raw, 32768, 'GRANT_ENCODING')
    need(shape(p, ['signed_grant', 'issuance']) and shape(p['signed_grant'], ['grant', 'signature']) and shape(p['issuance'], ['txid']), 'GRANT_ENCODING')
    g = p['signed_grant']['grant']
    names = list(GRANT)
    if 'grantee_name' in g:
        names.insert(names.index('contract_sha256'), 'grantee_name')
    if 'budget' in g:
        names.insert(names.index('consent'), 'budget')
    need(shape(g, names) and shape(g['seal'], ['txid', 'vout']) and shape(g['consent'], ['contract_sha256', 'consent_event', 'landlord_sig']), 'GRANT_ENCODING')
    need(all(type(g[k]) is str for k in ['network', 'genesis', 'agent_name', 'landlord_name', 'issuer_key', 'grantee_key', 'contract_sha256'])
         and all(type(g[k]) is int for k in ['version', 'not_before', 'not_after']) and type(g['scope']) is list
         and type(g['seal']['vout']) is int and g['seal']['vout'] <= 2**32-1, 'GRANT_ENCODING')
    need(g['version'] == 3 and NETWORKS.get(g['network']) == g['genesis'] and name(g['agent_name']) and name(g['landlord_name'])
         and g['agent_name'] != g['landlord_name'] and ('grantee_name' not in g or name(g['grantee_name'])) and key(g['issuer_key']) and key(g['grantee_key'])
         and hx(g['contract_sha256'], 64) and hx(g['seal']['txid'], 64) and hx(p['issuance']['txid'], 64)
         and ordered(g['scope']) and set(g['scope']) <= {'deliver', 'names.register', 'pay', 'publish', 'repository.push', 'secret.release'}
         and g['not_before'] < g['not_after'] <= MAX_TIME and g.get('budget', 0) <= MAX_MONEY, 'GRANT_FIELD')
    need(verify(g['issuer_key'], sha(b'swarma-grant-v3'+octets(g)), p['signed_grant']['signature']), 'GRANT_SIGNATURE')
    need(at >= g['not_before'], 'GRANT_NOT_YET_VALID')
    need(at < g['not_after'], 'GRANT_EXPIRED')
    cons = g['consent']; e = cons['consent_event']
    need(cons['contract_sha256'] == g['contract_sha256'] and event(e, at) and e['created_at'] < g['not_after']
         and e['pubkey'] == g['grantee_key'] and e['kind'] == 8181 and e['content'] == ''
         and verify(g['issuer_key'], g['contract_sha256'], cons['landlord_sig']), 'GRANT_CONSENT')
    return p


def binding(g, raw):
    need(sha(raw) == g['contract_sha256'], 'CONTRACT_HASH')
    c = contract(raw)
    need(all(c[k] == g[k] for k in ['network', 'landlord_name', 'agent_name', 'grantee_key', 'not_before', 'not_after']), 'CONTRACT_MISMATCH')
    need(g['scope'] == (['pay'] if 'spend' in c['actions'] else []) + (['repository.push'] if 'land' in c['actions'] else []), 'SCOPE_MISMATCH')
    need(g.get('budget', 0) == c['spend_budget'], 'BUDGET_MISMATCH')
    tags = [['t', 'swarma-rental-consent-v1'], ['contract', sha(raw)], ['booking', sha(raw+b'booking')], ['privacy', sha(b'swarma-trust-privacy-v1')]]
    need(g['consent']['consent_event']['tags'] == tags, 'CONSENT_TAGS')
    return c


def row_fit(pc, cc):
    d = pc['delegate']
    need(1 <= cc['ordinal'] <= len(d['slots']), 'CHILD_ORDINAL')
    row = d['slots'][cc['ordinal']-1]
    need(cc['agent_name'] == row['executor'], 'CHILD_AGENT_NOT_ALLOWED')
    need(cc['grantee_key'] == row['grantee'], 'CHILD_GRANTEE_NOT_ALLOWED')
    need(set(cc['actions']) <= set(d['actions']), 'CHILD_ACTIONS_WIDER')
    need(set(cc['repos']) <= set(pc['repos']), 'CHILD_REPOS_WIDER')
    need(cc['spend_budget'] <= row['cap'], 'CHILD_BUDGET_OVER')
    need(pc['not_before'] <= cc['not_before'] < cc['not_after'] <= pc['not_after'], 'CHILD_WINDOW_NOT_NESTED')


def notary_key(raw, grant=False):
    code = "MVP_NAME_VALUE" if grant else "NOTARY_KEY"
    need(len(raw) <= 520, code)
    try:
        text = raw.decode('utf-8')
        decoder = json.JSONDecoder(object_pairs_hook=Object, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        obj, end = decoder.raw_decode(text, len(text)-len(text.lstrip()))
        need(isinstance(obj, Object) and end == len(text), code)
        seen = set()
        for k, _ in obj.pairs:
            # ASCII names have the same simple-fold conflict here. The long-s
            # variant is included because Python casefold and Go EqualFold
            # both fold it to the ASCII s in swarma/nostr.
            folded = k.casefold()
            if folded in ('swarma', 'nostr'):
                need(k == folded and k not in seen, code)
                seen.add(k)
        need('swarma' in seen, code)
        i = text.index('{') + 1
        authority = None
        while True:
            i += len(text[i:])-len(text[i:].lstrip())
            if text[i] == '}':
                break
            k, i = decoder.raw_decode(text, i)
            i += len(text[i:])-len(text[i:].lstrip())
            need(text[i] == ':', code)
            i += 1
            i += len(text[i:])-len(text[i:].lstrip())
            start = i
            _, i = decoder.raw_decode(text, i)
            if k == 'swarma':
                authority = text[start:i].encode('utf-8')
            i += len(text[i:])-len(text[i:].lstrip())
            if text[i] == ',':
                i += 1
                continue
            break
        binding = load(authority, 520, code)
        if grant:
            need(shape(binding, ['landlord']) and shape(binding['landlord'], ['grant']) and key(binding['landlord']['grant']), code)
            return binding['landlord']['grant']
        need(shape(binding, ['notary']) and shape(binding['notary'], ['attest']) and key(binding['notary']['attest']), code)
        return binding['notary']['attest']
    except (ValueError, UnicodeError, IndexError, TypeError):
        raise Refused(code) from None


def check(v):
    at = v['at']
    need(type(at) is int and 1 <= at <= MAX_TIME, 'AT_TIME')
    pp = grant(v['parent'].encode(), at); cp = grant(v['child'].encode(), at)
    p = pp['signed_grant']['grant']; c = cp['signed_grant']['grant']
    pc = binding(p, v['parent_contract'].encode()); cc = binding(c, v['child_contract'].encode())
    pid = sha(octets(pp['signed_grant'])); cid = sha(octets(cp['signed_grant']))
    need(cc['parent_grant_id'] == pid, 'PARENT_ID_MISMATCH')
    need(pc['parent_grant_id'] == '' and pid != cid, 'CHAIN_DEPTH')
    need(pc['delegate']['depth'] == 1, 'NOT_DELEGABLE')
    need(all(p[k] == c[k] for k in ['network', 'genesis', 'landlord_name', 'issuer_key']), 'SUBJECT_MISMATCH')
    try:
        e = load(v['request'].encode(), 16384, 'DELEGATION_REQUEST')
        need(event(e, MAX_TIME) and e['pubkey'] == p['grantee_key'] and e['kind'] == 8186 and e['content'] == ''
             and p['not_before'] <= e['created_at'] < p['not_after'] and len(e['tags']) == 5 and len(e['tags'][4]) == 2
             and hx(e['tags'][4][1], 64), 'DELEGATION_REQUEST')
        need(e['tags'] == [['t', 'swarma-delegation-request-v1'], ['parent', pid], ['contract', c['contract_sha256']],
                           ['ordinal', str(cc['ordinal'])], ['nonce', e['tags'][4][1]]], 'DELEGATION_REQUEST')
    except (KeyError, TypeError, IndexError):
        raise Refused('DELEGATION_REQUEST') from None
    row_fit(pc, cc)
    need(pc['scope_text_sha256'] == cc['scope_text_sha256'], 'TEXT_JUDGEMENT_REQUIRED')
    for contract_, field in [(pc, 'parent_text'), (cc, 'child_text')]:
        h = contract_['scope_text_sha256']; text = v.get(field, '').encode()
        need(sha(text) == h if h else not text, 'DELEGATION_BUNDLE')
    pol = load(v['policy'].encode(), 8192, 'OWNER_EVIDENCE_REQUIRED')
    fields = 'parent_grant_id child_grant_id issuer_owner delegator_owner notary_name notary_owner agreed_by'.split()
    fields += (['mode'] if 'mode' in pol else []) + (['mode_approvals'] if 'mode_approvals' in pol else [])
    need(shape(pol, fields) and ('mode' not in pol or isinstance(pol['mode'], str) and pol['mode'] != '')
         and ('mode_approvals' not in pol or isinstance(pol['mode_approvals'], list) and len(pol['mode_approvals']) > 0)
         and all(shape(a, ['owner', 'name', 'registration', 'signature']) and isinstance(a['owner'], str) and isinstance(a['signature'], str) for a in pol.get('mode_approvals', []))
         and pol['parent_grant_id'] == pid and pol['child_grant_id'] == cid and all(owner(pol[k]) for k in ['issuer_owner', 'delegator_owner', 'notary_owner'])
         and ordered(pol['agreed_by']) and all(map(owner, pol['agreed_by'])), 'OWNER_EVIDENCE_REQUIRED')
    mode = pol.get('mode', '')
    need(mode in ['', 'mvp-pair-owned-notary'], 'POLICY_MODE_UNSUPPORTED')
    need(mode or 'mode_approvals' not in pol, 'POLICY_MODE_REQUIRED')
    designated = next((n for n in pc['delegate']['notaries'] if n['name'] == pol['notary_name']), None)
    need(designated is not None, 'NOTARY_NOT_DESIGNATED')
    need(designated['owner'] == pol['notary_owner'], 'NOTARY_NAME_CHANGED')
    if mode:
        need(pol['issuer_owner'][2:] != pol['delegator_owner'][2:], 'MVP_MODE_PAIR_REQUIRED')
        need('names' in v, 'MVP_CHAIN_READ_REQUIRED')
        approvals = pol.get('mode_approvals', [])
        need(len(approvals) == 2, 'MVP_MODE_APPROVAL_REQUIRED')
        need([a['owner'] for a in approvals] == sorted([pol['issuer_owner'], pol['delegator_owner']]), 'MVP_MODE_APPROVAL_REQUIRED')
        need(approvals[0]['name'] != approvals[1]['name'], 'MVP_OWNER_NAME_REUSED')
        need(approvals[0]['registration'] != approvals[1]['registration'], 'MVP_OWNER_REGISTRATION_REUSED')
        st = load(v['statement'].encode(), 8192, 'STATEMENT_FIELD')
        need(shape(st, ['notary_seal', 'tip_height', 'tip_hash']) and type(st['tip_height']) is int and st['tip_height'] >= 0 and hx(st['tip_hash'],64), 'STATEMENT_FIELD')
        signed = {k: pol[k] for k in fields if k != 'mode_approvals'}
        identities = [{k:a[k] for k in ['owner','name','registration']} for a in approvals]
        digest = sha(b'swarma-notary-local-policy-v1' + octets(signed) + octets(identities))
        for a in approvals:
            need(owner(a['owner']) and name(a['name']) and shape(a['registration'], ['txid','vout']) and hx(a['registration']['txid'],64) and type(a['registration']['vout']) is int and 0 <= a['registration']['vout'] <= 2**32-1, 'MVP_MODE_APPROVAL_REQUIRED')
            observed = next((n for n in v['names'] if n['name'] == a['name']), None)
            need(observed is not None and not observed.get('unreadable',False), 'MVP_NAME_UNREADABLE')
            need(observed['height'] == st['tip_height'] and observed['blockhash'] == st['tip_hash'], 'MVP_NAME_VIEW_MISMATCH')
            need(observed['registration'] == a['registration'], 'MVP_NAME_REGISTRATION_MISMATCH')
            k = notary_key(observed['value'].encode(), grant=True)
            need(k == a['owner'][2:] and verify(k, digest, a['signature']), 'MVP_MODE_APPROVAL_REQUIRED')
    if pol['issuer_owner'] == pol['delegator_owner']:
        need(pol['notary_owner'] == pol['issuer_owner'], 'NOTARY_OWNER_RELATION')
    else:
        need(pol['notary_owner'] not in [pol['issuer_owner'], pol['delegator_owner']] or mode == 'mvp-pair-owned-notary', 'NOTARY_OWNER_RELATION')
        need({pol['issuer_owner'], pol['delegator_owner']} <= set(pol['agreed_by']), 'CROSS_OWNER_CERTIFIER_REQUIRED')
    nk = notary_key(v['notary_value'].encode())
    need(nk != p['grantee_key'], 'NOTARY_IS_DELEGATOR')
    need(nk != c['grantee_key'], 'NOTARY_IS_DELEGATEE')
    need(pol['notary_name'] not in [p['agent_name'], c['agent_name']], 'NOTARY_IS_EXECUTOR')
    st = load(v['statement'].encode(), 8192, 'STATEMENT_FIELD')
    need(shape(st, ['notary_seal', 'tip_height', 'tip_hash']) and shape(st['notary_seal'], ['txid', 'vout', 'script'])
         and hx(st['notary_seal']['txid'], 64) and type(st['notary_seal']['vout']) is int and st['notary_seal']['vout'] <= 2**32-1
         and isinstance(st['notary_seal']['script'], str) and 0 < len(st['notary_seal']['script']) <= 20000
         and len(st['notary_seal']['script']) % 2 == 0 and hx(st['notary_seal']['script'], len(st['notary_seal']['script']))
         and type(st['tip_height']) is int and hx(st['tip_hash'], 64), 'STATEMENT_FIELD')
    a = dict(zip('profile kind network genesis landlord_name notary_name notary_key parent_grant_id parent_contract_sha256 child_grant_id child_contract_sha256 ordinal textual mechanical notary_seal tip_height tip_hash attested_at'.split(),
                 ['swarma-notary-attestation/1', 'child-within-parent', p['network'], p['genesis'], p['landlord_name'], pol['notary_name'], nk,
                  pid, p['contract_sha256'], cid, c['contract_sha256'], cc['ordinal'], 'identical' if pc['scope_text_sha256'] else 'none', 'pass', st['notary_seal'], st['tip_height'], st['tip_hash'], at]))
    raw = octets(a)
    need(len(raw) <= MAX_ATTESTATION_BYTES, 'ATTESTATION_TOO_LARGE')
    return {'attestation': raw.decode('ascii'), 'digest': sha(b'swarma-notary-v1'+raw)}


def outcome(v):
    try:
        return 'ATTEST', check(v)
    except Refused as e:
        return str(e), None


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]/'testdata/vectors.json'
    corpus = json.loads(path.read_text())
    boundaries = {'positive-attestation-8191': 8191, 'positive-attestation-8192': 8192, 'negative-attestation-8193': 8193}
    seen = set()
    for v in corpus['vectors']:
        code, result = outcome(v)
        assert code == v['expected'], (v['name'], code, v['expected'])
        if v['name'] in boundaries:
            seen.add(v['name'])
            # Recompose exact boundary bytes independently of check's result:
            # the input statement fits, yet the full candidate can overflow.
            a = json.loads(corpus['vectors'][0]['result']['attestation'])
            st = json.loads(v['statement'])
            a.update(notary_seal=st['notary_seal'], tip_height=st['tip_height'], tip_hash=st['tip_hash'])
            raw = octets(a)
            assert len(v['statement'].encode()) < 8192 and len(raw) == boundaries[v['name']], v['name']
            if len(raw) > 8192:
                assert result is None, v['name']
                try:
                    load(raw, MAX_ATTESTATION_BYTES, 'ATTESTATION_SHAPE')
                except Refused as e:
                    assert str(e) == 'ATTESTATION_SHAPE', v['name']
                else:
                    raise AssertionError((v['name'], 'oversized signed-object decode accepted'))
        if result:
            assert result == v['result'], v['name']
            a = load(result['attestation'].encode(), MAX_ATTESTATION_BYTES, 'ATTESTATION_SHAPE')
            assert verify(a['notary_key'], result['digest'], v['attestation_signature']), v['name']
            envelope = dict(attestation=a, signature=v['attestation_signature'])
            assert sha(octets(envelope)) == v['attestation_id'], v['name']
            preimage = b'swarma-attest-v1' + bytes.fromhex(v['attestation_id']+a['child_grant_id']+a['parent_grant_id'])
            assert '6a03534c044201'+sha(preimage)+'01'+v['attestation_id'] == v['anchor_script'], v['name']
        else:
            assert result is None, (v['name'], 'partial refusal output')
    assert seen == set(boundaries), 'missing attestation boundary vectors'
    for v in corpus['row_vectors']:
        code = 'ATTEST'
        try:
            row_fit(v['parent'], v['child'])
        except Refused as e:
            code = str(e)
        assert code == v['expected'], (v['name'], code)
    print(f"PASS independent reader: {len(corpus['vectors'])} signed-bundle vectors, {len(corpus['row_vectors'])} isolated row vectors")


if __name__ == '__main__':
    main()
