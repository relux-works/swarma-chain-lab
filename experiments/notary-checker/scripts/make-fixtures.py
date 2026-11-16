#!/usr/bin/env python3
"""Reproduce only synthetic fixtures using the explicitly PUBLIC test keys.

No randomness, key generation, real keys, services, network or wall clock.
Expected codes below are requirements, never derived from the Go implementation.
"""
import copy
import json
from functools import lru_cache
from pathlib import Path
import reference as r

ROOT = Path(__file__).resolve().parents[1]
TEST_KEYS = json.loads((ROOT/'testdata/keys.json').read_text())
AT = 1700000100


def public(secret):
    return f'{r.mul(secret)[0]:064x}'


def owner(role):
    x, y = r.mul(TEST_KEYS[role])
    return ('03' if y % 2 else '02') + f'{x:064x}'


@lru_cache(maxsize=None)
def sign(secret, message):
    d = secret
    point = r.mul(d)
    if point[1] % 2:
        d = r.N-d
    pk = point[0].to_bytes(32, 'big')
    msg = bytes.fromhex(message)
    # BIP-340 auxiliary randomness is the fixed 32 zero octets, TEST ONLY.
    aux = r.tagged('BIP0340/aux', bytes(32))
    t = bytes(a ^ b for a, b in zip(d.to_bytes(32, 'big'), aux))
    k = int.from_bytes(r.tagged('BIP0340/nonce', t+pk+msg), 'big') % r.N
    R = r.mul(k)
    if R[1] % 2:
        k = r.N-k
    rx = R[0].to_bytes(32, 'big')
    e = int.from_bytes(r.tagged('BIP0340/challenge', rx+pk+msg), 'big') % r.N
    return (rx + ((k+e*d) % r.N).to_bytes(32, 'big')).hex()


def event(role, kind, tags, at=AT-10):
    e = dict(id='', pubkey=public(TEST_KEYS[role]), created_at=at, kind=kind, tags=tags, content='', sig='')
    e['id'] = r.event_id(e)
    e['sig'] = sign(TEST_KEYS[role], e['id'])
    return e


def zero_delegate():
    return dict(depth=0, actions=[], budget=0, slots=[], notaries=[], checkpoint='')


def contracts():
    p = dict(profile='swarma-trust-contract/2', network='regtest', landlord_name='id/principal', agent_name='id/executor',
             grantee_key=public(TEST_KEYS['delegator']), actions=['instruct', 'land', 'review'], repos=['https://git.example/project/core'],
             spend_budget=0, not_before=AT-100, not_after=AT+100, scope_text_sha256='', parent_grant_id='', ordinal=0,
             delegate=dict(depth=1, actions=['instruct', 'land', 'review'], budget=0,
                           slots=[dict(executor='id/worker', grantee=public(TEST_KEYS['delegatee']), cap=0, notary='id/certifier')],
                           notaries=[dict(name='id/certifier', registration=dict(txid='11'*32, vout=0), owner=owner('issuer_owner'))], checkpoint='22'*32), note='')
    c = copy.deepcopy(p)
    c.update(agent_name='id/worker', grantee_key=public(TEST_KEYS['delegatee']), not_before=AT-50, not_after=AT+50,
             parent_grant_id='00'*32, ordinal=1, delegate=zero_delegate())
    return p, c


def grant(c, role, raw=None, patch=None):
    raw = r.octets(c) if raw is None else raw
    ch = r.sha(raw)
    tags = [['t', 'swarma-rental-consent-v1'], ['contract', ch], ['booking', r.sha(raw+b'booking')], ['privacy', r.sha(b'swarma-trust-privacy-v1')]]
    g = dict(version=3, network=c['network'], genesis=r.NETWORKS[c['network']], agent_name=c['agent_name'], landlord_name=c['landlord_name'],
             issuer_key=public(TEST_KEYS['issuer']), grantee_key=c['grantee_key'], contract_sha256=ch,
             scope=(['pay'] if 'spend' in c['actions'] else []) + (['repository.push'] if 'land' in c['actions'] else []),
             not_before=c['not_before'], not_after=c['not_after'], seal=dict(txid=('33' if role == 'delegator' else '44')*32, vout=0))
    if c['spend_budget']:
        g['budget'] = c['spend_budget']
    g['consent'] = dict(contract_sha256=ch, consent_event=event(role, 8181, tags), landlord_sig=sign(TEST_KEYS['issuer'], ch))
    if patch:
        patch(g)
    if 'budget' in g:
        consent = g.pop('consent'); g['consent'] = consent
    signed = dict(grant=g, signature=sign(TEST_KEYS['issuer'], r.sha(b'swarma-grant-v3'+r.octets(g))))
    return dict(signed_grant=signed, issuance=dict(txid='55'*32)), r.sha(r.octets(signed))


def bundle(pc=None, cc=None, raw_parent=None, raw_child=None, parent_patch=None, child_patch=None):
    default_p, default_c = contracts()
    p = default_p if pc is None else pc
    c = default_c if cc is None else cc
    pp, pid = grant(p, 'delegator', raw_parent, parent_patch)
    c['parent_grant_id'] = pid if c['parent_grant_id'] == '00'*32 else c['parent_grant_id']
    # Mutations of lexical child bytes are applied after the real parent ID.
    child_bytes = r.octets(c)
    if raw_child:
        child_bytes = raw_child(child_bytes)
    cp, cid = grant(c, 'delegatee', child_bytes, child_patch)
    request = event('delegator', 8186, [['t', 'swarma-delegation-request-v1'], ['parent', pid], ['contract', r.sha(child_bytes)], ['ordinal', str(c['ordinal'])], ['nonce', '66'*32]])
    pol = dict(parent_grant_id=pid, child_grant_id=cid, issuer_owner=owner('issuer_owner'), delegator_owner=owner('issuer_owner'),
               notary_name='id/certifier', notary_owner=owner('issuer_owner'), agreed_by=[])
    statement = dict(notary_seal=dict(txid='77'*32, vout=0, script='76a914'+'88'*20+'88ac'), tip_height=100, tip_hash='99'*32)
    return dict(parent=r.encode(pp), child=r.encode(cp), parent_contract=(raw_parent or r.octets(p)).decode(), child_contract=child_bytes.decode(),
                request=r.encode(request), policy=r.encode(pol), notary_value=r.encode(dict(swarma=dict(notary=dict(attest=public(TEST_KEYS['notary']))))),
                statement=r.encode(statement), parent_text='', child_text='', at=AT)


vectors = []


def add(name, expected, v=None, claim=None):
    v = bundle() if v is None else v
    if expected == 'GRANT_SIGNATURE':
        child_id = r.sha(r.octets(json.loads(v['child'])['signed_grant']))
        edit(v, 'policy', lambda x: x.update(child_grant_id=child_id))
    v = dict(name=name, claim=claim or name, expected=expected, **v)
    if expected == 'ATTEST':
        v['result'] = r.check(v)
        # Fixed fixture signature binds exactly the unsigned candidate bytes.
        v['attestation_signature'] = sign(TEST_KEYS['notary'], v['result']['digest'])
        envelope = dict(attestation=json.loads(v['result']['attestation']), signature=v['attestation_signature'])
        v['attestation_id'] = r.sha(r.octets(envelope))
        preimage = b'swarma-attest-v1'+bytes.fromhex(v['attestation_id'])+bytes.fromhex(json.loads(v['policy'])['child_grant_id'])+bytes.fromhex(json.loads(v['policy'])['parent_grant_id'])
        v['anchor_script'] = '6a03534c044201'+r.sha(preimage)+'01'+v['attestation_id']
    vectors.append(v)


def edit(v, field, fn):
    x = json.loads(v[field]); fn(x); v[field] = r.encode(x)
    return v


def contract_case(name, expected, change, parent=False, **kw):
    p, c = contracts()
    change(p if parent else c)
    add(name, expected, bundle(p, c, **kw))


add('positive-same-owner', 'ATTEST', claim='Canonical signed depth-1 bundle yields exactly the 18-member candidate and fixed-prefix digest.')

p, c = contracts(); c.update(actions=['instruct'], repos=[])
add('positive-narrower', 'ATTEST', bundle(p, c))
p, c = contracts(); text = 'Only the agreed component.'
p['scope_text_sha256'] = c['scope_text_sha256'] = r.sha(text.encode())
v = bundle(p, c); v['parent_text'] = v['child_text'] = text
add('positive-identical-text', 'ATTEST', v, 'Equal text octets are bound, never interpreted.')
p, c = contracts(); p['delegate']['notaries'][0]['owner'] = owner('notary_owner')
v = bundle(p, c)
edit(v, 'policy', lambda x: x.update(delegator_owner=owner('delegator_owner'), notary_owner=owner('notary_owner'), agreed_by=sorted([owner('issuer_owner'), owner('delegator_owner')])))
add('positive-cross-owner', 'ATTEST', v)
# D9 in force accepts any designated notary; pending J2 must not be smuggled in.
p, c = contracts(); n = copy.deepcopy(p['delegate']['notaries'][0]); n['name'] = 'id/second-certifier'; p['delegate']['notaries'].append(n)
v = bundle(p, c); edit(v, 'policy', lambda x: x.update(notary_name=n['name']))
add('positive-other-designated-notary', 'ATTEST', v)

contract_case('negative-actions', 'CHILD_ACTIONS_WIDER', lambda p: p['delegate'].update(actions=['instruct', 'land']), parent=True)
contract_case('negative-repositories', 'CHILD_REPOS_WIDER', lambda c: c.update(repos=['https://git.example/project/core.git']))
contract_case('negative-budget-d12', 'CHILD_ACTIONS_WIDER', lambda c: c.update(actions=['instruct', 'land', 'review', 'spend'], spend_budget=1))
contract_case('negative-budget-without-spend', 'CONTRACT_BUDGET', lambda c: c.update(spend_budget=1))
contract_case('negative-delegated-spend', 'CONTRACT_DELEGATE', lambda p: (p.update(actions=['instruct', 'land', 'review', 'spend'], spend_budget=1), p['delegate'].update(actions=['spend'], budget=1)), parent=True)
contract_case('negative-window-before', 'CHILD_WINDOW_NOT_NESTED', lambda c: c.update(not_before=AT-101))
contract_case('negative-window-after', 'CHILD_WINDOW_NOT_NESTED', lambda c: c.update(not_after=AT+101))
contract_case('negative-ordinal', 'CHILD_ORDINAL', lambda c: c.update(ordinal=2))
contract_case('negative-executor', 'CHILD_AGENT_NOT_ALLOWED', lambda c: c.update(agent_name='id/other-worker'))
p,c=contracts(); p['delegate']['slots'][0]['grantee']=public(TEST_KEYS['other'])
add('negative-grantee', 'CHILD_GRANTEE_NOT_ALLOWED', bundle(p,c))
contract_case('negative-depth-two', 'CHAIN_DEPTH', lambda p: p.update(parent_grant_id='aa'*32,ordinal=1,delegate=zero_delegate()),parent=True)
contract_case('negative-child-redelegation', 'CONTRACT_PARENT', lambda c: c['delegate'].update(depth=1))
contract_case('negative-not-delegable', 'NOT_DELEGABLE', lambda p: p.update(delegate=zero_delegate()), parent=True)
contract_case('negative-parent-id', 'PARENT_ID_MISMATCH', lambda c: c.update(parent_grant_id='ff'*32))
contract_case('negative-subject', 'SUBJECT_MISMATCH', lambda c: c.update(landlord_name='id/other-principal'))
contract_case('negative-profile', 'CONTRACT_PROFILE', lambda c: c.update(profile='swarma-trust-contract/1'))
contract_case('negative-field', 'CONTRACT_FIELD', lambda c: c.update(scope_text_sha256='FF'*32))
contract_case('negative-unknown-action', 'CONTRACT_ACTIONS', lambda c: c.update(actions=['instruct','land','review','unknown']))
contract_case('negative-repo-grammar', 'CONTRACT_REPOS', lambda c: c.update(repos=['https://git.example/../core']))
contract_case('negative-note', 'CONTRACT_NOTE', lambda c: c.update(note='x'*281))
contract_case('negative-parent-shape', 'CONTRACT_PARENT', lambda c: c.update(ordinal=0))
contract_case('negative-no-notaries', 'DELEGATE_NO_NOTARY', lambda p: p['delegate'].update(notaries=[]), parent=True)
contract_case('negative-row-unknown-member', 'CONTRACT_DELEGATE', lambda p: p['delegate']['slots'][0].update(extra=0), parent=True)
contract_case('negative-row-grantee-key', 'CONTRACT_DELEGATE', lambda p: p['delegate']['slots'][0].update(grantee='ff'*32), parent=True)
contract_case('negative-checkpoint', 'CONTRACT_DELEGATE', lambda p: p['delegate'].update(checkpoint=''), parent=True)
contract_case('negative-notary-pin', 'CONTRACT_DELEGATE', lambda p: p['delegate']['notaries'][0].update(owner='04'+'11'*32), parent=True)
contract_case('negative-contract-unknown-member', 'CONTRACT_ENCODING', lambda c: c.update(extra=0))
contract_case('negative-contract-newline', 'CONTRACT_ENCODING', lambda c: None, raw_child=lambda b: b+b'\n')
contract_case('negative-contract-space', 'CONTRACT_ENCODING', lambda c: None, raw_child=lambda b: b.replace(b'{', b'{ ', 1))
contract_case('negative-contract-number', 'CONTRACT_ENCODING', lambda c: None, raw_child=lambda b: b.replace(b'"spend_budget":0', b'"spend_budget":0e0'))
contract_case('negative-contract-escape', 'CONTRACT_ENCODING', lambda c: None, raw_child=lambda b: b.replace(b'id/worker', b'id\\/worker'))
contract_case('negative-contract-duplicate', 'CONTRACT_ENCODING', lambda c: None, raw_child=lambda b: b.replace(b'"ordinal":1', b'"ordinal":1,"ordinal":1'))
contract_case('negative-contract-malformed', 'CONTRACT_ENCODING', lambda c: None, raw_child=lambda b: b[:-1])
p,c=contracts(); c['scope_text_sha256']=r.sha(b'new text'); v=bundle(p,c);v['child_text']='new text';add('negative-text-different','TEXT_JUDGEMENT_REQUIRED',v)
v=copy.deepcopy(vectors[2]); v={k:v[k] for k in bundle()}; v['child_text']='other'; add('negative-text-octets', 'DELEGATION_BUNDLE', v)
# Above uses an identical-text positive as the baseline.
for name, at, code in [('negative-not-yet-valid', AT-101, 'GRANT_NOT_YET_VALID'), ('negative-expired', AT+100, 'GRANT_EXPIRED'), ('negative-no-time', 0, 'AT_TIME')]:
    v=bundle(); v['at']=at; add(name,code,v)
v=bundle(); edit(v,'child',lambda x:x['signed_grant'].update(signature='00'*64)); add('negative-signature', 'GRANT_SIGNATURE',v)
v=bundle(); edit(v,'child',lambda x:x['signed_grant'].update(signature=x['signed_grant']['signature'][:64]+f'{r.N:064x}')); add('negative-signature-s-overflow','GRANT_SIGNATURE',v)
v=bundle(); edit(v,'child',lambda x:x['signed_grant'].update(signature=f'{r.P:064x}'+x['signed_grant']['signature'][64:])); add('negative-signature-r-overflow','GRANT_SIGNATURE',v)
v=bundle(); v['child']+='\n'; add('negative-grant-newline','GRANT_ENCODING',v)
v=bundle(); edit(v,'child',lambda x:x.update(extra=0)); add('negative-grant-unknown-member','GRANT_ENCODING',v)
v=bundle(child_patch=lambda g:g.update(version=4)); add('negative-grant-version','GRANT_FIELD',v)
v=bundle(child_patch=lambda g:g['consent'].update(landlord_sig='00'*64)); add('negative-consent-signature','GRANT_CONSENT',v)
v=bundle(child_patch=lambda g:g.update(contract_sha256='aa'*32)); add('negative-contract-hash-early-consent','GRANT_CONSENT',v)
v=bundle(); v['child_contract']+='\n'; add('negative-contract-hash','CONTRACT_HASH',v)
v=bundle(child_patch=lambda g:g.update(agent_name='id/other-worker')); add('negative-contract-binding','CONTRACT_MISMATCH',v)
v=bundle(child_patch=lambda g:g.update(scope=[])); add('negative-scope-binding','SCOPE_MISMATCH',v)
v=bundle(child_patch=lambda g:g.update(budget=1)); add('negative-budget-binding','BUDGET_MISMATCH',v)
def bad_tags(g):
    e=g['consent']['consent_event']; e['tags'][2][1]='aa'*32
    e['id']=r.event_id(e); e['sig']=sign(TEST_KEYS['delegatee'],e['id'])
v=bundle(child_patch=bad_tags); add('negative-consent-tags','CONSENT_TAGS',v)
for field,value in [('kind',8185),('sig','00'*64)]:
    v=bundle(); edit(v,'request',lambda e:e.update({field:value})); add('negative-request-'+field,'DELEGATION_REQUEST',v)
v=bundle(); v['request']=''; add('negative-request-missing','DELEGATION_REQUEST',v)
v=bundle(); v['policy']=''; add('negative-owner-evidence','OWNER_EVIDENCE_REQUIRED',v)
v=bundle(); edit(v,'policy',lambda x:x.update(issuer_owner=owner('delegator_owner'),delegator_owner=owner('delegator_owner'))); add('negative-owner-relation','NOTARY_OWNER_RELATION',v)
v=bundle(); edit(v,'policy',lambda x:x.update(delegator_owner=owner('delegator_owner'),agreed_by=sorted([owner('issuer_owner'),owner('delegator_owner')]))); add('negative-cross-owner-not-third-party','NOTARY_OWNER_RELATION',v)
v=copy.deepcopy(vectors[3]); v={k:v[k] for k in bundle()}; edit(v,'policy',lambda x:x.update(agreed_by=[])); add('negative-cross-owner-missing-certifier','CROSS_OWNER_CERTIFIER_REQUIRED',v)
v=bundle(); edit(v,'policy',lambda x:x.update(notary_name='id/unknown-certifier')); add('negative-not-designated','NOTARY_NOT_DESIGNATED',v)
p,c=contracts();p['delegate']['notaries'][0]['owner']=owner('other');v=bundle(p,c);add('negative-owner-pin-mismatch','NOTARY_NAME_CHANGED',v)
for name,value in [('negative-notary-key','ff'*32),('negative-notary-is-delegator',public(TEST_KEYS['delegator'])),('negative-notary-is-delegatee',public(TEST_KEYS['delegatee']))]:
    v=bundle(); edit(v,'notary_value',lambda x:x['swarma']['notary'].update(attest=value))
    add(name,{'negative-notary-key':'NOTARY_KEY','negative-notary-is-delegator':'NOTARY_IS_DELEGATOR','negative-notary-is-delegatee':'NOTARY_IS_DELEGATEE'}[name],v)
p,c=contracts(); p['delegate']['notaries'][0]['name']=p['agent_name']; p['delegate']['slots'][0]['notary']=p['agent_name']
v=bundle(p,c); edit(v,'policy',lambda x:x.update(notary_name=p['agent_name'])); add('negative-notary-is-executor','NOTARY_IS_EXECUTOR',v)
v=bundle(); edit(v,'notary_value',lambda x:x['swarma']['notary'].update(extra='')); add('negative-notary-unknown-member','NOTARY_KEY',v)
v=bundle(); edit(v,'statement',lambda x:x.update(tip_hash='')); add('negative-statement','STATEMENT_FIELD',v)


p,c=contracts(); second=copy.deepcopy(p['delegate']['slots'][0]); second['executor']='id/second-worker'; p['delegate']['slots'].append(second); c.update(ordinal=2,agent_name='id/second-worker')
add('positive-second-row','ATTEST',bundle(p,c))
p,c=contracts(); second=copy.deepcopy(p['delegate']['slots'][0]); second['executor']='id/second-worker'; p['delegate']['slots'].append(second); c.update(ordinal=2)
add('negative-other-row-executor','CHILD_AGENT_NOT_ALLOWED',bundle(p,c))
v=bundle(); edit(v,'notary_value',lambda x:x.update(metadata=None,nostr={'names':{'_':public(TEST_KEYS['other'])}})); add('positive-name-extensions','ATTEST',v)
v=bundle(); v['notary_value']=v['notary_value'][:-1]+',"swarma":'+r.encode(json.loads(v['notary_value'])['swarma'])+'}'; add('negative-name-duplicate','NOTARY_KEY',v)
v=bundle(); edit(v,'notary_value',lambda x:x.update(Swarma={})); add('negative-name-alias','NOTARY_KEY',v)
v=bundle(); v['notary_value'] += ' '; add('negative-name-trailing','NOTARY_KEY',v)

contract_case('negative-child-not-yet-valid', 'GRANT_NOT_YET_VALID', lambda c: c.update(not_before=AT+1))
contract_case('negative-child-expired', 'GRANT_EXPIRED', lambda c: c.update(not_after=AT))
v=bundle(); edit(v,'policy',lambda x:x.update(parent_grant_id='ff'*32)); add('negative-policy-binding','OWNER_EVIDENCE_REQUIRED',v)
contract_case('negative-duplicate-depth-first-zero','CONTRACT_DELEGATE',lambda c:None,raw_child=lambda b:b.replace(b'"depth":0',b'"depth":0,"depth":1'))
contract_case('negative-duplicate-depth-first-one','CONTRACT_PARENT',lambda c:None,raw_child=lambda b:b.replace(b'"depth":0',b'"depth":1,"depth":0'))
# Empty notaries must win over malformed row members under rule 9 step 2.
contract_case('negative-no-notaries-order','DELEGATE_NO_NOTARY',lambda p:(p['delegate'].update(notaries=[]),p['delegate']['slots'][0].pop('cap')),parent=True)

v=copy.deepcopy(vectors[3]); v={k:v[k] for k in bundle()}; edit(v,'policy',lambda x:x.update(notary_name='')); add('negative-cross-owner-no-certifier','NOTARY_NOT_DESIGNATED',v)
p,c=contracts(); p['delegate']['notaries'][0]['owner']=owner('delegator_owner'); v=bundle(p,c); edit(v,'policy',lambda x:x.update(delegator_owner=owner('delegator_owner'),notary_owner=owner('delegator_owner'),agreed_by=sorted([owner('issuer_owner'),owner('delegator_owner')]))); add('negative-cross-owner-delegator-only','NOTARY_OWNER_RELATION',v)
for suffix,change in [('parent',lambda e:e['tags'][1].__setitem__(1,'aa'*32)),('contract',lambda e:e['tags'][2].__setitem__(1,'aa'*32)),('ordinal',lambda e:e['tags'][3].__setitem__(1,'01')),('nonce',lambda e:e['tags'][4].__setitem__(1,'')),('time',lambda e:e.update(created_at=AT-101))]:
    v=bundle(); e=json.loads(v['request']); change(e); e['id']=r.event_id(e); e['sig']=sign(TEST_KEYS['delegator'],e['id']); v['request']=r.encode(e); add('negative-request-binding-'+suffix,'DELEGATION_REQUEST',v)

contract_case('negative-parent-row-cap','CONTRACT_DELEGATE',lambda p:p['delegate']['slots'][0].update(cap=1),parent=True)

p,c=contracts(); rows=[]
for name,expected,budget in [('row-zero-positive','ATTEST',0),('row-budget-over','CHILD_BUDGET_OVER',1)]:
    cc=copy.deepcopy(c); cc['spend_budget']=budget
    rows.append(dict(name=name,claim='Isolated row-cap defense; NOT admission of a spend grant.',parent=p,child=cc,expected=expected))

# Exact-size padding uses pushes of at most 520 bytes followed by OP_DROP,
# keeping the seal script below the opcode limit as well as the element limit.
def script_padding(size):
    result = bytearray()
    while size:
        if size >= 260:
            count = min(520, size-4)
            part = b'\x4d' + count.to_bytes(2, 'little') + bytes(count) + b'\x75'
        elif size >= 79:
            count = min(255, size-3)
            part = bytes([0x4c, count]) + bytes(count) + b'\x75'
        elif size >= 3:
            count = min(75, size-2)
            part = bytes([count]) + bytes(count) + b'\x75'
        else:
            part = b'\x00\x75' if size == 2 else b'\x61'
        result.extend(part)
        size -= len(part)
    return result.hex()


# Pin the complete document sizes independently of either reader's size limit.
# The odd-size neighbors use one extra decimal digit in the explicit tip height.
for size in (8191, 8192, 8193):
    v = bundle()
    a = json.loads(vectors[0]['result']['attestation'])
    st = json.loads(v['statement'])
    extra = size - len(r.octets(a))
    if extra % 2:
        st['tip_height'] = a['tip_height'] = 1000
        extra -= 1
    padding_bytes = extra // 2
    st['notary_seal']['script'] = script_padding(padding_bytes) + st['notary_seal']['script']
    a['notary_seal'] = st['notary_seal']
    assert len(r.octets(a)) == size and len(r.octets(st)) < 8192
    v['statement'] = r.encode(st)
    name = ('positive-attestation-' if size <= 8192 else 'negative-attestation-') + str(size)
    add(name, 'ATTEST' if size <= 8192 else 'ATTESTATION_TOO_LARGE', v,
        f'A statement below its own cap composes to exactly {size} attestation bytes; no partial output on refusal.')

# Local deployment approvals sign every policy field except the approvals array.
# These use only the PUBLIC fixed owner test secrets, never production keys.
def approve_mode(v):
    pol = json.loads(v['policy'])
    pol.pop('mode_approvals', None)
    roles = {owner(k): k for k in ('issuer_owner', 'delegator_owner', 'other')}
    identities = []
    names = []
    st = json.loads(v['statement'])
    for k in sorted({pol['issuer_owner'], pol['delegator_owner']}):
        role = roles[k]
        name = 'id/fixture-' + role.replace('_', '-')
        registration = dict(txid=('a1' if role == 'issuer_owner' else 'a2' if role == 'delegator_owner' else 'a3')*32, vout=0)
        identities.append(dict(owner=k, name=name, registration=registration))
        names.append(dict(name=name, registration=registration, value=r.encode(dict(swarma=dict(landlord=dict(grant=public(TEST_KEYS[role]))))), height=st['tip_height'], blockhash=st['tip_hash']))
    digest = r.sha(b'swarma-notary-local-policy-v1' + r.octets(pol) + r.octets(identities))
    pol['mode_approvals'] = [dict(**a, signature=sign(TEST_KEYS[roles[a['owner']]], digest)) for a in identities]
    v['names'] = names
    v['policy'] = r.encode(pol)
    return v


# Re-sign only identities after deliberate fixture changes; public test keys only.
def resign_identities(v):
    pol = json.loads(v['policy']); approvals = pol.pop('mode_approvals')
    identities = [{k:a[k] for k in ('owner','name','registration')} for a in approvals]
    digest = r.sha(b'swarma-notary-local-policy-v1' + r.octets(pol) + r.octets(identities))
    roles = {owner(k): k for k in ('issuer_owner','delegator_owner','other')}
    pol['mode_approvals'] = [dict(**a,signature=sign(TEST_KEYS[roles[a['owner']]],digest)) for a in identities]
    v['policy'] = r.encode(pol)


def mvp_bundle(notary_role='issuer_owner', note=''):
    p, c = contracts()
    p['note'] = note
    p['delegate']['notaries'][0]['owner'] = owner(notary_role)
    other = copy.deepcopy(p['delegate']['notaries'][0]); other['name'] = 'id/second-certifier'
    p['delegate']['notaries'].append(other)
    v = bundle(p, c)
    edit(v, 'policy', lambda x: x.update(delegator_owner=owner('delegator_owner'), notary_owner=owner(notary_role),
         agreed_by=sorted([owner('issuer_owner'), owner('delegator_owner')]), mode='mvp-pair-owned-notary'))
    return approve_mode(v)


for role in ('issuer_owner', 'delegator_owner', 'notary_owner'):
    add('positive-mvp-' + role.replace('_', '-'), 'ATTEST', mvp_bundle(role),
        'Explicit MVP mode with both exact-scope owner signatures; third-party affiliation still follows the strict path.')

v = mvp_bundle(); edit(v, 'policy', lambda x: x.pop('mode_approvals'))
add('negative-mvp-no-approvals', 'MVP_MODE_APPROVAL_REQUIRED', v, 'Mode alone and agreed_by cannot authorize pair-owned certification.')
for index in (0, 1):
    v = mvp_bundle(); edit(v, 'policy', lambda x: x.update(mode_approvals=[x['mode_approvals'][index]]))
    add('negative-mvp-one-approval-' + str(index), 'MVP_MODE_APPROVAL_REQUIRED', v, 'Either unilateral signature refuses; both owners must sign.')
v = mvp_bundle(); edit(v, 'policy', lambda x: x.update(mode_approvals=[x['mode_approvals'][0]] * 2))
add('negative-mvp-duplicate-approval', 'MVP_MODE_APPROVAL_REQUIRED', v)
v = mvp_bundle(); edit(v, 'policy', lambda x: x['mode_approvals'].reverse()); resign_identities(v)
add('negative-mvp-approval-order', 'MVP_MODE_APPROVAL_REQUIRED', v)
v = mvp_bundle(); edit(v, 'policy', lambda x: x['mode_approvals'][0].update(signature='00'*64))
add('negative-mvp-signature', 'MVP_MODE_APPROVAL_REQUIRED', v)
v = mvp_bundle(); edit(v, 'policy', lambda x: x['mode_approvals'][0].update(owner=owner('other')))
add('negative-mvp-unrelated-approver', 'MVP_MODE_APPROVAL_REQUIRED', v)
v = mvp_bundle(note='A different exact grant pair.')
edit(v, 'policy', lambda x: x.update(mode_approvals=json.loads(mvp_bundle()['policy'])['mode_approvals']))
add('negative-mvp-different-grant-pair', 'MVP_MODE_APPROVAL_REQUIRED', v, 'Approvals cannot be replayed on another valid recomputed grant pair.')
for field in ('parent_grant_id', 'child_grant_id'):
    v = mvp_bundle(); edit(v, 'policy', lambda x: x.update({field: 'ff'*32}))
    add('negative-mvp-wrong-' + field.replace('_', '-'), 'OWNER_EVIDENCE_REQUIRED', v)
v = mvp_bundle(); edit(v, 'policy', lambda x: x.update(delegator_owner=owner('other'), agreed_by=sorted([owner('issuer_owner'), owner('other')])))
add('negative-mvp-different-owner-pair', 'MVP_MODE_APPROVAL_REQUIRED', v)
v = mvp_bundle(); edit(v, 'policy', lambda x: x.update(issuer_owner=x['delegator_owner'], delegator_owner=x['issuer_owner']))
add('negative-mvp-swapped-owner-roles', 'MVP_MODE_APPROVAL_REQUIRED', v)
v = mvp_bundle(); edit(v, 'policy', lambda x: x.update(notary_name='id/second-certifier'))
add('negative-mvp-different-notary', 'MVP_MODE_APPROVAL_REQUIRED', v, 'Even another designated notary with the same owner needs fresh bilateral signatures.')
v = mvp_bundle(); edit(v, 'policy', lambda x: x.update(notary_name='id/unlisted-certifier'))
add('negative-mvp-undesignated-notary', 'NOTARY_NOT_DESIGNATED', v)
v = mvp_bundle('delegator_owner')
edit(v, 'policy', lambda x: x.update(mode_approvals=json.loads(mvp_bundle()['policy'])['mode_approvals']))
add('negative-mvp-different-notary-owner', 'MVP_MODE_APPROVAL_REQUIRED', v)
v = mvp_bundle(); edit(v, 'policy', lambda x: x.update(notary_owner=owner('delegator_owner')))
add('negative-mvp-owner-pin-mismatch', 'NOTARY_NAME_CHANGED', v)
v = mvp_bundle(); edit(v, 'policy', lambda x: (x.pop('mode'), x.pop('mode_approvals')))
add('negative-mvp-mode-absent', 'NOTARY_OWNER_RELATION', v, 'Absent mode retains strict third-owner rule even with both configured agreements.')
v = mvp_bundle(); edit(v, 'policy', lambda x: x.pop('mode'))
add('negative-mvp-approvals-without-mode', 'POLICY_MODE_REQUIRED', v)
v = mvp_bundle(); edit(v, 'policy', lambda x: x.update(mode='unknown-mode'))
add('negative-mvp-unknown-mode', 'POLICY_MODE_UNSUPPORTED', v)
v = mvp_bundle(); edit(v, 'policy', lambda x: x.update(mode=''))
add('negative-mvp-empty-mode', 'OWNER_EVIDENCE_REQUIRED', v)
v = mvp_bundle(); edit(v, 'policy', lambda x: x.update(delegator_owner=x['issuer_owner']))
add('negative-mvp-one-owner-pair', 'MVP_MODE_PAIR_REQUIRED', v)
v = mvp_bundle()
pol = json.loads(v['policy']); pol.pop('mode_approvals')
pol['delegator_owner'] = ('03' if pol['issuer_owner'].startswith('02') else '02') + pol['issuer_owner'][2:]
pol['agreed_by'] = sorted([pol['issuer_owner'], pol['delegator_owner']])
identities = [dict(owner=k, name='id/fixture-parity-'+str(i), registration=dict(txid=('a1' if i == 0 else 'a2')*32,vout=0)) for i,k in enumerate(pol['agreed_by'])]
digest = r.sha(b'swarma-notary-local-policy-v1' + r.octets(pol) + r.octets(identities))
pol['mode_approvals'] = [dict(**a,signature=sign(TEST_KEYS['issuer_owner'],digest)) for a in identities]
st=json.loads(v['statement'])
v['names']=[dict(name=a['name'],registration=a['registration'],value=r.encode(dict(swarma=dict(landlord=dict(grant=public(TEST_KEYS['issuer_owner']))))),height=st['tip_height'],blockhash=st['tip_hash']) for a in identities]
v['policy'] = r.encode(pol)
add('negative-mvp-opposite-owner-key', 'MVP_MODE_PAIR_REQUIRED', v,
    'Opposite compressed parities share one BIP-340 authority and cannot count as two owner signing keys, even with valid signatures.')
v = mvp_bundle('notary_owner'); edit(v, 'policy', lambda x: x.update(agreed_by=[])); approve_mode(v)
add('negative-mvp-third-party-no-agreement', 'CROSS_OWNER_CERTIFIER_REQUIRED', v, 'Third-party mode never waives the strict cross-owner agreement gate.')
v = mvp_bundle('notary_owner'); edit(v, 'policy', lambda x: x.pop('mode_approvals'))
add('negative-mvp-third-party-no-mode-approvals', 'MVP_MODE_APPROVAL_REQUIRED', v)



v=mvp_bundle(); v.pop('names')
add('negative-mvp-chain-read-required','MVP_CHAIN_READ_REQUIRED',v,'Running MVP cannot accept policy approvals without chain reads.')
v=mvp_bundle(); edit(v,'policy',lambda p:p['mode_approvals'][1].update(name=p['mode_approvals'][0]['name'])); resign_identities(v)
add('negative-mvp-owner-name-reused','MVP_OWNER_NAME_REUSED',v,'One owner name cannot occupy both approval slots even with two keys.')
v=mvp_bundle(); edit(v,'policy',lambda p:p['mode_approvals'][1].update(registration=p['mode_approvals'][0]['registration'])); v['names'][1]['registration']=v['names'][0]['registration']; resign_identities(v)
add('negative-mvp-owner-registration-reused','MVP_OWNER_REGISTRATION_REUSED',v,'Different names and signing keys with equal registration are one owner identity.')
v=mvp_bundle(); v['names'][0]['value']=r.encode(dict(swarma=dict(landlord=dict(grant=public(TEST_KEYS['other'])))))
add('negative-mvp-stale-grant-key','MVP_MODE_APPROVAL_REQUIRED',v,'An approval under an old key cannot override the current chain grant key.')
for label,change,code in [
 ('unreadable',lambda n:n.update(unreadable=True),'MVP_NAME_UNREADABLE'),
 ('unresolved',lambda n:n.update(name='id/fixture-missing'),'MVP_NAME_UNREADABLE'),
 ('malformed',lambda n:n.update(value='{'),'MVP_NAME_VALUE'),
 ('missing-grant',lambda n:n.update(value='{"swarma":{"landlord":{}}}'),'MVP_NAME_VALUE'),
 ('wrong-key-role',lambda n:n.update(value=r.encode(dict(swarma=dict(notary=dict(attest=public(TEST_KEYS['issuer_owner'])))))),'MVP_NAME_VALUE'),
 ('value-alias',lambda n:n.update(value=n['value'].replace('swarma','Swarma')),'MVP_NAME_VALUE'),
 ('value-duplicate',lambda n:n.update(value=n['value'][:-1]+',"swarma":{}}'),'MVP_NAME_VALUE'),
 ('value-noncanonical',lambda n:n.update(value=n['value'].replace('"grant":','"grant": ')),'MVP_NAME_VALUE'),
 ('height',lambda n:n.update(height=n['height']+1),'MVP_NAME_VIEW_MISMATCH'),
 ('hash',lambda n:n.update(blockhash='ff'*32),'MVP_NAME_VIEW_MISMATCH'),
 ('registration',lambda n:n.update(registration=dict(txid='ff'*32,vout=0)),'MVP_NAME_REGISTRATION_MISMATCH')]:
    v=mvp_bundle(); change(v['names'][0]); add('negative-mvp-name-'+label,code,v)
v=mvp_bundle(); v['names'][0]['value']=' {"extension":null,'+v['names'][0]['value'][1:]
add('positive-mvp-name-extension','ATTEST',v,'Top-level extensions remain allowed while the authority span is exact.')
v=mvp_bundle(); edit(v,'policy',lambda p:p['mode_approvals'][0].update(name='id/fixture-rebound')); v['names'][0]['name']='id/fixture-rebound'
add('negative-mvp-identity-signature-binding','MVP_MODE_APPROVAL_REQUIRED',v,'Changing a name with the same key and registration still needs fresh signatures.')


v=mvp_bundle()
v['names'][0]['value']=r.encode(dict(swarma=dict(landlord=dict(grant=public(TEST_KEYS['other'])))))
pol=json.loads(v['policy']); approvals=pol.pop('mode_approvals')
identities=[{k:a[k] for k in ('owner','name','registration')} for a in approvals]
digest=r.sha(b'swarma-notary-local-policy-v1'+r.octets(pol)+r.octets(identities))
approvals[0]['signature']=sign(TEST_KEYS['other'],digest)
pol['mode_approvals']=approvals;v['policy']=r.encode(pol)
add('positive-mvp-current-grant-key','ATTEST',v,'The chain current grant key may differ from the configured compressed owner identifier; only its signature authorizes approval.')

# Offline synthetic bundle only: no main-network node, wallet or RPC is used.
p, c = contracts(); p['network'] = c['network'] = 'main'
add('positive-main-network-bundle', 'ATTEST', bundle(p, c),
    'A correctly signed synthetic main-network bundle is valid for the pure checker; the regtest-only service must refuse it before signing.')

(ROOT/'testdata/vectors.json').write_text(json.dumps(dict(schema='notary-checker-lab-vectors/1', warning='Fixed public test keys; fabricated chain locators and policy affiliations; no live authority.', vectors=vectors,row_vectors=rows),indent=2)+'\n')
mvp_names=next(v['names'] for v in vectors if v['name']=='positive-mvp-issuer-owner')
(ROOT/'testdata/mvp-names.json').write_bytes(r.octets(mvp_names))
positive=ROOT/'testdata/positive'; positive.mkdir(exist_ok=True)
for k in ('parent','child','parent_contract','child_contract','request','policy','notary_value','statement'):
    (positive/(k.replace('_','-')+'.json')).write_text(vectors[0][k])
print(f'Wrote {len(vectors)} signed bundles and {len(rows)} isolated row vectors')
