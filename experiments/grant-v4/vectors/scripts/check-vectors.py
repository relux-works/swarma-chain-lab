#!/usr/bin/env python3
"""Independent LIP-0020 derivation, stdlib only; never imports or runs the lab.

BIP340 is implemented from the BIP's Specification / Default Signing /
Verification algorithms. Affine group arithmetic is deliberately simple and
variable time; it is used only with the three published test scalars.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
ASSENT = 'swarma-contract-assent/1'
ISSUANCE = 'swarma-issuance/1'
REGISTRY = {'swarma-grant/4', 'swarma-invocation/1', 'swarma-receipt/1',
            'swarma-seal-endorsement/1', ASSENT, ISSUANCE,
            'swarma-notary-attestation/2'}
MAX_NUMBER = 2**53 - 1
MAX_TIMESTAMP = 253402300799
MAX_AGE = 259200
REFUSALS = set('''WIRE_SIZE WIRE_JSON WIRE_DUPLICATE WIRE_VALUE WIRE_NUMBER
WIRE_STRING WIRE_NOT_CANONICAL WIRE_TYPE WIRE_MEMBER WIRE_INTEGER WIRE_KEY
WIRE_SIGNATURE_FORM WIRE_SIGNATURE WIRE_ID ASSENT_BINDING ASSENT_PARTY
CONSENT_SHAPE CONSENT_BINDING CONSENT_KEY CONSENT_EVIDENCE CONSENT_SIGNATURE
CONSENT_TIME CONSENT_AGE CONSENT_CONSUMED ISSUANCE_MODE ISSUANCE_FRAME
ISSUANCE_COMMITMENT'''.split())


class Refusal(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refusal(code)


def sha(b):
    return hashlib.sha256(b).digest()


def tagged(tag, b):
    prefix = sha(tag.encode('utf-8'))
    return sha(prefix + prefix + b)


def b32(n):
    return n.to_bytes(32, 'big')


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u:
        if (y + v) % P == 0:
            return None
        slope = 3*x*x * pow(2*y, -1, P) % P
    else:
        slope = (v-y) * pow(u-x, -1, P) % P
    z = (slope*slope-x-u) % P
    return z, (slope*(x-z)-y) % P


def mul(n, point=G):
    result = None
    while n:
        if n & 1:
            result = add(result, point)
        point = add(point, point)
        n >>= 1
    return result


def lift_x(x):
    if x >= P:
        return None
    c = (x**3 + 7) % P
    y = pow(c, (P+1)//4, P)
    if y*y % P != c:
        return None
    return x, y if y % 2 == 0 else P-y


def public_key(scalar):
    require(scalar in (1, 2, 3), 'PUBLIC_TEST_SCALAR_ONLY')
    return b32(mul(scalar)[0]).hex()


def sign(scalar, message):
    require(scalar in (1, 2, 3), 'PUBLIC_TEST_SCALAR_ONLY')
    point = mul(scalar)
    d = scalar if point[1] % 2 == 0 else N-scalar
    t = bytes(a ^ b for a, b in zip(b32(d), tagged('BIP0340/aux', bytes(32))))
    nonce = int.from_bytes(tagged('BIP0340/nonce', t+b32(point[0])+message), 'big') % N
    require(nonce != 0, 'BIP340_NONCE_ZERO')
    r = mul(nonce)
    k = nonce if r[1] % 2 == 0 else N-nonce
    challenge = int.from_bytes(tagged('BIP0340/challenge', b32(r[0])+b32(point[0])+message), 'big') % N
    signature = b32(r[0]) + b32((k+challenge*d) % N)
    verify(public_key(scalar), message, signature)
    return signature


def hex_form(s, length):
    return isinstance(s, str) and re.fullmatch('[0-9a-f]{%d}' % (2*length), s) is not None


def check_key(key):
    require(hex_form(key, 32), 'WIRE_MEMBER')
    point = lift_x(int(key, 16))
    require(point is not None, 'WIRE_KEY')
    return point


def signature_form(sig):
    require(len(sig) == 64, 'WIRE_SIGNATURE_FORM')
    require(int.from_bytes(sig[:32], 'big') < P and int.from_bytes(sig[32:], 'big') < N,
            'WIRE_SIGNATURE')


def verify(key, message, sig):
    signature_form(sig)
    point = check_key(key)
    r, s = int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')
    e = int.from_bytes(tagged('BIP0340/challenge', sig[:32]+bytes.fromhex(key)+message), 'big') % N
    q = add(mul(s), mul((N-e) % N, point))
    require(q is not None and q[1] % 2 == 0 and q[0] == r, 'WIRE_SIGNATURE')


# JSON decoding preserves both duplicate names and the number token's grammar.
class Pairs(list):
    pass


class BadNumber(str):
    pass


def parse_wire(raw, limit, canonical=True):
    require(len(raw) <= limit, 'WIRE_SIZE')
    # RFC 8259 syntax/UTF-8 failure positions and the first lexical depth
    # excess are compared by byte offset, as W9.2 requires. A truncated deep
    # document can therefore fail depth before its later end-of-input error.
    decoded = raw.decode('utf-8', errors='surrogateescape')
    failures = []
    try:
        raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        failures.append((exc.start, 'WIRE_JSON'))
    try:
        value = json.loads(decoded, object_pairs_hook=Pairs,
                           parse_float=BadNumber,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, Pairs):
            failures.append((len(raw)-len(raw.lstrip()), 'WIRE_JSON'))
    except json.JSONDecodeError as exc:
        offset = len(decoded[:exc.pos].encode('utf-8', errors='surrogateescape'))
        failures.append((offset, 'WIRE_JSON'))
    except (ValueError, RecursionError):
        raise Refusal('WIRE_JSON') from None
    depth, quoted, escaped = 0, False, False
    for offset, octet in enumerate(raw):
        if quoted:
            if escaped:
                escaped = False
            elif octet == 92:
                escaped = True
            elif octet == 34:
                quoted = False
        elif octet == 34:
            quoted = True
        elif octet in (123, 91):
            depth += 1
            if depth > 16:
                failures.append((offset, 'WIRE_SIZE'))
                break
        elif octet in (125, 93):
            depth -= 1
    if failures:
        raise Refusal(min(failures)[1])
    defects = set()

    def walk(v, depth):
        if isinstance(v, (Pairs, list)):
            require(depth <= 16, 'WIRE_SIZE')
        if isinstance(v, Pairs):
            seen = set()
            result = {}
            for k, child in v:
                if k in seen:
                    defects.add('WIRE_DUPLICATE')
                seen.add(k)
                scan_string(k)
                result[k] = walk(child, depth+1)
            return result
        if isinstance(v, list):
            return [walk(child, depth+1) for child in v]
        if v is None:
            defects.add('WIRE_VALUE')
        elif isinstance(v, BadNumber) or (type(v) is int and not 0 <= v <= MAX_NUMBER):
            defects.add('WIRE_NUMBER')
        elif isinstance(v, str):
            scan_string(v)
        return v

    def scan_string(s):
        if any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in s):
            defects.add('WIRE_STRING')

    # -0 is syntactically an integer but violates W2.2's unsigned token grammar.
    # parse_int receives the untouched token, before Python's exact int conversion.
    def read_int(token):
        if token.startswith('-'):
            defects.add('WIRE_NUMBER')
        return int(token)
    value = json.loads(decoded, object_pairs_hook=Pairs,
                       parse_int=read_int, parse_float=BadNumber)
    value = walk(value, 1)
    for c in ('WIRE_DUPLICATE', 'WIRE_VALUE', 'WIRE_NUMBER', 'WIRE_STRING'):
        require(c not in defects, c)
    if canonical:
        require(encode(value, limit) == raw, 'WIRE_NOT_CANONICAL')
    return value


def serialize(v):
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode('utf-16-be'))
        return '{' + ','.join(serialize(k)+':'+serialize(v[k]) for k in keys) + '}'
    if isinstance(v, list):
        return '[' + ','.join(serialize(x) for x in v) + ']'
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False, separators=(',', ':'))
    if type(v) is int:
        return str(v)
    if type(v) is bool:
        return 'true' if v else 'false'
    raise Refusal('WIRE_VALUE')


def encode(value, limit):
    def validate(v, depth):
        if isinstance(v, (dict, list)):
            require(depth <= 16, 'WIRE_SIZE')
        if isinstance(v, dict):
            for key, child in v.items():
                validate(key, depth+1)
                validate(child, depth+1)
        elif isinstance(v, list):
            for child in v:
                validate(child, depth+1)
        elif isinstance(v, str):
            require(all(ord(c) >= 32 and not 0xD800 <= ord(c) <= 0xDFFF for c in v), 'WIRE_STRING')
        elif type(v) is int:
            require(0 <= v <= MAX_NUMBER, 'WIRE_NUMBER')
        elif type(v) is not bool:
            raise Refusal('WIRE_VALUE')
    validate(value, 1)
    require(isinstance(value, dict), 'WIRE_JSON')
    raw = serialize(value).encode('utf-8')
    require(len(raw) <= limit, 'WIRE_SIZE')
    return raw


def integer(value, bound):
    require(re.fullmatch(r'0|[1-9][0-9]*', value) is not None, 'WIRE_INTEGER')
    n = int(value)
    require(n <= bound, 'WIRE_INTEGER')
    return n


def exact(v, required, optional=()):
    return isinstance(v, dict) and set(required) <= v.keys() <= set(required) | set(optional)


def read_signed(raw, expected, context=None, references=()):
    require(expected == ASSENT, 'WIRE_TYPE')
    v = parse_wire(raw, 1024)
    require(exact(v, ('payload', 'signature')), 'WIRE_MEMBER')
    p = v['payload']
    require(isinstance(p, dict) and p.get('type') == ASSENT, 'WIRE_TYPE')
    require(exact(p, ('contract', 'genesis', 'party', 'type')), 'WIRE_MEMBER')
    require(all(hex_form(p[k], 32) for k in ('contract', 'genesis', 'party')), 'WIRE_MEMBER')
    check_key(p['party'])
    require(hex_form(v['signature'], 64), 'WIRE_SIGNATURE_FORM')
    payload = encode(p, 1024)
    digest = tagged(ASSENT, payload)
    verify(p['party'], digest, bytes.fromhex(v['signature']))
    identifier = sha(payload).hex()
    for reference in references:
        require(reference == identifier, 'WIRE_ID')
    if context is not None:
        require(p['genesis'] == context['genesis'] and p['contract'] == context['contract'], 'ASSENT_BINDING')
        require(p['party'] == context['party_public_key'], 'ASSENT_PARTY')
    return v, {'signed_hex': raw.hex(), 'payload_hex': payload.hex(),
               'payload_id': identifier, 'content_address': sha(raw).hex(),
               'typed_digest': digest.hex(), 'signature_hex': v['signature']}


def read_unsigned(raw, expected):
    require(expected == ISSUANCE, 'WIRE_TYPE')
    v = parse_wire(raw, 2048)
    require(v.get('type') == ISSUANCE, 'WIRE_TYPE')
    require(exact(v, ('contract', 'genesis', 'grant_id', 'grant_signature',
                      'issuer_assent', 'recipient_consent', 'type')), 'WIRE_MEMBER')
    a, c = v['issuer_assent'], v['recipient_consent']
    require(exact(a, ('party', 'signature')) and exact(c, ('event_id', 'signature'), ('name_output',)), 'WIRE_MEMBER')
    point = c.get('name_output')
    require(point is None or exact(point, ('txid', 'vout')), 'WIRE_MEMBER')
    require(all(hex_form(v[k], 32) for k in ('contract', 'genesis', 'grant_id')), 'WIRE_MEMBER')
    require(hex_form(v['grant_signature'], 64) and hex_form(a['party'], 32) and
            hex_form(a['signature'], 64) and hex_form(c['event_id'], 32), 'WIRE_MEMBER')
    if point is not None:
        require(hex_form(point['txid'], 32) and type(point['vout']) is int, 'WIRE_MEMBER')
        require(point['vout'] <= 2**32-1, 'WIRE_INTEGER')
    require(hex_form(c['signature'], 64), 'WIRE_MEMBER')
    check_key(a['party'])
    return {'preparation_hex': raw.hex(), 'commitment': tagged(ISSUANCE, raw).hex()}


EVENT_FIELDS = ('id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig')


def event_bytes(v):
    return ('{' + ','.join(serialize(k)+':'+serialize(v[k]) for k in EVENT_FIELDS) + '}').encode('ascii')


def event_preimage(v):
    return serialize([0, v['pubkey'], v['created_at'], v['kind'], v['tags'], v['content']]).encode('ascii')


def event_shape(raw):
    try:
        v = parse_wire(raw, 2048, canonical=False)
        require(exact(v, EVENT_FIELDS), 'CONSENT_SHAPE')
        require(all(ord(c) <= 126 for c in serialize(v)), 'CONSENT_SHAPE')
        require(hex_form(v['id'], 32) and hex_form(v['pubkey'], 32) and hex_form(v['sig'], 64), 'CONSENT_SHAPE')
        require(v['content'] == '' and type(v['kind']) is int and v['kind'] == 8181, 'CONSENT_SHAPE')
        require(type(v['created_at']) is int and 1 <= v['created_at'] <= MAX_TIMESTAMP, 'CONSENT_SHAPE')
        tags = v['tags']
        require(isinstance(tags, list) and len(tags) in (4, 5), 'CONSENT_SHAPE')
        for i, t in enumerate(tags):
            require(isinstance(t, list) and len(t) == 2 and all(isinstance(s, str) for s in t)
                    and t[0] == ('t', 'genesis', 'contract', 'issuer', 'name')[i], 'CONSENT_SHAPE')
        require(tags[0][1] == 'swarma-contract-consent/1', 'CONSENT_SHAPE')
        require(all(hex_form(tags[i][1], 32) for i in (1, 2, 3)), 'CONSENT_SHAPE')
        check_key(v['pubkey'])
        check_key(tags[3][1])
        require(event_bytes(v) == raw and sha(event_preimage(v)).hex() == v['id'], 'CONSENT_SHAPE')
        return v
    except (Refusal, UnicodeError):
        raise Refusal('CONSENT_SHAPE') from None


def read_consent(raw, ctx):
    v = event_shape(raw)
    tags = v['tags']
    require(tags[1][1] == ctx['genesis'] and tags[2][1] == ctx['contract']
            and tags[3][1] == ctx['issuer_public_key'], 'CONSENT_BINDING')
    if ctx['mode'] == 'key':
        require(len(tags) == 4, 'CONSENT_BINDING')
        require(v['pubkey'] == ctx['request_public_key'], 'CONSENT_KEY')
    elif ctx['mode'] == 'name':
        require(len(tags) == 5 and tags[4][1] == ctx['recipient_name'], 'CONSENT_BINDING')
        e = ctx.get('evidence')
        require(e is not None and e.get('confirmed', False) and e.get('height', 0) <= ctx['recent_block_height']
                and e.get('operation_of_name', False) and e.get('live_at_recent_block', False) and e.get('owner_matches', False)
                and (e.get('spent_at_height') is None or e['spent_at_height'] > ctx['recent_block_height']), 'CONSENT_EVIDENCE')
        require(e.get('yields_public_key') == v['pubkey'], 'CONSENT_KEY')
    else:
        raise Refusal('CONSENT_BINDING')
    try:
        verify(v['pubkey'], bytes.fromhex(v['id']), bytes.fromhex(v['sig']))
    except Refusal:
        raise Refusal('CONSENT_SIGNATURE') from None
    require(v['created_at'] <= ctx['clock'], 'CONSENT_TIME')
    return v


def consent_output(v):
    return {'event_hex': event_bytes(v).hex(), 'event_id': v['id'],
            'signature_hex': v['sig'], 'public_key': v['pubkey'], 'created_at': str(v['created_at'])}


def evaluate(op, x):
    if op == 'encode':
        return {'canonical_hex': encode(x['document'], x['limit']).hex()}
    if op == 'parse':
        value = parse_wire(bytes.fromhex(x['raw_hex']), x['limit'])
        return {'canonical_hex': encode(value, x['limit']).hex()}
    if op == 'integer':
        return {'value': str(integer(x['value'], int(x['bound'])))}
    if op in ('primitive', 'signature'):
        raw = encode(x['document'], 2**20)
        tag = x['document'].get('type')
        require(tag in REGISTRY if isinstance(tag, str) else False, 'WIRE_TYPE')
        digest = tagged(tag, raw)
        out = {'canonical_hex': raw.hex(), 'tag_hex': tag.encode().hex(),
               'tag_sha256': sha(tag.encode()).hex(), 'tagged_hash': digest.hex(),
               'typed_digest': digest.hex(), 'payload_id': sha(raw).hex()}
        if op == 'signature':
            out['public_key'] = public_key(x['public_test_scalar'])
            out['signature_hex'] = sign(x['public_test_scalar'], digest).hex()
        return out
    if op == 'key':
        check_key(x['public_key'])
        return {}
    if op == 'signature_form':
        raise NotJudged('preflight API success/refusal is not W5.2 verification')
    if op == 'verify':
        verify(x['public_key'], bytes.fromhex(x['digest']), bytes.fromhex(x['signature_hex']))
        return {}
    if op == 'memberless_signed':
        value = parse_wire(bytes.fromhex(x['raw_hex']), 2048)
        require(exact(value, ('payload', 'signature')), 'WIRE_MEMBER')
        payload = value['payload']
        require(payload.get('type') == x['expected_type'], 'WIRE_TYPE')
        raw = encode(payload, 2048)
        verify(x['place_public_key'], tagged(payload['type'], raw), bytes.fromhex(value['signature']))
        # W3.1 rejects the actual, independently authenticated type-only input.
        require(payload['type'] in REGISTRY - {ASSENT, ISSUANCE}, 'MEMBERLESS_PLACE')
        raise Refusal('WIRE_TYPE')
    if op == 'signed':
        return read_signed(bytes.fromhex(x['raw_hex']), x['expected_type'],
                           x.get('context'), x.get('references', ()))[1]
    if op == 'unsigned':
        return read_unsigned(bytes.fromhex(x['raw_hex']), x['expected_type'])
    if op == 'consent_encode':
        if any(t[0] == 'name' and len(t[1].encode()) > 255 for t in x['tags']):
            raise NotJudged('name profile and inherited tag-value limit are unresolved')
        pk = public_key(x['public_test_scalar'])
        v = {'pubkey': pk, 'created_at': x['created_at'], 'kind': 8181,
             'tags': x['tags'], 'content': ''}
        preimage = event_preimage(v)
        identifier = sha(preimage)
        v['id'] = identifier.hex()
        v['sig'] = sign(x['public_test_scalar'], identifier).hex()
        event = event_bytes(v)
        event_shape(event)
        verify(pk, identifier, bytes.fromhex(v['sig']))
        return {'event_hex': event.hex(), 'id_preimage_hex': preimage.hex(),
                'event_id': identifier.hex(), 'signature_hex': v['sig'], 'public_key': pk}
    if op in ('consent', 'issuer'):
        ctx = dict(x['context'])
        if op == 'issuer' and ctx['mode'] == 'name':
            snapshot = x.get('snapshot')
            require(snapshot is not None, 'CONSENT_EVIDENCE')
            n = snapshot['name']
            ctx['recent_block_height'] = snapshot['recent_block_height']
            ctx['evidence'] = {'confirmed': n['confirmed'], 'height': n['height'],
                               'operation_of_name': True, 'live_at_recent_block': n['live'],
                               'owner_matches': n['owner_matches'], 'yields_public_key': n['yields_public_key']}
        v = read_consent(bytes.fromhex(x['raw_hex']), ctx)
        if op == 'issuer':
            if ctx['clock']-v['created_at'] > MAX_AGE and v['id'] in x.get('consumed_event_ids', []):
                raise NotJudged('W7.8/W7.9 do not order age and consumption')
            require(ctx['clock']-v['created_at'] <= MAX_AGE, 'CONSENT_AGE')
            require(v['id'] not in x.get('consumed_event_ids', []), 'CONSENT_CONSUMED')
            return {}
        return consent_output(v)
    if op == 'issuance':
        g = x['stated_grant_facts']
        if g is None:
            raise NotJudged('absent-grant API has no specified W9.4 step-1 code')
        point = x.get('name_output')
        if point is not None and point['vout'] > 2**32-1:
            raise NotJudged('evidence outpoint bound/refusal placement is unspecified')
        require(g['mode'] in ('key', 'name') and ((g['mode'] == 'name') == (point is not None)), 'ISSUANCE_MODE')
        context = {'genesis': g['genesis'], 'contract': g['contract'], 'party_public_key': g['party_public_key']}
        assent, _ = read_signed(bytes.fromhex(x['assent_hex']), ASSENT, context)
        context = {k: g[k] for k in ('mode', 'genesis', 'contract', 'issuer_public_key',
                                    'request_public_key', 'recipient_name', 'recent_block_height')}
        context.update(clock=x['clock'], evidence=x.get('stated_evidence'))
        consent = read_consent(bytes.fromhex(x['consent_hex']), context)
        rc = {'event_id': consent['id'], 'signature': consent['sig']}
        if point is not None:
            rc['name_output'] = {'txid': point['txid'], 'vout': point['vout']}
        document = {'type': ISSUANCE, 'genesis': g['genesis'], 'contract': g['contract'],
                    'grant_id': g['grant_id'], 'grant_signature': g['grant_signature'],
                    'issuer_assent': {'party': assent['payload']['party'], 'signature': assent['signature']},
                    'recipient_consent': rc}
        raw = encode(document, 2048)
        result = read_unsigned(raw, ISSUANCE)
        require(hex_form(g['content_address'], 32), 'ISSUANCE_FRAME')
        script = bytes.fromhex(x['frame_hex'])
        require(x['frame_value'] == 0 and x['op_return_count'] == 1 and len(script) == 72, 'ISSUANCE_FRAME')
        require(script[:7] == bytes.fromhex('6a03534c014202') and script[39] == 1
                and script[40:] == bytes.fromhex(g['content_address']), 'ISSUANCE_FRAME')
        require(script[7:39].hex() == result['commitment'], 'ISSUANCE_COMMITMENT')
        result['frame_hex'] = script.hex()
        return result
    raise ValueError('unknown operation')


def checked_evaluate(op, inputs):
    try:
        out = evaluate(op, inputs)
        return dict(out, code='ok')
    except Refusal as refusal:
        return {'code': str(refusal)}


def self_check():
    # BIP340 official vector 0 is an external positive control, not Go output.
    expected = ('e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215'
                '25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0')
    require(sign(3, bytes(32)).hex() == expected, 'BIP340_CONTROL_SIGN')
    sig = bytes.fromhex(expected)
    verify(public_key(3), bytes(32), sig)
    # The same independent verifier must reject an altered message beside that control.
    try:
        verify(public_key(3), bytes(31)+b'\x01', sig)
    except Refusal as refusal:
        require(str(refusal) == 'WIRE_SIGNATURE', 'BIP340_CONTROL_WRONG_REFUSAL')
    else:
        raise ValueError('BIP340 negative control survived')


class NotJudged(Exception):
    """A lab API verdict not determined by the pinned specification."""


def derivable_bytes(op, x):
    # Even where a verdict is not specified, every published successful byte
    # output is re-derived without making that API decision.
    if op == 'signature_form':
        return {'signature_hex': bytes.fromhex(x['signature_hex']).hex()}
    if op == 'consent_encode':
        v = {'pubkey': public_key(x['public_test_scalar']), 'created_at': x['created_at'],
             'kind': 8181, 'tags': x['tags'], 'content': ''}
        pre = event_preimage(v)
        identifier = sha(pre)
        v.update(id=identifier.hex(), sig=sign(x['public_test_scalar'], identifier).hex())
        return {'event_hex': event_bytes(v).hex(), 'id_preimage_hex': pre.hex(),
                'event_id': identifier.hex(), 'signature_hex': v['sig'], 'public_key': v['pubkey']}
    return {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('vectors', type=Path, nargs='?', default=Path(__file__).resolve().parents[1]/'vectors.json')
    args = parser.parse_args()
    try:
        self_check()
        data = json.loads(args.vectors.read_text(encoding='utf-8'))
        require(data['format'] == 'swarma-lab-primitives/1' and
                data['scope'] == 'no valid swarma-grant/4 vectors until LIP-0020 defines its members; arithmetic and stated facts only' and
                data['spec_revision'] == 'bd3bc80e5543d8a563343ec05abd1a5f3f67284c' and
                data['lab_revision'] == '8a47f1a984cd93864402f7fdc09d2eba0d890b90' and
                data['lab_spec_revision'] == 'adae6e7669601f271f7d0d9cdd91ecee7d19bf02' and
                data['public_test_scalars'] == [1, 2, 3] and data['aux_rand'] == '00'*32,
                'FIXTURE_METADATA')
        seen, codes, findings, not_judged = set(), Counter(), [], []
        rows = {r['id']: r for r in data['vectors']}
        for row in data['vectors']:
            require(row['id'] not in seen and row['id'] and row['purpose'] and row['reason']
                    and row['spec'].startswith('LIP-0020 '), 'FIXTURE_ID_OR_CITATION')
            require(row['basis'] in ('spec', 'lab-choice') or row['basis'].startswith('contingent:'), 'FIXTURE_BASIS')
            if row['output']['code'] != 'ok':
                neighbour = rows.get(row.get('valid_neighbour'))
                require(neighbour is not None and neighbour['output']['code'] == 'ok' and row.get('defects'), 'FIXTURE_NEIGHBOUR_OR_DEFECTS')
            seen.add(row['id'])
            try:
                actual = checked_evaluate(row['operation'], row['input'])
                require(row['basis'] != 'lab-choice', 'UNLABELLED_LAB_JUDGMENT')
                codes[actual['code']] += 1
                expected = row['output']
            except NotJudged as exc:
                require(row['basis'] == 'lab-choice', 'UNLABELLED_LAB_CHOICE')
                not_judged.append((row['id'], str(exc)))
                derived = derivable_bytes(row['operation'], row['input'])
                expected = {k: v for k, v in row['output'].items() if k != 'code'}
                actual = {k: derived[k] for k in expected if k in derived}
            if actual != expected:
                fields = sorted(k for k in actual.keys() | expected.keys() if actual.get(k) != expected.get(k))
                findings.append(f"FINDING {row['id']} ({row['spec']}): disagreement in {','.join(fields)}")
        require(REFUSALS <= codes.keys(), 'FIXTURE_MISSING_REFUSAL_CLASS')
        for identifier, reason in not_judged:
            print(f'not judged: {identifier}: {reason}')
        for finding in findings:
            print(finding, file=sys.stderr)
        if findings:
            return 1
        successes = sum(r['output']['code'] == 'ok' for r in data['vectors'])
        print(f"agreement: {len(seen)} vectors; all {successes} valid byte outputs; {len(not_judged)} verdicts not judged; {len(REFUSALS)} specified refusal classes; BIP340 controls passed")
        return 0
    except (OSError, ValueError, KeyError, TypeError, Refusal) as exc:
        print(f'check failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
