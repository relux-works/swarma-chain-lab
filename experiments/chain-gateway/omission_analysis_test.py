# Adapted from the Opus review-of-record omission aid, PR review 5920320803.
# Its original rules are retained; Tip.time, bracket consistency, Source F5 and
# shared lexical/integer kinds are added. This is independent of the Go harness.
# Run: python3 -B omission_analysis_test.py fixtures/vectors.json
# It fails for baseline mismatches or any unpinned rule/group. Redundant lexical
# guards are tested in explicit groups, not silently counted as killed alone.
# Independent Python mirror of experiments/chain-gateway/schema_test.go for single-rule omission analysis.
# Usage: python3 -B chaingw-c1-omission-analysis.py <checkout>/experiments/chain-gateway/fixtures/vectors.json
# Prints 'baseline mismatches' (expected: []) and, per rule, whether disabling it flips any shared vector.
# UNPINNED + non-redundant (see review F4) means a consumer mirror can omit the rule and still pass all vectors.
import json, re, sys, base64, binascii

MAXI = 9007199254740991
NAME = re.compile(r'^[a-z0-9][a-z0-9/._-]*$')
HASH = re.compile(r'^[0-9a-f]{64}$')
INT = re.compile(r'^(0|[1-9][0-9]*)$')
CODES = ["unavailable", "not_found", "malformed", "rate_limited", "unauthorized", "tip_moved"]
NUMRE = re.compile(r'-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?')

class Bad(Exception):
    pass

class Num(str):
    pass

OFF = set()
def on(r):
    return r not in OFF

def parse(raw, limit):
    if on('size') and not (0 < len(raw) <= limit):
        raise Bad('size')
    try:
        s = raw.decode('utf-8')
    except UnicodeDecodeError:
        if on('utf8'):
            raise Bad('utf8')
        s = raw.decode('utf-8', 'replace')
    i = [0]
    def ws():
        while i[0] < len(s) and s[i[0]] in ' \t\n\r':
            i[0] += 1
    def string():
        assert s[i[0]] == '"'
        j = i[0] + 1
        out = []
        while True:
            if j >= len(s):
                raise Bad('eof in string')
            c = s[j]
            if c == '"':
                break
            if c == '\\':
                e = s[j + 1]
                if e == 'u':
                    out.append(chr(int(s[j + 2:j + 6], 16))); j += 6; continue
                out.append({'"': '"', '\\': '\\', '/': '/', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t'}[e]); j += 2; continue
            if ord(c) < 0x20:
                raise Bad('raw control')
            out.append(c); j += 1
        rawtext = s[i[0] + 1:j]
        i[0] = j + 1
        return ''.join(out), rawtext
    def value(depth):
        ws()
        if i[0] >= len(s):
            raise Bad('eof')
        c = s[i[0]]
        if c == '{':
            if on('depth') and depth > 8:
                raise Bad('depth')
            i[0] += 1
            m = {}
            ws()
            if s[i[0]] == '}':
                i[0] += 1; return m
            while True:
                ws()
                if s[i[0]] != '"':
                    raise Bad('key type')
                k, kraw = string()
                if on('escaped_key') and '\\' in kraw:
                    raise Bad('escaped key')
                if on('ascii_key') and any(ord(ch) < 0x20 or ord(ch) > 0x7e for ch in k):
                    raise Bad('non-ascii key')
                for old in m:
                    if on('dup_exact') and old == k:
                        raise Bad('dup')
                    if on('dup_fold') and old != k and old.casefold() == k.casefold():
                        raise Bad('fold')
                ws()
                if s[i[0]] != ':':
                    raise Bad('colon')
                i[0] += 1
                m[k] = value(depth + 1)
                ws()
                if s[i[0]] == ',':
                    i[0] += 1; continue
                if s[i[0]] == '}':
                    i[0] += 1; return m
                raise Bad('object end')
        if c == '[':
            if on('depth') and depth > 8:
                raise Bad('depth')
            i[0] += 1
            a = []
            ws()
            if s[i[0]] == ']':
                i[0] += 1; return a
            while True:
                a.append(value(depth + 1))
                ws()
                if s[i[0]] == ',':
                    i[0] += 1; continue
                if s[i[0]] == ']':
                    i[0] += 1; return a
                raise Bad('array end')
        if c == '"':
            return string()[0]
        if s.startswith('true', i[0]):
            i[0] += 4; return True
        if s.startswith('false', i[0]):
            i[0] += 5; return False
        if s.startswith('null', i[0]):
            i[0] += 4
            if on('null'):
                raise Bad('null')
            return None
        mm = NUMRE.match(s, i[0])
        if mm and mm.end() > i[0]:
            i[0] = mm.end(); return Num(mm.group(0))
        raise Bad('token')
    v = value(1)
    ws()
    if i[0] != len(s):
        if on('trailing'):
            raise Bad('trailing')
    if on('canonical'):
        if enc(v) != s:
            raise Bad('noncanonical')
    if not isinstance(v, dict):
        raise Bad('root')
    return v

def encstr(x):
    o = ['"']
    for ch in x:
        if ch == '"': o.append('\\"')
        elif ch == '\\': o.append('\\\\')
        elif ch == '\n': o.append('\\n')
        elif ch == '\r': o.append('\\r')
        elif ch == '\t': o.append('\\t')
        elif ch == '\b': o.append('\\b')
        elif ch == '\f': o.append('\\f')
        elif ord(ch) < 0x20 or ch in '\u2028\u2029': o.append('\\u%04x' % ord(ch))
        else: o.append(ch)
    o.append('"')
    return ''.join(o)

def enc(v):
    if isinstance(v, dict):
        return '{' + ','.join(encstr(k) + ':' + enc(v[k]) for k in sorted(v, key=lambda z: z.encode())) + '}'
    if isinstance(v, list):
        return '[' + ','.join(enc(x) for x in v) + ']'
    if v is True: return 'true'
    if v is False: return 'false'
    if v is None: return 'null'
    if isinstance(v, Num): return str(v)
    return encstr(v)

def fields(v, *keys):
    if not isinstance(v, dict):
        raise Bad('object')
    if on('exact_fields'):
        if len(v) != len(keys):
            raise Bad('fields')
    for k in keys:
        if k not in v:
            raise Bad('missing ' + k)
    return v

def integer(v, mx, rule):
    if not isinstance(v, Num):
        return False
    if on('int_minimal') and not INT.match(v):
        return False
    try:
        n = int(v)
    except ValueError:
        n = float(v)
    if on(rule) and n > mx:
        return False
    return True

def isstr(v): return isinstance(v, str) and not isinstance(v, Num)
def hashok(v): return isstr(v) and (HASH.match(v) is not None if on('hash') else True)
def nameok(v):
    if not isstr(v): return False
    if on('name_len') and not (1 <= len(v.encode()) <= 255): return False
    if on('name_pattern') and not NAME.match(v): return False
    return True
def netok(v): return (v in ('main', 'regtest')) if on('network_enum') else isstr(v)

def tip(v):
    if on('tip_object'):
        m = fields(v, 'hash', 'height', 'time')
        if not hashok(m['hash']) or not integer(m['height'], MAXI, 'height_max'):
            raise Bad('tip')
        if not integer(m['time'], MAXI, 'time_max'): raise Bad('time')

def outpoint(m): return hashok(m['txid']) and integer(m['vout'], 4294967295, 'vout_max')

def namerec(v, at):
    m = fields(v, 'expired', 'height', 'name', 'name_block_hash', 'txid', 'value_b64', 'vout')
    if (on('expired_bool') and not isinstance(m['expired'], bool)) or not integer(m['height'], MAXI, 'height_max') or not nameok(m['name']) or not hashok(m['name_block_hash']) or not outpoint(m):
        raise Bad('name record')
    if on('name_le_tip') and int(m['height']) > int(at['height']):
        raise Bad('future name')
    if on('name_hash_at_tip') and m['height'] == at['height'] and m['name_block_hash'] != at['hash']:
        raise Bad('name block at tip')
    s = m['value_b64']
    if not isstr(s): raise Bad('value type')
    try:
        b = base64.b64decode(s, validate=on('b64_alphabet'))
    except (binascii.Error, ValueError):
        raise Bad('b64')
    if on('b64_roundtrip') and base64.b64encode(b).decode() != s:
        raise Bad('b64 roundtrip')
    if on('value_520') and len(b) > 520:
        raise Bad('520')

def sealrec(v, at):
    keys = ('state', 'txid', 'vout') if v.get('state') == 'not_in_utxo_set' else ('confirmations', 'script_pubkey', 'state', 'txid', 'vout')
    m = fields(v, *keys)
    if not outpoint(m) or (on('state_enum') and m['state'] not in ('unspent', 'unconfirmed', 'spend_pending', 'not_in_utxo_set')): raise Bad('seal')
    if m['state'] == 'not_in_utxo_set': return
    if not integer(m['confirmations'], MAXI, 'confirmations_max'): raise Bad('confirmations')
    n = int(m['confirmations'])
    if on('confirmations_state') and ((m['state'] == 'unconfirmed' and n != 0) or (m['state'] != 'unconfirmed' and not (1 <= n <= int(at['height'])+1))): raise Bad('state confirmations')
    x = m['script_pubkey']
    if not isstr(x): raise Bad('script type')
    if on('script_max') and len(x) > 20000: raise Bad('script max')
    if on('script_even') and len(x) % 2: raise Bad('script even')
    if on('script_hex') and not re.fullmatch('[0-9a-f]*', x): raise Bad('script hex')

def request(m):
    m = fields(m, 'method', 'params', 'v')
    if on('version') and m['v'] != '1': raise Bad('v')
    meth = m['method']
    if meth == 'getblockcount':
        fields(m['params'])
    elif meth == 'name_show':
        p = fields(m['params'], 'name')
        if not nameok(p['name']): raise Bad('name')
    elif meth == 'gettxout':
        p = fields(m['params'], 'txid', 'vout')
        if not outpoint(p): raise Bad('outpoint')
    else:
        if on('method_closed'): raise Bad('method')

def response(m):
    if m.get('ok') is False:
        m = fields(m, 'error', 'ok', 'v') if on('refusal_fields') else m
        if on('version') and m['v'] != '1': raise Bad('v')
        p = fields(m['error'], 'code') if on('refusal_fields') else m['error']
        if on('code_enum') and p.get('code') not in CODES: raise Bad('code')
        return
    m = fields(m, 'method', 'network', 'ok', 'result', 'tip', 'v')
    if (on('ok_true') and m['ok'] is not True) or (on('version') and m['v'] != '1') or not netok(m['network']):
        raise Bad('envelope')
    tip(m['tip'])
    at = m['tip'] if isinstance(m['tip'], dict) else {'height': '0', 'hash': ''}
    meth = m['method']
    if meth == 'getblockcount':
        if on('gbc_result_empty'): fields(m['result'])
    elif meth == 'name_show': namerec(m['result'], at)
    elif meth == 'gettxout': sealrec(m['result'], at)
    else:
        if on('method_closed'): raise Bad('method')

def snapshot(m):
    m = fields(m, 'consistency', 'mode', 'names', 'network', 'seals', 'tip', 'v', 'written_at')
    if (on('mode') and m['mode'] != 'observe_only') or (on('version') and m['v'] != '1') or not netok(m['network']) or not integer(m['written_at'], MAXI, 'written_max'):
        raise Bad('envelope')
    if on('consistency') and m['consistency'] != 'bracketed': raise Bad('consistency')
    tip(m['tip'])
    at = m['tip']
    ns = m['names']
    if not isinstance(ns, list) or (on('names_min') and len(ns) < 1) or (on('names_max') and len(ns) > 16): raise Bad('names cap')
    prev = None
    for n in ns:
        namerec(n, at)
        s = n['name']
        if prev is not None:
            if on('names_dup') and s == prev: raise Bad('dup name')
            if on('names_order') and s < prev: raise Bad('name order')
        prev = s
    ss = m['seals']
    if not isinstance(ss, list) or (on('seals_min') and len(ss) < 1) or (on('seals_max') and len(ss) > 256): raise Bad('seals cap')
    p = None
    for x in ss:
        sealrec(x, at)
        if p is not None:
            if on('seals_txid_order') and x['txid'] < p['txid']: raise Bad('txid order')
            if x['txid'] == p['txid']:
                if on('seals_dup') and int(x['vout']) == int(p['vout']): raise Bad('dup seal')
                if on('seals_vout_order') and int(x['vout']) < int(p['vout']): raise Bad('vout order')
        p = x

def validate(kind, raw):
    limit = 4096
    if kind == 'snapshot_size':
        if on('size') and not (0 < len(raw) <= 65536): raise Bad('snapsize')
        return
    if kind in ('frame_request', 'frame_response'):
        if kind == 'frame_request': limit = 1024
        if on('frame_nonempty') and len(raw) < 2: raise Bad('frame empty')
        if on('frame_lf') and (len(raw) == 0 or raw[-1:] != b'\n'): raise Bad('frame lf')
        if on('frame_size') and len(raw) - 1 > limit: raise Bad('frame size')
        if on('frame_single') and b'\n' in raw[:-1]: raise Bad('frame single')
        return
    if kind == 'request': limit = 1024
    elif kind == 'snapshot': limit = 65536
    m = parse(raw, 1024 if kind in ('lexical', 'integer_n', 'integer_o') else limit)
    if kind == 'lexical': return
    if kind in ('integer_n', 'integer_o'):
        m = fields(m, 'n')
        if not integer(m['n'], MAXI if kind == 'integer_n' else 4294967295, 'height_max' if kind == 'integer_n' else 'vout_max'): raise Bad('integer')
        return
    {'request': request, 'response': response, 'snapshot': snapshot}[kind](m)

def verdicts(vs):
    out = {}
    for v in vs:
        raw = v['wire'].encode() if v.get('wire') is not None else base64.b64decode(v['wire_b64'])
        try:
            validate(v['kind'], raw); ok = True
        except (Bad, KeyError, TypeError, IndexError, ValueError, AttributeError) as e:
            ok = False
        out[v['name']] = ok
    return out

RULES = ['size', 'utf8', 'escaped_key', 'ascii_key', 'dup_exact', 'dup_fold', 'depth', 'null', 'trailing', 'canonical',
         'exact_fields', 'int_minimal', 'height_max', 'vout_max', 'written_max', 'hash', 'name_len', 'name_pattern', 'network_enum',
         'tip_object', 'expired_bool', 'name_le_tip', 'name_hash_at_tip', 'b64_alphabet', 'b64_roundtrip', 'value_520', 'state_enum',
         'version', 'method_closed', 'refusal_fields', 'code_enum', 'ok_true', 'gbc_result_empty', 'mode', 'names_min', 'names_max',
         'names_dup', 'names_order', 'seals_min', 'seals_max', 'seals_dup', 'seals_txid_order', 'seals_vout_order',
         'frame_nonempty', 'frame_lf', 'frame_size', 'frame_single', 'time_max', 'consistency', 'confirmations_max', 'confirmations_state', 'script_max', 'script_even', 'script_hex']

# These guards overlap by construction: full-byte canonicalization also rejects
# duplicate/escaped/trailing representations, while canonical base64 implies its
# alphabet. Remove the overlapping guards together to isolate the primary guard.
# A single-rule survivor is reported explicitly, with its narrowed claim.
WITNESSES = {'escaped_key':'lexical_escape', 'dup_exact':'lexical_duplicate', 'trailing':'lexical_trailing', 'b64_alphabet':'response_name_base64_alphabet'}
REDUNDANT = {
    'escaped_key': ('escaped_key', 'canonical'),
    'dup_exact': ('dup_exact', 'canonical'),
    'trailing': ('trailing', 'canonical'),
    'b64_alphabet': ('b64_alphabet', 'b64_roundtrip'),
}

def analyze(vs):
    OFF.clear()
    base = verdicts(vs)
    mism = [v['name'] for v in vs if base[v['name']] != v['valid']]
    print('baseline mismatches vs expected:', mism)
    omissions = []
    for r in RULES:
        OFF.clear(); OFF.add(r)
        got = verdicts(vs)
        flips = [n for n in got if got[n] != base[n]]
        if flips:
            print('PINNED   %-20s %s' % (r, flips[:6]))
        elif r in REDUNDANT:
            OFF.update(REDUNDANT[r])
            grouped = verdicts(vs)
            killed = [n for n in grouped if grouped[n] != base[n]]
            print('SURVIVOR %-20s bounded by %s; group killed by %s' % (r, REDUNDANT[r], [WITNESSES[r]] if WITNESSES[r] in killed else []))
            if WITNESSES[r] not in killed: omissions.append(r)
        else:
            print('OMISSION %-20s []' % r)
            omissions.append(r)
    OFF.clear()
    print('omissions:', omissions)
    return not mism and not omissions

if __name__ == '__main__':
    with open(sys.argv[1]) as f:
        corpus = json.load(f)
    sys.exit(0 if analyze(corpus) else 1)
