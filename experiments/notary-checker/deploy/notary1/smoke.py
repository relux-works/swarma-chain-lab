#!/usr/bin/env python3
"""Target-operator-only private regtest smoke; never run on the producer host.

No keygen, secret export, node launch, anchor broadcast or response logging.
The receipt is the only operator record of the generated public key; the
explicitly authorized VM-local name value necessarily carries it too.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.dont_write_bytecode = True
PACK = Path(__file__).resolve().parent
MODULE = PACK.parents[1]
STATE = Path('/var/lib/notary1-install')
RECEIPT = STATE / 'receipt.md'
KEY_LABEL = 'regtest_public_key_receipt_only:\n'
CLI = ['/usr/sbin/runuser', '-u', 'namecoin-node', '--',
       '/opt/namecoin/28.0/bin/namecoin-cli',
       '-conf=/etc/namecoin/notary1-regtest.conf', '-datadir=/var/lib/namecoind-regtest',
       '-regtest=1', '-rpcconnect=127.0.0.1', '-rpcport=18443',
       '-rpccookiefile=/run/namecoind-regtest/.cookie']


class Stop(Exception):
    pass


def need(ok, code):
    if not ok:
        raise Stop(code)


def octets(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def receipt_key(raw):
    need(raw.count(KEY_LABEL) == 1, 'RECEIPT_KEY_LABEL')
    public = raw.split(KEY_LABEL)[1].split('\n', 1)[0]
    need(re.fullmatch('[0-9a-f]{64}', public) is not None, 'RECEIPT_KEY_FORMAT')
    return public


def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and
             stat.S_IMODE(info.st_mode) == 0o600, 'PRIVATE_FILE')
        raw = stream.read(1048577)
        need(len(raw) <= 1048576, 'PRIVATE_FILE_SIZE')
        return raw


def record(line):
    # Call sites supply fixed verdicts or public hashes, never RPC/HTTP bodies.
    fd = os.open(RECEIPT, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    with os.fdopen(fd, 'a') as stream:
        stream.write(line + '\n')


def create(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)


def rpc(method, *params, wallet=False, absent=False):
    # -stdin keeps the name value and name_new randomness out of process argv.
    args = CLI + (['-rpcwallet=notary1-smoke'] if wallet else []) + ['-stdin', method]
    lines = [str(p) if not isinstance(p, (dict, list, bool)) else octets(p).decode() for p in params]
    need(all('\n' not in p and '\r' not in p for p in lines), 'RPC_ARGUMENT')
    result = subprocess.run(args, input=('\n'.join(lines) + '\n').encode() if lines else b'',
                            capture_output=True, timeout=60, check=False)
    if absent:
        need(result.returncode != 0 and b'error code: -4\n' in result.stderr, 'NAME_ALREADY_PRESENT')
        return None
    need(result.returncode == 0, 'RPC_' + method.upper())
    try:
        return json.loads(result.stdout)
    except ValueError:
        return result.stdout.decode().strip()


def view():
    info = rpc('getblockchaininfo')
    need(info['chain'] == 'regtest' and rpc('getconnectioncount') == 0, 'REGTEST_ISOLATION')
    return info


def mine(count, address):
    before = view()
    hashes = rpc('generatetoaddress', count, address)
    after = view()
    need(len(hashes) == count and after['blocks'] == before['blocks'] + count, 'MINE_CONFIRMATION')
    return after


def binding(public):
    spec = json.loads((PACK / 'smoke-binding.json').read_bytes())
    need(spec['name'] == json.loads((PACK / 'deployment-policy.json').read_bytes())['notary_name'], 'SMOKE_NAME')
    return spec['name'], json.loads(octets(spec['value']).replace(b'RECEIPT_PUBLIC_KEY', public.encode())), spec['absent_value']


def reference():
    # Load only the reviewed sibling source, never cwd or PYTHONPATH modules.
    path = MODULE / 'scripts/reference.py'
    spec = importlib.util.spec_from_file_location('reference', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fresh_bundle(registration, info, public):
    ref = reference()
    # Reuse just the existing, reviewed encoders, not the vector-writing tail.
    path = MODULE / 'scripts/make-fixtures.py'
    source = path.read_text()
    need(source.count('\nvectors = []') == 1, 'ENCODER_BOUNDARY')
    sys.modules['reference'] = ref
    env = {'__file__': str(path)}
    exec(compile(source.split('\nvectors = []')[0], str(path), 'exec'), env)
    # Throwaway fixture signers live only in this process, never a file/receipt.
    env['TEST_KEYS'] = {role: secrets.randbelow(ref.N - 1) + 1 for role in env['TEST_KEYS']}
    env['AT'] = int(time.time())
    env['event'].__defaults__ = (env['AT'] - 10,)
    parent, child = env['contracts']()
    parent.update(not_before=env['AT'] - 300, not_after=env['AT'] + 3600)
    child.update(not_before=env['AT'] - 100, not_after=env['AT'] + 1800)
    parent['delegate']['notaries'][0]['registration'] = registration
    bundle = env['bundle'](parent, child)
    name, value, _ = binding(public)
    policy = json.loads(bundle['policy'])
    need(policy['notary_name'] == name and 'mode' not in policy and not policy['agreed_by'], 'STRICT_POLICY')
    statement = json.loads(bundle['statement'])
    statement.update(tip_height=info['blocks'], tip_hash=info['bestblockhash'])
    request = {k: json.loads(bundle[k]) for k in ('parent', 'child', 'parent_contract', 'child_contract', 'request')}
    request.update(policy_reference=digest(octets(policy)), statement=statement)
    # Independent offline preflight before provisioning any policy or signing.
    candidate = dict(bundle, policy=octets(policy).decode(), statement=octets(statement).decode(),
                     notary_value=octets(value).decode())
    need(ref.check(candidate)['digest'], 'BUNDLE_PREFLIGHT')
    return policy, request


def check_response(status, result, expected, request, policy, public):
    if expected != 'ATTEST':
        need(status == 422 and result == {'decision': expected}, 'REFUSAL_EXACT')
        return
    need(status == 200 and set(result) == {'decision', 'signed_attestation', 'anchor_frame'} and
         result['decision'] == 'ATTEST', 'POSITIVE_ATTEST')
    envelope = result['signed_attestation']
    need(set(envelope) == {'attestation', 'signature'}, 'ENVELOPE_SHAPE')
    attestation = envelope['attestation']
    ref = reference()
    _, value, _ = binding(public)
    bundle = {k: octets(request[k]).decode() for k in
              ('parent', 'child', 'parent_contract', 'child_contract', 'request', 'statement')}
    bundle.update(policy=octets(policy).decode(), notary_value=octets(value).decode(),
                  parent_text='', child_text='', at=attestation['attested_at'])
    expected_candidate = ref.check(bundle)
    need(octets(attestation).decode() == expected_candidate['attestation'] and
         abs(int(time.time()) - attestation['attested_at']) <= 60, 'ATTESTATION_BINDINGS')
    need(ref.verify(public, expected_candidate['digest'], envelope['signature']), 'BIP340_SIGNATURE')
    aid = digest(octets(envelope))
    commitment = digest(b'swarma-attest-v1' + bytes.fromhex(aid) +
                        bytes.fromhex(policy['child_grant_id']) + bytes.fromhex(policy['parent_grant_id']))
    frame = '6a03534c044201' + commitment + '01' + aid
    need(result['anchor_frame'] == frame and len(bytes.fromhex(frame)) == 72, 'ANCHOR_FRAME')


def post(request):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request('http://127.0.0.1:8080/v1/attest', octets(request),
                                 {'Content-Type': 'application/json'})
    try:
        response = opener.open(req, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(16385)
        need(len(raw) <= 16384, 'HTTP_SIZE')
        return response.code, json.loads(raw, object_pairs_hook=unique)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'JSON_DUPLICATE')
        result[key] = value
    return result


def observed(name, value):
    opts = dict(nameEncoding='utf8', valueEncoding='utf8')
    current = rpc('name_show', name, opts)
    need(current['name'] == name and current['value'] == octets(value).decode() and
         current['name_encoding'] == 'utf8' and current['value_encoding'] == 'utf8' and
         not current.get('expired', False) and current['expires_in'] > 0, 'NAME_VALUE_CONFIRMATION')
    history = rpc('name_history', name, opts)
    # Compare the resolver's fields, not wallet-only or future RPC extensions.
    fields = ('name', 'value', 'txid', 'vout', 'height', 'expires_in', 'expired',
              'name_encoding', 'value_encoding')
    need(len(history) >= 1 and all(history[-1].get(k) == current.get(k) for k in fields), 'NAME_HISTORY_CONFIRMATION')
    return {'txid': history[0]['txid'], 'vout': history[0]['vout']}


def prepare(public):
    # One-shot only: abort before mutations on any prior artifacts or wallet.
    need(all(not os.path.lexists(STATE / name) for name in
             ('smoke-policy.json', 'smoke-request.json', 'smoke-address.json', 'certify.started')), 'EXISTING_SMOKE')
    view()
    name, value, _ = binding(public)
    rpc('name_show', name, absent=True)
    need(all(w['name'] != 'notary1-smoke' for w in rpc('listwalletdir')['wallets']), 'EXISTING_WALLET')
    rpc('createwallet', 'notary1-smoke', False, False, '', False, True)
    address = rpc('getnewaddress', wallet=True)
    mine(110, address)
    txid, rand = rpc('name_new', name, wallet=True)
    mine(12, address)
    rpc('name_firstupdate', name, rand, txid, octets(value).decode(), wallet=True)
    info = mine(1, address)
    registration = observed(name, value)
    policy, request = fresh_bundle(registration, info, public)
    create(STATE / 'smoke-policy.json', octets(policy))
    create(STATE / 'smoke-request.json', octets(request))
    create(STATE / 'smoke-address.json', octets(address))
    record('binding_registration_and_tip: ' + octets(dict(registration=registration, tip_height=info['blocks'], tip_hash=info['bestblockhash'])).decode())
    record('smoke_policy_sha256: ' + digest(octets(policy)))
    record('smoke_request_sha256: ' + digest(octets(request)))
    record('smoke_prepare: PASS')


def readiness(public):
    status, response = post({})
    check_response(status, response, 'POLICY_REFERENCE', None, None, public)
    record('refusal_control_http_and_decision: 422 POLICY_REFERENCE')


def certify(public):
    policy_raw = private_read(STATE / 'smoke-policy.json')
    request = json.loads(private_read(STATE / 'smoke-request.json'))
    policy = json.loads(policy_raw)
    address = json.loads(private_read(STATE / 'smoke-address.json'))
    need(Path('/etc/notary-service/deployment-policy.json').read_bytes() == policy_raw and
         request['policy_reference'] == digest(policy_raw), 'INSTALLED_SMOKE_POLICY')
    create(STATE / 'certify.started', b'One positive submission only; reconcile receipt before any retry.\n')
    name, value, absent = binding(public)
    info = view()
    need(request['statement']['tip_height'] == info['blocks'] and
         request['statement']['tip_hash'] == info['bestblockhash'], 'PRE_SUBMIT_TIP')
    observed(name, value)
    status, response = post(request)
    check_response(status, response, 'ATTEST', request, policy, public)
    record('positive_smoke_http_decision_signature_anchor: 200 ATTEST BIP340_PASS FRAME_72_BYTES_PASS')
    # The adjacent control changes only the binding and the necessarily new tip.
    # No policy/name/parser bypass, second service, alternate node or key import.
    try:
        view()
        rpc('name_update', name, octets(absent).decode(), wallet=True)
        info = mine(1, address)
        observed(name, absent)
        request['statement'].update(tip_height=info['blocks'], tip_hash=info['bestblockhash'])
        record('binding_absent_request_sha256: ' + digest(octets(request)))
        status, response = post(request)
        check_response(status, response, 'NOTARY_KEY', request, policy, public)
        record('binding_absent_control_http_decision_signed_fields: 422 NOTARY_KEY NONE')
    finally:
        # Keep the authorized local binding; failure here is not acceptance.
        view()
        rpc('name_update', name, octets(value).decode(), wallet=True)
        mine(1, address)
        observed(name, value)
        record('binding_restored_private_regtest_only: PASS')
    rpc('unloadwallet', 'notary1-smoke')
    record('positive_smoke: PASS_WITH_ADJACENT_BINDING_ABSENT_CONTROL')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('prepare', 'readiness', 'certify'))
    args = parser.parse_args()
    need(os.geteuid() == 0 and STATE.is_dir() and not STATE.is_symlink() and
         STATE.stat().st_uid == 0 and stat.S_IMODE(STATE.stat().st_mode) == 0o700, 'TARGET_CUSTODY')
    public = receipt_key(private_read(RECEIPT).decode())
    {'prepare': prepare, 'readiness': readiness, 'certify': certify}[args.phase](public)
    print('PASS SMOKE_' + args.phase.upper())


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # Never echo exceptions, argv, RPC data, HTTP responses or key material.
        print('FAIL SMOKE_ABORT_RECONCILE_PRIVATE_RECEIPT', file=sys.stderr)
        sys.exit(1)
