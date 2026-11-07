#!/usr/bin/env python3
"""Disposable closed regtest. Export only the explicit public document map.

The transaction/signature/verification paths have no simulated-chain adapter.
Mainnet entry is an unconditional stop, before RPC or wallet/address creation.
"""
import argparse
import base64
import hashlib
import hmac
import http.client
import json
import os
import secrets
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from protocol import GENESIS, READ_METHODS, RPCError, ReadRPC, canon, H
from transaction import build_signed
from funding import funding_model

os.umask(0o077)
LAB = Path('/lab'); NODE = LAB / 'node'; PUBLIC = LAB / 'public'
PORT = 18443
RATE_NMC_KVB = Decimal('0.00200000')  # bounded assumption, NOT a mainnet quote
RATE_SAT_VB = 200
VSIZE_CAP = 600
TX_FEE_CAP = Decimal('0.00120000')
FUNDING = Decimal(funding_model()['recipient_required_sat']) / Decimal(100000000)
ROLE_B_FUNDING = Decimal('0.01436600')
SEAL_VALUE = Decimal('0.00100000')
NAME_LOCK = Decimal('0.01000000')
MAX_OPERATIONS = 10
# DER signature lengths vary. These ceilings exceed the measured signed
# templates and admit no extra input, changed name length or transaction shape.
SIZE_CEILINGS = {'fund_B': 230, 'A_name_new': 252, 'B_name_new': 252,
    'A_name_firstupdate': 514, 'B_name_firstupdate': 514,
    'A_seal_funding': 230, 'B_seal_funding': 230,
    'A_grant_anchor': 534, 'B_grant_anchor': 534, 'A_seal_revoke': 196,
    'bootstrap_exact_lab_funding': 230}
BASE_SIZE_CEILINGS = dict(SIZE_CEILINGS)
# Separate disposable regression budget, not part of the original ten-operation
# workflow's conditional funding calculation. No mainnet permission is implied.
LINEAGE_SIZE_CEILINGS = {'lineage_control_funding_A': 230, 'lineage_control_funding_B': 230,
    'lineage_A_same_owner': 600, 'lineage_A_away': 600, 'lineage_A_return': 600}
SIZE_CEILINGS.update(LINEAGE_SIZE_CEILINGS)
FEE_CEILINGS = {key: Decimal(size * RATE_SAT_VB) / Decimal(100000000)
                for key, size in SIZE_CEILINGS.items()}
FEE_CEILINGS['A_seal_revoke'] = Decimal('0.00050000')
MAINNET_BROADCAST = False
R = {'started_at': None, 'status': 'RUNNING', 'network': 'regtest',
     'mainnet_broadcast_enabled': MAINNET_BROADCAST, 'transactions': [], 'cases': {},
     'rpc_calls': [], 'cleanup': {}, 'limitations': [
         'single trusted fully validating node; no SPV or independent tip qualification',
         'tip equality is not an atomic mempool snapshot and cannot detect ABA tip changes',
         'one-block final means this lab policy only, not irreversible consensus finality',
         'requests are multi-use; nonce is signed but no replay ledger is provided',
         'delegation/transfer/rotation are refused; optional narrowed child not implemented',
         'mainnet fees, relay, inclusion, node-at-tip and funding are not observed',
     ]}
DOCS = {}; CHILDREN = []; STATE = {}; COOKIE = None; DEADLINE = None; OBSERVER = None


def utc():
    return datetime.now(timezone.utc).isoformat()


def bounds():
    if time.time() >= DEADLINE:
        raise RuntimeError('immutable execution/export deadline reached')
    fs = os.statvfs('/lab')
    used = (fs.f_blocks - fs.f_bfree) * fs.f_frsize
    if used > 1200 * 1024 * 1024:
        raise RuntimeError('private tmpfs stop threshold 1200 MiB')
    return used


def write(name, obj):
    # Only public data may be passed here. No config, wallet, cookie or node log.
    obj = json.loads(json.dumps(obj, default=str))
    DOCS[name] = obj
    (PUBLIC / name).write_bytes(canon(obj))


def rpc(method, *params, wallet=''):
    global COOKIE
    bounds()
    if COOKIE is None:
        COOKIE = (NODE / 'regtest/.cookie').read_text().strip()
    start = time.monotonic_ns()
    conn = http.client.HTTPConnection('127.0.0.1', PORT, timeout=10)
    try:
        body = json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': params},
                          default=lambda x: float(x) if isinstance(x, Decimal) else str(x))
        conn.request('POST', '/wallet/' + wallet if wallet else '/', body,
                     {'Authorization': 'Basic ' + base64.b64encode(COOKIE.encode()).decode(),
                      'Content-Type': 'application/json'})
        response = conn.getresponse()
        result = json.loads(response.read(8 * 1024 * 1024), parse_float=Decimal)
        code = result['error']['code'] if result.get('error') else None
        R['rpc_calls'].append({'method': method, 'wallet_role': wallet or 'node',
                              'at': utc(), 'elapsed_ns': time.monotonic_ns() - start,
                              'http_status': response.status, 'rpc_code': code})
        if code is not None:
            message = result['error']['message'][:500]
            for secret in (COOKIE, COOKIE.split(':', 1)[-1]):
                message = message.replace(secret, '<redacted>')
            R['rpc_calls'][-1]['error_message'] = message
            raise RPCError(method, response.status, code)
        return result['result']
    finally:
        conn.close()


def check_network():
    info = rpc('getblockchaininfo')
    if info['chain'] != 'regtest' or rpc('getblockhash', 0) != GENESIS['regtest']:
        raise RuntimeError('wrong network; signing/broadcast refused')


def mine(count=1):
    check_network()
    return rpc('generatetoaddress', count, STATE['miner'])


def txdata(txid):
    return rpc('getrawtransaction', txid, True)


def point(txid, address):
    output = next(v for v in txdata(txid)['vout'] if v['scriptPubKey'].get('address') == address)
    return {'txid': txid, 'vout': output['n'], 'script': output['scriptPubKey']['hex'],
            'value': str(output['value'])}


def measure(label, txid, started_ns, broadcast_at, experiment=True):
    before = txdata(txid)
    if before.get('confirmations', 0) != 0 or txid not in rpc('getrawmempool'):
        raise RuntimeError('broadcast not observed in mempool; stop without rebroadcast')
    mining_started_at = utc()
    mine()
    mining_returned_at = utc()
    tx = txdata(txid)
    inclusion_observed_at = utc()
    inclusion_observed_ns = time.monotonic_ns()
    if tx.get('confirmations', 0) != 1:
        raise RuntimeError('inclusion/reorg surprise; stop')
    ins = sum(Decimal(str(txdata(v['txid'])['vout'][v['vout']]['value'])) for v in tx['vin'])
    fee = ins - sum(Decimal(str(v['value'])) for v in tx['vout'])
    if fee > FEE_CEILINGS[label] or tx['vsize'] > SIZE_CEILINGS[label]:
        raise RuntimeError('fee/size surprise exceeds precomputed cap; stop')
    row = {'operation': label, 'txid': txid, 'bytes': tx['size'], 'vbytes': tx['vsize'],
           'weight': tx['weight'], 'fee_nmc': str(fee), 'fee_cap_nmc': str(FEE_CEILINGS[label]),
           'size_ceiling_vbytes': SIZE_CEILINGS[label],
           'broadcast_at': broadcast_at, 'observed_inclusion_at': inclusion_observed_at,
           'mining_started_at': mining_started_at, 'mining_returned_at': mining_returned_at,
           'broadcast_to_inclusion_ns': inclusion_observed_ns - started_ns,
           'height': rpc('getblockheader', tx['blockhash'])['height'],
           'blockhash': tx['blockhash'], 'confirmations': tx['confirmations'],
           'mempool_seen_before_mining': True, 'experiment_budget': experiment,
           'timing_kind': 'local generated regtest block; not a mainnet latency estimate'}
    R['transactions'].append(row)
    if experiment and sum(x['experiment_budget'] for x in R['transactions']) > MAX_OPERATIONS:
        raise RuntimeError('transaction-count budget exceeded')
    # Raw signed transactions contain no private signing material; these public
    # closed-regtest bytes permit fee/size and name/commitment inspection.
    write(label + '-transaction.json', tx)
    return row


def send(label, method, *params, wallet='', experiment=True):
    check_network()
    start = time.monotonic_ns(); at = utc()
    if method == 'sendrawtransaction':
        validate_signed(params[0], label)
        start = time.monotonic_ns(); at = utc()
    txid = rpc(method, *params, wallet=wallet)
    if method != 'sendrawtransaction':
        # walletbroadcast=0 makes wallet helpers construct/commit locally only.
        # Apply exact signed fee/size/policy guards before the first broadcast.
        raw = rpc('gettransaction', txid, wallet=wallet)['hex']
        actual_txid, start, at = broadcast_checked(raw, label)
        if actual_txid != txid:
            raise RuntimeError('wallet transaction identity mismatch')
    return txid, measure(label, txid, start, at, experiment)


def validate_signed(raw, label):
    check_network()
    decoded = rpc('decoderawtransaction', raw)
    fee = sum(Decimal(str(txdata(v['txid'])['vout'][v['vout']]['value'])) for v in decoded['vin']) - sum(Decimal(str(v['value'])) for v in decoded['vout'])
    if decoded['vsize'] > SIZE_CEILINGS[label] or not 0 <= fee <= FEE_CEILINGS[label]:
        raise RuntimeError('signed transaction exceeds fee/size cap before broadcast')
    accepted = rpc('testmempoolaccept', [raw])[0]
    if not accepted['allowed']:
        R['last_policy_refusal'] = {k: accepted[k] for k in ('allowed', 'reject-reason') if k in accepted}
        raise RuntimeError('transaction not relayable; stop without replacement')
    return decoded


def broadcast_checked(raw, label):
    validate_signed(raw, label)
    started = time.monotonic_ns(); at = utc()
    txid = rpc('sendrawtransaction', raw, Decimal('0.00300000'))
    return txid, started, at


def raw_signed(role, inputs, outputs, name_op=None):
    return build_signed(rpc, check_network, role, inputs, outputs,
                        rate_sat_vb=RATE_SAT_VB, vsize_cap=VSIZE_CAP,
                        fee_cap=TX_FEE_CAP, name_op=name_op)


def identity(role):
    return {k: STATE[role][k] for k in ('name', 'address', 'pubkey', 'identity_txid')}


def setup():
    check_network()
    STATE['genesis'] = rpc('getblockhash', 0)
    for role in ('miner', 'A', 'B'):
        rpc('createwallet', role, False, False, '', False, False)
        address = rpc('getnewaddress', '', 'legacy', wallet=role)
        STATE[role] = {'address': address, 'pubkey': rpc('getaddressinfo', address, wallet=role)['pubkey']}
        rpc('settxfee', RATE_NMC_KVB, wallet=role)
    STATE['miner'] = STATE['miner']['address']
    mine(120)
    check_network()
    policy = rpc('getnetworkinfo'); pool = rpc('getmempoolinfo')
    R['policy'] = {'core_subversion': policy['subversion'], 'core_version': policy['version'],
                   'relayfee_nmc_kvb': str(policy['relayfee']),
                   'incrementalfee_nmc_kvb': str(policy['incrementalfee']),
                   'mempoolminfee_nmc_kvb': str(pool['mempoolminfee']),
                   'estimatesmartfee': rpc('estimatesmartfee', 6),
                   'configured_wallet_rate_nmc_kvb': str(RATE_NMC_KVB),
                   'rate_status': 'bounded assumption; estimator unavailable on fresh closed regtest',
                   'fresh_mainnet_policy_estimator_check_required': True}
    if max(policy['relayfee'], pool['mempoolminfee']) > RATE_NMC_KVB:
        raise RuntimeError('fresh node minimum fee exceeds assumption')
    send('bootstrap_exact_lab_funding', 'sendtoaddress', STATE['A']['address'], FUNDING,
         wallet='miner', experiment=False)
    send('fund_B', 'sendtoaddress', STATE['B']['address'], ROLE_B_FUNDING, wallet='A')
    # Random neutral names, checked against this node before creating either.
    suffix = secrets.token_hex(6)
    for role in ('A', 'B'):
        STATE[role]['name'] = 'd/synthetic-trust-' + suffix + '-' + role.lower()
        try:
            rpc('name_show', STATE[role]['name'])
        except RPCError as error:
            if error.code != -4:
                raise
            R.setdefault('names_free_checks', []).append({'name': STATE[role]['name'], 'at': utc(),
                                                        'rpc_code': error.code, 'free': True})
        else:
            raise RuntimeError('name already exists; stop')
    pending = {}
    for role in ('A', 'B'):
        check_network()
        start = time.monotonic_ns(); at = utc()
        pending[role] = rpc('name_new', STATE[role]['name'], wallet=role)
        raw = rpc('gettransaction', pending[role][0], wallet=role)['hex']
        actual_txid, start, at = broadcast_checked(raw, role + '_name_new')
        if actual_txid != pending[role][0]:
            raise RuntimeError('name reservation identity mismatch')
        measure(role + '_name_new', pending[role][0], start, at)
    # name_new has already one/two confirmations. Twelve additional blocks
    # conservatively satisfy the consensus maturity without a polling loop.
    mine(12)
    for role in ('A', 'B'):
        value = canon({'pubkey': STATE[role]['pubkey']}).decode()
        assert len(value.encode()) <= 520
        txid, _ = send(role + '_name_firstupdate', 'name_firstupdate', STATE[role]['name'],
                        pending[role][1], pending[role][0], value,
                        {'destAddress': STATE[role]['address']}, wallet=role)
        STATE[role]['identity_txid'] = txid
    write('identities.json', {role: identity(role) for role in ('A', 'B')})


def issue(issuer, grantee):
    address = STATE[issuer]['address']
    seal_tx, _ = send(issuer + '_seal_funding', 'sendtoaddress', address, SEAL_VALUE, wallet=issuer)
    seal = point(seal_tx, address)
    if not rpc('lockunspent', False, [{'txid': seal['txid'], 'vout': seal['vout']}], wallet=issuer):
        raise RuntimeError('dedicated seal coin-selection lock failed')
    height = rpc('getblockcount')
    g = {'version': 'synthetic-notarized-grant-v1', 'chain_genesis': STATE['genesis'],
         'issuer': identity(issuer), 'grantee': STATE[grantee]['address'], 'seal': seal,
         'action': 'read', 'resource': 'synthetic/item', 'nonce': issuer + '-to-' + grantee,
         'not_before_height': height, 'expires_height': height + 20,
         'delegation': False, 'transfer': False}
    check_network()
    sig = rpc('signmessage', address, 'notary-lab/grant-v1:' + H(g), wallet=issuer)
    info = rpc('name_show', STATE[issuer]['name'])
    value = canon({'grant': H(g)}).decode()
    assert len(value.encode()) <= 520
    raw = raw_signed(issuer, [{'txid': info['txid'], 'vout': info['vout']}],
                     [{address: NAME_LOCK}, {'data': H(g)}],
                     {'op': 'name_update', 'name': STATE[issuer]['name'], 'value': value})
    txid, row = send(issuer + '_grant_anchor', 'sendrawtransaction', raw, Decimal('0.00220000'))
    fixture = {'grant': g, 'grant_signature': sig,
               'anchor': {k: row[k] for k in ('txid', 'height', 'blockhash')}}
    label = issuer + '-to-' + grantee
    write(label + '-grant.json', g)
    write(label + '-grant-signature.json', sig)
    write(label + '-fixture.json', fixture)
    write(label + '-pins.json', {'issuer': identity(issuer), 'grantee': identity(grantee)})
    request = {'name': g['issuer']['name'], 'action': 'read', 'resource': 'synthetic/item',
               'grant_sha256': H(g), 'nonce': label + '-request-1'}
    sign_request(label, request, grantee)
    return fixture


def sign_request(label, request, role):
    check_network()
    sig = rpc('signmessage', STATE[role]['address'], 'swarma-chain-lab/request-v0:' + H(request), wallet=role)
    write(label + '-request.json', request)
    write(label + '-request-signature.json', sig)


def verifier(label, base, request_base=None, expected='admit', reason=None, capability='observer'):
    request_base = request_base or base
    event = {'type': 'verify', 'input': {'network': 'regtest' if capability == 'observer' else 'main',
             'fixture': DOCS[base + '-fixture.json'], 'pins': DOCS[base + '-pins.json'],
             'request': DOCS[request_base + '-request.json'],
             'signature': DOCS[request_base + '-request-signature.json']}}
    print(json.dumps(event), flush=True)
    for _ in range(4096):
        bounds()
        raw = sys.stdin.buffer.readline(262145)
        if not raw or len(raw) > 262144:
            raise RuntimeError('verification pipe closed/oversize')
        item = json.loads(raw)
        if item.get('type') == 'verdict':
            result = item['result']; verifier_exit = item['exit']; break
        if item.get('type') != 'rpc' or item.get('method') not in READ_METHODS:
            raise RuntimeError('restricted read-only pipe protocol violation')
        try:
            value = OBSERVER.call(item['method'], *item.get('params', []))
            reply = {'type': 'rpc_result', 'result': value}
        except Exception:
            reply = {'type': 'rpc_result', 'error': 'unavailable'}
        print(json.dumps(reply), flush=True)
    else:
        raise RuntimeError('verification RPC count bound')
    R['cases'][label] = {'actual': result, 'exit': verifier_exit,
                          'expected': expected, 'expected_reason': reason,
                          'pass': result['decision'] == expected and (reason is None or result['reason'] == reason)}
    if not R['cases'][label]['pass']:
        raise RuntimeError('control failed: ' + label)
    return result


def controls(a, b):
    verifier('A_grants_B_valid', 'A-to-B')
    verifier('B_grants_A_valid', 'B-to-A')
    req = dict(DOCS['A-to-B-request.json'])
    sign_request('wrong-key', req, 'A')
    verifier('wrong_key', 'A-to-B', 'wrong-key', 'refuse', 'REQUEST_SIGNATURE')
    req['action'] = 'write'
    sign_request('wrong-action', req, 'B')
    verifier('wrong_action_genuinely_B_signed', 'A-to-B', 'wrong-action', 'refuse', 'REQUEST_SCOPE')
    write('tampered-grant-fixture.json', {**a, 'grant': {**a['grant'], 'resource': 'synthetic/other'}})
    write('tampered-grant-pins.json', DOCS['A-to-B-pins.json'])
    verifier('tampered_grant_signature', 'tampered-grant', 'A-to-B', 'refuse', 'ISSUER_SIGNATURE')
    verifier('wrong_network_capability', 'A-to-B', expected='refuse',
             reason='UNAVAILABLE_OR_MALFORMED', capability='wrong-network')
    seal = a['grant']['seal']
    # Explicit input overrides the coin-selection lock. The value is returned
    # to A minus the capped fee; no extra transfer or externally funded input.
    raw = rpc('createrawtransaction', [{'txid': seal['txid'], 'vout': seal['vout']}],
              [{rpc('getnewaddress', '', 'legacy', wallet='A'): SEAL_VALUE - Decimal('0.00050000')}])
    check_network()
    signed = rpc('signrawtransactionwithwallet', raw, wallet='A')
    if not signed['complete']:
        raise RuntimeError('revocation signature incomplete')
    d = rpc('decoderawtransaction', signed['hex'])
    if d['vsize'] > VSIZE_CAP or Decimal('0.00050000') > TX_FEE_CAP:
        raise RuntimeError('revocation exceeds cap')
    if not rpc('testmempoolaccept', [signed['hex']])[0]['allowed']:
        raise RuntimeError('revocation not relayable')
    verifier('before_actual_seal_spend', 'A-to-B')
    txid, start, at = broadcast_checked(signed['hex'], 'A_seal_revoke')
    if txid not in rpc('getrawmempool'):
        raise RuntimeError('revocation absent from mempool')
    R['revocation_mempool'] = {'txid': txid, 'at': utc(),
        'chain_only_unspent': rpc('gettxout', seal['txid'], seal['vout'], False) is not None,
        'including_mempool_unspent': rpc('gettxout', seal['txid'], seal['vout'], True) is not None}
    if not R['revocation_mempool']['chain_only_unspent'] or R['revocation_mempool']['including_mempool_unspent']:
        raise RuntimeError('unexpected mempool/chain seal state')
    verifier('actual_spend_mempool_refuse', 'A-to-B', expected='refuse', reason='SEAL_SPENT_INCLUDING_MEMPOOL')
    measure('A_seal_revoke', txid, start, at)
    verifier('actual_spend_one_block_refuse', 'A-to-B', expected='refuse', reason='SEAL_SPENT_INCLUDING_MEMPOOL')
    verifier('B_grant_still_valid_after_A_revokes', 'B-to-A')
    target = b['grant']['expires_height']
    empty_expiry_blocks = mine(target - 1 - rpc('getblockcount'))
    verifier('expiry_height_minus_one', 'B-to-A')
    mine()
    verifier('actual_height_expired', 'B-to-A', expected='refuse', reason='EXPIRED_OR_PREMATURE')
    return empty_expiry_blocks


def lineage_controls(b, empty_expiry_blocks):
    """Real current-output controls with unchanged signed grant bytes.

    After the original workflow and budget snapshot, intentionally invalidate
    only its empty expiry blocks. Both issuance anchors and the actual seal
    revocation remain confirmed. This is an explicit disposable test fork,
    never an operational reorg-recovery or replacement transaction policy.
    """
    if not empty_expiry_blocks:
        raise RuntimeError('missing controlled empty expiry branch')
    before = {'height': rpc('getblockcount'), 'hash': rpc('getbestblockhash')}
    rpc('invalidateblock', empty_expiry_blocks[0])
    after = {'height': rpc('getblockcount'), 'hash': rpc('getbestblockhash')}
    if after['height'] >= b['grant']['expires_height'] - 3:
        raise RuntimeError('insufficient unchanged grant lifetime for lineage controls')
    grant_hash = H(b['grant'])
    R['controlled_empty_block_fork'] = {'before': before, 'after': after,
        'invalidated_first_empty_block': empty_expiry_blocks[0],
        'purpose': 'test-only restore of pre-expiry state; no anchor or spend is removed'}
    verifier('lineage_before_updates', 'B-to-A')
    first_row = len(R['transactions'])
    send('lineage_control_funding_A', 'sendtoaddress', STATE['A']['address'],
         Decimal('0.00400000'), wallet='miner', experiment=False)
    send('lineage_control_funding_B', 'sendtoaddress', STATE['B']['address'],
         Decimal('0.00200000'), wallet='miner', experiment=False)
    for label, signer, destination, expected, reason in (
        ('lineage_A_same_owner', 'A', 'A', 'admit', None),
        ('lineage_A_away', 'A', 'B', 'refuse', 'CURRENT_NAME_BINDING'),
        ('lineage_A_return', 'B', 'A', 'refuse', 'GRANTEE_PREDECESSOR_NAME_OWNER')):
        info = rpc('name_show', STATE['A']['name'])
        raw = raw_signed(signer, [{'txid': info['txid'], 'vout': info['vout']}],
            [{STATE[destination]['address']: NAME_LOCK}],
            {'op': 'name_update', 'name': STATE['A']['name'], 'value': '{}'})
        send(label, 'sendrawtransaction', raw, Decimal('0.00220000'), experiment=False)
        if H(b['grant']) != grant_hash or rpc('getblockcount') >= b['grant']['expires_height']:
            raise RuntimeError('lineage control changed grant or exceeded unchanged expiry')
        verifier(label, 'B-to-A', expected=expected, reason=reason)
    rows = R['transactions'][first_row:]
    control_fees = sum(Decimal(row['fee_nmc']) for row in rows)
    fee_cap = sum(FEE_CEILINGS[key] for key in LINEAGE_SIZE_CEILINGS)
    if len(rows) != 5 or control_fees > fee_cap or FUNDING + Decimal('0.00600000') + fee_cap >= Decimal('0.5'):
        raise RuntimeError('separate lineage regression budget exceeded')
    R['lineage_controls'] = {'grant_sha256': grant_hash, 'signed_grant_unchanged': True,
        'height': rpc('getblockcount'), 'expires_height': b['grant']['expires_height'],
        'same_request_and_signature': True, 'extra_regtest_funding_nmc': '0.00600000',
        'operations': len(rows), 'fee_cap_nmc': str(fee_cap), 'actual_fees_nmc': str(control_fees),
        'scope': 'disposable real regtest transfer controls; generation control is separately synthetic offline'}


def capability_denials(password):
    denials = []
    for method in ('signmessage', 'sendrawtransaction', 'getnewaddress', 'listwallets',
                   'stop', 'createwallet', 'signrawtransactionwithwallet'):
        c = http.client.HTTPConnection('127.0.0.1', PORT, timeout=5)
        c.request('POST', '/', json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': []}),
                  {'Authorization': 'Basic ' + base64.b64encode(('observer:' + password).encode()).decode()})
        response = c.getresponse(); status = response.status; response.read(); c.close()
        denials.append({'method': method, 'http_status': status, 'denied_before_execution': status == 403})
        if status != 403:
            raise RuntimeError('observer capability unexpectedly permits ' + method)
    R['core_enforced_readonly_denials'] = denials


def finish_budget():
    rows = [x for x in R['transactions'] if x['experiment_budget']]
    fees = sum(Decimal(x['fee_nmc']) for x in rows)
    total_fee_cap = sum(FEE_CEILINGS[key] for key in BASE_SIZE_CEILINGS if key != 'bootstrap_exact_lab_funding')
    fee_margin = total_fee_cap / 10
    model = funding_model()
    balances = {role: str(rpc('getbalance', wallet=role)) for role in ('A', 'B')}
    R['funding'] = {
        'exact_conditional_funding_nmc': str(FUNDING), 'external_budget_ceiling_nmc': '0.50000000',
        'smallest_under_declared_caps': True,
        'minimum_kind': model['minimum_kind'],
        'cashflow_model': model,
        'names_locked_nmc': '0.02000000', 'seals_initially_locked_nmc': '0.00200000',
        'fees_ceiling_nmc': str(total_fee_cap),
        'explicit_fee_margin_nmc': str(fee_margin),
        'margin_policy': '10 percent of individually capped transaction fees, rounded to exact satoshis',
        'formula': 'max(A prefix liquidity, A final requirement after fixed B transfer); funder fee separate',
        'final_live_seal_nmc': '0.00100000',
        'returned_A_seal_change_nmc': '0.00050000',
        'timing_forced_surplus_nmc': str(Decimal(model['timing_forced_surplus_sat']) / Decimal(100000000)),
        'size_ceilings_vbytes': SIZE_CEILINGS,
        'fee_ceilings_nmc': {key: str(value) for key, value in FEE_CEILINGS.items()},
        'experiment_operations': len(rows), 'actual_regtest_fees_nmc': str(fees),
        'actual_regtest_fees_satoshis': int(fees * 100000000),
        'remaining_in_names_nmc': '0.02000000', 'remaining_live_seal_nmc': '0.00100000',
        'A_B_wallet_balances_including_locked_seal_excluding_names_nmc': balances,
        'unspent_total_excluding_names_nmc': str(sum(Decimal(x) for x in balances.values())),
        'bootstrap_fee_nmc': R['transactions'][0]['fee_nmc'],
        'bootstrap_fee_excluded_from_requested_funding': 'paid by synthetic miner; future funder transaction outside lab spend',
        'future_mainnet_fee_quote': None, 'future_mainnet_inclusion_seconds': None,
        'future_mainnet_funding_address': None,
        'fresh_node_policy_size_check_before_spend_required': True,
        'validity': 'conditional cap, not a mainnet quote; if fresh policy exceeds rate or a signed tx exceeds its per-operation ceiling STOP and recompute before authorization',
    }
    if fees > total_fee_cap or len(rows) != MAX_OPERATIONS:
        raise RuntimeError('funding model operation/fee mismatch')
    if (int(total_fee_cap * 100000000) != model['experimental_fee_caps_sat'] or
            FUNDING != Decimal(model['recipient_required_sat']) / Decimal(100000000)):
        raise RuntimeError('exact funding formula mismatch')
    expected = FUNDING - fees - Decimal('0.02000000')
    if sum(Decimal(x) for x in balances.values()) != expected:
        raise RuntimeError('funding conservation failed')


def main():
    global DEADLINE, OBSERVER
    parser = argparse.ArgumentParser()
    parser.add_argument('--network', choices=('regtest', 'main'), default='regtest')
    parser.add_argument('--deadline', type=float, required=True)
    args = parser.parse_args()
    # Operational gate is deliberately not expressible as an environment flag.
    if args.network != 'regtest' or MAINNET_BROADCAST:
        print(json.dumps({'status': 'BLOCKED', 'reason': 'MAINNET_BROADCAST_DISABLED',
                          'rpc_connections': 0, 'wallets_created': 0, 'addresses_created': 0}))
        return 2
    DEADLINE = min(args.deadline, time.time() + 1400)
    R['started_at'] = utc()
    for path in (NODE, PUBLIC, LAB/'home', LAB/'tmp', LAB/'cache', LAB/'capability',
                 LAB/'capability/observer', LAB/'capability/wrong-network'):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)
    password = secrets.token_hex(32); salt = secrets.token_hex(16)
    authhash = hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()
    conf = ('regtest=1\nserver=1\nlisten=0\ndnsseed=0\ndiscover=0\n'
            'txindex=1\nprinttoconsole=0\nlogips=0\nrpcwhitelistdefault=0\n'
            'rpcauth=observer:' + salt + '$' + authhash + '\n'
            'rpcwhitelist=observer:' + ','.join(sorted(READ_METHODS)) + '\n'
            'walletbroadcast=0\nfallbackfee=' + str(RATE_NMC_KVB) + '\nmaxtxfee=' + str(RATE_NMC_KVB) + '\n'
            'deprecatedrpc=create_bdb\n[regtest]\nconnect=0\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport=' + str(PORT) + '\n')
    (NODE/'namecoin.conf').write_text(conf)
    for network, label in (('regtest', 'observer'), ('main', 'wrong-network')):
        (LAB/'capability'/label/'rpc.json').write_bytes(canon({
            'host': '127.0.0.1', 'port': PORT, 'username': 'observer',
            'password': password, 'network': network}))
    OBSERVER = ReadRPC({'host': '127.0.0.1', 'port': PORT, 'username': 'observer',
                        'password': password, 'network': 'regtest'})
    exitcode = 1
    try:
        R['executed_source_sha256'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(Path('/src').iterdir()) if path.suffix == '.py' or path.name == 'run.sh'}
        R['read_rpc_allowlist'] = sorted(READ_METHODS)
        R['namespace_boundary'] = {'host_home_entries': list(Path('/home').iterdir()),
            'signer_uid_namespace': os.getuid(), 'ssh_auth_sock_present': 'SSH_AUTH_SOCK' in os.environ,
            'home_modes': {str(p): oct(p.stat().st_mode & 0o777) for p in (LAB/'home', LAB/'tmp', LAB/'cache')},
            'network_interfaces': sorted(p.name for p in Path('/sys/class/net').iterdir()) if Path('/sys/class/net').exists() else 'sysfs not mounted',
            'scope': 'offline node namespace; separate verifier namespace uses only read-only stdio pipe'}
        # Do not export Path objects even when an isolation check fails.
        R['namespace_boundary']['host_home_entries'] = [str(x) for x in R['namespace_boundary']['host_home_entries']]
        if R['namespace_boundary']['host_home_entries'] or R['namespace_boundary']['ssh_auth_sock_present']:
            raise RuntimeError('host home/socket isolation failed')
        R['core_sha256'] = hashlib.sha256(Path('/runtime/namecoind').read_bytes()).hexdigest()
        if R['core_sha256'] != 'dc7430676e445af3992430e036f7c1a17bea44f757e9cf25b69205e39625f2f7':
            raise RuntimeError('Core binary pin mismatch')
        logfile = open(LAB/'node-private.log', 'wb')
        node = subprocess.Popen(['/runtime/namecoind', '-datadir=' + str(NODE)],
                                stdout=logfile, stderr=logfile)
        CHILDREN.append(('Core', node))
        until = min(DEADLINE, time.time() + 25)
        while time.time() < until:
            if node.poll() is not None:
                logfile.flush()
                startup = (LAB/'node-private.log').read_bytes()
                R['startup_log_sha256'] = hashlib.sha256(startup).hexdigest()
                errors = [line for line in startup.decode(errors='replace').splitlines()
                          if line.startswith('Error:')]
                safe = '\n'.join(errors)[:1000]
                for secret in (password, salt, authhash, COOKIE or '<no-cookie>'):
                    safe = safe.replace(secret, '<redacted>')
                R['startup_errors'] = safe
                raise RuntimeError('Core exited before readiness: ' + str(node.returncode))
            try:
                check_network(); break
            except (OSError, RPCError, ValueError, http.client.HTTPException):
                time.sleep(0.1)
        else:
            raise RuntimeError('Core readiness bound 25 seconds')
        capability_denials(password)
        setup()
        a = issue('A', 'B'); b = issue('B', 'A')
        empty_expiry_blocks = controls(a, b)
        finish_budget()
        lineage_controls(b, empty_expiry_blocks)
        R['final_tip'] = {'height': rpc('getblockcount'), 'hash': rpc('getbestblockhash')}
        R['private_tmpfs_bytes_at_finish'] = bounds()
        R['status'] = 'PASS'; exitcode = 0
    except Exception as error:
        # Exception strings are restricted to our fixed errors/RPC method+code;
        # never dump locals, RPC bodies, arbitrary node logs or tracebacks.
        R['status'] = 'FAILED'
        R['failure'] = {'type': type(error).__name__, 'message': str(error)[:300]}
    finally:
        for role, process in CHILDREN:
            try:
                if process.poll() is None:
                    try:
                        rpc('stop')
                    except Exception:
                        process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait(timeout=5)
                R['cleanup'][role] = {'exit': process.returncode, 'reaped': process.poll() is not None}
            except Exception:
                R['cleanup'][role] = {'reaped': False}
                exitcode = 1
        R['finished_at'] = utc()
        R['cleanup']['private_state'] = 'tmpfs discarded by namespace exit; never exported'
        print(json.dumps({'result': R, 'public_documents': DOCS}, default=str, sort_keys=True), flush=True)
    return exitcode


if __name__ == '__main__':
    def terminate(signum, frame):
        raise RuntimeError('termination signal; stop and clean own children')
    signal.signal(signal.SIGTERM, terminate)
    raise SystemExit(main())
