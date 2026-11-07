"""Experimental full-node grant checks; Python standard library only.

Grant schema, canonicalisation and grant signature domain are reused from the
notary experiment. The signed-request fields/domain come from the earlier
chain-backed grant lab; requests here use the grantee's existing Core
signmessage key instead of its optional Ed25519 adapter.
"""
import base64
import hashlib
import http.client
import ipaddress
import json
import time
import sys
from decimal import Decimal
from pathlib import Path

GENESIS = {
    'regtest': '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206',
    'main': '000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770',
}
READ_METHODS = frozenset({
    'getbestblockhash', 'getblockcount', 'getblockhash', 'getblockheader',
    'getblockchaininfo', 'getrawtransaction', 'gettxout', 'name_show',
    'verifymessage',
})


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def H(obj):
    return hashlib.sha256(canon(obj)).hexdigest()


def load(path):
    data = Path(path).read_bytes()
    if len(data) > 65536:
        raise ValueError('public input exceeds 64 KiB')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


class RPCError(RuntimeError):
    def __init__(self, method, status, code=None):
        super().__init__('RPC method %s HTTP %s code %s' % (method, status, code))
        self.status, self.code = status, code


class ReadRPC:
    """Capability contains ONLY a dedicated Core-whitelisted observer login.

    No wallet path, cookie, arbitrary endpoint URL, environment credential or
    signing method is accepted by this client. Core enforces the same list.
    """
    def __init__(self, config):
        if set(config) != {'host', 'port', 'username', 'password', 'network'}:
            raise ValueError('capability schema')
        if not ipaddress.ip_address(config['host']).is_loopback:
            raise ValueError('loopback capability required')
        if config['network'] not in GENESIS or config['username'] != 'observer':
            raise ValueError('network/observer capability')
        if type(config['port']) is not int or not 1 <= config['port'] <= 65535:
            raise ValueError('port')
        self.config = config

    def call(self, method, *params):
        if method not in READ_METHODS:
            raise ValueError('read-only RPC method rejected before connection')
        c = self.config
        conn = http.client.HTTPConnection(c['host'], c['port'], timeout=5)
        try:
            auth = base64.b64encode((c['username'] + ':' + c['password']).encode()).decode()
            conn.request('POST', '/', json.dumps({'jsonrpc': '1.0', 'id': 1,
                         'method': method, 'params': params}),
                         {'Authorization': 'Basic ' + auth, 'Content-Type': 'application/json'})
            res = conn.getresponse()
            raw = res.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024 or res.status != 200:
                raise RPCError(method, res.status)
            obj = json.loads(raw)
            if obj.get('error'):
                raise RPCError(method, res.status, obj['error']['code'])
            return obj['result']
        finally:
            conn.close()

    def check_network(self):
        c = self.config
        info = self.call('getblockchaininfo')
        if info['chain'] != c['network'] or self.call('getblockhash', 0) != GENESIS[c['network']]:
            raise ValueError('wrong network/genesis')
        if info.get('initialblockdownload'):
            raise ValueError('full node is not ready')


class PipeRPC:
    """Dedicated read-only RPC pipe from a separate fully isolated sandbox.

    The broker applies ReadRPC and Core's own observer whitelist. No password,
    cookie, wallet file, endpoint selector or broadcast method crosses the pipe.
    """
    def __init__(self, network):
        if network not in GENESIS:
            raise ValueError('network')
        self.config = {'network': network}

    def call(self, method, *params):
        if method not in READ_METHODS:
            raise ValueError('read-only method rejected before pipe')
        print(json.dumps({'type': 'rpc', 'method': method, 'params': params}), flush=True)
        line = sys.stdin.buffer.readline(8 * 1024 * 1024 + 1)
        if not line or len(line) > 8 * 1024 * 1024:
            raise ValueError('RPC pipe closed/oversize')
        reply = json.loads(line)
        if reply.get('type') != 'rpc_result' or reply.get('error'):
            raise RPCError(method, 'pipe-unavailable')
        return reply['result']

    check_network = ReadRPC.check_network


def signature(rpc, address, signature_, domain, obj):
    return rpc.call('verifymessage', address, signature_, domain + H(obj)) is True


def transition_error(rpc, tx, ident, commitment):
    """Same-owner lineage back to a pinned firstupdate, from notary/lab.py.

    Rotation, transfer and re-registration are deliberately excluded. This lab
    bounds 128 transitions and 16 inputs per transaction, failing closed.
    """
    seen = set()
    for depth in range(128):
        if tx.get('confirmations', 0) < 1:
            return 'UNCONFIRMED_LINEAGE'
        ops = [v for v in tx['vout'] if 'nameOp' in v['scriptPubKey']]
        if len(ops) != 1:
            return 'OP_COUNT'
        sp = ops[0]['scriptPubKey']; op = sp['nameOp']
        if op.get('op') != 'name_update' or op.get('name') != ident['name'] or sp.get('address') != ident['address']:
            return 'NAME_OWNER_OPERATION'
        if depth == 0 and commitment is not None and op.get('value') != canon(commitment).decode():
            return 'COMMITMENT'
        named = []
        if len(tx['vin']) > 16:
            return 'INPUT_LIMIT'
        for vin in tx['vin']:
            if 'txid' not in vin:
                continue
            point = (vin['txid'], vin['vout'])
            prev = rpc.call('getrawtransaction', point[0], True)
            pv = prev['vout'][point[1]]
            if 'nameOp' in pv['scriptPubKey']:
                named.append((point, prev, pv))
        if len(named) != 1:
            return 'PREDECESSOR_COUNT'
        point, prev, pv = named[0]; ps = pv['scriptPubKey']; po = ps['nameOp']
        if po.get('name') != ident['name'] or ps.get('address') != ident['address']:
            return 'PREDECESSOR_NAME_OWNER'
        if prev.get('confirmations', 0) < 1 or point in seen:
            return 'PREDECESSOR_CONFIRMATIONS_CYCLE'
        seen.add(point)
        if point[0] == ident['identity_txid']:
            if po.get('op') != 'name_firstupdate' or json.loads(po['value']).get('pubkey') != ident['pubkey']:
                return 'IDENTITY_KEY_OPERATION'
            return None
        tx = prev
    return 'LINEAGE_LIMIT'


def current_grantee_error(rpc, current, ident):
    """Bind the current name output to the pinned generation and owner.

    A matching address or signing key alone does not establish name ownership
    continuity. Values may change under the same owner, including grant updates.
    """
    tx = rpc.call('getrawtransaction', current['txid'], True)
    ops = [v for v in tx['vout'] if 'nameOp' in v['scriptPubKey']]
    if tx['txid'] != current['txid'] or len(ops) != 1 or ops[0]['n'] != current['vout']:
        return 'CURRENT_OUTPUT'
    if tx.get('confirmations', 0) < 1:
        return 'UNCONFIRMED_LINEAGE'
    sp = ops[0]['scriptPubKey']; op = sp['nameOp']
    if op.get('name') != ident['name'] or sp.get('address') != ident['address']:
        return 'NAME_OWNER_OPERATION'
    if current['txid'] == ident['identity_txid']:
        if op.get('op') != 'name_firstupdate' or json.loads(op['value']).get('pubkey') != ident['pubkey']:
            return 'IDENTITY_KEY_OPERATION'
        return None
    return transition_error(rpc, tx, ident, None)


def decision(rpc, fixture, request, request_signature, expected_issuer, expected_grantee):
    def refuse(reason):
        return {'decision': 'refuse', 'reason': reason}
    g = fixture['grant']
    if g['version'] != 'synthetic-notarized-grant-v1':
        return refuse('GRANT_VERSION')
    if g['chain_genesis'] != GENESIS[rpc.config['network']]:
        return refuse('CHAIN_BINDING')
    if g['issuer'] != expected_issuer or g['grantee'] != expected_grantee['address']:
        return refuse('IDENTITY_PIN')
    if g['delegation'] is not False or g['transfer'] is not False:
        return refuse('UNSUPPORTED_DELEGATION_TRANSFER')
    if not signature(rpc, g['issuer']['address'], fixture['grant_signature'], 'notary-lab/grant-v1:', g):
        return refuse('ISSUER_SIGNATURE')
    height = rpc.call('getblockcount')
    if type(g['not_before_height']) is not int or type(g['expires_height']) is not int:
        return refuse('HEIGHT_SCHEMA')
    if not g['not_before_height'] <= height < g['expires_height']:
        return refuse('EXPIRED_OR_PREMATURE')
    if request['name'] != g['issuer']['name'] or request['grant_sha256'] != H(g):
        return refuse('REQUEST_BINDING')
    if request['action'] != g['action'] or request['resource'] != g['resource']:
        return refuse('REQUEST_SCOPE')
    if not signature(rpc, g['grantee'], request_signature, 'swarma-chain-lab/request-v0:', request):
        return refuse('REQUEST_SIGNATURE')
    for ident in (expected_issuer, expected_grantee):
        current = rpc.call('name_show', ident['name'])
        if current.get('expired') or current['address'] != ident['address']:
            return refuse('CURRENT_NAME_BINDING')
        initial = rpc.call('getrawtransaction', ident['identity_txid'], True)
        if initial.get('confirmations', 0) < 1:
            return refuse('IDENTITY_CONFIRMATIONS')
        matching = [v for v in initial['vout'] if v['scriptPubKey'].get('nameOp', {}).get('name') == ident['name']
                    and v['scriptPubKey'].get('address') == ident['address']]
        if len(matching) != 1 or matching[0]['scriptPubKey']['nameOp']['op'] != 'name_firstupdate':
            return refuse('IDENTITY_OPERATION')
        if json.loads(matching[0]['scriptPubKey']['nameOp']['value']).get('pubkey') != ident['pubkey']:
            return refuse('IDENTITY_KEY')
    error = current_grantee_error(rpc, current, expected_grantee)
    if error:
        return refuse('GRANTEE_' + error)
    anchor = fixture['anchor']
    if rpc.call('getblockhash', anchor['height']) != anchor['blockhash']:
        return refuse('ANCHOR_REORGED')
    tx = rpc.call('getrawtransaction', anchor['txid'], True)
    if tx.get('blockhash') != anchor['blockhash'] or tx.get('confirmations', 0) < 1:
        return refuse('ANCHOR_CONFIRMATIONS')
    error = transition_error(rpc, tx, g['issuer'], {'grant': H(g)})
    if error:
        return refuse('ISSUANCE_' + error)
    # The active same-owner name must still be this issuance in this fixture.
    if rpc.call('name_show', g['issuer']['name'])['txid'] != anchor['txid']:
        return refuse('NAME_CHANGED_AFTER_ISSUANCE')
    if not any(v['scriptPubKey']['hex'] == '6a20' + H(g) for v in tx['vout']):
        return refuse('TRANSACTION_HASH_COMMITMENT')
    pt = g['seal']
    if type(pt['vout']) is not int or pt['vout'] < 0:
        return refuse('SEAL_INDEX')
    seal_tx = rpc.call('getrawtransaction', pt['txid'], True)
    if seal_tx.get('confirmations', 0) < 1:
        return refuse('UNCONFIRMED_SEAL')
    prev = seal_tx['vout'][pt['vout']]
    if prev['scriptPubKey'].get('address') != g['issuer']['address'] or prev['scriptPubKey']['hex'] != pt['script'] or Decimal(str(prev['value'])) != Decimal(pt['value']):
        return refuse('SEAL_OWNERSHIP')
    live = rpc.call('gettxout', pt['txid'], pt['vout'], True)
    if not live:
        return refuse('SEAL_SPENT_INCLUDING_MEMPOOL')
    if live.get('confirmations', 0) < 1:
        return refuse('UNCONFIRMED_SEAL')
    return {'decision': 'admit', 'reason': 'CURRENT_TRUSTED_FULL_NODE', 'height': height}


def verify(rpc, fixture, request, request_signature, expected_issuer, expected_grantee):
    started = time.monotonic_ns()
    try:
        tip = rpc.call('getbestblockhash')
        rpc.check_network()
        result = decision(rpc, fixture, request, request_signature, expected_issuer, expected_grantee)
        if rpc.call('getbestblockhash') != tip:
            result = {'decision': 'refuse', 'reason': 'UNAVAILABLE_TIP_CHANGED'}
        result['tip'] = tip
    except (KeyError, TypeError, ValueError, IndexError, ArithmeticError, OSError, RPCError, http.client.HTTPException):
        result = {'decision': 'refuse', 'reason': 'UNAVAILABLE_OR_MALFORMED'}
    result['elapsed_ns'] = time.monotonic_ns() - started
    return result
