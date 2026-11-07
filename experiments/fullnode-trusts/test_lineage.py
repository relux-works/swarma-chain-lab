"""Offline causal RPC controls, not new chain or signature observations.

Transfer controls reuse the sealed review's unchanged public grant/request.
The separate generation timeline uses an explicitly symbolic signature oracle
and a long-lived synthetic grant: no claim of a real signed generation grant.
"""
import json
from pathlib import Path
import unittest
import protocol

PUBLIC = Path(__file__).parent / 'receipts/public'


def load(name):
    return json.loads((PUBLIC / name).read_text())


class Frozen(protocol.ReadRPC):
    def __init__(self, case):
        self.config = {'network': 'regtest'}
        self.calls = []
        self.case = case
        self.fixture = load('A-to-B-fixture.json')
        self.pins = load('A-to-B-pins.json')
        self.request = load('A-to-B-request.json')
        self.signature = load('A-to-B-request-signature.json')
        self.docs = {load(p.name)['txid']: load(p.name) for p in PUBLIC.glob('*-transaction.json')}
        self.current = load('B-to-A-fixture.json')['anchor']['txid']
        self.height = 142
        self.timeline = None

    def update(self, txid, previous, address=None, op='name_update', value='{}'):
        name = self.pins['grantee']['name']
        v = next(v for v in self.docs[previous]['vout'] if 'nameOp' in v['scriptPubKey'])
        self.docs[txid] = {'txid': txid, 'confirmations': 1,
            'vin': [{'txid': previous, 'vout': v['n']}], 'vout': [{'n': 0,
            'scriptPubKey': {'address': address or self.pins['grantee']['address'],
                'nameOp': {'op': op, 'name': name, 'value': value}}}]}
        self.current = txid

    def call(self, method, *args):
        self.calls.append((method, args))
        if method == 'getbestblockhash':
            return '44' * 32
        if method == 'getblockchaininfo':
            return {'chain': 'regtest', 'initialblockdownload': False}
        if method == 'getblockcount':
            return self.height
        if method == 'getblockhash':
            return protocol.GENESIS['regtest'] if args[0] == 0 else self.fixture['anchor']['blockhash']
        if method == 'verifymessage':
            known = {(self.pins['issuer']['address'], self.fixture['grant_signature'],
                      'notary-lab/grant-v1:' + protocol.H(self.fixture['grant'])),
                     (self.pins['grantee']['address'], self.signature,
                      'swarma-chain-lab/request-v0:' + protocol.H(self.request))}
            return args in known  # symbolic oracle over explicitly allowed public inputs
        if method == 'getrawtransaction':
            if self.case == 'unavailable' and args[0] == self.current:
                raise OSError('offline missing lineage observation')
            return self.docs[args[0]]
        if method == 'name_show':
            ident = self.pins['issuer'] if args[0] == self.pins['issuer']['name'] else self.pins['grantee']
            txid = self.fixture['anchor']['txid'] if ident is self.pins['issuer'] else self.current
            named = next(v for v in self.docs[txid]['vout'] if 'nameOp' in v['scriptPubKey'])
            return {'expired': False, 'address': ident['address'], 'txid': txid, 'vout': named['n']}
        if method == 'gettxout':
            return {'confirmations': 3}
        raise AssertionError((method, args))

    def verify(self):
        return protocol.verify(self, self.fixture, self.request, self.signature,
                               self.pins['issuer'], self.pins['grantee'])

    def generation_grant(self):
        # Separate fully synthetic grant/anchor and signature oracle. Issuance
        # at 30000 renews the issuer before its initial generation can expire;
        # the grantee's last update at 142 is still live at that issuance.
        old_hash = protocol.H(self.fixture['grant'])
        self.fixture['grant']['not_before_height'] = 29999
        self.fixture['grant']['expires_height'] = 40000
        new_hash = protocol.H(self.fixture['grant'])
        self.request['grant_sha256'] = new_hash
        tx = self.docs[self.fixture['anchor']['txid']]
        tx['txid'] = 'a1' * 32
        tx['blockhash'] = 'a2' * 32
        for v in tx['vout']:
            sp = v['scriptPubKey']
            if 'nameOp' in sp:
                sp['nameOp']['value'] = protocol.canon({'grant': new_hash}).decode()
            elif sp['hex'] == '6a20' + old_hash:
                sp['hex'] = '6a20' + new_hash
        self.docs[tx['txid']] = tx
        self.fixture['anchor'] = {'height': 30000, 'txid': tx['txid'], 'blockhash': tx['blockhash']}
        self.height = 30001

    def new_generation(self):
        self.timeline = {'old_last_update': 142, 'expiration_depth': 36000,
                         'issuer_grant_update': 30000, 'new_reservation': 36120,
                         'new_firstupdate': 36143, 'current_height': 36144,
                         'grant_expiry': 40000}
        self.height = 36144
        self.update('dd' * 32, self.current, op='name_firstupdate',
                    value=json.dumps({'pubkey': self.pins['grantee']['pubkey']}))
        self.docs['dd' * 32]['vin'] = [{'txid': 'bb' * 32, 'vout': 0}]
        self.docs['bb' * 32] = {'txid': 'bb' * 32, 'confirmations': 25,
            'vin': [], 'vout': [{'n': 0, 'scriptPubKey': {'nameOp': {'op': 'name_new'}}}]}
        self.update('ee' * 32, self.current)


class LineageControls(unittest.TestCase):
    def test_original_baseline(self):
        self.assertEqual(Frozen('baseline').verify()['decision'], 'admit')

    def test_pinned_firstupdate_can_be_current(self):
        rpc = Frozen('firstupdate')
        rpc.current = rpc.pins['grantee']['identity_txid']
        self.assertEqual(rpc.verify()['decision'], 'admit')

    def test_legitimate_same_owner_value_update(self):
        rpc = Frozen('same_owner')
        rpc.update('aa' * 32, rpc.current, value='{"grant":"another-current-value"}')
        rpc.height = 143
        self.assertEqual(rpc.verify()['decision'], 'admit')

    def test_reviewer_transfer_away_return_before_unchanged_expiry(self):
        rpc = Frozen('away_return')
        original = protocol.canon(rpc.fixture)
        rpc.update('cc' * 32, rpc.current, address=rpc.pins['issuer']['address'])
        rpc.update('ee' * 32, rpc.current)
        rpc.height = 144
        self.assertLess(rpc.height, rpc.fixture['grant']['expires_height'])
        result = rpc.verify()
        self.assertEqual(result['reason'], 'GRANTEE_PREDECESSOR_NAME_OWNER')
        self.assertEqual(original, protocol.canon(rpc.fixture))
        self.assertIn(('getrawtransaction', ('cc' * 32, True)), rpc.calls)

    def test_new_generation_same_key_with_feasible_long_lived_grant(self):
        rpc = Frozen('generation')
        rpc.generation_grant()
        self.assertEqual(rpc.verify()['decision'], 'admit')
        unchanged = protocol.canon(rpc.fixture)
        rpc.new_generation()
        t = rpc.timeline
        self.assertGreater(t['new_firstupdate'], t['old_last_update'] + t['expiration_depth'])
        self.assertGreaterEqual(t['new_firstupdate'] - t['new_reservation'], 12)
        self.assertLess(t['issuer_grant_update'], t['old_last_update'] + t['expiration_depth'])
        self.assertLess(t['current_height'], t['issuer_grant_update'] + t['expiration_depth'])
        self.assertLess(t['current_height'], t['grant_expiry'])
        self.assertEqual(rpc.verify()['reason'], 'GRANTEE_NAME_OWNER_OPERATION')
        self.assertEqual(unchanged, protocol.canon(rpc.fixture))

    def test_missing_rpc_does_not_skip_lineage(self):
        self.assertEqual(Frozen('unavailable').verify()['reason'], 'UNAVAILABLE_OR_MALFORMED')

    def test_transition_budget_exhaustion_refuses(self):
        rpc = Frozen('limit')
        for n in range(129):
            rpc.update('%064x' % (1000 + n), rpc.current)
        self.assertEqual(rpc.verify()['reason'], 'GRANTEE_LINEAGE_LIMIT')

    def test_input_budget_exhaustion_refuses(self):
        rpc = Frozen('inputs')
        rpc.update('aa' * 32, rpc.current)
        rpc.docs[rpc.current]['vin'] *= 17
        self.assertEqual(rpc.verify()['reason'], 'GRANTEE_INPUT_LIMIT')

    def test_wrong_current_output_refuses(self):
        rpc = Frozen('output')
        original = rpc.call
        def call(method, *args):
            result = original(method, *args)
            if method == 'name_show' and args[0] == rpc.pins['grantee']['name']:
                result['vout'] = 123
            return result
        rpc.call = call
        self.assertEqual(rpc.verify()['reason'], 'GRANTEE_CURRENT_OUTPUT')


if __name__ == '__main__':
    unittest.main(verbosity=2)
