"""Exact T1 workflow over the finite collector; no wallet/node creation or CLI.

Public names, keys, addresses and random 20-byte reservation salts arrive from
the separately admitted new experimental wallets. No owner wallet is read.
Grant and request domains/schema are the existing closed-regtest protocol.
"""
from decimal import Decimal
from protocol import GENESIS, H, canon, verify as protocol_verify
from mainnet import Intent, Stop, T1_ORDER, SAT, json_safe
from t1b import SIZES, payload


class ReadOnlyView:
    config = {'network': 'main'}

    def __init__(self, collector):
        self.collector = collector

    def call(self, method, *params):
        # Do not widen the protocol verifier's reviewed read capability.
        from protocol import READ_METHODS
        if method not in READ_METHODS:
            raise Stop('VERIFIER_METHOD_DENIED')
        return self.collector.call(self.collector.read, method, *params)

    def check_network(self):
        if self.config != {'network': 'main'}:
            raise ValueError('wrong verifier capability network')
        self.collector.network()


class Workflow:
    def __init__(self, collector, public_identities):
        self.c, self.ids = collector, {}
        if set(public_identities) != {'A', 'B'}:
            raise Stop('TWO_NEW_IDENTITIES_REQUIRED')
        for role, item in public_identities.items():
            if set(item) != {'name', 'address', 'pubkey', 'rand'}:
                raise Stop('PUBLIC_IDENTITY_SCHEMA')
            if not item['name'].startswith('d/synthetic-trust-') or len(item['name'].encode()) > 64:
                raise Stop('SYNTHETIC_NAME_BOUND')
            if len(bytes.fromhex(item['rand'])) != 20 or len(bytes.fromhex(item['pubkey'])) not in (33, 65):
                raise Stop('PUBLIC_KEY_OR_NONCE_BOUND')
            self.ids[role] = dict(item)
        if any(self.ids['A'][k] == self.ids['B'][k] for k in ('name', 'address', 'pubkey', 'rand')):
            raise Stop('DISTINCT_NEW_IDENTITIES_REQUIRED')
        self.c._gate('new_experimental_identities', {'source': self.c.source, 'identities': self.ids})
        self.reservations, self.seals, self.fixtures, self.requests = {}, {}, {}, {}
        self.verifier = ReadOnlyView(collector)
        self.c.after_broadcast = self.mempool_revoke_control

    def identity(self, role):
        return {k: self.ids[role][k] for k in ('name', 'address', 'pubkey', 'identity_txid')}

    def read_tx(self, txid):
        return self.c.call(self.c.read, 'getrawtransaction', txid, True)

    def point(self, txid, role, *, named=False):
        outputs = [v for v in self.read_tx(txid)['vout']
                   if v['scriptPubKey'].get('address') == self.ids[role]['address']
                   and ('nameOp' in v['scriptPubKey']) is named]
        if len(outputs) != 1:
            raise Stop('OUTPUT_SELECTION')
        v = outputs[0]
        return {'txid': txid, 'vout': v['n'], 'script': v['scriptPubKey']['hex'],
                'value': str(v['value'])}

    def sign(self, role, domain, obj):
        if domain not in ('notary-lab/grant-v1:', 'swarma-chain-lab/request-v0:'):
            raise Stop('SIGNATURE_DOMAIN')
        self.c.network()
        return self.c.rpc_for_builder('signmessage', self.ids[role]['address'], domain + H(obj), wallet=role)

    def transfer(self):
        return self.c.run_next(Intent('fund_B', 'A', (),
                    ({self.ids['B']['address']: Decimal('.01436600')},)))

    def reserve(self, role):
        # The external custody gate confirms name absence before reservation.
        # No wallet name_new helper is allowed: it could auto-broadcast.
        self.c._gate('name_unused', {'name': self.ids[role]['name'], 'tip': self.c.tip})
        op = {k: self.ids[role][k] for k in ('name', 'rand')}
        op['op'] = 'name_new'
        row = self.c.run_next(Intent(role + '_name_new', role, (),
                          ({self.ids[role]['address']: Decimal('.01')},), op))
        self.reservations[role] = self.point(row['txid'], role, named=True)

    def maturity(self):
        # Finite wait inside the original shared clock; never generate blocks.
        # Both reservations need 12 actual active-chain confirmations.
        until = min(self.c.deadline, self.c.clock() + 7200)
        for _ in range(241):
            self.c.network()
            txs = [self.read_tx(self.reservations[r]['txid']) for r in ('A', 'B')]
            if all(t.get('confirmations', 0) >= 12 for t in txs):
                return
            if self.c.clock() >= until:
                break
            self.c.pause(min(30, max(0, until - self.c.clock())))
        raise Stop('NAME_MATURITY_DEADLINE')

    def firstupdate(self, role):
        item = self.ids[role]
        op = {'op': 'name_firstupdate', 'name': item['name'], 'rand': item['rand'],
              'value': canon({'pubkey': item['pubkey']}).decode()}
        point = self.reservations[role]
        row = self.c.run_next(Intent(role + '_name_firstupdate', role,
                    ({'txid': point['txid'], 'vout': point['vout']},),
                    ({item['address']: Decimal('.01')},), op))
        self.ids[role]['identity_txid'] = row['txid']

    def seal(self, role):
        row = self.c.run_next(Intent(role + '_seal_funding', role, (),
                    ({self.ids[role]['address']: Decimal('.001')},)))
        self.seals[role] = self.point(row['txid'], role)
        if self.c.rpc_for_builder('lockunspent', False,
                [{'txid': row['txid'], 'vout': self.seals[role]['vout']}], wallet=role) is not True:
            raise Stop('SEAL_COIN_SELECTION_LOCK')

    def anchor(self, issuer, grantee):
        self.c.network()
        height = self.c.tip[0]
        grant = {'version': 'synthetic-notarized-grant-v1',
            'chain_genesis': GENESIS['main'],
            'issuer': self.identity(issuer), 'grantee': self.ids[grantee]['address'],
            'seal': self.seals[issuer], 'action': 'read', 'resource': 'synthetic/item',
            'nonce': issuer + '-to-' + grantee, 'not_before_height': height,
            'expires_height': height + 20, 'delegation': False, 'transfer': False}
        signature = self.sign(issuer, 'notary-lab/grant-v1:', grant)
        current = self.c.call(self.c.read, 'name_show', self.ids[issuer]['name'])
        op = {'op': 'name_update', 'name': self.ids[issuer]['name'],
              'value': canon({'grant': H(grant)}).decode()}
        row = self.c.run_next(Intent(issuer + '_grant_anchor', issuer,
            ({'txid': current['txid'], 'vout': current['vout']},),
            ({self.ids[issuer]['address']: Decimal('.01')}, {'data': H(grant)}), op))
        self.fixtures[issuer] = {'grant': grant, 'grant_signature': signature,
            'anchor': {'txid': row['txid'], 'height': row['height'], 'blockhash': row['block_hash']}}
        request = {'name': grant['issuer']['name'], 'action': 'read', 'resource': 'synthetic/item',
                   'grant_sha256': H(grant), 'nonce': issuer + '-to-' + grantee + '-request-1'}
        self.requests[issuer] = request, self.sign(grantee, 'swarma-chain-lab/request-v0:', request)
        self.c.record({'event': 'PUBLIC_GRANT', 'fixture': self.fixtures[issuer],
                       'request': request, 'request_signature': self.requests[issuer][1]})

    def verify(self, issuer, grantee, label, expected, *, fixture=None, request=None, signature=None,
               reason=None, view=None):
        self.c.network()
        original_request, original_signature = self.requests[issuer]
        result = protocol_verify(view or self.verifier, fixture or self.fixtures[issuer],
            request or original_request, signature if signature is not None else original_signature,
            self.identity(issuer), self.identity(grantee))
        self.c.record({'event': 'T1_CONTROL', 'label': label, 'result': result, 'expected': expected})
        if result['decision'] != expected or reason is not None and result['reason'] != reason:
            raise Stop('T1_CONTROL_FAILED_' + label)

    def revoke(self):
        point = self.seals['A']
        self.verify('A', 'B', 'before_actual_seal_spend', 'admit')
        row = self.c.run_next(Intent('A_seal_revoke', 'A',
            ({'txid': point['txid'], 'vout': point['vout']},),
            ({self.ids['A']['address']: Decimal(point['value']) - Decimal('.0005')},),
            exact_input=point))
        return row

    def mempool_revoke_control(self, intent, txid):
        point = self.seals['A']
        chain = self.c.call(self.c.read, 'gettxout', point['txid'], point['vout'], False)
        pool = self.c.call(self.c.read, 'gettxout', point['txid'], point['vout'], True)
        if chain is None or pool is not None:
            raise Stop('REVOCATION_MEMPOOL_BOUNDARY_NOT_OBSERVED')
        self.verify('A', 'B', 'actual_spend_mempool_refuse', 'refuse', reason='SEAL_SPENT_INCLUDING_MEMPOOL')
        self.c.record({'event': 'REVOCATION_MEMPOOL_SUSPENDED', 'txid': txid,
                       'one_block_finality': 'experimental policy, reversible by reorg'})

    def core_controls(self):
        self.verify('A', 'B', 'A_grants_B_valid', 'admit')
        self.verify('B', 'A', 'B_grants_A_valid', 'admit')
        req = dict(self.requests['A'][0])
        self.verify('A', 'B', 'wrong_key', 'refuse', signature=self.sign('A', 'swarma-chain-lab/request-v0:', req),
                    reason='REQUEST_SIGNATURE')
        req['action'] = 'write'
        self.verify('A', 'B', 'wrong_scope', 'refuse', request=req,
                    signature=self.sign('B', 'swarma-chain-lab/request-v0:', req), reason='REQUEST_SCOPE')
        fixture = dict(self.fixtures['A'], grant=dict(self.fixtures['A']['grant'], resource='synthetic/other'))
        self.verify('A', 'B', 'tampered_grant', 'refuse', fixture=fixture, reason='ISSUER_SIGNATURE')
        wrong = ReadOnlyView(self.c)
        wrong.config = {'network': 'regtest'}
        self.verify('A', 'B', 'wrong_network_capability', 'refuse', view=wrong, reason='UNAVAILABLE_OR_MALFORMED')
        self.c._gate('core_controls_before_revoke', {'source': self.c.source,
                     'fixtures_sha256': H(self.fixtures), 'operations': list(T1_ORDER)})

    def expiry_controls(self):
        target = self.fixtures['B']['grant']['expires_height']
        until = min(self.c.deadline, self.c.clock() + 7200)
        before_seen = False
        for _ in range(721):
            self.c.network()
            height = self.c.tip[0]
            if height == target - 1 and not before_seen:
                self.verify('B', 'A', 'expiry_height_minus_one', 'admit')
                before_seen = True
            if height >= target:
                self.verify('B', 'A', 'actual_height_expired', 'refuse', reason='EXPIRED_OR_PREMATURE')
                if not before_seen:
                    raise Stop('EXPIRY_BOUNDARY_NOT_OBSERVED')
                return
            if self.c.clock() >= until:
                break
            self.c.pause(min(10, max(0, until - self.c.clock())))
        raise Stop('EXPIRY_DEADLINE')

    def run(self):
        try:
            self.transfer()
            self.reserve('A'); self.reserve('B')
            self.maturity()
            self.firstupdate('A'); self.firstupdate('B')
            self.seal('A'); self.anchor('A', 'B')
            self.seal('B'); self.anchor('B', 'A')
            self.core_controls()
            self.revoke()
            self.verify('A', 'B', 'one_block_revoke_refuse', 'refuse', reason='SEAL_SPENT_INCLUDING_MEMPOOL')
            self.verify('B', 'A', 'other_grant_still_valid', 'admit')
            self.expiry_controls()
            self.c._gate('T1_core_passes_before_T1b', {'source': self.c.source,
                         'fixtures_sha256': H(self.fixtures), 'T1_results': json_safe(self.c.rows)})
            for n in SIZES:
                self.c.run_next(Intent('opreturn_' + str(n), 'A', (), ({'data': payload(n).hex()},)))
            self.c.network()
            self.c.record({'event': 'COMPLETE', 'operations': self.c.index,
                           'total_fee_sat': self.c.fees})
            return list(self.c.rows)
        except Exception:
            self.c.stopped = True
            self.c.record({'event': 'WORKFLOW_STOP', 'next_index': self.c.index,
                           'rebroadcast': False, 'resume_supported': False})
            raise
