"""Synthetic offline source controls only. No node, mainnet, wallet or keys.

The in-memory RPC schema double exercises the main-network guard with public
constants. Its generated transactions are the zero-prevout serialization
fixtures, not signed transactions or observations of any chain.

The original structural controls explicitly disable observation scheduling
and its feasibility check in the TEST DOUBLE, to retain exact-raw admission,
stop-first and serialization coverage independently of timing. test_boundaries exercises the actual scheduler,
preparation and fail-closed phase contract with no such override. Structural success is not runtime feasibility.
"""
import copy
import hashlib
import json
import math
import unittest
from datetime import datetime, timezone
from decimal import Decimal
from unittest.mock import patch

import mainnet as m
import mainnet_t1 as w
import t1b


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def pause(self, amount):
        self.now += amount


class SyntheticRPC:
    """In-memory call control; never a chain/wallet implementation."""
    def __init__(self, clock):
        self.clock, self.calls = clock, []
        self.data, self.raw, self.txid = b'', '', ''
        self.sent, self.allowed = False, True
        self.included, self.reorg = True, False
        self.send_error, self.quote_missing = False, False
        self.extra_input, self.change_owned, self.changed_output = False, True, False
        self.local_pool, self.fail_method = True, None
        self.height = 100

    def __call__(self, method, *args, wallet=''):
        self.calls.append((method, args, wallet))
        if method == self.fail_method:
            raise OSError('synthetic transport error; should never be copied')
        if method == 'getblockchaininfo':
            height = self.height
            return {'chain': 'main', 'initialblockdownload': False, 'blocks': height,
                    'headers': height, 'bestblockhash': 'b'*64}
        if method == 'getblockhash':
            return m.GENESIS['main'] if args[0] == 0 else ('d'*64 if self.reorg else 'b'*64)
        if method == 'getnetworkinfo':
            return {'version': 280000, 'relayfee': Decimal('.00001')}
        if method == 'getmempoolinfo':
            return {'mempoolminfee': Decimal('.00001')}
        if method == 'estimatesmartfee':
            return {'errors': ['SYNTHETIC_NO_QUOTE']} if self.quote_missing else {'feerate': Decimal('.001')}
        if method == 'createrawtransaction':
            self.data = bytes.fromhex(args[1][0]['data'])
            def serialize(fee):
                old, new = t1b.script(self.data), m.null_data(self.data)
                return t1b.serialize(self.data, fee).replace(
                    t1b.compact(len(old)) + old, t1b.compact(len(new)) + new, 1)
            fee = len(serialize(0)) * 200
            self.raw = serialize(fee).hex()
            self.txid = hashlib.sha256(hashlib.sha256(bytes.fromhex(self.raw)).digest()).digest()[::-1].hex()
            return self.raw
        if method == 'fundrawtransaction':
            return {'hex': self.raw, 'fee': Decimal(len(bytes.fromhex(self.raw))*200)/m.SAT}
        if method == 'signrawtransactionwithwallet':
            return {'hex': self.raw, 'complete': True}  # symbolic; no signing
        if method == 'decoderawtransaction':
            size = len(bytes.fromhex(self.raw))
            return {'txid': self.txid, 'vsize': size, 'weight': size * 4,
                'vin': [{'txid': '0'*64, 'vout': 0}] * (2 if self.extra_input else 1),
                'vout': [{'n': 0, 'value': 0,
                          'scriptPubKey': {'hex': m.null_data(self.data + (b'X' if self.changed_output else b'')).hex()}},
                         {'n': 1, 'value': Decimal(10000000-size*200)/m.SAT,
                          'scriptPubKey': {'address': 'synthetic-change'}}]}
        if method == 'getaddressinfo':
            return {'ismine': self.change_owned, 'iswatchonly': False}
        if method == 'gettxout':
            return {'confirmations': 12, 'value': Decimal('.1')}
        if method == 'getrawtransaction':
            if args[0] == '0'*64:
                return {'vout': [{'value': Decimal('.1')}]}
            if len(args) >= 2 and args[1] is False:
                return self.raw
            return {'confirmations': 1 if self.included else 0, 'blockhash': 'b'*64}
        if method == 'testmempoolaccept':
            return [{'allowed': self.allowed, 'reject-reason': 'SYNTHETIC_LOCAL_REFUSAL'}]
        if method == 'sendrawtransaction':
            if self.send_error:
                raise OSError('SYNTHETIC_AMBIGUOUS_SEND')
            self.sent = True
            self.height += 1
            return self.txid
        if method == 'getrawmempool':
            return [self.txid] if self.local_pool else []
        if method == 'getblockheader':
            return {'height': self.height, 'time': 1234567890}
        if method == 'getblock':
            return {'tx': [{'txid': 'e'*64, 'vin': [{'coinbase': '00'}]}, {'txid': self.txid}],
                    'auxpow': None}
        raise AssertionError('unexpected synthetic method: ' + method)


class Tests(unittest.TestCase):
    def setup_control(self, *, enforce_observation_contract=False, observer_destination='127.0.0.1', **admission_delta):
        self.clock = Clock()
        self.rpc = SyntheticRPC(self.clock)
        self.journal, self.gates = [], []
        self.peer_status, self.marker_refuse = 'observed', False
        self.gate_change_raw, self.journal_fail = False, False

        def gate(kind, binding):
            self.gates.append((kind, copy.deepcopy(binding)))
            if kind == 'Meta_each_exact_raw_transaction' and self.marker_refuse:
                return None
            return 'a'*64

        def journal(row):
            if self.journal_fail and row['event'] == 'BROADCAST_ATTEMPT':
                raise OSError('SYNTHETIC_JOURNAL_FAILURE')
            self.journal.append(copy.deepcopy(row))

        def peer(binding):
            return {'status': self.peer_status, 'txid': binding['txid'],
                    'raw_sha256': binding['raw_sha256'], 'kind': 'SYNTHETIC_OFFLINE_CONTROL',
                    'evidence_kind': 'remote_mempool', 'observer_label': 'synthetic',
                    # Do not round the synthetic observation into the fake clock's future.
                    'observed_at_utc': datetime.fromtimestamp(math.floor(self.clock()*1000000)/1000000, timezone.utc).isoformat()}

        source = {'head': '1'*40, 'tree': '2'*40}
        admission = {'started_monotonic': 1000, 'deadline_monotonic': 22600,
                     'deadline_utc_epoch': 22600, 'funding_address': 'SYNTHETIC_NEW_ADDRESS',
                     'requested_funding_sat': 6866200, 'recomputed_required_sat': 6866200}
        admission.update(admission_delta)
        self.c = m.Collector(m.Capability(self.rpc, m.OBSERVE, destination=observer_destination), m.Capability(self.rpc, m.BUILD),
              {r: m.Capability(self.rpc, m.WALLET, wallet='synthetic-new-' + r) for r in ('A', 'B')},
              m.Capability(self.rpc, m.BROADCAST), peer, gate, journal, source=source,
              admission=admission, clock=self.clock, wall=self.clock, pause=self.clock.pause)
        # Isolated collector control at T1b boundary; this does not attest T1
        # execution or use a fake-mainnet report. Workflow sequence is separate.
        self.c.index = 10
        if not enforce_observation_contract:
            # TEST ONLY: never a product option or runtime admission override.
            self.c.observation_slot = lambda cap, method: None
            self.c.require_preparation_capacity = lambda intent: None
        return self.c

    def intent(self, n=80):
        return m.Intent('opreturn_' + str(n), 'A', (), ({'data': t1b.payload(n).hex()},))

    def sends(self):
        return [x for x in self.rpc.calls if x[0] == 'sendrawtransaction']

    def test_capability_rejects_before_transport(self):
        touched = []
        cap = m.Capability(lambda *a, **kw: touched.append(a), m.OBSERVE)
        for method in ('signmessage', 'sendrawtransaction', 'importprivkey', 'name_new',
                       'createwallet', 'getnewaddress', 'listwallets', 'stop', 'generatetoaddress'):
            with self.assertRaises(m.Stop):
                cap(method)
        with self.assertRaises(m.Stop):
            cap('name_show', 'synthetic', wallet='owner')
        self.assertEqual(touched, [])

    def test_conditional_model_and_no_cap_filling(self):
        self.assertEqual(t1b.budget()['owner_cap_sat'], 100000000)
        self.assertEqual(t1b.budget()['all_in_required_sat'], 6866200)
        for delta in ({'requested_funding_sat': 100000000, 'recomputed_required_sat': 100000000},
                      {'requested_funding_sat': 6866201}, {'deadline_monotonic': 22601},
                      {'deadline_monotonic': float('nan')}, {'started_monotonic': 1001},
                      {'funding_address': ''}):
            with self.subTest(delta=delta), self.assertRaises(m.Stop):
                self.setup_control(**delta)

    def test_all_exact_serializations_single_admission_each_before_send(self):
        self.setup_control()
        for n in t1b.SIZES:
            row = self.c.run_next(self.intent(n))
            self.assertEqual(row['operation'], 'opreturn_' + str(n))
            self.assertEqual(row['miner_attribution'].split(':')[0], 'UNKNOWN')
        markers = [b for kind, b in self.gates if kind == 'Meta_each_exact_raw_transaction']
        self.assertEqual(len(markers), 7)
        self.assertEqual(len(self.sends()), 7)
        for marker, sent, n in zip(markers, self.sends(), t1b.SIZES):
            self.assertEqual(marker['raw_hex'], sent[1][0])
            self.assertEqual(marker['raw_sha256'], m.sha(bytes.fromhex(sent[1][0])))
            self.assertIn(t1b.payload(n), bytes.fromhex(sent[1][0]))
        events = [r['event'] for r in self.journal]
        self.assertEqual(events.count('BROADCAST_ATTEMPT'), 7)
        self.assertEqual(events.count('PEER_OBSERVED'), 7)
        self.assertEqual(events.count('INCLUSION'), 7)

    def test_refusal_unknown_and_deadlines_are_terminal(self):
        cases = ('policy', 'marker', 'peer_unknown', 'peer_refused', 'peer_pending',
                 'inclusion', 'reorg', 'rpc', 'input', 'change', 'payload',
                 'journal', 'send', 'local_pool', 'deadline', 'order')
        for case in cases:
            with self.subTest(case=case):
                self.setup_control()
                if case == 'policy': self.rpc.allowed = False
                if case == 'marker': self.marker_refuse = True
                if case.startswith('peer_'): self.peer_status = {'peer_unknown': 'unknown', 'peer_refused': 'refused', 'peer_pending': 'pending'}[case]
                if case == 'inclusion': self.rpc.included = False
                if case == 'reorg': self.rpc.reorg = True
                if case == 'rpc': self.rpc.fail_method = 'getnetworkinfo'
                if case == 'input': self.rpc.extra_input = True
                if case == 'change': self.rpc.change_owned = False
                if case == 'payload': self.rpc.changed_output = True
                if case == 'journal': self.journal_fail = True
                if case == 'send': self.rpc.send_error = True
                if case == 'local_pool': self.rpc.local_pool = False
                if case == 'deadline': self.clock.now = 22600
                if case == 'order': self.c.index = 11
                with self.assertRaises(m.Stop): self.c.run_next(self.intent())
                count = len(self.sends())
                self.assertLessEqual(count, 1)
                with self.assertRaises(m.Stop): self.c.run_next(self.intent())
                self.assertEqual(len(self.sends()), count)
                self.assertTrue(self.c.stopped)
                if case in ('policy', 'marker', 'rpc', 'input', 'change', 'payload', 'journal', 'deadline', 'order'):
                    self.assertEqual(count, 0)
                if case == 'policy':
                    self.assertTrue(any(r.get('result', [{}])[0].get('reject-reason') == 'SYNTHETIC_LOCAL_REFUSAL'
                        for r in self.journal if r['event'] == 'LOCAL_POLICY_RESULT'))

    def test_timing_and_response_bounds_before_send(self):
        self.setup_control()
        self.c.calls = 2100
        with self.assertRaises(m.Stop): self.c.run_next(self.intent())
        self.assertEqual(self.sends(), [])
        self.setup_control()
        self.c.response_bytes = 64 * 1024 * 1024
        with self.assertRaises(m.Stop): self.c.run_next(self.intent())
        self.assertEqual(self.sends(), [])
        self.setup_control()
        old = self.c.gates
        def slow_gate(kind, binding):
            if kind == 'Meta_each_exact_raw_transaction': self.clock.now += 181
            return old(kind, binding)
        self.c.gates = slow_gate
        with self.assertRaisesRegex(m.Stop, 'PREPARATION_DEADLINE'):
            self.c.run_next(self.intent())
        self.assertEqual(self.sends(), [])

    def test_grant_short_push_differs_from_large_payload_push(self):
        self.assertEqual(m.null_data(b'x'*32), b'\x6a\x20' + b'x'*32)
        for n in t1b.SIZES:
            self.assertEqual(m.null_data(t1b.payload(n)), t1b.script(t1b.payload(n)))

    def test_mutated_marker_binding_and_late_peer_cannot_authorize(self):
        self.setup_control()
        old = self.c.gates
        def mutate(kind, binding):
            if kind == 'Meta_each_exact_raw_transaction': binding['raw_hex'] += '00'
            return old(kind, binding)
        self.c.gates = mutate
        with self.assertRaisesRegex(m.Stop, 'ADMISSION_BINDING_MUTATED'):
            self.c.run_next(self.intent())
        self.assertEqual(self.sends(), [])
        self.setup_control()
        old_peer = self.c.peer
        def late(binding):
            self.clock.now += 121
            return old_peer(binding)
        self.c.peer = late
        with self.assertRaises(m.Stop): self.c.run_next(self.intent())
        self.assertEqual(len(self.sends()), 1)
        self.assertEqual(self.c.index, 10)

    def test_workflow_selects_only_expected_operations_and_seal(self):
        self.setup_control()
        public = {r: {'name': 'd/synthetic-trust-control-' + r.lower(),
                       'address': 'SYNTHETIC_' + r, 'pubkey': ('02' if r == 'A' else '03') + 'ab'*32,
                       'rand': ('11' if r == 'A' else '22')*20} for r in ('A', 'B')}
        workflow = w.Workflow(self.c, public)
        intents = []
        workflow.point = lambda txid, role, named=False: {'txid': txid, 'vout': 0,
                                                         'script': '00', 'value': '.001'}
        self.c.run_next = lambda intent: intents.append(intent) or {'txid': 'c'*64}
        self.c.rpc_for_builder = lambda *args, **kwargs: True
        workflow.transfer(); workflow.reserve('A'); workflow.reserve('B')
        workflow.firstupdate('A'); workflow.firstupdate('B')
        workflow.seal('A')
        self.assertEqual(tuple(i.operation for i in intents), m.T1_ORDER[:6])
        self.assertEqual(intents[0].outputs, ({'SYNTHETIC_B': Decimal('.014366')},))
        self.assertEqual(intents[3].inputs, ({'txid': 'c'*64, 'vout': 0},))
        self.assertEqual(intents[3].name_op['value'], '{"pubkey":"' + public['A']['pubkey'] + '"}')
        workflow.verify = lambda *args, **kwargs: None
        workflow.revoke()
        self.assertEqual(intents[-1].operation, 'A_seal_revoke')
        self.assertEqual(intents[-1].exact_input, workflow.seals['A'])
        self.assertEqual(intents[-1].outputs, ({'SYNTHETIC_A': Decimal('.0005')},))

    def test_workflow_anchors_existing_mutual_grant_domains_and_bytes(self):
        self.setup_control()
        public = {r: {'name': 'd/synthetic-trust-control-' + r.lower(),
                       'address': 'SYNTHETIC_' + r, 'pubkey': ('02' if r == 'A' else '03') + 'ab'*32,
                       'rand': ('11' if r == 'A' else '22')*20} for r in ('A', 'B')}
        workflow = w.Workflow(self.c, public)
        signatures, intents = [], []
        for role, txid in (('A', 'c'*64), ('B', 'd'*64)):
            workflow.ids[role]['identity_txid'] = txid
            workflow.seals[role] = {'txid': txid, 'vout': 1, 'script': '00', 'value': '.001'}
        original_call = self.c.call
        def read(cap, method, *params, **kwargs):
            if method == 'name_show': return {'txid': 'e'*64, 'vout': 0}
            return original_call(cap, method, *params, **kwargs)
        self.c.call = read
        self.c.run_next = lambda intent: intents.append(intent) or {'txid': 'f'*64, 'height': 100, 'block_hash': 'b'*64}
        def symbolic(method, *params, **kwargs):
            signatures.append((method, params, kwargs))
            return 'SYNTHETIC_SIGNATURE_ORACLE_NOT_A_SIGNATURE'
        self.c.rpc_for_builder = symbolic
        workflow.anchor('A', 'B'); workflow.anchor('B', 'A')
        self.assertEqual([i.operation for i in intents], ['A_grant_anchor', 'B_grant_anchor'])
        for issuer, grantee, intent in zip(('A', 'B'), ('B', 'A'), intents):
            grant = workflow.fixtures[issuer]['grant']
            self.assertEqual(grant['version'], 'synthetic-notarized-grant-v1')
            self.assertEqual(grant['issuer'], workflow.identity(issuer))
            self.assertEqual(grant['grantee'], public[grantee]['address'])
            self.assertEqual(grant['seal'], workflow.seals[issuer])
            raw_canonical = json.dumps(grant, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
            commitment = hashlib.sha256(raw_canonical).hexdigest()
            self.assertEqual(intent.outputs[1], {'data': commitment})
            self.assertEqual(intent.name_op['value'], '{"grant":"' + commitment + '"}')
            self.assertTrue(any(p[1][-1] == 'notary-lab/grant-v1:' + commitment for p in signatures))
            req, sig = workflow.requests[issuer]
            req_hash = hashlib.sha256(json.dumps(req, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            self.assertTrue(any(p[1][-1] == 'swarma-chain-lab/request-v0:' + req_hash for p in signatures))
            self.assertEqual(sig, 'SYNTHETIC_SIGNATURE_ORACLE_NOT_A_SIGNATURE')


if __name__ == '__main__':
    print('SYNTHETIC_OFFLINE_SOURCE_CONTROLS_ONLY; actual node/mainnet/wallet/signature/broadcast operations = 0')
    unittest.main(verbosity=2)
