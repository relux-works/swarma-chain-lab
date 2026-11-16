#!/usr/bin/env python3
"""Offline controls: no RPC/HTTP calls, subprocesses, key files or node startup."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
PACK = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('smoke', PACK / 'smoke.py')
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class SmokeTests(unittest.TestCase):
    def setUp(self):
        self.vector = next(v for v in json.loads((smoke.MODULE / 'testdata/vectors.json').read_bytes())['vectors']
                           if v['name'] == 'positive-same-owner')
        self.policy = json.loads(self.vector['policy'])
        self.request = {k: json.loads(self.vector[k]) for k in
                        ('parent', 'child', 'parent_contract', 'child_contract', 'request', 'statement')}
        self.request['policy_reference'] = smoke.digest(smoke.octets(self.policy))
        self.public = json.loads(self.vector['notary_value'])['swarma']['notary']['attest']
        self.result = dict(decision='ATTEST', signed_attestation=dict(
            attestation=json.loads(self.vector['result']['attestation']),
            signature=self.vector['attestation_signature']), anchor_frame=self.vector['anchor_script'])

    # Claim: exactly one correctly labelled receipt key is accepted; absent, duplicate and malformed fields refuse beside that control.
    def test_receipt_only_key(self):
        raw = smoke.KEY_LABEL + self.public + '\n'
        self.assertTrue(smoke.receipt_key(raw) == self.public)
        for bad in ('', raw + raw, smoke.KEY_LABEL + 'invalid\n'):
            with self.assertRaises(smoke.Stop):
                smoke.receipt_key(bad)

    # Claim: a newly encoded current strict /2 depth-1 bundle binds the observed registration/tip and never embeds the retained public key in files.
    def test_fresh_bundle(self):
        registration = dict(txid='ab' * 32, vout=2)
        info = dict(blocks=123, bestblockhash='cd' * 32)
        policy, request = smoke.fresh_bundle(registration, info, self.public)
        delegate = request['parent_contract']['delegate']
        self.assertTrue(policy['notary_name'] == 'id/certifier' and 'mode' not in policy)
        self.assertTrue(delegate['depth'] == 1 and request['child_contract']['delegate']['depth'] == 0)
        self.assertTrue(delegate['notaries'][0]['registration'] == registration)
        self.assertTrue(request['statement']['tip_height'] == 123 and request['statement']['tip_hash'] == 'cd' * 32)
        self.assertTrue(request['policy_reference'] == smoke.digest(smoke.octets(policy)))
        self.assertTrue(self.public.encode() not in smoke.octets([policy, request]))
        self.assertLessEqual(len(smoke.octets(request)), 65536)
        # Negative beside the positive: an invalid registration fails independent preflight.
        with self.assertRaises(Exception):
            smoke.fresh_bundle(dict(txid='invalid', vout=2), info, self.public)

    # Claim: a known positive BIP-340/envelope/frame verifies; changed signature, frame, binding or HTTP status fails beside it.
    def test_positive_and_corruption(self):
        with patch.object(smoke.time, 'time', return_value=self.vector['at']):
            smoke.check_response(200, self.result, 'ATTEST', self.request, self.policy, self.public)
            for field in ('signature', 'anchor', 'binding', 'status'):
                bad = copy.deepcopy(self.result)
                if field == 'signature':
                    bad['signed_attestation']['signature'] = '00' * 64
                elif field == 'anchor':
                    bad['anchor_frame'] = '00' * 72
                elif field == 'binding':
                    bad['signed_attestation']['attestation']['notary_name'] = 'id/other'
                with self.assertRaises(smoke.Stop):
                    smoke.check_response(422 if field == 'status' else 200, bad,
                                         'ATTEST', self.request, self.policy, self.public)

    # Claim: only exact 422 NOTARY_KEY without signed fields passes the absent-binding control; alternate refusals/statuses/fields fail.
    def test_refusal_exact(self):
        smoke.check_response(422, {'decision': 'NOTARY_KEY'}, 'NOTARY_KEY', self.request, self.policy, self.public)
        for status, body in ((200, {'decision': 'NOTARY_KEY'}),
                             (422, {'decision': 'NODE_TIP_MISMATCH'}),
                             (422, {'decision': 'NOTARY_KEY', 'signed_attestation': {}})):
            with self.assertRaises(smoke.Stop):
                smoke.check_response(status, body, 'NOTARY_KEY', self.request, self.policy, self.public)

    # Claim: observation requires canonical UTF-8 name/value and matching resolver history fields, ignoring only unrelated RPC extensions beside mismatching-value refusals.
    def test_observation_contract(self):
        name, value, _ = smoke.binding(self.public)
        current = dict(name=name, value=smoke.octets(value).decode(), txid='ab' * 32, vout=2,
                       height=123, expires_in=100, expired=False, name_encoding='utf8', value_encoding='utf8')
        with patch.object(smoke, 'rpc', side_effect=[dict(current, wallet_extension=True), [current]]) as rpc:
            self.assertTrue(smoke.observed(name, value) == dict(txid='ab' * 32, vout=2))
            self.assertTrue(all(call.args[-1] == dict(nameEncoding='utf8', valueEncoding='utf8') for call in rpc.call_args_list))
            rpc.side_effect = [dict(current, value='{}'), [current]]
            with self.assertRaises(smoke.Stop):
                smoke.observed(name, value)
            rpc.side_effect = [current, [dict(current, txid='cd' * 32)]]
            with self.assertRaises(smoke.Stop):
                smoke.observed(name, value)

    # Claim: readiness records only an exact POLICY_REFERENCE refusal, and never records a success for a signed or alternate response.
    def test_readiness(self):
        with patch.object(smoke, 'post', return_value=(422, {'decision': 'POLICY_REFERENCE'})) as post, \
             patch.object(smoke, 'record') as record:
            smoke.readiness(self.public)
            self.assertEqual(post.call_args.args, ({},))
            self.assertTrue(record.call_args.args == ('refusal_control_http_and_decision: 422 POLICY_REFERENCE',))
            record.reset_mock()
            post.return_value = (200, self.result)
            with self.assertRaises(smoke.Stop):
                smoke.readiness(self.public)
            self.assertEqual(record.call_count, 0)

    # Claim: certify sends one positive plus the adjacent absent-binding control, refreshes only the tip, restores the binding and unloads the wallet; a one-shot collision prevents all POSTs.
    def test_certify_sequence_and_one_shot(self):
        files = {'smoke-policy.json': smoke.octets(self.policy),
                 'smoke-request.json': smoke.octets(self.request), 'smoke-address.json': b'"local-address"'}
        reads = Path.read_bytes
        def read_bytes(path):
            return files['smoke-policy.json'] if str(path) == '/etc/notary-service/deployment-policy.json' else reads(path)
        sent = []
        def post(request):
            sent.append(copy.deepcopy(request))
            return (200, self.result) if len(sent) == 1 else (422, {'decision': 'NOTARY_KEY'})
        tip = self.request['statement']
        with patch.object(smoke, 'private_read', side_effect=lambda p: files[p.name]), \
             patch.object(Path, 'read_bytes', read_bytes), \
             patch.object(smoke, 'create') as create, patch.object(smoke, 'record') as record, \
             patch.object(smoke, 'rpc') as rpc, patch.object(smoke, 'observed'), \
             patch.object(smoke, 'view', return_value=dict(blocks=tip['tip_height'], bestblockhash=tip['tip_hash'])), \
             patch.object(smoke, 'mine', return_value=dict(blocks=tip['tip_height'] + 1, bestblockhash='ee' * 32)), \
             patch.object(smoke, 'post', side_effect=post) as post_mock, \
             patch.object(smoke.time, 'time', return_value=self.vector['at']):
            smoke.certify(self.public)
            self.assertEqual(len(sent), 2)
            positive, negative = copy.deepcopy(sent)
            positive.pop('statement')
            negative.pop('statement')
            self.assertTrue(positive == negative)
            self.assertEqual(sent[1]['statement']['tip_height'], tip['tip_height'] + 1)
            self.assertEqual(create.call_count, 1)
            self.assertTrue(create.call_args.args[0].name == 'certify.started')
            self.assertTrue([call.args[0] for call in rpc.call_args_list] == ['name_update', 'name_update', 'unloadwallet'])
            self.assertTrue('PASS_WITH_ADJACENT' in record.call_args.args[0])
            create.side_effect = FileExistsError
            post_mock.reset_mock()
            with self.assertRaises(FileExistsError):
                smoke.certify(self.public)
            self.assertEqual(post_mock.call_count, 0)
            # Negative beside the successful sequence: refusal mismatch still restores, but never records acceptance.
            sent.clear()
            create.side_effect = None
            rpc.reset_mock()
            record.reset_mock()
            def wrong_control(request):
                sent.append(copy.deepcopy(request))
                return (200, self.result) if len(sent) == 1 else (422, {'decision': 'NODE_TIP_MISMATCH'})
            post_mock.side_effect = wrong_control
            with self.assertRaises(smoke.Stop):
                smoke.certify(self.public)
            self.assertTrue([call.args[0] for call in rpc.call_args_list] == ['name_update', 'name_update'])
            self.assertTrue(all('PASS_WITH_ADJACENT' not in call.args[0] for call in record.call_args_list))

    # Claim: prepare mines maturity/12/1 blocks around the policy-name registration, writes no retained key bytes, and aborts on an existing name before wallet creation.
    def test_prepare_order_and_absence_gate(self):
        registration = dict(txid='ab' * 32, vout=2)
        def rpc(method, *args, **kwargs):
            if method == 'listwalletdir':
                return {'wallets': []}
            if method == 'getnewaddress':
                return 'local-address'
            if method == 'name_new':
                return ['txid', 'throwaway-randomness']
        with patch.object(smoke.os.path, 'lexists', return_value=False), \
             patch.object(smoke, 'view'), patch.object(smoke, 'rpc', side_effect=rpc) as rpc_mock, \
             patch.object(smoke, 'mine', return_value=dict(blocks=123, bestblockhash='cd' * 32)) as mine, \
             patch.object(smoke, 'observed', return_value=registration), \
             patch.object(smoke, 'fresh_bundle', return_value=(self.policy, self.request)), \
             patch.object(smoke, 'create') as create, patch.object(smoke, 'record') as record:
            smoke.prepare(self.public)
            self.assertEqual([call.args[0] for call in mine.call_args_list], [110, 12, 1])
            methods = [call.args[0] for call in rpc_mock.call_args_list]
            self.assertEqual(methods, ['name_show', 'listwalletdir', 'createwallet', 'getnewaddress', 'name_new', 'name_firstupdate'])
            update = rpc_mock.call_args_list[-1].args
            self.assertTrue(update[1] == self.policy['notary_name'] and json.loads(update[-1]) == smoke.binding(self.public)[1])
            self.assertTrue(all(self.public.encode() not in call.args[1] for call in create.call_args_list))
            self.assertTrue(all(self.public not in call.args[0] for call in record.call_args_list))
            rpc_mock.reset_mock()
            create.reset_mock()
            rpc_mock.side_effect = smoke.Stop('NAME_ALREADY_PRESENT')
            with self.assertRaises(smoke.Stop):
                smoke.prepare(self.public)
            self.assertEqual(rpc_mock.call_count, 1)
            self.assertEqual(create.call_count, 0)

    # Claim: RPC value and name_new randomness are supplied via stdin, never argv; a failed RPC aborts beside the successful capture.
    def test_rpc_stdin_and_abort(self):
        response = type('Result', (), {'returncode': 0, 'stdout': b'"txid"', 'stderr': b''})()
        value = smoke.octets(smoke.binding(self.public)[1]).decode()
        with patch.object(smoke.subprocess, 'run', return_value=response) as run:
            smoke.rpc('name_firstupdate', 'id/certifier', 'throwaway-randomness', 'txid', value, wallet=True)
            args = run.call_args.args[0]
            self.assertTrue('-stdin' in args and value not in args and 'throwaway-randomness' not in args)
            self.assertTrue(value.encode() in run.call_args.kwargs['input'])
            response.returncode = 1
            with self.assertRaises(smoke.Stop):
                smoke.rpc('name_firstupdate', 'id/certifier', 'throwaway-randomness', 'txid', value, wallet=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
