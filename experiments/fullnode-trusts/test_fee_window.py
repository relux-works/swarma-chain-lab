"""Offline paired fixed-fee/block-window controls; no network or real signing."""
import copy
import hashlib
import json
import unittest
from decimal import Decimal

import mainnet as m
from funding import funder_record
import test_mainnet as harness_module


class FeeWindow(unittest.TestCase):
    def harness(self, heights=(101,), inclusion=None, peer='observed', reorg=None):
        h = harness_module.Tests()
        h.setup_control(enforce_observation_contract=True)
        h.peer_status = peer
        transport = h.rpc.__class__.__call__
        heights = iter(heights)
        state = {'height': 100, 'polls': 0, 'hash_reads': 0}

        def block_hash(height):
            return 'b'*64 if height == 100 else hashlib.sha256(str(height).encode()).hexdigest()

        def rpc(method, *params, wallet=''):
            if method == 'getblockchaininfo' and h.rpc.sent:
                state['height'] = next(heights, state['height'])
                state['polls'] += 1
                height = state['height']
                return {'chain': 'main', 'initialblockdownload': False,
                        'blocks': height, 'headers': height,
                        'bestblockhash': 'd'*64 if reorg == 'tip' else block_hash(height)}
            if method == 'getblockhash' and h.rpc.sent:
                state['hash_reads'] += 1
                # Change the baseline ancestor even while tip height grows.
                if reorg in ('ancestor', 'tip') and params[0] == 100:
                    return 'd'*64
                return m.GENESIS['main'] if params[0] == 0 else block_hash(params[0])
            if method == 'getrawtransaction' and h.rpc.sent and params[0] == h.rpc.txid:
                if params[1] is False:
                    return h.rpc.raw
                confirmed = inclusion is not None and state['height'] >= inclusion
                return {'confirmations': state['height']-inclusion+1 if confirmed else 0,
                        'blockhash': block_hash(inclusion) if confirmed else None}
            if method == 'getblockheader' and h.rpc.sent:
                return {'height': inclusion, 'time': 1234567890}
            return transport(h.rpc, method, *params, wallet=wallet)
        for cap in (h.c.read, h.c.build, h.c.broadcast, *h.c.wallets.values()):
            cap._transport = rpc
        return h, state

    def terminal(self, h, reason):
        with self.assertRaisesRegex(m.Stop, reason):
            h.c.run_next(h.intent())
        sends = len(h.sends())
        reads = len(h.rpc.calls)
        before = (h.c.started, h.c.deadline, h.c.deadline_wall, h.c.series_start,
                  copy.deepcopy(h.c.broadcast_window))
        with self.assertRaisesRegex(m.Stop, 'TERMINAL_NO_RETRY'):
            h.c.run_next(h.intent())
        self.assertEqual(len(h.sends()), sends)
        self.assertEqual(len(h.rpc.calls), reads)
        self.assertEqual(before, (h.c.started, h.c.deadline, h.c.deadline_wall,
                                 h.c.series_start, h.c.broadcast_window))
        self.assertEqual(h.c.index, 10)
        self.assertTrue(h.c.stopped)
        return sends

    def test_estimator_missing_error_and_extreme_quote_are_irrelevant(self):
        for estimator in ('missing', 'transport_error', 'extreme_quote'):
            h, _ = self.harness(inclusion=101)
            h.rpc.quote_missing = estimator == 'missing'
            if estimator == 'transport_error':
                h.rpc.fail_method = 'estimatesmartfee'
            row = h.c.run_next(h.intent())
            self.assertEqual(row['height'], 101)
            self.assertEqual(len(h.sends()), 1)
            self.assertNotIn('estimatesmartfee', [c[0] for c in h.rpc.calls])
            policy = next(r['snapshot'] for r in h.journal if r['event'] == 'POLICY')
            self.assertEqual(policy['rate_sat_vb'], 200)
            self.assertIsNone(policy['estimator_quote'])
            self.assertIsNone(policy['inclusion_quote'])

    def test_policy_floor_still_blocks_before_construction(self):
        h, _ = self.harness(inclusion=101)
        old = h.c.read._transport
        def high(method, *params, wallet=''):
            if method == 'getmempoolinfo':
                return {'mempoolminfee': Decimal('.00200001')}
            return old(method, *params, wallet=wallet)
        h.c.read._transport = high
        self.assertEqual(self.terminal(h, 'FRESH_FEE_MODEL_REQUIRED'), 0)
        self.assertNotIn('createrawtransaction', [c[0] for c in h.rpc.calls])

    def test_paired_confirmed_and_unconfirmed_at_sixth_native_block(self):
        for inclusion in (106, None):
            h, state = self.harness(heights=range(101, 107), inclusion=inclusion)
            if inclusion is None:
                self.assertEqual(self.terminal(h, 'SIX_BLOCK_INCLUSION_STOP'), 1)
            else:
                row = h.c.run_next(h.intent())
                self.assertEqual(row['height'], 106)
                self.assertEqual(len(h.sends()), 1)
                self.assertEqual(h.c.index, 11)
            self.assertEqual(state['height'], 106)
            self.assertGreaterEqual(state['polls'], 6)
            print('PAIRED_SIX_BLOCK', json.dumps({'inclusion': inclusion, **state}))

    def test_sixth_block_during_peer_wait_is_terminal(self):
        h, state = self.harness(heights=range(101, 107), peer='pending')
        self.assertEqual(self.terminal(h, 'SIX_BLOCK_INCLUSION_STOP'), 1)
        self.assertEqual(state['polls'], 6)
        self.assertLess(h.clock() - h.c.step_start, 120)

    def test_skipped_tip_does_not_widen_original_six_block_window(self):
        for inclusion, passes in ((106, True), (107, False), (None, False)):
            h, state = self.harness(heights=(107,), inclusion=inclusion)
            if passes:
                row = h.c.run_next(h.intent())
                self.assertEqual(row['height'], 106)
                windows = [r for r in h.journal if r['event'] == 'SIX_BLOCK_WINDOW']
                self.assertTrue(windows)
                self.assertTrue(all(r['limit_height'] == 106 for r in windows))
            else:
                self.terminal(h, 'SIX_BLOCK_INCLUSION_STOP')
            self.assertEqual(state['height'], 107)

    def test_stalled_chain_and_five_blocks_keep_original_time_bound(self):
        for heights in ((100,), (101, 102, 103, 104, 105)):
            h, state = self.harness(heights=heights)
            self.assertEqual(self.terminal(h, 'INCLUSION_DEADLINE'), 1)
            self.assertLess(state['height'], 106)
            self.assertGreater(state['polls'], 6)
            stops = [r['reason'] for r in h.journal if r['event'] == 'STOP']
            self.assertNotIn('SIX_BLOCK_INCLUSION_STOP', stops)
            print('STALLED_NATIVE_CHAIN', json.dumps(state))

    def test_reorg_never_rebases_broadcast_window(self):
        for heights, reorg in (((99,), None), ((101,), 'ancestor'), ((100,), 'tip'),
                               ((101, 102, 101), None)):
            h, _ = self.harness(heights=heights, reorg=reorg)
            self.assertEqual(self.terminal(h, 'REORG'), 1)
            self.assertEqual(h.c.broadcast_window[0], 100)

    def test_remote_block_cannot_substitute_for_peer_mempool_observation(self):
        h, _ = self.harness(inclusion=101)
        old = h.c.peer
        def remote_block(binding):
            return dict(old(binding), evidence_kind='remote_block')
        h.c.peer = remote_block
        self.assertEqual(self.terminal(h, 'PEER_EVIDENCE_KIND'), 1)
        self.assertFalse(any(r['event'] == 'INCLUSION' for r in h.journal))

    def test_funder_fee_planning_line_is_not_a_cap(self):
        for fee in (46000, 50600, 50601, 60000):
            row = funder_record(6815600, fee)
            self.assertTrue(row['within_owner_cap'])
            self.assertEqual(row['recipient_required_sat'], 6815600)
            self.assertEqual(row['all_in_provision_sat'], 6815600 + fee + (fee+9)//10)
            self.assertFalse(row['spend_authorized'])
        self.assertFalse(funder_record(6815600, 100000000)['within_owner_cap'])
        for invalid in (-1, 1.5, True):
            with self.assertRaises(ValueError):
                funder_record(6815600, invalid)


if __name__ == '__main__':
    unittest.main(verbosity=2)
