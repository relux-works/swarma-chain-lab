"""Offline causal core/T1b neighbors; real collector flow, synthetic RPC only."""
import copy
import unittest
from datetime import datetime, timezone

import mainnet as m
import test_fee_window as window


class RelayPolicy(unittest.TestCase):
    def harness(self, *, core=True, **kwargs):
        h, state = window.FeeWindow().harness(**kwargs)
        h.observations = []
        transport = h.c.read._transport
        def read(method, *params, wallet=''):
            result = transport(method, *params, wallet=wallet)
            h.observations.append((method, params, result))
            return result
        h.c.read._transport = read
        if core:
            h.c.index = m.ORDER.index('A_grant_anchor')
        intent = (m.Intent('A_grant_anchor', 'A', (), ({'data': '11'*32},))
                  if core else h.intent())
        return h, state, intent

    def stop(self, h, intent, reason):
        index = h.c.index
        with self.assertRaisesRegex(m.Stop, reason):
            h.c.run_next(intent)
        self.assertEqual(h.c.index, index)
        self.assertFalse(any(r['event'] == 'INCLUSION' for r in h.journal))
        calls = h.c.calls
        clocks = (h.c.started, h.c.deadline, h.c.deadline_wall, h.c.step_start,
                  h.c.series_start, copy.deepcopy(h.c.broadcast_window))
        with self.assertRaisesRegex(m.Stop, 'TERMINAL_NO_RETRY'):
            h.c.run_next(intent)
        self.assertEqual(h.c.calls, calls)
        self.assertEqual(clocks, (h.c.started, h.c.deadline, h.c.deadline_wall,
                                 h.c.step_start, h.c.series_start, h.c.broadcast_window))

    def test_missing_receipt_core_includes_exact_bytes_without_peer_wait(self):
        for absence in (None, 'absent', 'unknown', 'pending'):
            h, _, intent = self.harness(inclusion=101)
            polls = []
            if absence is None:
                h.c.peer = None
            else:
                h.c.peer = lambda binding: polls.append(binding) or {'status': absence}
            row = h.c.run_next(intent)
            self.assertEqual(row['mode'], m.CORE_MODE)
            self.assertEqual(row['remote_mempool_status'], 'UNKNOWN')
            self.assertIsNone(row['peer_receipt_sha256'])
            self.assertIsNone(row['block_receipt_sha256'])
            self.assertEqual(len(polls), 0 if absence is None else 1)
            self.assertLess(row['inclusion_monotonic'] - row['broadcast_monotonic'], 30)
            self.assertEqual(len(h.sends()), 1)
            self.assertTrue(any(r['event'] == 'REMOTE_MEMPOOL_UNKNOWN' for r in h.journal))
            self.assertFalse(any(r['event'] == 'PEER_OBSERVED' for r in h.journal))
            marker = next(b for k, b in h.gates if k == 'Meta_each_exact_raw_transaction')
            self.assertEqual(marker['mode'], m.CORE_MODE)
            self.assertEqual(marker['raw_hex'], h.sends()[0][1][0])
            self.assertEqual(marker['raw_sha256'], row['raw_sha256'])
            exact = [c for c in h.observations if c[0] == 'getrawtransaction' and c[1][1] is False]
            self.assertTrue(exact)
            self.assertEqual(exact[-1][2], marker['raw_hex'])

    def test_t1b_missing_receipt_and_remote_block_cannot_advance(self):
        for absence in (None, 'absent', 'unknown', 'pending', 'remote_block'):
            h, _, intent = self.harness(core=False, inclusion=101)
            old = h.c.peer
            if absence is None:
                h.c.peer = None
                reason = 'PEER_OBSERVER_REQUIRED'
            elif absence == 'remote_block':
                h.c.peer = lambda binding: dict(old(binding), evidence_kind='remote_block')
                reason = 'PEER_EVIDENCE_KIND'
            else:
                h.c.peer = lambda binding: {'status': absence}
                reason = 'PEER_'
            self.stop(h, intent, reason)
            self.assertEqual(len(h.sends()), 0 if absence is None else 1)

    def test_authenticated_remote_mempool_neighbor_passes_in_both_modes(self):
        for core in (True, False):
            h, _, intent = self.harness(core=core, inclusion=101)
            index = h.c.index
            clocks = (h.c.started, h.c.deadline, h.c.deadline_wall)
            row = h.c.run_next(intent)
            self.assertEqual(row['mode'], m.CORE_MODE if core else m.SERIES_MODE)
            self.assertEqual(row['remote_mempool_status'], 'OBSERVED')
            self.assertEqual(row['peer_receipt_sha256'], 'a'*64)
            self.assertFalse(any(r['event'] == 'REMOTE_MEMPOOL_UNKNOWN' for r in h.journal))
            binding = next(b for k, b in h.gates if k == 'remote_peer_evidence')
            self.assertEqual(binding['operation'], intent.operation)
            self.assertEqual(binding['mode'], row['mode'])
            self.assertEqual(binding['evidence']['evidence_kind'], 'remote_mempool')
            self.assertEqual(len(h.sends()), 1)
            self.assertEqual(h.c.index, index + 1)
            self.assertEqual(clocks, (h.c.started, h.c.deadline, h.c.deadline_wall))
            self.assertEqual([r['event'] for r in h.journal].count('PEER_OBSERVED'), 1)
            self.assertEqual([r['event'] for r in h.journal].count('INCLUSION'), 1)

    def remote_gate_state(self, h):
        # Capture at the actual gate, after the one synthetic send and before
        # rejection. Starting a step legitimately sets its clocks/window.
        return copy.deepcopy((h.c.index, h.c.started, h.c.deadline, h.c.deadline_wall,
            h.c.step_start, h.c.series_start, h.c.phase_deadline, h.c.phase_reason,
            h.c.broadcast_window, h.c.calls, h.c.response_bytes, h.c.fees,
            h.c.used_raw, h.c.rows, h.c.anchors, h.c.source, h.clock()))

    def refuse_remote_gate(self, core, reply, reason):
        h, _, intent = self.harness(core=core, inclusion=101)
        initial = (h.c.index, h.c.started, h.c.deadline, h.c.deadline_wall)
        gate, peer = h.c.gates, h.c.peer
        gate_states, polls = [], []
        def observed(binding):
            polls.append(copy.deepcopy(binding))
            return peer(binding)
        def remote_gate(kind, binding):
            if kind == 'remote_peer_evidence':
                self.assertEqual(binding['source'], h.c.source)
                self.assertEqual(binding['operation'], intent.operation)
                self.assertEqual(binding['mode'], m.CORE_MODE if core else m.SERIES_MODE)
                self.assertEqual(binding['evidence']['evidence_kind'], 'remote_mempool')
                self.assertEqual(len(h.sends()), 1)
                gate_states.append(self.remote_gate_state(h))
                return reply(binding)
            return gate(kind, binding)
        h.c.peer, h.c.gates = observed, remote_gate
        self.stop(h, intent, '^' + reason + '$')
        self.assertEqual(len(gate_states), 1)
        self.assertEqual(len(polls), 1)
        self.assertEqual(self.remote_gate_state(h), gate_states[0])
        self.assertEqual(initial, (h.c.index, h.c.started, h.c.deadline, h.c.deadline_wall))
        self.assertEqual(len(h.sends()), 1)
        self.assertTrue(h.c.stopped)
        self.assertEqual(len(h.c.used_raw), 1)
        self.assertIsNotNone(h.c.broadcast_window)
        events = [r['event'] for r in h.journal]
        self.assertEqual(events.count('BROADCAST_ATTEMPT'), 1)
        self.assertFalse(set(events) & {'PEER_OBSERVED', 'PEER_BLOCK_OBSERVED',
                                       'REMOTE_MEMPOOL_UNKNOWN', 'INCLUSION'})
        self.assertFalse(any(r['event'] == 'ADMISSION' and
            r['kind'] == 'remote_peer_evidence' for r in h.journal))
        self.assertEqual([r['reason'] for r in h.journal if r['event'] == 'STOP'],
                         [reason, 'TERMINAL_NO_RETRY'])

    def test_remote_evidence_gate_cannot_mutate_nested_canonical_binding(self):
        fields = (('evidence', 'txid'), ('evidence', 'raw_sha256'),
                  ('source', 'head'), ('source', 'tree'), ('operation',), ('mode',))
        for core in (True, False):
            for path in fields:
                with self.subTest(core=core, path=path):
                    def mutate(binding):
                        target = binding
                        for key in path[:-1]:
                            target = target[key]
                        target[path[-1]] += '00'
                        return 'a'*64  # Valid digest must not mask mutation.
                    self.refuse_remote_gate(core, mutate, 'ADMISSION_BINDING_MUTATED')

    def test_remote_evidence_gate_refuses_malformed_receipt_digests(self):
        receipts = ('', 'a'*63, 'g'*64, 'A'*64, None, 123, True, [], {})
        for core in (True, False):
            for receipt in receipts:
                with self.subTest(core=core, receipt=receipt):
                    self.refuse_remote_gate(core, lambda binding: receipt,
                                           'ADMISSION_REFUSED_remote_peer_evidence')

    def test_t1b_remote_block_refuses_before_remote_authentication_gate(self):
        h, _, intent = self.harness(core=False, inclusion=101)
        peer = h.c.peer
        snapshots = []
        def remote_block(binding):
            return dict(peer(binding), evidence_kind='remote_block',
                        block_hash=m.sha(b'101'), height=101)
        h.c.peer = remote_block
        observe = h.c.observe_peer
        def observed(binding):
            evidence = observe(binding)
            snapshots.append(self.remote_gate_state(h))
            return evidence
        h.c.observe_peer = observed
        self.stop(h, intent, '^PEER_EVIDENCE_KIND$')
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(self.remote_gate_state(h), snapshots[0])
        self.assertEqual(len(h.sends()), 1)
        self.assertFalse(any(kind == 'remote_peer_evidence' for kind, _ in h.gates))
        self.assertFalse(any(r['event'] in ('PEER_OBSERVED', 'PEER_BLOCK_OBSERVED',
            'REMOTE_MEMPOOL_UNKNOWN', 'INCLUSION') for r in h.journal))

    def test_exact_raw_and_mode_admissions_cannot_be_mutated(self):
        for core in (True, False):
            for field in ('raw_hex', 'mode'):
                h, _, intent = self.harness(core=core, inclusion=101)
                gate = h.c.gates
                def mutate(kind, binding):
                    if kind == 'Meta_each_exact_raw_transaction':
                        binding[field] += '00'
                    return gate(kind, binding)
                h.c.gates = mutate
                self.stop(h, intent, 'ADMISSION_BINDING_MUTATED')
                self.assertEqual(h.sends(), [])

    def test_core_remote_block_requires_authentication_and_exact_active_inclusion(self):
        for failure in (None, 'block_hash', 'height', 'raw', 'membership', 'unconfirmed', 'auth'):
            h, _, intent = self.harness(inclusion=None if failure == 'unconfirmed' else 101)
            old = h.c.peer
            block_hash = m.sha(b'101')
            h.c.peer = lambda binding: dict(old(binding), evidence_kind='remote_block',
                block_hash='f'*64 if failure == 'block_hash' else block_hash,
                height=102 if failure == 'height' else 101)
            transport = h.c.read._transport
            def rpc(method, *params, wallet=''):
                if failure == 'raw' and method == 'getrawtransaction' and params[1] is False:
                    return h.rpc.raw + '00'
                if failure == 'membership' and method == 'getblock':
                    return {'tx': [{'txid': 'e'*64}]}
                return transport(method, *params, wallet=wallet)
            h.c.read._transport = rpc
            if failure == 'auth':
                gate = h.c.gates
                h.c.gates = lambda kind, binding: None if kind == 'remote_peer_evidence' else gate(kind, binding)
            if failure is None:
                row = h.c.run_next(intent)
                self.assertEqual(row['block_hash'], block_hash)
                self.assertEqual(row['remote_mempool_status'], 'UNKNOWN')
                self.assertIsNone(row['peer_receipt_sha256'])
                self.assertEqual(row['block_receipt_sha256'], 'a'*64)
            else:
                reason = {'block_hash': 'PEER_BLOCK_BINDING', 'height': 'PEER_BLOCK_BINDING',
                          'raw': 'EXACT_INCLUSION_MISMATCH', 'membership': 'EXACT_INCLUSION_MISMATCH',
                          'unconfirmed': 'INCLUSION_DEADLINE', 'auth': 'ADMISSION_REFUSED_remote_peer_evidence'}[failure]
                self.stop(h, intent, reason)

    def test_invalid_evidence_is_not_missing_receipt(self):
        for core in (True, False):
            for failure in ('txid', 'raw_sha256', 'future', 'prebroadcast', 'wrongsource',
                            'local_mempool', 'refused', 'malformed', 'disguised_absence'):
                h, _, intent = self.harness(core=core, inclusion=101)
                old = h.c.peer
                def peer(binding):
                    evidence = old(binding)
                    if failure in ('txid', 'raw_sha256'):
                        evidence[failure] = 'f'*64
                    elif failure in ('future', 'prebroadcast'):
                        evidence['observed_at_utc'] = datetime.fromtimestamp(
                            h.clock() + (100 if failure == 'future' else -100), timezone.utc).isoformat()
                    elif failure == 'wrongsource':
                        evidence['observer_label'] = 'unadmitted'
                    elif failure == 'local_mempool':
                        evidence['evidence_kind'] = 'local_mempool'
                    elif failure == 'refused':
                        evidence['status'] = 'refused'
                    elif failure == 'malformed':
                        return {}
                    elif failure == 'disguised_absence':
                        evidence.update(status='unknown', raw_sha256='f'*64)
                    return evidence
                h.c.peer = peer
                gate = h.c.gates
                h.c.gates = lambda kind, binding: (None if kind == 'remote_peer_evidence' and
                    binding['evidence']['observer_label'] == 'unadmitted' else gate(kind, binding))
                self.stop(h, intent, 'PEER_|ADMISSION_REFUSED_')
                self.assertFalse(any(r['event'] == 'REMOTE_MEMPOOL_UNKNOWN' for r in h.journal))

    def test_core_absent_retains_six_successors_skipped_heights_and_reorg(self):
        cases = (((106,), 106, None, None), ((107,), 106, None, None),
                 ((107,), 107, None, 'SIX_BLOCK_INCLUSION_STOP'),
                 (range(101, 107), None, None, 'SIX_BLOCK_INCLUSION_STOP'),
                 ((101,), 101, 'ancestor', 'REORG'), ((99,), None, None, 'REORG'))
        for heights, inclusion, reorg, reason in cases:
            h, _, intent = self.harness(heights=heights, inclusion=inclusion, reorg=reorg)
            h.c.peer = None
            if reason:
                self.stop(h, intent, reason)
                self.assertEqual(h.c.broadcast_window[0], 100)
            else:
                self.assertEqual(h.c.run_next(intent)['height'], 106)

    def test_core_missing_receipt_cannot_accept_wrong_raw_or_block_membership(self):
        for failure in ('raw', 'membership'):
            h, _, intent = self.harness(inclusion=101)
            h.c.peer = None
            transport = h.c.read._transport
            def rpc(method, *params, wallet=''):
                if failure == 'raw' and method == 'getrawtransaction' and params[1] is False:
                    return h.rpc.raw + '00'
                if failure == 'membership' and method == 'getblock':
                    return {'tx': [{'txid': 'f'*64}]}
                return transport(method, *params, wallet=wallet)
            h.c.read._transport = rpc
            self.stop(h, intent, 'EXACT_INCLUSION_MISMATCH')

    def test_missing_receipt_does_not_reset_inclusion_or_step_clocks(self):
        h, _, intent = self.harness(inclusion=None)
        def absent(binding):
            h.clock.pause(9)  # within the existing per-call bound
            return {'status': 'absent'}
        h.c.peer = absent
        self.stop(h, intent, 'INCLUSION_DEADLINE')
        sent = next(r['monotonic'] for r in h.journal if r['event'] == 'BROADCAST_ATTEMPT')
        self.assertEqual(h.c.phase_deadline, min(h.c.step_start + 1500, sent + 1320))
        self.assertLess(h.clock() - sent, 1321)

    def test_core_absent_keeps_earlier_time_call_byte_cancel_and_meta_bounds(self):
        for bound in ('time', 'calls', 'bytes', 'cancel', 'meta'):
            h, _, intent = self.harness(inclusion=None)
            h.c.peer = None
            initial = (h.c.started, h.c.deadline, h.c.deadline_wall)
            gate = h.c.gates
            if bound == 'meta':
                h.c.gates = lambda kind, binding: None if kind == 'Meta_each_exact_raw_transaction' else gate(kind, binding)
            elif bound == 'time':
                h.c.deadline = h.c.deadline_wall = h.clock() + 100
                initial = (h.c.started, h.c.deadline, h.c.deadline_wall)
            else:
                journal = h.c.journal
                def record(row):
                    journal(row)
                    if row['event'] == 'REMOTE_MEMPOOL_UNKNOWN':
                        if bound == 'calls': h.c.calls = 2100
                        if bound == 'bytes': h.c.response_bytes = 64*1024*1024
                        if bound == 'cancel': h.c.stopped = True
                h.c.journal = record
            reason = {'time': 'IMMUTABLE_DEADLINE', 'calls': 'RPC_COUNT_BOUND',
                      'bytes': 'RPC_RESPONSE_BOUND', 'cancel': 'TERMINAL_NO_RETRY',
                      'meta': 'ADMISSION_REFUSED_Meta_each_exact_raw_transaction'}[bound]
            self.stop(h, intent, reason)
            self.assertEqual(initial, (h.c.started, h.c.deadline, h.c.deadline_wall))
            self.assertEqual(len(h.sends()), 0 if bound == 'meta' else 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
