"""Focused OFFLINE causal controls; no node, actual signing or networking.

Verifier tests execute the actual nested bwrap/exec/pipe boundary. Scheduler
tests use a fake monotonic clock and count each actual double invocation.
"""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import mainnet as m
import mainnet_t1 as workflow_module
import test_mainnet as harness_module
from test_lineage import Frozen
import verifier_process as vp


class Boundaries(unittest.TestCase):
    def harness(self):
        h = harness_module.Tests()
        h.setup_control(enforce_observation_contract=True)
        return h

    def public(self, rpc):
        return {'network': 'regtest', 'fixture': rpc.fixture, 'request': rpc.request,
                'signature': rpc.signature, 'pins': rpc.pins}

    def test_actual_exec_boundary_with_parent_capabilities_environment_and_fd(self):
        rpc = Frozen('baseline')
        public = self.public(rpc)
        original = copy.deepcopy(public)
        calls = []
        class SyntheticSigner:
            def sign(self):
                calls.append('SIGNER_REACHED')
                raise AssertionError('signer must remain unreachable')
        collector_shaped_parent = {'wallets': {'A': SyntheticSigner()},
            'broadcaster': SyntheticSigner(), 'gate': SyntheticSigner()}
        with tempfile.TemporaryFile(dir=os.environ['TMPDIR']) as canary:
            canary.write(b'SYNTHETIC_FD_CANARY_NOT_A_SECRET')
            canary.flush()
            os.set_inheritable(canary.fileno(), True)
            with patch.dict(os.environ, {'SYNTHETIC_SIGNER_CANARY': 'not-a-secret',
                                        'SSH_AUTH_SOCK': '/nonexistent-synthetic-socket'}):
                result = vp.verify_public(public, rpc.call, timeout_s=20)
        self.assertEqual(result['decision'], 'admit')
        self.assertEqual(public, original)
        self.assertTrue(collector_shaped_parent)  # retained only in parent
        self.assertEqual(calls, [])
        facts = result['process_boundary']
        self.assertEqual(set(facts['fds']), {'0', '1', '2'})
        self.assertEqual(facts['fds'], {'0': 'pipe', '1': 'pipe', '2': '/dev/null'})
        self.assertNotIn('SYNTHETIC_SIGNER_CANARY', facts['environment_keys'])
        self.assertNotIn('SSH_AUTH_SOCK', facts['environment_keys'])
        self.assertEqual(facts['source_files'], ['pipe_verify.py', 'protocol.py'])
        self.assertFalse(facts['collector_signer_broadcaster_gate_modules_present'])
        self.assertEqual(facts['forbidden_capability_object_types'], [])
        self.assertNotEqual(facts['pid_namespace'], os.readlink('/proc/self/ns/pid'))
        self.assertNotEqual(facts['net_namespace'], os.readlink('/proc/self/ns/net'))
        self.assertEqual(set(result['read_only_methods_rejected_before_pipe']),
            {'signmessage', 'sendrawtransaction', 'getnewaddress', 'createwallet', 'stop'})
        print('ACTUAL_ISOLATED_PROCESS_BOUNDARY', json.dumps(facts, sort_keys=True))

    def test_public_serialization_rejects_object_references_before_process(self):
        rpc = Frozen('baseline')
        for field in ('fixture', 'request', 'signature', 'pins'):
            public = self.public(rpc)
            public[field] = object()
            with self.subTest(field=field), patch.object(vp, '_send') as send:
                with self.assertRaises(TypeError):
                    vp.verify_public(public, rpc.call, timeout_s=20)
                send.assert_not_called()
        public = dict(self.public(rpc), collector=object())
        with self.assertRaises(ValueError):
            vp.verify_public(public, rpc.call, timeout_s=20)

    def test_broker_rejects_signer_broadcast_and_proxy_messages_before_dispatch(self):
        rpc = Frozen('baseline')
        for method in ('signmessage', 'sendrawtransaction', 'fundrawtransaction', 'getaddressinfo'):
            touched = []
            with self.subTest(method=method):
                with self.assertRaisesRegex(ValueError, 'VERIFIER_READ_METHOD_DENIED'):
                    vp._dispatch({'type': 'rpc', 'method': method, 'params': []},
                                 lambda *args: touched.append(args))
            self.assertEqual(touched, [])

    def test_unchanged_lineage_decisions_through_real_process(self):
        for case in ('baseline', 'unavailable'):
            rpc = Frozen(case)
            expected = rpc.verify()
            result = vp.verify_public(self.public(rpc), rpc.call, timeout_s=20)
            self.assertEqual((result['decision'], result['reason']),
                             (expected['decision'], expected['reason']))

    def test_actual_workflow_serializes_public_values_with_collector_in_parent_only(self):
        h = self.harness()
        rpc = Frozen('baseline')
        identities = {role: dict(rpc.pins[pin], rand=nonce*20)
                      for role, pin, nonce in (('A', 'issuer', '11'), ('B', 'grantee', '22'))}
        for item in identities.values():
            item.pop('identity_txid')
        workflow = workflow_module.Workflow(h.c, identities)
        for role, pin in (('A', 'issuer'), ('B', 'grantee')):
            workflow.ids[role]['identity_txid'] = rpc.pins[pin]['identity_txid']
        workflow.fixtures['A'] = rpc.fixture
        workflow.requests['A'] = (rpc.request, rpc.signature)
        # Enter at the verifier boundary, independently of mainnet readiness.
        # All original read calls still use the real scheduler and broker.
        h.c.network = lambda: None
        h.c.read._transport = lambda method, *params, wallet='': rpc.call(method, *params)
        touches = []
        for cap in (*h.c.wallets.values(), h.c.broadcast, h.c.build):
            cap._transport = lambda *args, **kw: touches.append(args)
        wire = []
        original_send = vp._send
        def traced(value, deadline):
            wire.append(copy.deepcopy(value))
            return original_send(value, deadline)
        with patch.object(vp, '_send', traced):
            workflow.verify('A', 'B', 'actual_isolated_workflow_boundary', 'admit', network='regtest')
        self.assertEqual(touches, [])
        self.assertEqual(set(wire[0]), {'type', 'input'})
        self.assertEqual(set(wire[0]['input']), {'network', 'fixture', 'request', 'signature', 'pins'})
        self.assertEqual(set(wire[0]['input']['pins']), {'issuer', 'grantee'})
        result = h.journal[-1]['result']
        self.assertEqual(result['decision'], 'admit')
        self.assertEqual(result['process_boundary']['source_files'], ['pipe_verify.py', 'protocol.py'])
        self.assertNotEqual(result['process_boundary']['pid_namespace'], os.readlink('/proc/self/ns/pid'))

    def test_reservation_dual_clock_boundaries_before_any_t1b_activity(self):
        for monotonic, wall, enough in ((12100, 12100, True), (12099.999, 12099.999, True),
                (12100.001, 12100, False), (12100, 12100.001, False),
                (22600, 22600, False), (22601, 22601, False),
                (11000, 22600, False), (22600, 11000, False)):
            with self.subTest(monotonic=monotonic, wall=wall):
                h = self.harness()
                h.clock.now = monotonic
                h.c.wall = lambda: wall
                immutable = (h.c.started, h.c.deadline, h.c.deadline_wall)
                before_rpc, before_gates = len(h.rpc.calls), len(h.gates)
                expected = ('SYNTHETIC_AFTER_RESERVATION' if enough else
                            'STOP_INSUFFICIENT_SHARED_TIME')
                def after_reservation(intent):
                    raise m.Stop('SYNTHETIC_AFTER_RESERVATION')
                h.c.require_preparation_capacity = after_reservation
                with self.assertRaisesRegex(m.Stop, '^' + expected + '$'):
                    h.c.run_next(h.intent())
                self.assertTrue(h.c.stopped)
                self.assertEqual(len(h.rpc.calls), before_rpc)
                self.assertEqual(len(h.gates), before_gates)
                self.assertEqual(h.sends(), [])
                self.assertEqual(h.c.index, 10)
                self.assertEqual((h.c.started, h.c.deadline, h.c.deadline_wall), immutable)
                self.assertEqual(h.c.series_start, monotonic if enough else None)
                with self.assertRaisesRegex(m.Stop, 'TERMINAL_NO_RETRY'):
                    h.c.run_next(h.intent())

    def test_series_start_is_not_reset_on_reentry(self):
        h = self.harness()
        h.clock.now = 12100
        h.c.begin_t1b()
        start = h.c.series_start
        h.clock.pause(100)
        h.c.begin_t1b()
        self.assertEqual(h.c.series_start, start)
        self.assertEqual(h.c.started, 1000)
        h.clock.now = 22600
        with self.assertRaises(m.Stop):
            h.c.begin_t1b()

    def trace(self, h):
        timed = []
        original = h.rpc.__class__.__call__
        def transport(method, *params, wallet=''):
            timed.append((h.clock(), method, params))
            return original(h.rpc, method, *params, wallet=wallet)
        for cap in (h.c.read, h.c.build, h.c.broadcast, *h.c.wallets.values()):
            cap._transport = transport
        original_peer = h.c.peer
        h.c.peer = lambda binding: timed.append((h.clock(), 'remote_peer_observation', ())) or original_peer(binding)
        return timed

    def test_real_scheduler_counts_every_anchor_and_remote_observation(self):
        h = self.harness()
        timed = self.trace(h)
        h.c.anchors = [(n, 'b'*64) for n in range(1, 18)]
        h.c.network()
        h.c.peer = lambda binding: timed.append((h.clock(), 'remote_peer_observation', ())) or {'status': 'pending'}
        h.c.observe_peer({})
        h.c.network()
        for previous, current in zip(timed, timed[1:]):
            self.assertGreaterEqual(current[0] - previous[0] + 1e-9,
                                    10 if current[1] == 'remote_peer_observation' else .1)
        self.assertEqual(len(timed), 2 * (4 + 17) + 1)
        for n in range(1, 18):
            self.assertEqual(sum(method == 'getblockhash' and params == (n,)
                                 for _, method, params in timed), 2)
        print('ACTUAL_SCHEDULED_DOUBLE_CALLS', json.dumps(timed))

    def test_destination_and_public_neighbor_controls_in_every_phase(self):
        # Method allowlists alone never earn the own-loopback exception.
        for destination in (None, 'localhost', '127.0.0.2', '::1', 'public.example'):
            h = harness_module.Tests()
            with self.subTest(destination=destination), self.assertRaisesRegex(m.Stop, 'OWN_LOOPBACK_OBSERVER_REQUIRED'):
                h.setup_control(enforce_observation_contract=True, observer_destination=destination)
            self.assertEqual(h.rpc.calls, [])
        for phase in ('initialization', 'verifier', 'preparation', 'peer', 'inclusion', 'maturity', 'expiry'):
            h = self.harness()
            timed = []
            h.c.phase_deadline, h.c.phase_reason = h.clock()+100, 'SYNTHETIC_PHASE_BOUND'
            def transport(label):
                return lambda method, *params, wallet='': timed.append((h.clock(), label, method)) or {}
            h.c.read._transport = transport('own-loopback')
            public = m.Capability(transport('public-same-read-method'), m.OBSERVE, destination='public.example')
            spoof = m.Capability(transport('foreign-loopback-label'), m.OBSERVE, destination='127.0.0.1')
            for cap in (h.c.read, h.c.read, public, h.c.read, public, h.c.read, spoof):
                h.c.call(cap, 'getblockchaininfo')
            for previous, current in zip(timed, timed[1:]):
                self.assertGreaterEqual(current[0]-previous[0]+1e-9, .1 if current[1]=='own-loopback' else 10)
            self.assertGreaterEqual(timed[4][0]-timed[2][0], 10)
            print('DESTINATION_NEIGHBOR_CONTROL', phase, json.dumps(timed))
        # Initialization also uses the real scheduler, before a phase exists.
        h = self.harness()
        initial = [r['monotonic'] for r in h.journal if r['event']=='RPC']
        self.assertEqual(len(initial), 3)
        self.assertGreaterEqual(min(b-a for a,b in zip(initial,initial[1:]))+1e-9, .1)
        custody = next(binding for kind,binding in h.gates if kind=='capability_custody')
        self.assertEqual(custody['observer_destination'], '127.0.0.1')
        self.assertEqual(custody['public_observation_interval_s'], 10)
        self.assertEqual(custody['loopback_observation_interval_s'], .1)

    def test_scheduler_preserves_phase_global_call_and_single_flight_bounds(self):
        h = self.harness()
        before = len(h.rpc.calls)
        h.c.phase_deadline = h.clock() + .05
        h.c.phase_reason = 'PEER_DEADLINE_UNKNOWN'
        with self.assertRaisesRegex(m.Stop, 'PEER_DEADLINE_UNKNOWN'):
            h.c.call(h.c.read, 'getblockchaininfo')
        self.assertEqual(len(h.rpc.calls), before)
        h = self.harness()
        h.c.calls = 2100
        with self.assertRaisesRegex(m.Stop, 'RPC_COUNT_BOUND'):
            h.c.observe_peer({})
        h = self.harness()
        self.assertTrue(h.c._rpc_lock.acquire(False))
        try:
            with self.assertRaisesRegex(m.Stop, 'RPC_IN_FLIGHT'):
                h.c.call(h.c.read, 'getblockchaininfo')
        finally:
            h.c._rpc_lock.release()
        h.c.deadline_wall = h.clock() + .05
        with self.assertRaisesRegex(m.Stop, 'IMMUTABLE_DEADLINE'):
            h.c.call(h.c.read, 'getblockchaininfo')
        h = self.harness()
        before = len(h.rpc.calls)
        h.c.pause = lambda seconds: None
        with self.assertRaisesRegex(m.Stop, 'OBSERVATION_CLOCK_OR_SLEEP'):
            h.c.call(h.c.read, 'getblockchaininfo')
        self.assertEqual(len(h.rpc.calls), before)

    def test_actual_preparation_and_peer_feasibility_without_timing_bypass(self):
        for anchors, calls in ((0,21), (10,51), (12,57), (13,60), (16,69)):
            h = self.harness()
            h.c.anchors = [(n, 'b'*64) for n in range(1,anchors+1)]
            timed = self.trace(h)
            row = h.c.run_next(h.intent())
            self.assertEqual(row['status'], 'INCLUDED_ACTIVE_AT_OBSERVATION')
            sent = next(i for i,(_,method,_) in enumerate(timed) if method=='sendrawtransaction')
            prep = [(t,method) for t,method,_ in timed[:sent] if method in m.OBSERVE]
            self.assertEqual(len(prep), calls)
            prep_seconds = timed[sent][0] - (timed[0][0]-.1)
            self.assertAlmostEqual(prep_seconds, calls*.1)
            self.assertLess(prep_seconds, 180)
            peer_time = next(t for t,method,_ in timed if method=='remote_peer_observation')
            self.assertLess(peer_time-timed[sent][0], 120)
            self.assertEqual(len(h.sends()), 1)  # synthetic schema double only
            print('ACTUAL_FULL_PREPARATION_AND_PEER', json.dumps({'anchors':anchors,
                'preparation_observer_calls':len(prep),'preparation_seconds':prep_seconds,
                'peer_seconds_after_symbolic_send':peer_time-timed[sent][0], 'trace':m.json_safe(timed)}))

    @patch.object(m, 'LOOPBACK_OBSERVATION_INTERVAL_S', 1)
    @patch.object(m, 'PREPARATION_S', 60)
    def test_historical_three_pass_preparation_constraint_and_causal_negative(self):
        for anchors in (13,16):
            h = self.harness()
            h.c.anchors = [(n, 'b'*64) for n in range(1,anchors+1)]
            before = len(h.rpc.calls)
            with self.assertRaisesRegex(m.Stop, 'STOP_OBSERVATION_PREPARATION_CONTRACT'):
                h.c.run_next(h.intent())
            record = next(row for row in h.journal if row['event']=='CONTRACT_CONSTRAINT')
            self.assertEqual(record['minimum_observation_calls'], 3*(4+anchors)+10)
            self.assertEqual(record['minimum_span_s'], 3*(4+anchors)+9)
            self.assertEqual(record['rpc_interval_s'], 1)
            self.assertEqual(len(h.rpc.calls), before)
            self.assertEqual(h.sends(), [])
            print('REMAINING_EXACT_SOURCE_CONSTRAINT', json.dumps(record,sort_keys=True))
            # Causal counterexample: bypass ONLY the capacity guard in test,
            # retain the real 1/s scheduler and every real path/deadline check.
            h = self.harness()
            h.c.anchors = [(n, 'b'*64) for n in range(1,anchors+1)]
            h.c.require_preparation_capacity = lambda intent: None
            timed = self.trace(h)
            with self.assertRaisesRegex(m.Stop, 'PREPARATION_DEADLINE'):
                h.c.run_next(h.intent())
            self.assertEqual(h.sends(), [])
            self.assertTrue(h.c.stopped)
            print('CAUSAL_PREPARATION_DEADLINE', anchors, json.dumps(timed))

    @patch.object(m, 'LOOPBACK_OBSERVATION_INTERVAL_S', 1)
    @patch.object(m, 'PREPARATION_S', 60)
    def test_historical_series_stops_at_fourth_size_without_reset_or_extra_io(self):
        h = self.harness()
        h.c.anchors = [(n, 'b'*64) for n in range(1,11)]
        starts = []
        for n in m.SIZES[:3]:
            h.c.run_next(h.intent(n))
            starts.append(h.c.series_start)
        self.assertEqual(len(h.c.anchors),13)
        self.assertEqual(starts,[starts[0]]*3)
        before = len(h.rpc.calls)
        with self.assertRaisesRegex(m.Stop,'STOP_OBSERVATION_PREPARATION_CONTRACT'):
            h.c.run_next(h.intent(m.SIZES[3]))
        self.assertEqual(len(h.rpc.calls),before)
        self.assertEqual(len(h.sends()),3)
        self.assertEqual(h.c.index,13)
        self.assertEqual(h.c.series_start,starts[0])
        print('ACTUAL_SERIES_REMAINING_CONSTRAINT',json.dumps({'completed_sizes':list(m.SIZES[:3]),
            'refused_size':m.SIZES[3],'anchors':len(h.c.anchors),'calls':h.c.calls,
            'immutable_series_start':h.c.series_start,'monotonic':h.clock()}))

    def test_actual_all_series_sizes_without_timing_bypass_or_clock_reset(self):
        h = self.harness()
        h.c.anchors = [(n, 'b'*64) for n in range(1,11)]
        immutable = (h.c.started, h.c.deadline, h.c.deadline_wall)
        timed = self.trace(h)
        results = []
        series_start = None
        for n in m.SIZES:
            row = h.c.run_next(h.intent(n))
            self.assertEqual(row['status'], 'INCLUDED_ACTIVE_AT_OBSERVATION')
            if series_start is None:
                series_start = h.c.series_start
            self.assertEqual(h.c.series_start, series_start)
            self.assertEqual((h.c.started, h.c.deadline, h.c.deadline_wall), immutable)
            results.append({'size': n, 'elapsed_series_s': h.clock()-series_start})
        self.assertEqual(len(h.sends()), len(m.SIZES))
        self.assertEqual(len(h.c.anchors), 10+len(m.SIZES))
        self.assertEqual(h.c.index, 10+len(m.SIZES))
        self.assertLess(h.c.calls, 2100)
        raw_go = [binding for kind,binding in h.gates if kind=='Meta_each_exact_raw_transaction']
        self.assertEqual(len(raw_go), len(m.SIZES))
        observations = [(t,method) for t,method,_ in timed if method in m.OBSERVE or method=='remote_peer_observation']
        for previous,current in zip(observations,observations[1:]):
            self.assertGreaterEqual(current[0]-previous[0]+1e-9,
                10 if current[1]=='remote_peer_observation' else .1)
        print('ACTUAL_FULL_SERIES', json.dumps({'sizes':results, 'calls':h.c.calls,
            'immutable_clocks':immutable, 'series_start':series_start,
            'exact_raw_GO_count':len(raw_go), 'anchors':len(h.c.anchors)}))

    def test_preparation_180_allows_slow_gate_but_preserves_exclusive_deadline(self):
        for delay, succeeds in ((100, True), (180, False)):
            h = self.harness()
            h.c.anchors = [(n, 'b'*64) for n in range(1,11)]
            original = h.c.gates
            def gate(kind, binding):
                if kind == 'Meta_each_exact_raw_transaction':
                    h.clock.pause(delay)
                return original(kind, binding)
            h.c.gates = gate
            if succeeds:
                row = h.c.run_next(h.intent())
                self.assertEqual(row['status'], 'INCLUDED_ACTIVE_AT_OBSERVATION')
                self.assertEqual(len(h.sends()), 1)
            else:
                with self.assertRaisesRegex(m.Stop, 'PREPARATION_DEADLINE'):
                    h.c.run_next(h.intent())
                self.assertEqual(h.sends(), [])
                self.assertTrue(h.c.stopped)
            print('PREPARATION_GATE_LATENCY_CONTROL', delay, succeeds, h.clock())

    def test_real_scheduler_late_exact_raw_admission_stops_before_send(self):
        h = self.harness()
        h.c.anchors = [(n, 'b'*64) for n in range(1,11)]
        original_gate=h.c.gates
        def late_gate(kind,binding):
            if kind=='Meta_each_exact_raw_transaction':
                h.clock.pause(180)
            return original_gate(kind,binding)
        h.c.gates=late_gate
        with self.assertRaisesRegex(m.Stop,'PREPARATION_DEADLINE'):
            h.c.run_next(h.intent())
        self.assertEqual(h.sends(),[])
        self.assertTrue(h.c.stopped)

    def test_peer_bound_stays_120_after_slow_preparation(self):
        h = self.harness()
        h.c.anchors = [(n, 'b'*64) for n in range(1,11)]
        h.peer_status = 'pending'
        original = h.c.gates
        def gate(kind, binding):
            if kind == 'Meta_each_exact_raw_transaction':
                h.clock.pause(100)
            return original(kind, binding)
        h.c.gates = gate
        timed = self.trace(h)
        with self.assertRaisesRegex(m.Stop, 'PEER_DEADLINE_UNKNOWN'):
            h.c.run_next(h.intent())
        sent = next(t for t,method,_ in timed if method=='sendrawtransaction')
        self.assertAlmostEqual(h.c.phase_deadline-sent, 120)
        self.assertAlmostEqual(h.clock()-sent, 120)
        self.assertEqual(len(h.sends()), 1)
        self.assertEqual(h.c.index, 10)
        self.assertTrue(h.c.stopped)
        print('PEER_120_AFTER_SLOW_PREPARATION', json.dumps({'sent':sent,
            'deadline':h.c.phase_deadline, 'stopped_at':h.clock()}))

    def test_actual_peer_and_inclusion_poll_paths_share_scheduler(self):
        for pending_peer in (True, False):
            h = self.harness()
            h.c.anchors = [(n, 'b'*64) for n in range(1,11)]
            h.peer_status = 'pending' if pending_peer else 'observed'
            h.rpc.included = False
            timed = self.trace(h)
            expected = 'PEER_DEADLINE_UNKNOWN' if pending_peer else 'INCLUSION_DEADLINE'
            with self.assertRaisesRegex(m.Stop, expected):
                h.c.run_next(h.intent())
            observations = [(t,method) for t,method,_ in timed if method in m.OBSERVE or method=='remote_peer_observation']
            for previous,current in zip(observations,observations[1:]):
                self.assertGreaterEqual(current[0]-previous[0]+1e-9,10 if current[1]=='remote_peer_observation' else .1)
            public = [t for t,method in observations if method=='remote_peer_observation']
            if pending_peer:
                self.assertGreater(len(public),1)
                self.assertGreaterEqual(min(b-a for a,b in zip(public,public[1:])),10)
            self.assertEqual(len(h.sends()),1)
            self.assertEqual(h.c.index,10)
            self.assertTrue(h.c.stopped)
            print('ACTUAL_POLL_PATH', expected, json.dumps(observations))


if __name__ == '__main__':
    unittest.main(verbosity=2)
