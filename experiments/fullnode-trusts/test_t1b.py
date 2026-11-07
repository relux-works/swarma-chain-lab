#!/usr/bin/env python3
"""Offline independent decoding, shared-path regression and stop controls."""
import ast
import copy
import os
import stat
import unittest
from decimal import Decimal, Inexact, Rounded, localcontext
from pathlib import Path
from unittest.mock import patch
import t1b
from transaction import build_signed


class Tests(unittest.TestCase):
    def test_exact_payloads_and_independent_decode(self):
        expected_scripts = (83, 103, 203, 524, 1004, 4004, 10004)
        for n, scriptlen in zip(t1b.SIZES, expected_scripts):
            raw, rpc = t1b.construct_fixture(n)
            self.assertEqual(len(t1b.payload(n)), n)
            self.assertEqual(len(t1b.script(t1b.payload(n))), scriptlen)
            # Independent parser: fixed legacy input, CompactSize output length.
            self.assertEqual(raw[:5], bytes.fromhex('0100000001'))
            self.assertEqual(raw[5:41], b'\0' * 36)
            self.assertEqual(raw[41], 107)
            self.assertEqual(raw[42:149], b'\0' * 107)
            self.assertEqual(raw[153], 2)
            pos = 162
            if raw[pos] == 253:
                count = int.from_bytes(raw[pos+1:pos+3], 'little'); pos += 3
            else:
                count = raw[pos]; pos += 1
            self.assertEqual(count, scriptlen)
            sc = raw[pos:pos+count]; pos += count
            self.assertEqual(sc[0], 106)
            if sc[1] == 76:
                length, start = sc[2], 3
            else:
                self.assertEqual(sc[1], 77)
                length, start = int.from_bytes(sc[2:4], 'little'), 4
            self.assertEqual(length, n)
            self.assertEqual(sc[start:], t1b.payload(n))
            value = int.from_bytes(raw[pos:pos+8], 'little'); pos += 8
            self.assertEqual(value + rpc.fee_sat, 10000000)
            self.assertEqual(raw[pos], 25); pos += 1
            self.assertEqual(raw[pos:pos+25], bytes.fromhex('76a914') + b'\0'*20 + bytes.fromhex('88ac'))
            self.assertEqual(raw[pos+25:], b'\0'*4)
            self.assertLessEqual(len(raw), t1b.VSIZE_CAPS[n])
            self.assertNotIn('sendrawtransaction', rpc.calls)
            with self.assertRaises(ValueError):
                rpc('sendrawtransaction', raw.hex())

    def test_extracted_original_t1_equivalence(self):
        # Exact prior source is public input; isolate only the original function.
        old = ast.parse(Path('/inputs/original-lab.py').read_text())
        fn = next(x for x in old.body if isinstance(x, ast.FunctionDef) and x.name == 'raw_signed')
        code = compile(ast.Module(body=[fn], type_ignores=[]), '<prior-T1-builder>', 'exec')
        for failure in ('none', 'funded', 'incomplete', 'size', 'fee', 'negative', 'policy'):
            def run(original):
                rpc = t1b.SyntheticRPC(t1b.payload(80))
                calls = []
                def adapter(method, *params, **kwargs):
                    calls.append((method, params, kwargs))
                    value = rpc(method, *params, **kwargs)
                    if method == 'fundrawtransaction' and failure == 'funded':
                        value['fee'] = Decimal(1)
                    if method == 'signrawtransactionwithwallet' and failure == 'incomplete':
                        value['complete'] = False
                    if method == 'decoderawtransaction':
                        if failure == 'size': value['vsize'] = 601
                        if failure == 'fee': value['vout'] = [{'value': 0}]
                        if failure == 'negative': value['vout'] = [{'value': 1}]
                    if method == 'testmempoolaccept' and failure == 'policy':
                        value[0]['allowed'] = False
                    return value
                checked = []
                def network(): checked.append(True)
                ns = {'rpc': adapter, 'check_network': network, 'Decimal': Decimal,
                      'RATE_SAT_VB': 200, 'VSIZE_CAP': 600, 'TX_FEE_CAP': Decimal('.0012'),
                      'txdata': lambda txid: adapter('getrawtransaction', txid, True)}
                try:
                    if original:
                        exec(code, ns)
                        value = ns['raw_signed']('synthetic', [], [{'data': t1b.payload(80).hex()}])
                    else:
                        value = build_signed(adapter, network, 'synthetic', [],
                            [{'data': t1b.payload(80).hex()}], rate_sat_vb=200,
                            vsize_cap=600, fee_cap=Decimal('.0012'))
                    result = ('ok', value)
                except RuntimeError as error:
                    result = ('error', str(error))
                return result, calls, checked
            self.assertEqual(run(True), run(False), failure)

    def test_budgets(self):
        b = t1b.budget()
        self.assertEqual(b['all_in_required_sat'], 6866200)
        self.assertEqual(b['t1b_fee_caps_sat'], 3488000)
        self.assertEqual(b['all_fee_caps_sat'], 4242000)
        self.assertEqual(b['fee_margin_sat'], 424200)
        self.assertLess(b['all_in_required_sat'], b['owner_cap_sat'])
        self.assertLessEqual(t1b.SERIES_CAP_S, t1b.T1_CAP_S)
        self.assertIsNone(b['live_estimator_quote'])

    def test_budget_render_ignores_decimal_context(self):
        expected = t1b.budget()
        self.assertEqual(expected['all_in_required_sat'], 6866200)
        self.assertEqual(expected['all_in_required_nmc'], '0.06866200')
        for precision in (1, 28, 80):
            for inexact, rounded in ((False, False), (True, False), (False, True), (True, True)):
                with self.subTest(precision=precision, traps=(inexact, rounded)), localcontext() as ctx:
                    ctx.prec = precision
                    ctx.traps[Inexact], ctx.traps[Rounded] = inexact, rounded
                    ctx.clear_flags()
                    self.assertEqual(t1b.budget(), expected)
                    self.assertFalse(any(ctx.flags.values()))
                    self.assertEqual(ctx.prec, precision)
                    self.assertEqual(ctx.traps[Inexact], inexact)
                    self.assertEqual(ctx.traps[Rounded], rounded)

    def test_budget_render_integer_boundaries_and_sign(self):
        # Inject only the model's total to exercise display boundaries; this
        # neither admits a negative funding input nor changes any funding cap.
        cases = ((0, '0.00000000'), (1, '0.00000001'),
                 (99999999, '0.99999999'), (100000000, '1.00000000'),
                 (2**64 - 1, '184467440737.09551615'),
                 (-1, '-0.00000001'), (-100000001, '-1.00000001'))
        for total, text in cases:
            for precision in (1, 80):
                with self.subTest(total=total, precision=precision), localcontext() as ctx:
                    ctx.prec = precision
                    ctx.traps[Inexact] = ctx.traps[Rounded] = True
                    model = {'all_in_required_sat': total, 'recipient_required_sat': 0}
                    with patch.object(t1b, 'funding_model', return_value=model):
                        result = t1b.budget()
                    self.assertEqual(result['all_in_required_nmc'], text)
                    self.assertEqual(result['all_in_required_sat'], total)
                    self.assertEqual(result['headroom_sat'], 100000000 - total)
                    self.assertEqual(result['owner_cap_sat'], 100000000)
                    self.assertIs(result['cashflow_model'], model)

    def test_budget_funding_domain_remains_nonnegative_integers(self):
        for invalid in (-1, True, 1.5, Decimal('1')):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                t1b.funding_model((invalid,))

    def good(self, n=80):
        return {'payload_bytes': n, 'elapsed_s': 100, 'series_elapsed_s': 100,
            'preparation_elapsed_s': 10, 'relay_elapsed_s': 10, 'inclusion_wait_s': 80,
            't1_elapsed_s': 100, 'local_allowed': True, 'peer_status': 'observed',
            'peer_receipt_sha256': 'a'*64, 'reorg': False,
            'inclusion': {'block_hash': 'b'*64, 'height': 1,
                'header_time_utc': '2026-01-01T00:00:00+00:00',
                'observed_at_utc': '2026-01-01T00:01:00+00:00',
                'active_chain_receipt_sha256': 'c'*64, 'tx_in_block_receipt_sha256': 'd'*64}}

    def test_stop_first_no_skip_retry_or_unknown_promotion(self):
        self.assertEqual(t1b.advance([]), 80)
        row = self.good()
        self.assertEqual(t1b.advance([row]), 100)
        cases = [({'local_allowed': False}, 'STOP_LOCAL_POLICY_REFUSAL'),
                 ({'local_allowed': None}, 'STOP_LOCAL_POLICY_UNKNOWN'),
                 ({'peer_status': 'refused'}, 'STOP_PEER_RELAY_REFUSAL'),
                 ({'peer_status': 'unknown'}, 'STOP_PEER_RELAY_UNKNOWN'),
                 ({'peer_receipt_sha256': None}, 'STOP_PEER_RELAY_UNKNOWN'),
                 ({'inclusion': None}, 'STOP_NOT_MINED_WITHIN_WAIT'),
                 ({'reorg': True}, 'STOP_REORG'),
                 ({'reorg': None}, 'STOP_REORG_UNKNOWN'),
                 ({'preparation_elapsed_s': 61}, 'STOP_PHASE_BUDGET_OR_UNKNOWN'),
                 ({'relay_elapsed_s': 121}, 'STOP_PHASE_BUDGET_OR_UNKNOWN'),
                 ({'inclusion_wait_s': 1321}, 'STOP_PHASE_BUDGET_OR_UNKNOWN'),
                 ({'relay_elapsed_s': None}, 'STOP_PHASE_BUDGET_OR_UNKNOWN'),
                 ({'elapsed_s': 1501}, 'STOP_STEP_BUDGET'),
                 ({'series_elapsed_s': 10501}, 'STOP_SERIES_BUDGET'),
                 ({'series_elapsed_s': -1}, 'STOP_SERIES_BUDGET'),
                 ({'series_elapsed_s': float('nan')}, 'STOP_SERIES_BUDGET'),
                 ({'series_elapsed_s': float('inf')}, 'STOP_SERIES_BUDGET'),
                 ({'t1_elapsed_s': 21601}, 'STOP_T1_SIX_HOUR_CAP')]
        for delta, expected in cases:
            bad = copy.deepcopy(row); bad.update(delta)
            self.assertEqual(t1b.outcome(bad), expected)
            self.assertIsNone(t1b.advance([bad]))
        for key in row['inclusion']:
            bad = copy.deepcopy(row); del bad['inclusion'][key]
            self.assertEqual(t1b.outcome(bad), 'STOP_INCLUSION_EVIDENCE_MISSING')
        with self.assertRaises(ValueError): t1b.advance([self.good(100)])
        self.assertIsNone(t1b.advance([self.good(n) for n in t1b.SIZES]))

    def test_signed_fixture_manifest_matches_generation(self):
        import tempfile
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as directory:
            t1b.manifest(Path(directory))
            expected = Path(__file__).with_name('t1b-fixtures')
            files = sorted(p.name for p in Path(directory).iterdir())
            self.assertEqual(files, sorted(p.name for p in expected.iterdir()))
            for name in files:
                self.assertEqual((Path(directory)/name).read_bytes(), (expected/name).read_bytes(), name)

    def test_containment(self):
        for name in ('HOME', 'TMPDIR', 'XDG_CACHE_HOME'):
            p = Path(os.environ[name])
            self.assertTrue(p.is_absolute())
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o700)
        for p in ('/home/agent', '/run/user', '/root/.ssh', '/tmp/ssh-agent'):
            self.assertFalse(Path(p).exists())
        self.assertFalse(os.environ.get('SSH_AUTH_SOCK'))
        for p in ('tcp', 'tcp6', 'udp', 'udp6'):
            self.assertEqual(len(Path('/proc/net', p).read_text().splitlines()), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
