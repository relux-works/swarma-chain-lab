"""Offline value accounting controls; no chain, wallet, signer or RPC."""
import unittest
from decimal import Decimal
from unittest.mock import patch

import funding
import lab
import mainnet
import t1b


class FundingTests(unittest.TestCase):
    def test_fixed_source_caps_and_transfer(self):
        self.assertEqual(tuple(funding.T1_SIZES), mainnet.T1_ORDER)
        self.assertEqual(funding.T1_SIZES, mainnet.T1_SIZES)
        self.assertEqual(funding.ROLE_B_FUNDING_SAT, int(lab.ROLE_B_FUNDING * 100000000))
        self.assertEqual(funding.T1_FEE_CAPS, {
            op: int(lab.FEE_CEILINGS[op] * 100000000)
            for op in funding.T1_FEE_CAPS})
        self.assertEqual(sum(funding.T1_FEE_CAPS.values()), 708000)

    def test_t1_prefixes_and_revoke_reuse(self):
        model = funding.funding_model()
        self.assertEqual(model['recipient_required_sat'], 2888600)
        self.assertEqual(lab.FUNDING, Decimal('.02888600'))
        expected = [
            ('fund_B', 1406000, 1436600),
            ('A_name_new', 355600, 1436600),
            ('B_name_new', 355600, 386200),
            ('A_name_firstupdate', 252800, 386200),
            ('B_name_firstupdate', 252800, 283400),
            ('A_seal_funding', 106800, 283400),
            ('A_grant_anchor', 0, 283400),
            ('B_seal_funding', 0, 137400),
            ('B_grant_anchor', 0, 30600),
            ('A_seal_revoke', 50000, 30600)]
        self.assertEqual([(r['operation'], r['cash_sat']['A'], r['cash_sat']['B'])
                          for r in model['operations']], expected)
        self.assertEqual(model['B_required_from_fixed_transfer_sat'], 1406000)
        self.assertEqual(model['timing_forced_surplus_sat'], 9800)
        before, after = model['operations'][-2:]
        self.assertEqual(before['seals_locked_sat'], {'A': 100000, 'B': 100000})
        self.assertEqual(after['seals_locked_sat'], {'A': 0, 'B': 100000})
        self.assertEqual(after['cash_delta_sat']['A'], 50000)
        self.assertEqual(after['fee_sat'], 50000)

    def test_final_algebra_alone_fails_t1_peak(self):
        # The final-liability correction alone misses A's pre-revoke peak.
        final_algebra = 2000000 + 100000 + 708000 + 70800
        rows = funding.cashflow(final_algebra)
        self.assertEqual(min(r['cash_sat']['A'] for r in rows), -9800)
        rows = funding.cashflow(2888599)
        self.assertEqual(min(r['cash_sat']['A'] for r in rows), -1)
        # Fixed B has spare cash then, but source has no B-to-A return step.
        self.assertGreater(rows[6]['cash_sat']['B'], 0)

    def test_combined_final_floor_dominates_peak(self):
        b = t1b.budget()
        model = b['cashflow_model']
        self.assertEqual(b['recipient_required_sat'], 6815600)
        self.assertEqual(b['all_in_required_sat'], 6866200)
        self.assertEqual(model['A_peak_drawdown_sat'], 6326600)
        self.assertEqual(model['A_final_requirement_sat'], 6815600)
        self.assertEqual(model['funder_fee_paid_separately_sat'], 46000)
        self.assertEqual(model['funder_fee_margin_held_separately_sat'], 4600)
        self.assertEqual(model['experimental_fee_margin_sat'], 419600)
        self.assertEqual(model['timing_forced_surplus_sat'], 0)
        rows = model['operations']
        self.assertEqual(rows[8]['cash_sat']['A'], 3927000)
        self.assertEqual(rows[9]['cash_sat']['A'], 3977000)
        self.assertEqual([r['cash_sat']['A'] for r in rows[10:]],
                         [3917000, 3853000, 3769000, 3621000, 3377000, 2533000, 489000])
        self.assertEqual(rows[-1]['cash_sat'], {'A': 489000, 'B': 30600})
        self.assertEqual(model['final_cash_sat'], 419600 + 100000)
        caps = [t1b.VSIZE_CAPS[n] * 200 for n in t1b.SIZES]
        short = funding.cashflow(6815599, caps)
        self.assertEqual(sum(short[-1]['cash_sat'].values()), 419600 + 100000 - 1)
        self.assertTrue(all(min(r['cash_sat'].values()) >= 0 for r in short))
        # Old additive upper's extra provision is neither fee nor principal.
        self.assertEqual(6966200 - b['all_in_required_sat'], 100000)
        self.assertIsNone(b['live_estimator_quote'])

    def test_conservation_every_prefix_and_early_stop(self):
        for caps in ((), (60000,), tuple(t1b.VSIZE_CAPS[n] * 200 for n in t1b.SIZES)):
            model = funding.funding_model(caps, final_reserve_sat=100000)
            for row in model['operations']:
                value = sum(row['cash_sat'].values())
                value += sum(row['names_locked_sat'].values())
                value += sum(row['seals_locked_sat'].values())
                self.assertEqual(value + row['cumulative_fee_sat'], model['recipient_required_sat'])
                self.assertGreaterEqual(min(row['cash_sat'].values()), 0)
            self.assertGreaterEqual(model['final_cash_sat'],
                                    model['experimental_fee_margin_sat'] + 100000)

    def test_reject_non_satoshi_inputs(self):
        for value in (-1, True, 1.5):
            with self.assertRaises(ValueError):
                funding.cashflow(value)
            with self.assertRaises(ValueError):
                funding.funding_model((value,))

    def test_retained_lab_budget_report_uses_peak_model(self):
        # getbalance includes the live B seal but excludes named outputs.
        rows = [{'experiment_budget': False, 'fee_nmc': '0.00046000'}]
        rows += [{'experiment_budget': True, 'fee_nmc': str(Decimal(fee) / 100000000)}
                 for fee in funding.T1_FEE_CAPS.values()]
        report = {'transactions': rows}
        def balances(method, *, wallet):
            self.assertEqual(method, 'getbalance')
            return {'A': Decimal('.00050000'), 'B': Decimal('.00130600')}[wallet]
        with patch.object(lab, 'R', report), patch.object(lab, 'rpc', balances):
            lab.finish_budget()
        b = report['funding']
        self.assertTrue(b['smallest_under_declared_caps'])
        self.assertEqual(Decimal(b['exact_conditional_funding_nmc']), Decimal('.02888600'))
        self.assertEqual(Decimal(b['timing_forced_surplus_nmc']), Decimal('.00009800'))
        self.assertEqual(b['cashflow_model']['final_cash_sat'], 80600)


if __name__ == '__main__':
    unittest.main(verbosity=2)
