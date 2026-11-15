"""Controls for the published wallet behavioral witness gate."""
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('wallet_gate', Path(__file__).with_name('check-published-wallet-grantcheck.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class PublishedWalletControls(unittest.TestCase):
    # Claim: both named runs must finish with their intended verdict; an absent
    # test, skip, compile/setup failure, or unrelated assertion cannot qualify.
    def test_behavioral_witness_is_specific(self):
        for _, name, _, witness in gate.CASES:
            def output(action, text):
                return '\n'.join(json.dumps(e) for e in [
                    {'Test': name, 'Action': 'run'},
                    {'Test': name, 'Action': 'output', 'Output': text},
                    {'Test': name, 'Action': action}])
            self.assertTrue(gate.behavior_verified(output('pass', ''), name, False, witness))
            self.assertTrue(gate.behavior_verified(output('fail', witness), name, True, witness))
            for bad in ('', output('skip', witness), output('fail', 'connection refused'),
                        output('pass', witness), output('fail', witness).replace(name, 'Other')):
                self.assertFalse(gate.behavior_verified(bad, name, True, witness))
            self.assertFalse(gate.behavior_verified(output('fail', witness), name, False, witness))


if __name__ == '__main__':
    unittest.main()
