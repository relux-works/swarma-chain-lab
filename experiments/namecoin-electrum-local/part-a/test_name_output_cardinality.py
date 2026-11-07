"""Offline parser coverage; the synthetic duplicate asserts no consensus validity.

Run with the pinned ElectrumX modules on PYTHONPATH. No service is required.
"""
from types import SimpleNamespace
import unittest

from electrumx.lib.script import OpCodes

import thin


class NameOutputCardinalityTests(unittest.TestCase):
    def test_singleton_mapping_and_duplicate_rejection(self):
        name = 'd/offline-fixture'
        value = '{"test":1}'
        owner = bytes.fromhex('76a914' + '11' * 20 + '88ac')
        script = (
            bytes([thin.Coin.OP_NAME_UPDATE])
            + thin.Script.push_data(name.encode())
            + thin.Script.push_data(value.encode())
            + bytes([OpCodes.OP_2DROP, OpCodes.OP_DROP])
            + owner
        )
        output = SimpleNamespace(pk_script=script)
        self.assertEqual(thin.parse_name(SimpleNamespace(outputs=[output]), name), {
            'vout': 0,
            'value': value,
            'script': script.hex(),
            'address_script': owner.hex(),
        })

        # Change only cardinality: the real Coin/Script parser sees the same bytes.
        with self.assertRaises(AssertionError) as refusal:
            thin.parse_name(SimpleNamespace(outputs=[output, output]), name)
        self.assertEqual(str(refusal.exception), 'exactly one requested name output required')


if __name__ == '__main__':
    unittest.main(verbosity=2)
