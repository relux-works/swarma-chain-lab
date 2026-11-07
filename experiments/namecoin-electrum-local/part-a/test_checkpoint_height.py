"""Offline checkpoint-domain regression using an unchanged recorded regtest proof.

Run with the pinned ElectrumX modules on PYTHONPATH. No service is required.
The fixture is the actual header/branch/root returned at checkpoint height 222;
replaying it tests this helper, not execution of a new node or server runtime.
"""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import thin


class CheckpointHeightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads((Path(__file__).parent / 'tests/checkpoint-222.json').read_text())
        cls.proof = cls.fixture['header_proof']
        cls.anchor = cls.fixture['anchor']

    def test_actual_checkpoint_tip(self):
        raw = thin.header_proof(self.proof, 222, self.anchor)
        self.assertEqual(thin.h(raw)[::-1].hex(), self.fixture['actual_tip_hash'])

    def test_actual_padding_position_rejected(self):
        # Canonical folding alone accepts both positions: the final leaf repeats.
        leaf = self.fixture['actual_tip_hash']
        self.assertEqual(thin.fold(leaf, self.proof['branch'], 223), self.anchor['root'])
        with self.assertRaises(ValueError):
            thin.header_proof(self.proof, 223, self.anchor)

    def test_invalid_entry_domains_rejected_before_fold(self):
        for height in (-1, -223, 223, 224, 256, 1 << 30, 222.0, 223.0,
                       True, False, '222', None, [], {}):
            with self.subTest(height=height), patch.object(thin, 'fold') as fold:
                with self.assertRaises(ValueError):
                    thin.header_proof(self.proof, height, self.anchor)
                fold.assert_not_called()

    def test_invalid_checkpoint_domains_rejected_before_fold(self):
        for height in (-1, -2, 222.0, True, False, '222', None, [], {}, 1 << 30):
            anchor = dict(self.anchor, height=height)
            with self.subTest(height=height), patch.object(thin, 'fold') as fold:
                with self.assertRaises(ValueError):
                    thin.header_proof(self.proof, 0, anchor)
                fold.assert_not_called()
        for anchor in (None, [], {}, {'root': self.anchor['root']}, {'height': 222}):
            with self.subTest(anchor=anchor), patch.object(thin, 'fold') as fold:
                with self.assertRaises(ValueError):
                    thin.header_proof(self.proof, 0, anchor)
                fold.assert_not_called()
        for root in (None, 0, True, '', '00' * 31, '00' * 33, 'zz' * 32, ' ' * 64):
            with self.subTest(root=root), patch.object(thin, 'fold') as fold:
                with self.assertRaises(ValueError):
                    thin.header_proof(self.proof, 0, dict(self.anchor, root=root))
                fold.assert_not_called()

    def test_adjacent_height_root_header_branch_corruption(self):
        with self.assertRaises(AssertionError):
            thin.header_proof(self.proof, 221, self.anchor)
        corrupt_root = ('1' if self.anchor['root'][0] != '1' else '0') + self.anchor['root'][1:]
        with self.assertRaises(AssertionError):
            thin.header_proof(self.proof, 222, dict(self.anchor, root=corrupt_root))
        for field in ('root', 'header'):
            obj = copy.deepcopy(self.proof)
            raw = bytearray.fromhex(obj[field]); raw[0] ^= 1
            obj[field] = raw.hex()
            with self.subTest(field=field), self.assertRaises(AssertionError):
                thin.header_proof(obj, 222, self.anchor)
        obj = copy.deepcopy(self.proof)
        raw = bytearray.fromhex(obj['branch'][1]); raw[0] ^= 1
        obj['branch'][1] = raw.hex()
        with self.assertRaises(AssertionError):
            thin.header_proof(obj, 222, self.anchor)
        for branch in (self.proof['branch'][:-1], self.proof['branch'] + [self.proof['branch'][0]]):
            with self.subTest(depth=len(branch)), self.assertRaises(AssertionError):
                thin.header_proof(dict(self.proof, branch=branch), 222, self.anchor)

    def test_small_in_range_controls(self):
        # Synthetic trees exercise lower bounds independently of the recorded tip.
        raw = bytes.fromhex(self.proof['header'])
        for count in (1, 2, 3, 4, 5):
            headers = [raw[:-4] + n.to_bytes(4, 'little') for n in range(count)]
            hashes = [thin.h(header) for header in headers]
            for height, header in enumerate(headers):
                branch, root = thin.M.branch_and_root(hashes, height)
                anchor = {'height': count - 1, 'root': root[::-1].hex()}
                obj = {'header': header.hex(), 'root': anchor['root'],
                       'branch': [x[::-1].hex() for x in branch]}
                with self.subTest(count=count, height=height):
                    self.assertEqual(thin.header_proof(obj, height, anchor), header)


if __name__ == '__main__':
    unittest.main(verbosity=2)
