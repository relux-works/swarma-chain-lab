"""Positive inventory and planted cross-observer payment-key controls."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
CHECKER = Path(os.environ.get('DETACHED_V2_CHECKER', REPO / '.scripts/check-detached-v2-consumers.py'))
spec = importlib.util.spec_from_file_location('detached_guard', CHECKER)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
INVENTORY = json.loads((REPO / '.scripts/detached-v2-consumers.json').read_text())


class DetachedConsumerGuard(unittest.TestCase):
    # Claim: the actual production inventory is a valid positive control.
    def test_reviewed_repository(self):
        self.assertEqual(guard.check(REPO, INVENTORY), [])

    def fixture(self, root):
        for relative in INVENTORY:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((REPO / relative).read_bytes())

    # Claim: a payment-key plant in EVERY real reviewed path is caught, even when
    # it reuses an already inventoried ID token; no semantic parser is claimed.
    def test_real_consumer_cross_observer_payment_control(self):
        for relative in INVENTORY:
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                self.fixture(root)
                self.assertEqual(guard.check(root, INVENTORY), [])
                path = root / relative
                path.write_bytes(path.read_bytes() + b'\nfunc crossObserverPaymentKey(r Receipt) { crossObserverPayments[r.CertificateSHA256] = true }\n')
                self.assertIn('changed detached-v2 consumer: ' + relative,
                              guard.check(root, INVENTORY))

    # Claim: a new production path cannot use a detached ID without review.
    def test_new_cross_observer_consumer(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.fixture(root)
            path = root / 'experiments/payment-chain/cross_observer.go'
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('package payment\nfunc key(r rental.Receipt) string { return r.CertificateSHA256 }\n')
            self.assertEqual(guard.check(root, INVENTORY),
                             ['unreviewed detached-v2 reference: experiments/payment-chain/cross_observer.go'])

    # Claim: deleting a reviewed path fails closed rather than narrowing scope.
    def test_missing_consumer(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.fixture(root)
            relative = 'experiments/rental/presentation.go'
            (root / relative).unlink()
            self.assertEqual(guard.check(root, INVENTORY), ['missing detached-v2 consumer: ' + relative])


if __name__ == '__main__':
    unittest.main()
