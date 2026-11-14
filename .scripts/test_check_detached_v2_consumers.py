"""Positive inventory and planted cross-observer payment-key controls."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
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
        for suffix, plant in {
            '.go': 'package payment\nfunc key(r rental.Receipt) string { return r.CertificateSHA256 }\n',
            '.py': 'cross_observer_payments[receipt["certificate_sha256"]] = True\n',
            '.sh': 'jq -r .certificate_sha256 receipts.json > payment-key\n',
        }.items():
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch)
                self.fixture(root)
                relative = 'experiments/payment-chain/cross_observer' + suffix
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(plant)
                self.assertEqual(guard.check(root, INVENTORY),
                                 ['unreviewed detached-v2 reference: ' + relative])

    def cli(self, root):
        return subprocess.run([sys.executable, '-B', str(CHECKER), '--root', str(root)],
                              capture_output=True, text=True)

    def real_modules(self, root):
        self.fixture(root)
        for name in ('rental', 'single-use', 'sealwatch', 'payment-chain', 'rental-booking'):
            shutil.copytree(REPO / 'experiments' / name, root / 'experiments' / name,
                            dirs_exist_ok=True)
        return root / 'experiments/rental'

    def go(self, module, *args):
        result = subprocess.run(['go', *args], cwd=module, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    # Claim: compiled test_*.go and normal-name consumers are rejected; real *_test.go remains excluded.
    def test_compiled_test_prefix_production_consumer(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            module = self.real_modules(root)
            self.assertEqual(self.cli(root).returncode, 0)
            plant = ('package rental\n'
                     'var crossObserverPayments = map[string]bool{}\n'
                     'func crossObserverPayment(receipt Receipt) {\n'
                     '    crossObserverPayments[receipt.CertificateSHA256] = true\n}\n')
            for name in ('test_cross_observer_payment.go', 'cross_observer_payment.go',
                         'cross_observer_payment_test.go'):
                with self.subTest(name=name):
                    path = module / name
                    path.write_text(plant)
                    try:
                        subprocess.run(['gofmt', '-w', str(path)], check=True, capture_output=True)
                        self.go(module, 'vet', '-mod=readonly', '.')
                        self.go(module, 'build', '-p', '1', '-mod=readonly', '.')
                        package = json.loads(self.go(module, 'list', '-mod=readonly', '-json', '.'))
                        is_test = name.endswith('_test.go')
                        self.assertIn(name, package['TestGoFiles' if is_test else 'GoFiles'])
                        if is_test:
                            self.assertNotIn(name, package['GoFiles'])
                            self.go(module, 'test', '-p', '1', '-mod=readonly', '-run', '^$', '.')
                        verdict = self.cli(root)
                        self.assertEqual(verdict.returncode, 0 if is_test else 1, verdict.stdout + verdict.stderr)
                        if not is_test:
                            self.assertIn('unreviewed detached-v2 reference: experiments/rental/' + name,
                                          verdict.stdout)
                    finally:
                        path.unlink()

    # Claim: explicit builds compile directory/build-tag plants, and the checker rejects every plant.
    def test_explicitly_compiled_directory_and_build_tag_consumers(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            module = self.real_modules(root)
            for relative in ('.temp/probe.go', 'testdata/probe.go', 'vendor/probe.go',
                             '.hidden/probe.go', '_hidden/probe.go', '.git/probe.go', 'tagged/probe.go'):
                with self.subTest(path=relative):
                    path = module / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    tag = '//go:build ignore\n\n' if relative.startswith('tagged/') else ''
                    path.write_text(tag + 'package probe\n'
                                    'import rental "github.com/relux-works/swarma-chain-lab/experiments/rental"\n'
                                    'var payments = map[string]bool{}\n'
                                    'func payment(receipt rental.Receipt) { payments[receipt.CertificateSHA256] = true }\n')
                    try:
                        subprocess.run(['gofmt', '-w', str(path)], check=True, capture_output=True)
                        self.go(module, 'vet', '-mod=readonly', relative)
                        self.go(module, 'build', '-p', '1', '-mod=readonly', relative)
                        package = json.loads(self.go(module, 'list', '-mod=readonly', '-json', relative))
                        self.assertIn('probe.go', package['GoFiles'])
                        verdict = self.cli(root)
                        self.assertEqual(verdict.returncode, 1, verdict.stdout + verdict.stderr)
                        self.assertIn('unreviewed detached-v2 reference: experiments/rental/' + relative,
                                      verdict.stdout)
                    finally:
                        path.unlink()

    # Claim: production-importable Python and shell/extensionless/unknown-suffix test_ names are scanned.
    def test_non_go_names_and_suffixes_are_scanned(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            self.fixture(root)
            for name in ('test_payment.py', 'payment_test.py', 'test_payment.sh',
                         'test_payment.bash', 'test_payment', 'test_payment.custom'):
                with self.subTest(name=name):
                    path = root / name
                    path.write_text('receipt = {"certificate_sha256": "fixture"}\n'
                                    'payments = {receipt["certificate_sha256"]: True}\n')
                    try:
                        if path.suffix == '.py':
                            imported = subprocess.run([sys.executable, '-B', '-c',
                                'import runpy, sys; assert runpy.run_path(sys.argv[1])["payments"] == {"fixture": True}',
                                str(path)], capture_output=True, text=True)
                            self.assertEqual(imported.returncode, 0, imported.stderr)
                        verdict = self.cli(root)
                        self.assertEqual(verdict.returncode, 1, verdict.stdout + verdict.stderr)
                        self.assertIn('unreviewed detached-v2 reference: ' + name, verdict.stdout)
                    finally:
                        path.unlink()

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
