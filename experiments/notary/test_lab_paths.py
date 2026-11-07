"""Offline path and supervisor admission controls; no runtime children.

Supervisor controls execute its source with fake process, clock and resource APIs.
"""
import ast
import datetime
import json
import os
import signal
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from lab_paths import lab_root


class LabPaths(unittest.TestCase):
    def test_required_and_absolute(self):
        for value in ['', 'notary-lab', 'relative/notary-lab', '/', '/tmp',
                      '/scratch/notary-lab/', '/scratch/../notary-lab']:
            with self.subTest(value=value), patch.dict(os.environ, {'NOTARY_LAB_ROOT': value}):
                with self.assertRaises(ValueError):
                    lab_root()
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                lab_root()

    def test_two_roots_and_spaces(self):
        with tempfile.TemporaryDirectory() as temp:
            for parent in ['first', 'second with spaces']:
                p = Path(temp) / parent / 'notary-lab'
                p.parent.mkdir(mode=0o700)
                with patch.dict(os.environ, {'NOTARY_LAB_ROOT': str(p)}):
                    self.assertEqual(lab_root(), p)
                    self.assertFalse(p.exists())

    def test_symlink_aliases_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            real = parent / 'real'
            real.mkdir(mode=0o700)
            alias = parent / 'alias'
            alias.symlink_to(real, target_is_directory=True)
            for p in [alias / 'notary-lab', parent / 'notary-lab']:
                if p.parent == parent:
                    p.symlink_to(real, target_is_directory=True)
                with patch.dict(os.environ, {'NOTARY_LAB_ROOT': str(p)}):
                    with self.assertRaises(ValueError):
                        lab_root()

    def test_lifecycle_uses_shared_root_guard(self):
        source = Path(__file__).parent
        for name in ['prepare-lab.py', 'cleanup.py', 'reset-own-generated.py']:
            tree = ast.parse((source / name).read_text())
            self.assertTrue(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                                and n.func.id == 'lab_root' for n in ast.walk(tree)), name)
        for name in ['sandbox.sh', 'reproduce.sh']:
            self.assertIn('from lab_paths import lab_root', (source / name).read_text())

    def test_no_literal_host_home_paths(self):
        source = Path(__file__).parent
        prefix = '/' + 'home/'
        for p in source.iterdir():
            if p.is_file() and p.suffix in ['.py', '.sh', '.md']:
                self.assertNotIn(prefix, p.read_text(), p.name)


class SupervisorAdmission(unittest.TestCase):
    cutoff = datetime.datetime.fromisoformat('2026-11-07T03:16:00+00:00').timestamp()

    def supervise(self, wall, *, running=False, advance=0, size=0, processes=1,
                  child_exit=0, termination_timeout=False):
        source = Path(__file__).with_name('supervise.py').read_text()
        observed = {'starts': [], 'signals': [], 'receipts': [], 'waits': []}
        clock = {'monotonic': 100.0}
        times = iter(wall)
        fake_time = types.SimpleNamespace(time=lambda: next(times),
                                          monotonic=lambda: clock['monotonic'],
                                          sleep=lambda _: self.fail('unexpected sleep'))

        class Child:
            pid = 123456
            returncode = None if running else child_exit

            def poll(self):
                clock['monotonic'] += advance
                return self.returncode

            def wait(self, timeout=None):
                observed['waits'].append(timeout)
                if termination_timeout and timeout is not None:
                    raise TimeoutError()
                self.returncode = child_exit
                return self.returncode

        def popen(command, **kwargs):
            observed['starts'].append((command, kwargs))
            return Child()

        class FakePath:
            def __init__(self, path):
                self.path = path

            def rglob(self, pattern):
                assert self.path in ['/private', '/public'] and pattern == '*'
                return [types.SimpleNamespace(is_symlink=lambda: False,
                        lstat=lambda: types.SimpleNamespace(st_blocks=size // 512))] if self.path == '/private' else []

            def iterdir(self):
                assert self.path == '/proc'
                return [types.SimpleNamespace(name=str(i)) for i in range(processes)]

            def write_text(self, text):
                assert self.path == '/public/supervision.json'
                observed['receipts'].append(json.loads(text))

        fake_resource = types.SimpleNamespace(setrlimit=lambda *args: None,
            **{name: name for name in ['RLIMIT_FSIZE', 'RLIMIT_NOFILE',
                                      'RLIMIT_CORE', 'RLIMIT_CPU', 'RLIMIT_AS']})
        modules = {'time': fake_time, 'resource': fake_resource,
                   'subprocess': types.SimpleNamespace(Popen=popen, TimeoutExpired=TimeoutError),
                   'pathlib': types.SimpleNamespace(Path=FakePath),
                   'os': types.SimpleNamespace(killpg=lambda pid, sig: observed['signals'].append((pid, sig)))}
        with patch.dict(sys.modules, modules), patch.object(sys, 'argv', ['supervise.py', '/offline-stub']):
            with self.assertRaises(SystemExit) as stopped:
                exec(compile(source, 'supervise.py', 'exec'), {'__name__': '__main__'})
        self.assertEqual(len(observed['receipts']), 1)
        receipt = observed['receipts'][0]
        self.assertEqual(receipt['exit'], stopped.exception.code)
        self.assertEqual(receipt['absolute_cutoff'], '2026-11-07T03:16:00Z')
        self.assertEqual(receipt['time_limit_seconds'], 2100)
        self.assertEqual(receipt['disk_limit_bytes'], 1900 * 1024**2)
        self.assertEqual(receipt['process_limit'], 32)
        return receipt, observed

    def test_expired_and_exact_cutoff_start_no_child(self):
        for wall in [self.cutoff, self.cutoff + 1]:
            with self.subTest(wall=wall):
                receipt, observed = self.supervise([wall, wall])
                self.assertEqual(receipt['exit'], 1)
                self.assertIsNone(receipt['child_exit'])
                self.assertFalse(receipt['child_started'])
                self.assertEqual(receipt['stop_reason'], 'ADMISSION_EXPIRED')
                self.assertEqual(observed['starts'], [])
                self.assertEqual(observed['signals'], [])

    def test_expiry_between_initial_clock_and_start_no_child(self):
        receipt, observed = self.supervise([self.cutoff - 1, self.cutoff])
        self.assertEqual(receipt['exit'], 1)
        self.assertFalse(receipt['child_started'])
        self.assertEqual(observed['starts'], [])

    def test_precutoff_completed_child_keeps_exit(self):
        for child_exit in [0, 7]:
            with self.subTest(child_exit=child_exit):
                receipt, observed = self.supervise([self.cutoff - .01] * 2, child_exit=child_exit)
                self.assertEqual(receipt['exit'], child_exit)
                self.assertEqual(receipt['child_exit'], child_exit)
                self.assertTrue(receipt['child_started'])
                self.assertIsNone(receipt['stop_reason'])
                self.assertEqual(observed['starts'], [(['/offline-stub'], {'start_new_session': True})])
                self.assertEqual(observed['signals'], [])

    def check_budget(self, reason, wall, **kwargs):
        receipt, observed = self.supervise([wall] * 2, running=True, **kwargs)
        self.assertEqual(receipt['exit'], 1)
        self.assertEqual(receipt['child_exit'], 0)
        self.assertTrue(receipt['child_started'])
        self.assertEqual(receipt['stop_reason'], reason)
        self.assertEqual(observed['signals'][0], (123456, signal.SIGTERM))
        self.assertEqual(observed['waits'][0], 5)
        return observed

    def test_absolute_cutoff_stop_child_zero_is_failure(self):
        self.check_budget('TIME_BUDGET', self.cutoff - 1, advance=1)

    def test_wall_budget_stop_child_zero_is_failure(self):
        self.check_budget('TIME_BUDGET', self.cutoff - 3000, advance=2100)

    def test_disk_budget_stop_child_zero_is_failure(self):
        self.check_budget('DISK_BUDGET', self.cutoff - 100, size=1900 * 1024**2 + 512)

    def test_process_budget_stop_child_zero_is_failure(self):
        self.check_budget('PROCESS_BUDGET', self.cutoff - 100, processes=33)

    def test_budget_kill_escalation_child_zero_is_failure(self):
        observed = self.check_budget('TIME_BUDGET', self.cutoff - 1, advance=1, termination_timeout=True)
        self.assertEqual(observed['signals'], [(123456, signal.SIGTERM), (123456, signal.SIGKILL)])
        self.assertEqual(observed['waits'], [5, None])


if __name__ == '__main__':
    unittest.main(verbosity=2)
