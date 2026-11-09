"""Bounded publication-check controls; no real identities or network access."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import quote

SCRIPT = Path(__file__).with_name('check-public-hygiene.py')
spec = importlib.util.spec_from_file_location('hygiene', SCRIPT)
hygiene = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hygiene)


def mxid(domain):
    return '@' + 'operator:' + domain


class HygieneControls(unittest.TestCase):
    # These examples remain allowed; suffix/prefix/Unicode lookalikes do not.
    def test_examples_and_nearby_domains(self):
        for domain in hygiene.EXAMPLE_DOMAINS:
            for allowed in (domain, domain.upper(), domain + ':8448'):
                with self.subTest(allowed=allowed):
                    self.assertEqual(list(hygiene.violations(mxid(allowed))), [])
            for denied in ('sub.' + domain, domain + '.blocked.invalid', domain + '-suffix', domain + 'é'):
                with self.subTest(denied=denied):
                    self.assertEqual(list(hygiene.violations(mxid(denied))), [1])

    # Literal, URL, JSON, HTML and common obfuscated forms reach the same refusal.
    def test_encoded_forms(self):
        raw = mxid('blocked.invalid')
        cases = [raw, quote(raw, safe=''), quote(quote(raw, safe=''), safe=''),
                 raw.replace('@', r'\u0040').replace(':', r'\u003a'),
                 raw.replace('@', r'\x40').replace(':', r'\x3a'),
                 raw.replace('@', '&#64;').replace(':', '&#58;'),
                 raw.replace('.', '[.]'), raw.replace('.', '(.)'),
                 raw.replace('.', r'\.'), raw.replace('@', '[@]').replace(':', '[:]')]
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(list(hygiene.violations(value)), [1])
        self.assertEqual(list(hygiene.violations(quote(mxid('example.invalid'), safe=''))), [])

    # IP/localhost Matrix IDs refuse; URL credentials are distinct syntax.
    def test_server_and_url_boundaries(self):
        for host in ('localhost', '127.0.0.1', '[::1]:8448'):
            self.assertEqual(list(hygiene.violations(mxid(host))), [1])
        for url in ('https://user:password@127.0.0.1:8448/path', 'ws://user@localhost:1234'):
            self.assertEqual(list(hygiene.violations(url)), [])
        self.assertEqual(list(hygiene.violations('https://matrix.to/#/' + mxid('blocked.invalid'))), [1])
        self.assertEqual(list(hygiene.violations('https://' + mxid('blocked.invalid'))), [1])

    # The real CLI accepts a tracked example, detects a planted violation with
    # the intended exit/message, and accepts the same file after restoration.
    # Untracked files are intentionally outside the CI publication boundary.
    def test_cli_control_plant(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(['git', 'init', '-q', tmp], check=True)
            candidate = root / 'fixture.txt'
            valid = mxid('example.invalid') + '\n'
            candidate.write_text(valid)
            subprocess.run(['git', '-C', tmp, 'add', 'fixture.txt'], check=True)
            def run():
                return subprocess.run([sys.executable, '-B', str(SCRIPT), tmp], capture_output=True, text=True)
            good = run()
            self.assertEqual(good.returncode, 0, good.stderr)
            planted = quote(mxid('blocked.invalid'), safe='')
            candidate.write_text(planted)
            bad = run()
            self.assertEqual(bad.returncode, 1, bad.stderr)
            self.assertIn('public hygiene: non-example Matrix ID', bad.stderr)
            self.assertNotIn(planted, bad.stderr)
            self.assertNotIn('blocked.invalid', bad.stderr)
            candidate.write_text(valid)
            (root / 'untracked.txt').write_text(planted)
            self.assertEqual(run().returncode, 0)

    # A tracked encoded filename is scanned even when its content is empty;
    # diagnostics identify it by hash and do not repeat the planted identity.
    def test_filename_control(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(['git', 'init', '-q', tmp], check=True)
            name = quote(mxid('blocked.invalid'), safe='') + '.txt'
            (Path(tmp) / name).write_text('')
            subprocess.run(['git', '-C', tmp, 'add', name], check=True)
            result = subprocess.run([sys.executable, '-B', str(SCRIPT), tmp], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn('filename-sha256=', result.stderr)
            self.assertNotIn(name, result.stderr)

    # Missing tracked content is a scan error, never a successful empty scan.
    def test_missing_tracked_file_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(['git', 'init', '-q', tmp], check=True)
            path = Path(tmp) / 'missing.txt'
            path.write_text('example')
            subprocess.run(['git', '-C', tmp, 'add', 'missing.txt'], check=True)
            path.unlink()
            result = subprocess.run([sys.executable, '-B', str(SCRIPT), tmp], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr.strip(), 'public hygiene: scan failed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
