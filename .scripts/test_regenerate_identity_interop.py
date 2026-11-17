"""Toolchain admission controls; exported bytes are checked separately in CI."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ExportToolchainTests(unittest.TestCase):
    # A supported patch reaches the clone boundary; an unsupported patch must
    # refuse with the named toolchain error before any clone is attempted.
    def check_version(self, version, allowed):
        (ROOT / '.temp').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / '.temp') as raw:
            scratch = Path(raw)
            tools = scratch / 'bin'
            tools.mkdir()
            marker = scratch / 'clone-attempt'
            go = tools / 'go'
            go.write_text('#!/bin/sh\nprintf "%s\\n" "go version go' + version + ' linux/amd64"\n')
            go.chmod(0o700)
            git = tools / 'git'
            git.write_text('#!/bin/sh\n: > "$EXPORT_CLONE_MARKER"\nexit 71\n')
            git.chmod(0o700)
            env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                       EXPORT_CLONE_MARKER=str(marker))
            result = subprocess.run(['bash', str(ROOT / '.scripts/regenerate-identity-interop.sh'),
                                     str(scratch / 'output')], cwd=ROOT, env=env,
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 71 if allowed else 2, result.stderr)
            self.assertEqual(marker.exists(), allowed)
            self.assertFalse((scratch / 'output').exists())
            if not allowed:
                self.assertIn('Go 1.26.8 or 1.26.10 required', result.stderr)

    def test_release_patch(self):
        self.check_version('1.26.8', True)

    def test_original_export_patch(self):
        self.check_version('1.26.10', True)

    def test_unsupported_patch_refuses_before_clone(self):
        self.check_version('1.26.9', False)
