#!/usr/bin/env python3
"""Offline release controls with disposable local keys; never use a release key.

Each rejection asserts its named verdict and absence of RELEASE_VERIFIED;
positive neighbors prove that rejection is not a verifier that rejects all.
No claim is made about operator custody or the provenance of a supplied rebuild.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('verify-release.sh').resolve()
TAG = 'notary-service/v0.1.1'
OLD_TAG = 'notary-service/v0.1.0'


class ReleaseVerification(unittest.TestCase):
    def command(self, *args):
        result = subprocess.run(args, cwd=self.repo, env=self.env,
                                capture_output=True, timeout=20)
        # Diagnostics may include ephemeral key material: never print them.
        self.assertEqual(result.returncode, 0, 'fixture command failed: ' + args[0])
        return result.stdout.decode().strip()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='release-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.release = self.root / 'release'
        self.release.mkdir()
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1',
                        GIT_CONFIG_GLOBAL=os.devnull)
        self.env.pop('GIT_CONFIG_COUNT', None)
        self.tag_key = self.root / 'tag-signer'
        self.command('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.tag_key))
        self.key = self.root / 'manifest-signer'
        self.command('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.key))
        self.allowed = self.root / 'allowed-signers'
        self.allowed.write_text('release-test namespaces="swarma-release" '
                                + self.key.with_suffix('.pub').read_text())
        self.tag_allowed = self.root / 'tag-allowed-signers'
        self.tag_allowed.write_text('tag-test namespaces="git" '
                                    + self.tag_key.with_suffix('.pub').read_text())
        self.command('git', 'init', '-q')
        for key, value in [('user.name', 'Release fixture'),
                           ('user.email', 'release@example.invalid'),
                           ('gpg.format', 'ssh'), ('user.signingkey', str(self.tag_key)),
                           ('gpg.ssh.allowedSignersFile', str(self.tag_allowed))]:
            self.command('git', 'config', key, value)
        (self.repo / 'source').write_text('disposable release fixture\n')
        self.command('git', 'add', 'source')
        self.command('git', '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture')
        self.command('git', 'tag', '-s', OLD_TAG, '-m', 'previous fixture')
        (self.repo / 'source').write_text('new release fixture revision\n')
        self.command('git', 'add', 'source')
        self.command('git', '-c', 'commit.gpgsign=false', 'commit', '-qm', 'new fixture')
        self.commit = self.command('git', 'rev-parse', 'HEAD')
        self.command('git', 'tag', '-s', TAG, '-m', 'disposable fixture')
        self.binary = self.release / 'notary-service-linux-amd64'
        self.binary.write_bytes(b'disposable binary fixture\n')
        self.rebuilt = self.root / 'rebuilt'
        shutil.copyfile(self.binary, self.rebuilt)
        self.manifest = self.release / 'SHA256SUMS'
        self.manifest.write_text(hashlib.sha256(self.binary.read_bytes()).hexdigest()
                                 + '  notary-service-linux-amd64\n')
        self.sign_manifest()

    def sign_manifest(self, namespace='swarma-release'):
        self.manifest.with_suffix('.sig').unlink(missing_ok=True)
        self.command('ssh-keygen', '-Y', 'sign', '-f', str(self.key),
                     '-n', namespace, str(self.manifest))

    def verify(self, refusal=None, signer='release-test', commit=None, tag=TAG,
               tag_allowed=None, manifest_allowed=None):
        args = [str(SCRIPT), str(self.repo), commit or self.commit]
        if tag is not None:
            args.append(tag)
        args.extend([str(self.release), str(self.rebuilt),
                     str(tag_allowed or self.tag_allowed),
                     str(manifest_allowed or self.allowed), signer])
        result = subprocess.run(args, cwd=self.repo, env=self.env,
                                capture_output=True, timeout=20)
        output = result.stdout.decode()
        self.assertEqual(result.stderr, b'')
        self.assertTrue(all(line.startswith(('PASS ', 'FAIL '))
                            for line in output.splitlines()), output)
        if refusal:
            self.assertEqual(result.returncode, 1)
            self.assertEqual(output.splitlines()[-1], 'FAIL ' + refusal)
            self.assertNotIn('RELEASE_VERIFIED', output)
        else:
            self.assertEqual(result.returncode, 0, output)
            self.assertEqual(output.splitlines()[-1], 'PASS RELEASE_VERIFIED')
        print(f'{self._testMethodName}: exit {result.returncode}; {output.splitlines()[-1]}',
              flush=True)

    # Distinct role keys authenticate the current release, never a default tag.
    # Every refusal asserts the exact verdict, exit 1 and no terminal success.
    def test_all_good(self):
        self.verify()

    # Canonical boundary and multi-digit versions work without a hard-coded release.
    def test_other_canonical_versions(self):
        for tag in ['notary-service/v0.0.0', 'notary-service/v12.34.56']:
            with self.subTest(tag=tag):
                self.command('git', 'tag', '-s', tag, '-m', 'version control')
                self.verify(tag=tag)

    # A well-formed absent tag still needs a trusted signature.
    def test_missing_tag(self):
        self.verify('TAG_SIGNATURE', tag='notary-service/v99.0.0')

    # Version input is required and canonical; shell syntax remains inert data.
    def test_missing_tag_parameter(self):
        self.verify('ARGUMENTS', tag=None)

    def test_malformed_tag_parameter(self):
        for tag in ['', 'v0.1.1', 'notary-service/v0.1',
                    'notary-service/v01.1.1', 'notary-service/v0.1.1-rc1',
                    'notary-service/v0.1.1\n', 'notary-service/v*',
                    'notary-service/v$(touch injected).1.1',
                    'notary-service/v`touch injected`.1.1',
                    'refs/tags/' + TAG, TAG + '; touch injected']:
            with self.subTest(tag=tag):
                self.verify('ARGUMENTS', tag=tag)
                self.assertFalse((self.repo / 'injected').exists())

    def test_old_tag_with_current_assets(self):
        self.verify('TAG_COMMIT', tag=OLD_TAG)

    # Cross-role signatures refuse even though each key is trusted for its own role.
    def test_bot_signed_manifest(self):
        self.manifest.with_suffix('.sig').unlink()
        self.command('ssh-keygen', '-Y', 'sign', '-f', str(self.tag_key),
                     '-n', 'swarma-release', str(self.manifest))
        self.verify('MANIFEST_SIGNATURE')

    def test_release_key_signed_tag(self):
        self.command('git', 'tag', '-d', TAG)
        self.command('git', '-c', 'user.signingkey=' + str(self.key),
                     'tag', '-s', TAG, '-m', 'wrong signing role')
        self.verify('TAG_SIGNATURE')

    def test_shared_allowed_signers(self):
        self.verify('ARGUMENTS', manifest_allowed=self.tag_allowed)

    def test_swapped_allowed_signers(self):
        self.verify('TAG_SIGNATURE', tag_allowed=self.allowed,
                    manifest_allowed=self.tag_allowed)

    # Exact membership includes hidden names; no directory entry may be a link,
    # directory or special file. lstat must reject even links to valid inputs.
    def test_extra_file(self):
        (self.release / 'unlisted').write_text('extra\n')
        self.verify('UNEXPECTED_RELEASE_FILE')

    def test_extra_hidden_file(self):
        (self.release / '.unlisted').write_text('extra\n')
        self.verify('UNEXPECTED_RELEASE_FILE')

    def test_subdirectory(self):
        (self.release / 'extra-directory').mkdir()
        self.verify('RELEASE_SUBDIRECTORY')

    def test_binary_symlink(self):
        self.binary.unlink()
        self.binary.symlink_to(self.rebuilt)
        self.verify('RELEASE_SYMLINK')

    def test_manifest_symlink(self):
        target = self.root / 'manifest'
        self.manifest.rename(target)
        self.manifest.symlink_to(target)
        self.verify('RELEASE_SYMLINK')

    def test_fifo(self):
        os.mkfifo(self.release / 'extra-fifo', 0o600)
        self.verify('RELEASE_NON_REGULAR_FILE')

    # Neighboring required-path variants must refuse before any read can block.
    def test_binary_fifo(self):
        self.binary.unlink()
        os.mkfifo(self.binary, 0o600)
        self.verify('RELEASE_NON_REGULAR_FILE')

    def test_binary_directory(self):
        self.binary.unlink()
        self.binary.mkdir()
        self.verify('RELEASE_SUBDIRECTORY')

    def test_signature_symlink(self):
        signature = self.manifest.with_suffix('.sig')
        target = self.root / 'signature'
        signature.rename(target)
        signature.symlink_to(target)
        self.verify('RELEASE_SYMLINK')

    def test_tampered_binary(self):
        self.binary.write_bytes(b'tampered\n')
        self.verify('BINARY_SHA256')

    def test_tampered_sha256sums(self):
        self.manifest.write_text('0' * 64 + '  notary-service-linux-amd64\n')
        self.verify('MANIFEST_SIGNATURE')

    def test_wrong_namespace(self):
        self.sign_manifest('wrong-namespace')
        self.verify('MANIFEST_SIGNATURE')

    def test_wrong_signer(self):
        self.verify('MANIFEST_SIGNATURE', signer='wrong-signer')

    def test_wrong_signing_key(self):
        other = self.root / 'other'
        self.command('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(other))
        self.manifest.with_suffix('.sig').unlink()
        self.command('ssh-keygen', '-Y', 'sign', '-f', str(other),
                     '-n', 'swarma-release', str(self.manifest))
        self.verify('MANIFEST_SIGNATURE')

    def test_signed_malformed_manifest(self):
        valid = self.manifest.read_bytes()
        for malformed in [valid + b'\n', valid[:-1], valid[:-1] + b'\x00\n']:
            with self.subTest(size=len(malformed)):
                self.manifest.write_bytes(malformed)
                self.sign_manifest()
                self.verify('MANIFEST_FORMAT')
        self.manifest.write_bytes(valid)
        self.sign_manifest()
        self.verify()

    def test_missing_signature(self):
        self.manifest.with_suffix('.sig').unlink()
        self.verify('MISSING_SIGNATURE')

    # Tag authentication, exact target, rebuild and manifest paths are independent gates.
    def test_unsigned_tag(self):
        self.command('git', 'tag', '-d', TAG)
        self.command('git', 'tag', TAG)
        self.verify('TAG_SIGNATURE')

    def test_wrong_tag_commit(self):
        self.verify('TAG_COMMIT', commit='0' * 40)

    def test_wrong_tag_key(self):
        other = self.root / 'other'
        self.command('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(other))
        self.command('git', 'tag', '-d', TAG)
        self.command('git', '-c', 'user.signingkey=' + str(other), 'tag', '-s', TAG, '-m', 'wrong key')
        self.verify('TAG_SIGNATURE')

    def test_wrong_rebuild(self):
        self.rebuilt.write_bytes(b'wrong rebuild\n')
        self.verify('REBUILD_SHA256')

    def test_signed_foreign_manifest_path(self):
        self.manifest.write_text(hashlib.sha256(self.binary.read_bytes()).hexdigest()
                                 + '  ../outside\n')
        self.sign_manifest()
        self.verify('MANIFEST_FORMAT')

    # Read failures must remain named verdicts, with no raw tool diagnostics.
    def test_unreadable_manifest(self):
        self.manifest.chmod(0)
        try:
            self.verify('MANIFEST_SIGNATURE')
        finally:
            self.manifest.chmod(0o600)
        self.verify()

    def test_unreadable_binary(self):
        self.binary.chmod(0)
        try:
            self.verify('BINARY_SHA256')
        finally:
            self.binary.chmod(0o600)
        self.verify()

    def test_missing_files(self):
        for path, verdict in [(self.binary, 'MISSING_BINARY'),
                              (self.manifest, 'MISSING_SHA256SUMS'),
                              (self.rebuilt, 'MISSING_REBUILD'),
                              (self.allowed, 'MISSING_MANIFEST_ALLOWED_SIGNERS'),
                              (self.tag_allowed, 'MISSING_TAG_ALLOWED_SIGNERS')]:
            with self.subTest(verdict=verdict):
                original = path.read_bytes()
                path.unlink()
                self.verify(verdict)
                path.write_bytes(original)
        self.verify()


if __name__ == '__main__':
    unittest.main(verbosity=2)
