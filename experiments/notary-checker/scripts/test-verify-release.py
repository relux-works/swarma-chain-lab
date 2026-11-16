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
        for name in list(self.env):
            if name.startswith(('GIT_CONFIG_', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR',
                                'GIT_OBJECT_', 'GIT_ALTERNATE_', 'GIT_NAMESPACE')):
                self.env.pop(name, None)
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                        HOME=str(self.root / 'home'), GNUPGHOME=str(self.root / 'gnupg'))
        Path(self.env['HOME']).mkdir()
        Path(self.env['GNUPGHOME']).mkdir(mode=0o700)
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
               tag_allowed=None, manifest_allowed=None, cwd=None, script=None):
        args = [str(script or SCRIPT), str(self.repo), commit or self.commit]
        if tag is not None:
            args.append(tag)
        args.extend([str(self.release), str(self.rebuilt),
                     str(tag_allowed or self.tag_allowed),
                     str(manifest_allowed or self.allowed), signer])
        result = subprocess.run(args, cwd=cwd or self.repo, env=self.env,
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
        return result

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

    # Explicit trust wins over each ambient Git config layer, even for valid SSH tags.
    def test_ambient_only_tag_key(self):
        other = self.root / 'ambient-signer'
        self.command('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(other))
        ambient = self.root / 'ambient-allowed'
        ambient.write_text('ambient ' + other.with_suffix('.pub').read_text())
        self.command('git', 'tag', '-d', TAG)
        self.command('git', '-c', 'user.signingkey=' + str(other),
                     'tag', '-s', TAG, '-m', 'ambient only')
        original_env = self.env.copy()
        for layer in ('local', 'global', 'parameters', 'count'):
            with self.subTest(layer=layer):
                self.env = original_env.copy()
                subprocess.run(['git', 'config', '--unset-all', 'gpg.ssh.allowedSignersFile'],
                               cwd=self.repo, env=self.env, capture_output=True, check=False)
                if layer == 'local':
                    self.command('git', 'config', 'gpg.ssh.allowedSignersFile', str(ambient))
                elif layer == 'global':
                    config = self.root / 'global-config'
                    config.write_text('[gpg "ssh"]\nallowedSignersFile = ' + str(ambient) + '\n')
                    self.env['GIT_CONFIG_GLOBAL'] = str(config)
                elif layer == 'parameters':
                    self.env['GIT_CONFIG_PARAMETERS'] = "'gpg.ssh.allowedSignersFile=" + str(ambient) + "'"
                else:
                    self.env.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='gpg.ssh.allowedSignersFile',
                                    GIT_CONFIG_VALUE_0=str(ambient))
                # Positive precondition: ambient Git actually trusts this exact tag.
                self.command('git', 'verify-tag', 'refs/tags/' + TAG)
                self.verify('TAG_SIGNATURE')

    # A configured verifier executable is never launched, in any Git config layer.
    def test_ambient_verifier_program(self):
        stub = self.root / 'verifier'
        marker = self.root / 'executed'
        stub.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\nexit 0\n')
        stub.chmod(0o700)
        self.command('git', 'config', 'gpg.ssh.program', str(stub))
        self.env['GIT_CONFIG_PARAMETERS'] = "'gpg.ssh.program=" + str(stub) + "'"
        self.env.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='gpg.ssh.program',
                        GIT_CONFIG_VALUE_0=str(stub))
        self.verify()
        self.assertFalse(marker.exists())

    # Non-SSH armor cannot reach an ambient OpenPGP verifier/keyring.
    def test_non_ssh_tag_signature(self):
        raw = self.command('git', 'cat-file', 'tag', 'refs/tags/' + TAG)
        payload = raw.split('-----BEGIN SSH SIGNATURE-----')[0]
        raw = payload + '-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n'
        result = subprocess.run(['git', 'hash-object', '-t', 'tag', '-w', '--stdin'],
                                input=raw.encode(), cwd=self.repo, env=self.env,
                                capture_output=True, check=True)
        self.command('git', 'update-ref', 'refs/tags/' + TAG, result.stdout.decode().strip())
        stub = self.root / 'pgp-verifier'
        marker = self.root / 'pgp-executed'
        stub.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\n'
                        'echo "[GNUPG:] NEWSIG"\n'
                        'echo "[GNUPG:] GOODSIG 0123456789ABCDEF Fixture"\n'
                        'echo "[GNUPG:] TRUST_ULTIMATE"\nexit 0\n')
        stub.chmod(0o700)
        self.command('git', 'config', 'gpg.program', str(stub))
        self.command('git', 'config', 'gpg.openpgp.program', str(stub))
        # This controlled backend makes the fallback observable without a real keyring.
        self.command('git', 'verify-tag', 'refs/tags/' + TAG)
        self.assertTrue(marker.exists())
        marker.unlink()
        self.verify('TAG_SIGNATURE')
        self.assertFalse(marker.exists())

    # Reject caller-relative trust paths even when both cwd locations have a file.
    def test_relative_trust_path(self):
        for path, kw in ((self.tag_allowed, 'tag_allowed'), (self.allowed, 'manifest_allowed')):
            shutil.copyfile(path, self.repo / path.name)
            with self.subTest(role=kw):
                self.verify('ARGUMENTS', cwd=self.root, **{kw: Path(path.name)})

    # Parent symlinks resolve physically before all signature consumers use the path.
    def test_physical_trust_paths(self):
        alias = self.root / 'trust-alias'
        alias.symlink_to(self.root, target_is_directory=True)
        tools = self.root / 'physical-tools'
        tools.mkdir()
        calls = self.root / 'trust-paths'
        real_ssh = shutil.which('ssh-keygen')
        wrapper = tools / 'ssh-keygen'
        wrapper.write_text('#!/bin/bash\n'
                           'previous=\nfor arg in "$@"; do\n'
                           '  if [[ $previous == -f ]]; then printf "%s\\n" "$arg" >> "'
                           + str(calls) + '"; fi\n  previous=$arg\ndone\n'
                           'exec "' + real_ssh + '" "$@"\n')
        wrapper.chmod(0o700)
        self.env['PATH'] = str(tools) + os.pathsep + self.env['PATH']
        self.verify(tag_allowed=alias / self.tag_allowed.name,
                    manifest_allowed=alias / self.allowed.name)
        # Assert the exact physical filenames consumed by every SSH trust lookup.
        consumed = set(calls.read_text().splitlines())
        self.assertEqual(consumed, {str(self.tag_allowed), str(self.allowed)})

    # Canonicalization preserves the exact filename, including trailing newlines.
    def test_trust_paths_with_trailing_newline(self):
        tag_path = self.root / 'tag-trust\n'
        manifest_path = self.root / 'manifest-trust\n'
        shutil.copyfile(self.tag_allowed, tag_path)
        shutil.copyfile(self.allowed, manifest_path)
        (self.root / 'tag-trust').write_text('')
        (self.root / 'manifest-trust').write_text('')
        self.verify(tag_allowed=tag_path, manifest_allowed=manifest_path)

    # A signature over another component's name cannot authorize this release name.
    def test_wrong_signed_tag_name(self):
        other = 'component/v0.1.1'
        self.command('git', 'tag', '-s', other, '-m', 'other component')
        oid = self.command('git', 'rev-parse', 'refs/tags/' + other)
        self.command('git', 'update-ref', 'refs/tags/' + TAG, oid)
        self.verify('TAG_IDENTITY')

    # Signed tag identity is byte-exact: CR cannot be normalized out of its header.
    def test_signed_tag_name_with_carriage_return(self):
        raw = self.command('git', 'cat-file', 'tag', 'refs/tags/' + TAG)
        payload = raw.split('-----BEGIN SSH SIGNATURE-----')[0]
        payload = payload.replace('tag ' + TAG + '\n', 'tag ' + TAG + '\r\n', 1).encode()
        message = self.root / 'tag-payload'
        message.write_bytes(payload)
        self.command('ssh-keygen', '-Y', 'sign', '-f', str(self.tag_key),
                     '-n', 'git', str(message))
        raw = payload + message.with_suffix('.sig').read_bytes()
        # Inject a signed malformed object without hash-object's fsck rejection.
        result = subprocess.run(['git', 'hash-object', '--literally', '-t', 'tag', '-w', '--stdin'],
                                input=raw, cwd=self.repo, env=self.env,
                                capture_output=True, check=True)
        self.command('git', 'update-ref', 'refs/tags/' + TAG, result.stdout.decode().strip())
        self.command('git', 'verify-tag', 'refs/tags/' + TAG)
        self.verify('TAG_IDENTITY')

    # Moving a ref after resolution cannot replace the pinned object's wrong target.
    # The inverse control keeps a valid pinned object valid despite the same move.
    def test_ref_moved_after_resolution(self):
        good = self.command('git', 'rev-parse', 'refs/tags/' + TAG)
        self.command('git', 'tag', '-d', TAG)
        self.command('git', 'tag', '-s', TAG, self.commit + '^', '-m', 'wrong target')
        bad = self.command('git', 'rev-parse', 'refs/tags/' + TAG)
        real_git = shutil.which('git')
        wrappers = self.root / 'tools'
        wrappers.mkdir()
        wrapper = wrappers / 'git'
        calls = self.root / 'resolutions'
        wrapper.write_text('#!/bin/bash\n'
                           'if [[ " $* " == *" rev-parse "* ]]; then\n'
                           '  printf "resolved\\n" >> "' + str(calls) + '"\n'
                           '  "' + real_git + '" "$@" || exit $?\n'
                           '  "' + real_git + '" -C "' + str(self.repo) + '" update-ref '
                           '"refs/tags/' + TAG + '" "$(cat "' + str(self.root / 'move-to') + '")"\n'
                           'else exec "' + real_git + '" "$@"; fi\n')
        wrapper.chmod(0o700)
        self.env['PATH'] = str(wrappers) + os.pathsep + self.env['PATH']
        for initial, moved, verdict in ((bad, good, 'TAG_COMMIT'), (good, bad, None)):
            (self.root / 'move-to').write_text(moved)
            subprocess.run([real_git, '-C', str(self.repo), 'update-ref', 'refs/tags/' + TAG, initial],
                           env=self.env, check=True, capture_output=True)
            calls.unlink(missing_ok=True)
            self.verify(verdict)
            self.assertEqual(calls.read_text().splitlines(), ['resolved'])

    # Copied merged trust files make the guard load-bearing even when signatures verify.
    def merged_roles(self):
        merged = ('tag-test ' + self.tag_key.with_suffix('.pub').read_text()
                  + 'release-test ' + self.key.with_suffix('.pub').read_text())
        self.tag_allowed.write_text(merged)
        self.allowed.write_text(merged)
        self.manifest.with_suffix('.sig').unlink()
        self.command('ssh-keygen', '-Y', 'sign', '-f', str(self.tag_key),
                     '-n', 'swarma-release', str(self.manifest))

    def test_merged_signer_roles(self):
        self.merged_roles()
        self.verify('SIGNER_ROLE_SEPARATION', signer='tag-test')

    # Removing only the separation guard makes the exact forbidden fixture succeed.
    def test_role_separation_mutant(self):
        self.merged_roles()
        self.verify('SIGNER_ROLE_SEPARATION', signer='tag-test')
        source = SCRIPT.read_text()
        start = '# BEGIN SIGNER_ROLE_SEPARATION\n'
        end = '# END SIGNER_ROLE_SEPARATION\n'
        self.assertEqual(source.count(start), 1)
        self.assertEqual(source.count(end), 1)
        first = source.index(start)
        last = source.index(end, first) + len(end)
        mutant = self.root / 'mutant.sh'
        mutant.write_text(source[:first] + source[last:])
        mutant.chmod(0o700)
        self.verify(signer='tag-test', script=mutant)

    # The downloaded inode cannot stand in for an independent build, even via hardlink.
    def test_download_as_rebuild(self):
        self.rebuilt = self.binary
        self.verify('ARGUMENTS')

    def test_download_hardlink_as_rebuild(self):
        self.rebuilt.unlink()
        self.rebuilt.hardlink_to(self.binary)
        self.verify('ARGUMENTS')

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
