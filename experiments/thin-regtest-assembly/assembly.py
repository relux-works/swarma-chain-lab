#!/usr/bin/env python3
"""Artifact and stage admission for the thin closed-regtest composition.

This is orchestration, never a certificate, signer, transaction or watcher.
The harness plan is local execution metadata, not a product wire format.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import zipfile
from datetime import datetime

COMPONENTS = ('wrapper', 'signer', 'anchor', 'watcher')
STAGES = ('publish_names', 'issue_certificate', 'anchor_certificate_and_seal',
          'sign_request', 'verify_admit', 'spend_seal',
          'verify_mempool_refuse', 'mine_one_block', 'verify_one_block_refuse')
OWNER = '@alexis:gr.relux.works'
TARGET = 'relux-works/matrix-grants-poc-261031'
NAMES = ['id/swarma-poc-alexis', 'id/swarma-poc-ivan-agent']
MAX_BYTES = 24 * 1024 * 1024


class Refusal(Exception):
    pass


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def contained(root, relative):
    root = Path(root).resolve(strict=True)
    p = Path(relative)
    if p.is_absolute() or '..' in p.parts or not p.parts:
        raise Refusal('unsafe artifact path')
    target = root / p
    if any(part.is_symlink() for part in [target, *target.parents] if part != root.parent):
        raise Refusal('symlink artifact')
    if not target.resolve(strict=True).is_relative_to(root) or not target.is_file():
        raise Refusal('artifact is not a contained regular file')
    return target


def canonical_h1(archive):
    """Go dirhash.HashZip: hash sorted filename/hash records, not ZIP bytes."""
    records = []
    with zipfile.ZipFile(archive) as z:
        names = [n for n in z.namelist() if not n.endswith('/')]
        if len(names) != len(set(names)):
            raise Refusal('duplicate module ZIP entry')
        if len(names) > 100000 or sum(i.file_size for i in z.infolist()) > 256*1024*1024:
            raise Refusal('module ZIP bound')
        for name in sorted(names):
            if '\n' in name or '\r' in name or name.startswith('/') or '..' in Path(name).parts:
                raise Refusal('unsafe module ZIP name')
            digest = hashlib.sha256(z.read(name)).hexdigest()
            records.append(digest + '  ' + name + '\n')
    return 'h1:' + base64.b64encode(hashlib.sha256(''.join(records).encode()).digest()).decode()


def verify_candidate(root, c, entries):
    bundle = c.get('bundle', 'source/signed-candidate.bundle')
    if bundle not in entries:
        raise Refusal('signed candidate bundle is not sealed')
    public = Path('/inputs/public-signing.pub')
    check = subprocess.run(['ssh-keygen', '-lf', str(public)], capture_output=True, text=True, timeout=5)
    if check.returncode or 'SHA256:+8CC4oJ0iYApdxtBAFOfp7x1wry/GONh0Gn75d4CG/U' not in check.stdout:
        raise Refusal('unexpected candidate signing selector')
    with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as temp:
        temp = Path(temp)
        allowed = temp/'allowed_signers'
        allowed.write_text('reluxzion ' + public.read_text())
        repo = temp/'repo'
        def git(*argv):
            r = subprocess.run(['git', *argv], env={**os.environ, 'GIT_CONFIG_NOSYSTEM':'1',
                               'GIT_CONFIG_GLOBAL':'/dev/null'}, capture_output=True, text=True, timeout=15)
            if r.returncode:
                raise Refusal('candidate Git verification failed')
            return r.stdout.strip()
        git('clone', '--no-checkout', str(contained(root, bundle)), str(repo))
        if git('-C', str(repo), 'rev-parse', c['head']+'^{commit}') != c['head']:
            raise Refusal('candidate head mismatch')
        if git('-C', str(repo), 'rev-parse', c['head']+'^{tree}') != c['tree']:
            raise Refusal('candidate tree mismatch')
        git('-C', str(repo), '-c', 'gpg.format=ssh', '-c',
            'gpg.ssh.allowedSignersFile='+str(allowed), 'verify-commit', c['head'])


def admit(plan, now=None, candidate_verifier=verify_candidate, acceptance=None):
    now = time.time() if now is None else now
    errors, verified = [], []
    if acceptance is None:
        errors.append({'component': 'composition', 'reason': 'immutable acceptance receipt required'})
    else:
        admitted_at = datetime.fromisoformat(acceptance['at']).timestamp()
        admitted_deadline = datetime.fromisoformat(acceptance['deadline']).timestamp()
        if plan.get('accepted_at_unix') != admitted_at or plan.get('acceptance_deadline_unix') != admitted_deadline:
            errors.append({'component': 'composition', 'reason': 'immutable acceptance clock mismatch'})
    if plan.get('network') != 'regtest':
        errors.append({'component': 'composition', 'reason': 'regtest only'})
    if plan.get('owner_mxid') != OWNER or plan.get('target') != TARGET or plan.get('names') != NAMES:
        errors.append({'component': 'composition', 'reason': 'fixed identity or target mismatch'})
    if plan.get('action') != 'repository.create':
        errors.append({'component': 'composition', 'reason': 'fixed verification action mismatch'})
    if now >= plan.get('execution_deadline_unix', 0):
        errors.append({'component': 'composition', 'reason': 'execution deadline expired'})
    if plan.get('execution_deadline_unix', float('inf')) > plan.get('acceptance_deadline_unix', 0) - 120:
        errors.append({'component': 'composition', 'reason': 'export reserve missing'})
    components = plan.get('components', {})
    for name in COMPONENTS:
        c = components.get(name, {})
        # Missing hashes stay null: mutable source is never substituted for a sealed candidate.
        if not c.get('manifest_sha256') or not c.get('head') or not c.get('tree'):
            errors.append({'component': name, 'head': c.get('head'), 'tree': c.get('tree'),
                           'manifest_sha256': c.get('manifest_sha256'), 'reason': 'exact signed candidate and manifest absent'})
            continue
        try:
            root = Path(c['root'])
            manifest = contained(root, c.get('manifest', 'SHA256SUMS'))
            if sha(manifest) != c['manifest_sha256']:
                raise Refusal('manifest hash mismatch')
            count, size, entries = 0, 0, set()
            for line in manifest.read_text().splitlines():
                if len(line) < 67 or line[64:66] not in ('  ', ' *'):
                    raise Refusal('manifest syntax')
                digest, rel = line[:64], line[66:]
                if len(digest) != 64 or any(x not in '0123456789abcdef' for x in digest) or rel in entries:
                    raise Refusal('manifest digest or duplicate')
                p = contained(root, rel)
                size += p.stat().st_size
                if size > MAX_BYTES:
                    raise Refusal('component public byte bound')
                if sha(p) != digest:
                    raise Refusal('artifact hash mismatch: ' + rel)
                count += 1
                entries.add(rel)
            required = c.get('required_files', ['source-map.json', 'interface.md', 'result.json'])
            if not set(required).issubset(entries):
                raise Refusal('required artifact not sealed')
            if count == 0:
                raise Refusal('empty manifest')
            candidate_verifier(root, c, entries)
            for dep in c.get('module_zips', []):
                if canonical_h1(contained(root, dep['path'])) != dep['h1']:
                    raise Refusal('canonical module h1 mismatch')
            verified.append({'component': name, 'manifest_sha256': sha(manifest),
                             'head': c['head'], 'tree': c['tree'], 'verified_files': count})
        except (Refusal, OSError, KeyError, ValueError, zipfile.BadZipFile, subprocess.TimeoutExpired) as e:
            errors.append({'component': name, 'reason': str(e)})
    return {'status': 'READY' if not errors else 'MISSING_OR_REFUSED', 'verified': verified,
            'missing': errors, 'closed_regtest_executed': False,
            'independent_whole_review': 'PENDING', 'meta_marker': 'PENDING'}


def birth(pid):
    # /proc stat field 22, robust to spaces and ')' in the comm field.
    return Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[19]


def run_child(argv, seconds, absolute_deadline):
    """Finite task-owned child; no arbitrary PID/host-service termination."""
    if not argv or not all(isinstance(x, str) for x in argv):
        raise Refusal('argv required')
    remaining = min(seconds, absolute_deadline-time.time())
    if remaining <= 0:
        raise Refusal('deadline before child creation')
    with open(os.devnull, 'rb') as null, tempfile.TemporaryFile(dir=os.environ['TMPDIR']) as stdout, tempfile.TemporaryFile(dir=os.environ['TMPDIR']) as stderr:
        p = subprocess.Popen(argv, stdin=null, stdout=stdout, stderr=stderr,
                             env={'PATH': '/usr/bin:/bin', 'HOME': os.environ['HOME'],
                                  'TMPDIR': os.environ['TMPDIR'],
                                  'XDG_CACHE_HOME': os.environ['XDG_CACHE_HOME']},
                             close_fds=True, start_new_session=True)
        started = time.time()
        identity = birth(p.pid)
        timed_out = False
        try:
            p.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            timed_out = True
            if p.poll() is None and birth(p.pid) == identity:
                os.killpg(p.pid, signal.SIGTERM)
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                if p.poll() is None and birth(p.pid) == identity:
                    os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=2)
        if stdout.tell()+stderr.tell() > 1024*1024:
            raise Refusal('stage output bound exceeded; private output withheld')
        stdout.seek(0); stderr.seek(0)
        out, err = stdout.read(), stderr.read()
        # Caller exports only a reviewed public result; arbitrary child stdout is not published.
        return {'started_unix': started, 'finished_unix': time.time(), 'exit': p.returncode,
                'timeout': timed_out, 'pid': p.pid, 'birth': identity, 'reaped': p.poll() is not None,
                'stdout_sha256': hashlib.sha256(out).hexdigest(),
                'stderr_sha256': hashlib.sha256(err).hexdigest()}


def run_stages(plan, executor, acceptance):
    """Run the already-admitted final composition driver in causal order.

    executor is provided by a separately assembled driver using the admitted
    component interfaces. No dummy component is shipped as an E2E substitute.
    """
    check = admit(plan, acceptance=acceptance)
    if check['status'] != 'READY':
        raise Refusal('component admission failed')
    receipts = []
    for stage in STAGES:
        if time.time() >= plan['execution_deadline_unix']:
            raise Refusal('execution deadline')
        receipt = executor(stage, plan['execution_deadline_unix'])
        receipts.append({'stage': stage, **receipt})
        if receipt.get('exit') != 0 or receipt.get('timeout') or not receipt.get('reaped'):
            return {'status': 'STAGE_FAILED', 'stage_receipts': receipts,
                    'closed_regtest_completed': False}
    return {'status': 'STAGES_COMPLETED_REQUIRES_EVIDENCE_REVIEW', 'stage_receipts': receipts,
            'closed_regtest_completed': False,
            'reason': 'A stage exit alone does not prove names, signatures, chain state, custody or causal refusal.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--plan', type=Path, required=True)
    p.add_argument('--acceptance', type=Path, required=True)
    args = p.parse_args()
    result = admit(json.loads(args.plan.read_text()), acceptance=json.loads(args.acceptance.read_text()))
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'READY' else 3


if __name__ == '__main__':
    raise SystemExit(main())
