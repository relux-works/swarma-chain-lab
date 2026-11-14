#!/usr/bin/env python3
"""Bounded lexical guard for the reviewed detached-v2 observer-local ID surface.

New references or any changed reviewed consumer bytes require a fresh audit.
This is not semantic taint analysis; aliases, computed field names and external
consumers are not proven safe by this check. Inventory reasons document scope.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / '.scripts/detached-v2-consumers.json'
REFERENCE = re.compile(
    r'\b(?:CheckV2|PresentV2|CachedCertificateV2|ParseDetachedEnvelope|'
    r'DetachedEnvelope|DetachedCertificate|IssueDetached|issueDetached|IssueResult|'
    r'issuedDetached|detachedState|seenSeal|readPresentations|cachedPresentation|'
    r'presentationCache|CertificateSHA256)\b|certificate_sha256')


def production_paths(root):
    return sorted(p for p in root.rglob('*.go')
                  if not p.name.endswith('_test.go')
                  and not any(part in {'.git', '.temp'} for part in p.relative_to(root).parts))


def check(root, inventory):
    errors = []
    found = set()
    for path in production_paths(root):
        relative = path.relative_to(root).as_posix()
        raw = path.read_bytes()
        if REFERENCE.search(raw.decode('utf-8')) or relative in inventory:
            found.add(relative)
            entry = inventory.get(relative)
            if entry is None:
                errors.append('unreviewed detached-v2 reference: ' + relative)
            elif hashlib.sha256(raw).hexdigest() != entry['sha256']:
                errors.append('changed detached-v2 consumer: ' + relative)
    for relative in sorted(set(inventory) - found):
        errors.append('missing detached-v2 consumer: ' + relative)
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    inventory = json.loads(MANIFEST.read_text())
    errors = check(args.root.resolve(strict=True), inventory)
    for error in errors:
        print(error)
    if not errors:
        print('detached-v2 consumer inventory: reviewed observer-local surface unchanged')
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
