#!/usr/bin/env python3
"""Reject non-example Matrix IDs in tracked file names and contents.

This is a bounded publication check, not a general secret scanner. Decode up to
four URL/JSON/HTML escape layers and common dot/colon/at obfuscations. Arbitrary
encryption, source-expression evaluation and Git history are outside its scope.
"""
import argparse
import hashlib
import html
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote


EXAMPLE_DOMAINS = frozenset({
    'example.invalid', 'example.test', 'example.com', 'example.org', 'example.net',
})
MXID = re.compile(r'@[A-Za-z0-9._=+/-]+:(?P<host>\[[0-9a-fA-F:.]+\]|[^\W_][\w.-]*)(?::[0-9]+)?')
URL_AUTHORITY = re.compile(r'(?:https?|wss?|ssh)://[^/\s\'"<>]*$', re.IGNORECASE)
ESCAPE = re.compile(r'\\(?:u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))')


def normalize(text):
    for _ in range(4):
        before = text
        text = unquote(html.unescape(text))
        text = ESCAPE.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), text)
        text = text.replace(r'\/', '/').replace(r'\@', '@').replace(r'\:', ':').replace(r'\.', '.')
        for old, new in (('[.]', '.'), ('(.)', '.'), ('[dot]', '.'), ('[:]', ':'), ('[@]', '@')):
            text = text.replace(old, new)
        if text == before:
            break
    return text


def violations(text):
    text = normalize(text)
    for match in MXID.finditer(text):
        # URL userinfo is not a Matrix ID; Matrix IDs in URL paths still count.
        if match.group('host').isdecimal() and URL_AUTHORITY.search(text[max(0, match.start()-2048):match.start()]):
            continue
        host = match.group('host').lower().rstrip('.')
        if host not in EXAMPLE_DOMAINS:
            yield text.count('\n', 0, match.start()) + 1


def scan(root):
    paths = subprocess.run(['git', '-C', str(root), 'ls-files', '-z'],
                           check=True, stdout=subprocess.PIPE).stdout.split(b'\0')
    found = []
    for raw in filter(None, paths):
        relative = raw.decode('utf-8', errors='surrogateescape')
        path = root / relative
        if path.is_symlink():
            raise ValueError('tracked symlink is not scanned')
        if not path.is_file():
            raise ValueError('tracked path is not a regular file')
        # Keep useful file locations, but redact identifying filenames as well.
        name_lines = list(violations(relative))
        label = 'filename-sha256=' + hashlib.sha256(raw).hexdigest() if name_lines else ascii(relative)
        for line in name_lines:
            found.append((label, 'filename', line))
        for line in violations(path.read_bytes().decode('utf-8', errors='replace')):
            found.append((label, 'content', line))
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', type=Path, default=Path('.'))
    args = parser.parse_args()
    try:
        found = scan(args.root.resolve(strict=True))
    except (OSError, ValueError, subprocess.CalledProcessError):
        print('public hygiene: scan failed', file=sys.stderr)
        return 2
    for label, kind, line in found:
        print(f'public hygiene: non-example Matrix ID in {label} {kind}, normalized line {line}', file=sys.stderr)
    if found:
        return 1
    print('public hygiene: tracked tree passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
