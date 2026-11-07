"""Explicit host root for a separately admitted, disposable laboratory run."""
import os
from pathlib import Path


def lab_root():
    raw = os.environ.get('NOTARY_LAB_ROOT', '')
    p = Path(raw)
    if not raw or not p.is_absolute() or p.name != 'notary-lab':
        raise ValueError('NOTARY_LAB_ROOT must be an absolute path ending in notary-lab')
    # Reject aliases, traversal and symlinks before preparation or deletion.
    if str(p) != raw or p.resolve() != p or p.is_symlink():
        raise ValueError('NOTARY_LAB_ROOT must be canonical and contain no symlinks')
    return p
