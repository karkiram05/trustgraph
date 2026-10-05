"""Bounded file reading shared by every parser.

TrustGraph is pointed at repositories it doesn't control (the real-world
evaluation scans public repos), so input files are treated as untrusted:
size-capped before they are read. Workflow and trust-policy files are small
in practice; the largest workflow in the real-world sample is under 100 KB.
"""
from __future__ import annotations

from pathlib import Path

MAX_FILE_BYTES = 1_000_000


def read_capped(path: Path) -> str:
    """Read a UTF-8 text file, refusing anything over MAX_FILE_BYTES."""
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"{path}: {size} bytes exceeds the {MAX_FILE_BYTES}-byte input limit")
    return path.read_text(encoding="utf-8")
