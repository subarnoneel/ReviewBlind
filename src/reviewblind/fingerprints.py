"""Stable finding fingerprints. See docs/ARCHITECTURE.md, section 7."""

from __future__ import annotations

import hashlib
import unicodedata

from reviewblind.utils.text import comparison_key

PREFIX = "rb1:"


def fingerprint(rule_id: str, path: str, matched: str) -> str:
    """Identify a leak independently of its line number, target and surrounding text.

    Fields are separated by NUL so that different fields can never produce the same input.
    """
    normalized_path = unicodedata.normalize("NFC", path.replace("\\", "/"))
    payload = "\0".join((rule_id, normalized_path, comparison_key(matched)))
    return PREFIX + hashlib.sha256(payload.encode("utf-8", "surrogatepass")).hexdigest()
