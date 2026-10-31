"""Reading and classifying untrusted files. Size caps are applied before any parsing."""

from __future__ import annotations

import codecs
import re
from pathlib import Path

from reviewblind.models import ArtifactKind

SNIFF_BYTES = 8192

_MANIFEST_NAMES = frozenset(
    {"pyproject.toml", "package.json", "setup.py", "setup.cfg", "citation.cff"}
)
_LEGAL_NAME = re.compile(r"(?:licen[cs]e|notice|copying|authors)(?:[._-].*)?", re.IGNORECASE)
_KIND_BY_EXTENSION = {
    ".ipynb": ArtifactKind.NOTEBOOK,
    ".pdf": ArtifactKind.PDF,
    ".png": ArtifactKind.IMAGE,
    ".jpg": ArtifactKind.IMAGE,
    ".jpeg": ArtifactKind.IMAGE,
    ".tif": ArtifactKind.IMAGE,
    ".tiff": ArtifactKind.IMAGE,
    ".webp": ArtifactKind.IMAGE,
    ".gif": ArtifactKind.IMAGE,
    ".bmp": ArtifactKind.IMAGE,
    ".zip": ArtifactKind.ARCHIVE,
    ".tar": ArtifactKind.ARCHIVE,
    ".gz": ArtifactKind.ARCHIVE,
    ".tgz": ArtifactKind.ARCHIVE,
    ".bz2": ArtifactKind.ARCHIVE,
    ".xz": ArtifactKind.ARCHIVE,
    ".7z": ArtifactKind.ARCHIVE,
    ".rar": ArtifactKind.ARCHIVE,
}
_BOMS = (
    # Longest first: the UTF-32 LE mark begins with the UTF-16 LE mark.
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


def _encoding_from_bom(head: bytes) -> str | None:
    for bom, encoding in _BOMS:
        if head.startswith(bom):
            return encoding
    return None


def looks_like_text(head: bytes) -> bool:
    """Whether the first bytes of a file look like text in an encoding we can read."""
    encoding = _encoding_from_bom(head)
    if encoding is not None:
        decoder = codecs.getincrementaldecoder(encoding)()
    elif b"\0" in head:
        return False
    else:
        decoder = codecs.getincrementaldecoder("utf-8")()
    try:
        # Not final: the sample may end partway through a multi-byte character.
        decoder.decode(head, final=False)
    except UnicodeDecodeError:
        return False
    return True


def classify(relpath: str, head: bytes) -> ArtifactKind:
    """Filename first, then extension, then content."""
    name = relpath.rsplit("/", 1)[-1]
    if name.lower() in _MANIFEST_NAMES or _LEGAL_NAME.fullmatch(name):
        return ArtifactKind.MANIFEST
    extension = name[name.rfind(".") :].lower() if "." in name else ""
    if extension in _KIND_BY_EXTENSION:
        return _KIND_BY_EXTENSION[extension]
    return ArtifactKind.TEXT if looks_like_text(head) else ArtifactKind.BINARY


def read_head(path: Path) -> bytes:
    with path.open("rb") as file:
        return file.read(SNIFF_BYTES)


def read_limited(path: Path, limit: int) -> bytes | None:
    """The whole file, or `None` if it is larger than `limit`, however large it claims to be."""
    with path.open("rb") as file:
        content = file.read(limit + 1)
    return None if len(content) > limit else content


def decode_text(content: bytes) -> str:
    """Decode file content. Raises `UnicodeDecodeError` if it is not valid text."""
    return content.decode(_encoding_from_bom(content[:4]) or "utf-8")
