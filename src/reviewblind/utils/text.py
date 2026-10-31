"""Unicode normalization, offset mapping and display sanitizing."""

from __future__ import annotations

import functools
import re
import sys
import unicodedata
from bisect import bisect_right

EVIDENCE_LIMIT = 160

_NON_ASCII_RUN = re.compile(r"[^\x00-\x7f]+")
_LINE_BREAK = re.compile(r"\r\n|\r|\n")
_HANGUL_VOWELS_AND_TAILS = range(0x1160, 0x1200)
_LINE_BREAKING_CONTROLS = frozenset("\t\n\v\f\r\x1c\x1d\x1e\x85\u2028\u2029")
_JOINERS = frozenset("\u200c\u200d")  # ZWNJ and ZWJ carry meaning in Bangla and other scripts


@functools.cache
def _segment_pattern() -> re.Pattern[str]:
    """Match one character plus everything that can compose with it under NFC.

    Built from the running Python's Unicode tables, because newer versions add compositions whose
    second character is not a combining mark: Kirat Rai vowel signs are letters. Building takes a
    moment, so it happens only for text that changes length when folded.
    """
    extenders = set(_HANGUL_VOWELS_AND_TAILS)
    for code_point in range(0x80, sys.maxunicode + 1):
        char = chr(code_point)
        if unicodedata.category(char)[0] == "M":
            extenders.add(code_point)
        decomposition = unicodedata.decomposition(char).split()
        if len(decomposition) == 2 and not decomposition[0].startswith("<"):
            extenders.add(int(decomposition[1], 16))
    members = "".join(f"\\U{code_point:08x}" for code_point in sorted(extenders))
    return re.compile(f"(?s).[{members}]*")


@functools.lru_cache(maxsize=4096)
def _fold(segment: str) -> str:
    return unicodedata.normalize("NFC", unicodedata.normalize("NFC", segment).casefold())


def _fold_preserving_length(text: str) -> str | None:
    """Fold text in one step if no character changes length, otherwise return `None`.

    Each stage is checked, because a growing and a shrinking character could otherwise cancel out
    and leave the total length equal while offsets inside the text had moved.
    """
    if not unicodedata.is_normalized("NFC", text):
        return None
    casefolded = text.casefold()
    if len(casefolded) != len(text):
        return None
    folded = unicodedata.normalize("NFC", casefolded)
    return folded if len(folded) == len(text) else None


class NormalizedText:
    """NFC-casefolded text that can map its offsets back to the original.

    Normalization can change length: `ß` folds to `ss`, and `e` plus a combining accent composes
    to one character. Mapping is stored as runs, so a mostly unchanged 8 MiB file stays cheap.
    """

    __slots__ = ("_norm_starts", "_opaque", "_orig_starts", "normalized", "original")

    def __init__(self, text: str) -> None:
        self.original = text
        self._norm_starts = [0]
        self._orig_starts = [0]
        self._opaque = [False]  # True for one segment whose length changed
        if text.isascii():
            self.normalized = text.lower()
            return
        folded = _fold_preserving_length(text)
        self.normalized = self._build(text) if folded is None else folded

    def _build(self, text: str) -> str:
        parts: list[str] = []
        norm_length = 0

        def add(orig_start: int, orig_end: int, folded: str) -> None:
            nonlocal norm_length
            if len(folded) != orig_end - orig_start:
                self._start_run(norm_length, orig_start, opaque=True)
            elif self._opaque[-1]:
                self._start_run(norm_length, orig_start, opaque=False)
            parts.append(folded)
            norm_length += len(folded)

        position = 0
        for run in _NON_ASCII_RUN.finditer(text):
            start = run.start()
            # A combining mark may attach to the ASCII character before it.
            if start > position and unicodedata.category(text[start])[0] == "M":
                start -= 1
            if start > position:
                add(position, start, text[position:start].lower())
            chunk = text[start : run.end()]
            folded = _fold_preserving_length(chunk)
            if folded is not None:
                add(start, run.end(), folded)
            else:
                for segment in _segment_pattern().finditer(chunk):
                    add(start + segment.start(), start + segment.end(), _fold(segment[0]))
            position = run.end()
        if position < len(text):
            add(position, len(text), text[position:].lower())
        return "".join(parts)

    def _start_run(self, norm_start: int, orig_start: int, *, opaque: bool) -> None:
        self._norm_starts.append(norm_start)
        self._orig_starts.append(orig_start)
        self._opaque.append(opaque)

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        """Map a non-empty span of `normalized` to the matching span of `original`."""
        return self._original_start(start), self._original_end(end)

    def _original_start(self, offset: int) -> int:
        run = bisect_right(self._norm_starts, offset) - 1
        if self._opaque[run]:
            return self._orig_starts[run]
        return self._orig_starts[run] + offset - self._norm_starts[run]

    def _original_end(self, offset: int) -> int:
        run = bisect_right(self._norm_starts, offset - 1) - 1
        if self._opaque[run]:
            is_last = run + 1 == len(self._orig_starts)
            return len(self.original) if is_last else self._orig_starts[run + 1]
        return self._orig_starts[run] + offset - self._norm_starts[run]


def normalize_text(text: str) -> str:
    """NFC plus casefold, using the same segmentation as `NormalizedText`."""
    return NormalizedText(text).normalized


def comparison_key(text: str) -> str:
    """The form used to compare values: normalized, with whitespace collapsed."""
    return " ".join(normalize_text(text).split())


def line_starts(text: str) -> list[int]:
    """Offsets at which each line of `text` begins."""
    return [0, *(match.end() for match in _LINE_BREAK.finditer(text))]


def line_and_column(starts: list[int], offset: int) -> tuple[int, int]:
    """The 1-based line and column of an offset, given the result of `line_starts`."""
    line = bisect_right(starts, offset)
    return line, offset - starts[line - 1] + 1


def sanitize_text(text: str) -> str:
    """Make repository-controlled text safe to display on one line.

    Removes terminal escapes, bidirectional overrides and other invisible controls, which could
    otherwise spoof a report (threat T-10). Line-breaking controls become spaces.
    """
    if text.isprintable():
        return text
    kept: list[str] = []
    for char in text:
        if char in _LINE_BREAKING_CONTROLS:
            kept.append(" ")
        elif char in _JOINERS or unicodedata.category(char) not in {"Cc", "Cf", "Cs"}:
            kept.append(char)
    return "".join(kept)


def sanitize_evidence(text: str) -> str:
    """Sanitize text and truncate it to the display limit."""
    clean = sanitize_text(text)
    if len(clean) <= EVIDENCE_LIMIT:
        return clean
    return clean[: EVIDENCE_LIMIT - 1] + "\u2026"
