"""Exact, boundary-aware matching of confirmed identities. There is no fuzzy matching."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TypeVar

from reviewblind.models import EvidenceClass, Identity, IdentityKind, Severity
from reviewblind.utils.text import NormalizedText, line_and_column, line_starts, normalize_text

T = TypeVar("T")

ACRONYM_MAX_LENGTH = 5

# Scripts written without spaces between words, where a neighbouring letter is not a boundary.
_UNSPACED_RANGES = (
    range(0x0E00, 0x0E80),  # Thai
    range(0x1100, 0x1200),  # Hangul Jamo
    range(0x3040, 0x3100),  # Hiragana and Katakana
    range(0x3130, 0x3190),  # Hangul compatibility Jamo
    range(0x31F0, 0x3200),  # Katakana extension
    range(0x3400, 0x4DC0),  # CJK extension A
    range(0x4E00, 0xA000),  # CJK unified
    range(0xAC00, 0xD7B0),  # Hangul syllables
    range(0xF900, 0xFB00),  # CJK compatibility
    range(0xFF66, 0xFFA0),  # Halfwidth Katakana
    range(0x20000, 0x32400),  # CJK extensions B and later
)


def is_acronym(value: str) -> bool:
    """A short, all-uppercase value such as `EU`. See "Evidence classes" in docs/RULES.md."""
    return len(value) <= ACRONYM_MAX_LENGTH and value.isalpha() and value.isupper()


def _is_word_char(char: str) -> bool:
    return unicodedata.category(char)[0] in {"L", "M", "N"}


def _is_unspaced(char: str) -> bool:
    return any(ord(char) in script for script in _UNSPACED_RANGES)


@dataclass(frozen=True)
class IdentityMatch:
    identity: Identity
    start: int  # offsets into the original text
    end: int
    matched: str  # the original text, exactly as written
    line: int
    column: int
    evidence_class: EvidenceClass


@dataclass(frozen=True)
class _Needle:
    identity: Identity
    pattern: re.Pattern[str]
    check_before: bool
    check_after: bool
    acronym: bool


def _compile(identity: Identity) -> _Needle:
    tokens = normalize_text(identity.value).split()
    if not tokens:
        raise ValueError("an identity must contain text other than whitespace")
    acronym = identity.kind in {IdentityKind.AFFILIATION, IdentityKind.ALIAS} and is_acronym(
        identity.value
    )
    return _Needle(
        identity=identity,
        pattern=re.compile(r"\s+".join(re.escape(token) for token in tokens)),
        check_before=not _is_unspaced(tokens[0][0]),
        check_after=not _is_unspaced(tokens[-1][-1]),
        acronym=acronym,
    )


def _evidence_class(needle: _Needle, matched: str) -> EvidenceClass:
    if needle.acronym:
        same_case = unicodedata.normalize("NFC", matched) == unicodedata.normalize(
            "NFC", needle.identity.value
        )
        return EvidenceClass.ACRONYM if same_case else EvidenceClass.AMBIGUOUS
    if needle.identity.kind is IdentityKind.AFFILIATION:
        return EvidenceClass.INDIRECT
    return EvidenceClass.DIRECT


class IdentityMatcher:
    """Finds every occurrence of a set of identities in text.

    Each identity is searched for separately, so a longer identity failing its boundary check
    cannot hide a shorter one at the same position. Patterns contain only escaped literals and
    `\\s+`, so matching cannot backtrack catastrophically (threat T-08).
    """

    def __init__(self, identities: Iterable[Identity]) -> None:
        needles: dict[str, _Needle] = {}
        for identity in identities:
            needles.setdefault(" ".join(normalize_text(identity.value).split()), _compile(identity))
        self._needles = tuple(needles.values())

    def find(self, text: str) -> list[IdentityMatch]:
        """All matches, ordered by position. Overlaps are kept: see `resolve_overlaps`."""
        index = NormalizedText(text)
        starts = line_starts(text)
        matches: list[IdentityMatch] = []
        for needle in self._needles:
            for norm_start, norm_end in self._spans(needle, index.normalized):
                start, end = index.original_span(norm_start, norm_end)
                line, column = line_and_column(starts, start)
                matched = text[start:end]
                matches.append(
                    IdentityMatch(
                        identity=needle.identity,
                        start=start,
                        end=end,
                        matched=matched,
                        line=line,
                        column=column,
                        evidence_class=_evidence_class(needle, matched),
                    )
                )
        matches.sort(key=lambda match: (match.start, -match.end, match.identity.value))
        return matches

    @staticmethod
    def _spans(needle: _Needle, normalized: str) -> Iterable[tuple[int, int]]:
        position = 0
        while found := needle.pattern.search(normalized, position):
            start, end = found.span()
            blocked_before = (
                needle.check_before and start > 0 and _is_word_char(normalized[start - 1])
            )
            blocked_after = (
                needle.check_after and end < len(normalized) and _is_word_char(normalized[end])
            )
            if blocked_before or blocked_after:
                position = start + 1
            else:
                yield start, end
                position = end


def resolve_overlaps(
    items: Iterable[T],
    span: Callable[[T], tuple[int, int]],
    severity: Callable[[T], Severity],
    rule_id: Callable[[T], str],
) -> list[T]:
    """Drop every item whose span lies inside another item's span.

    The longest span wins, then the higher severity, then the lower rule ID. Spans that only
    partly overlap both survive, because each may be a separate leak.
    """

    def priority(item: T) -> tuple[int, int, int, str]:
        start, end = span(item)
        return start, -(end - start), severity(item).rank, rule_id(item)

    kept: list[T] = []
    furthest_end = -1
    for item in sorted(items, key=priority):
        end = span(item)[1]
        if end > furthest_end:
            kept.append(item)
            furthest_end = end
    return kept
