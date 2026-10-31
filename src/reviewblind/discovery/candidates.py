"""Turns individual observations into ranked identity candidates. See docs/CLI.md."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from reviewblind.models import Confidence, IdentityKind
from reviewblind.utils.text import comparison_key, sanitize_text

MAX_VALUE_LENGTH = 200

_KIND_ORDER = list(IdentityKind)
_MINOR_WORDS = frozenset({"a", "an", "and", "at", "de", "for", "in", "of", "the"})
_WORD = re.compile(r"[^\W\d_]+")


class SourceClass(Enum):
    """Where evidence came from. Agreement between classes raises confidence."""

    GIT_HISTORY = "GIT_HISTORY"
    GIT_REMOTE = "GIT_REMOTE"
    MANIFEST = "MANIFEST"
    LATEX = "LATEX"
    ENVIRONMENT = "ENVIRONMENT"
    DERIVED = "DERIVED"


@dataclass(frozen=True)
class Observation:
    value: str
    kind: IdentityKind
    confidence: Confidence
    source: str  # what a person reads, such as `pyproject.toml author`
    source_class: SourceClass
    guess: bool = False  # inferred from other evidence, such as an email's local part


@dataclass(frozen=True)
class Candidate:
    value: str
    kind: IdentityKind
    confidence: Confidence
    sources: tuple[str, ...]


def person_kind(value: str) -> IdentityKind:
    """A one-word author is usually a handle, such as a Git `user.name` of `aliceexample`."""
    return IdentityKind.NAME if " " in value.strip() else IdentityKind.USERNAME


def _raised(confidence: Confidence) -> Confidence:
    return Confidence.HIGH if confidence is not Confidence.LOW else Confidence.MEDIUM


def _is_corroborated(group: list[Observation]) -> bool:
    """Two independent classes agree. A guess can support evidence but cannot be the only kind."""
    solid = {item.source_class for item in group if not item.guess}
    guesses = {item.source_class for item in group if item.guess}
    return len(solid) >= 2 or (bool(solid) and bool(guesses - solid))


def merge(observations: Iterable[Observation]) -> list[Candidate]:
    """Combine observations of one identity. Two source classes raise confidence by one level.

    Values come from files that may be hostile, so they are cleaned before anything shows or
    stores them, and absurdly long ones are dropped.
    """
    groups: dict[tuple[IdentityKind, str], list[Observation]] = {}
    for observation in observations:
        value = sanitize_text(observation.value).strip()
        key = comparison_key(value)
        if key and len(value) <= MAX_VALUE_LENGTH:
            clean = Observation(
                value,
                observation.kind,
                observation.confidence,
                observation.source,
                observation.source_class,
                observation.guess,
            )
            groups.setdefault((observation.kind, key), []).append(clean)

    candidates = []
    for (kind, _key), group in groups.items():
        best = max(group, key=lambda item: item.confidence)
        confidence = _raised(best.confidence) if _is_corroborated(group) else best.confidence
        sources = tuple(dict.fromkeys(item.source for item in group))
        candidates.append(Candidate(best.value, kind, confidence, sources))
    candidates.sort(
        key=lambda item: (
            item.confidence.rank,
            _KIND_ORDER.index(item.kind),
            comparison_key(item.value),
        )
    )
    return candidates


def _without_diacritics(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value)
    return "".join(char for char in decomposed if unicodedata.category(char)[0] != "M")


def _name_aliases(name: str) -> Iterable[str]:
    words = name.split()
    if len(words) >= 2:
        given, family = words[0], words[-1]
        yield f"{given[0]}. {family}"
        yield f"{family}, {given}"
        yield f"{family}, {given[0]}."
    folded = _without_diacritics(name)
    if folded != name:
        yield folded


def _acronym(affiliation: str) -> str | None:
    words = [word for word in _WORD.findall(affiliation) if word.lower() not in _MINOR_WORDS]
    if len(words) < 2:
        return None
    acronym = "".join(word[0] for word in words).upper()
    return acronym if acronym.isascii() else None


def derived_aliases(candidates: Iterable[Candidate]) -> list[Observation]:
    """Other forms of a name or institution. They need a person's confirmation, so they stay LOW."""
    derived: list[Observation] = []
    for candidate in candidates:
        if candidate.kind is IdentityKind.NAME and candidate.confidence is Confidence.HIGH:
            aliases = list(_name_aliases(candidate.value))
        elif candidate.kind is IdentityKind.AFFILIATION:
            acronym = _acronym(candidate.value)
            aliases = [acronym] if acronym else []
        else:
            aliases = []
        derived.extend(
            Observation(
                alias,
                IdentityKind.ALIAS,
                Confidence.LOW,
                f'derived alias of "{candidate.value}"',
                SourceClass.DERIVED,
            )
            for alias in aliases
        )
    return derived
