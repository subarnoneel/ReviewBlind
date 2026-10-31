"""Parses docs/RULES.md, so tests can hold the code to the specification."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from reviewblind.models import ALL_TARGETS, Confidence, Severity, Target

RULES_MD = Path(__file__).resolve().parent.parent / "docs" / "RULES.md"

_LETTERS = {
    "B": Severity.BLOCKER,
    "W": Severity.WARNING,
    "R": Severity.REVIEW,
    "I": Severity.INFO,
}
_TABLE_ROW = re.compile(
    r"^\| (?P<id>RB\d{3})(?P<container> ◆)? \| (?P<title>.+?) "
    r"\| (?P<mirror>[BWRI])(?P<mirror_mark>[†‡]?) "
    r"\| (?P<archive>[BWRI])(?P<archive_mark>[†‡]?) "
    r"\| (?P<repository>[BWRI])(?P<repository_mark>[†‡]?) "
    r"\| (?P<confidence>HIGH|MEDIUM|LOW) \| (?P<unconfirmed>.+?) \|$",
    re.MULTILINE,
)
_DETAIL = re.compile(
    r"^\*\*(?P<id>RB\d{3}) — (?P<title>.+?)\*\*(?P<container> ◆)?\n"
    r"- \*Detects:\* (?P<detects>.+)\n"
    r"- \*Why:\* (?P<why>.+)\n"
    r"- \*Fix:\* (?P<fix>.+)$",
    re.MULTILINE,
)
_POLICY = re.compile(r"([BWR]) \+ (HIGH|MEDIUM|LOW)")


@dataclass(frozen=True)
class DocUnconfirmed:
    severity: Severity
    confidence: Confidence
    targets: frozenset[Target]


@dataclass(frozen=True)
class DocRule:
    id: str
    title: str
    severity: dict[Target, Severity]
    confidence: Confidence
    container: bool
    identity_based: bool
    unconfirmed: DocUnconfirmed | None
    git_packaged: bool
    tracked: bool
    detects: str
    why: str
    fix: str


def _plain(text: str) -> str:
    return text.replace("`", "")


def _capitalized(text: str) -> str:
    plain = _plain(text)
    return plain[0].upper() + plain[1:]


def _unconfirmed(text: str) -> DocUnconfirmed | None:
    found = _POLICY.search(text)
    if found is None:
        return None
    targets = frozenset({Target.REPOSITORY}) if "`repository` only" in text else ALL_TARGETS
    return DocUnconfirmed(_LETTERS[found[1]], Confidence[found[2]], targets)


def load_rules() -> dict[str, DocRule]:
    """Every rule in the document, by ID. Details must exist for every row of the tables."""
    text = RULES_MD.read_text(encoding="utf-8")
    details = {match["id"]: match for match in _DETAIL.finditer(text)}
    rules: dict[str, DocRule] = {}
    for row in _TABLE_ROW.finditer(text):
        detail = details[row["id"]]
        marks = {row["mirror_mark"], row["archive_mark"], row["repository_mark"]}
        rules[row["id"]] = DocRule(
            id=row["id"],
            title=_plain(row["title"]),
            severity={
                Target.MIRROR: _LETTERS[row["mirror"]],
                Target.ARCHIVE: _LETTERS[row["archive"]],
                Target.REPOSITORY: _LETTERS[row["repository"]],
            },
            confidence=Confidence[row["confidence"]],
            container=row["container"] is not None,
            identity_based=row["unconfirmed"] != "n/a",
            unconfirmed=_unconfirmed(row["unconfirmed"]),
            git_packaged="\u2020" in marks,
            tracked="\u2021" in marks,
            detects=_capitalized(detail["detects"]),
            why=_capitalized(detail["why"]),
            fix=_capitalized(detail["fix"]),
        )
    return rules
