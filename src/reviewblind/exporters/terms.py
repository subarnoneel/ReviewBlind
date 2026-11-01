"""Term lists for anonymization proxies, built from a JSON report. See docs/CLI.md.

A report is untrusted input (threat T-14). It is checked against the schema, and its values are only
ever treated as data.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from reviewblind.utils.files import decode_text, read_limited
from reviewblind.utils.text import sanitize_text

SUPPORTED_SCHEMA_VERSION = 1
MAX_REPORT_BYTES = 256 * 1024 * 1024

_URL_RULES = frozenset({"RB105", "RB203", "RB204"})
_REGEX_SYNTAX = re.compile(r"[\\^$.|?*+()\[\]{}]")


class ReportError(ValueError):
    """The file is not a report this version can read. The message is safe to show."""


class TermFormat(StrEnum):
    ANONYMOUS_GITHUB = "anonymous-github"
    HIDO = "hido"
    PLAIN = "plain"


@dataclass(frozen=True)
class ExportSource:
    terms: tuple[str, ...]
    complete: bool


def _object(value: object, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReportError(f"malformed report: {where} must be an object")
    return value


def _array(value: object, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReportError(f"malformed report: {where} must be an array")
    return value


def _boolean(value: object, where: str) -> bool:
    if not isinstance(value, bool):
        raise ReportError(f"malformed report: {where} must be true or false")
    return value


def _term(value: object, where: str) -> str:
    # A line break would split one term into two, and the list is read one term per line.
    if not isinstance(value, str) or not value.strip() or sanitize_text(value) != value:
        raise ReportError(f"malformed report: {where} is not a usable term")
    return value.strip()


def _check_version(document: dict[str, Any]) -> None:
    version = document.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ReportError("malformed report: schema_version must be an integer")
    if version != SUPPORTED_SCHEMA_VERSION:
        raise ReportError(
            f"unsupported schema_version {version}. "
            f"This version of ReviewBlind reads version {SUPPORTED_SCHEMA_VERSION}."
        )
    if _object(document.get("tool"), "tool").get("name") != "reviewblind":
        raise ReportError("not a ReviewBlind scan report")


def _collect_terms(document: dict[str, Any]) -> list[str]:
    terms = []
    for index, item in enumerate(_array(document.get("identities"), "identities")):
        where = f"identities[{index}]"
        identity = _object(item, where)
        if _boolean(identity.get("confirmed"), f"{where}.confirmed"):
            terms.append(_term(identity.get("value"), f"{where}.value"))
    for index, item in enumerate(_array(document.get("findings"), "findings")):
        where = f"findings[{index}]"
        finding = _object(item, where)
        # A finding with no identity is an unconfirmed namespace, which may be someone else's.
        if finding.get("rule_id") in _URL_RULES and finding.get("identity") is not None:
            terms.append(_term(finding.get("matched"), f"{where}.matched"))
    return terms


def _longest_first(terms: Iterable[str]) -> tuple[str, ...]:
    kept: dict[str, str] = {}
    for term in sorted(terms, key=lambda item: (-len(item), item)):
        kept.setdefault(term.casefold(), term)
    return tuple(kept.values())


def parse_report(content: bytes) -> ExportSource:
    """The terms in a report, or `ReportError`. An empty list would look like a finished job."""
    try:
        parsed = json.loads(decode_text(content))
    except (ValueError, RecursionError) as error:
        raise ReportError("not a JSON report") from error
    document = _object(parsed, "the report")
    _check_version(document)
    complete = _boolean(_object(document.get("scan"), "scan").get("complete"), "scan.complete")
    terms = _longest_first(_collect_terms(document))
    if not terms:
        raise ReportError("the report has no confirmed identities, so there is nothing to export")
    return ExportSource(terms, complete)


def read_report(path: Path) -> ExportSource:
    try:
        content = read_limited(path, MAX_REPORT_BYTES)
    except OSError as error:
        raise ReportError(f"cannot read {path}: {error.strerror or error}") from error
    if content is None:
        raise ReportError(f"{path} is too large to be a report")
    return parse_report(content)


def _for_anonymous_github(term: str) -> str:
    # Each entry is compiled as a regular expression, and `term=>replacement` sets its own mask, so
    # an unescaped `=>` would cut the term short and write the rest of it into the output.
    return _REGEX_SYNTAX.sub(r"\\\g<0>", term).replace("=>", "=\\>")


def render_terms(terms: Iterable[str], term_format: TermFormat) -> str:
    """One term per line, with LF endings, since Anonymous GitHub splits its input on LF alone."""
    if term_format is TermFormat.ANONYMOUS_GITHUB:
        terms = map(_for_anonymous_github, terms)
    return "".join(f"{term}\n" for term in terms)
