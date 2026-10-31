"""Structured author and project metadata.

These files are data, whoever wrote them: `setup.py` is parsed and never run, and nothing here
imports or evaluates anything from the repository (threat T-01). Parsers check every type, because
a hostile file can put any value in any field.
"""

from __future__ import annotations

import ast
import configparser
import json
import re
import tomllib
import warnings
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

import yaml

from reviewblind.models import (
    Artifact,
    ArtifactKind,
    Detection,
    EvidenceClass,
    Location,
    SkipReason,
)
from reviewblind.scanners.base import ScanContext, confirmed_url_identity, read_text_artifact
from reviewblind.utils.text import comparison_key, excerpt, line_and_column, line_starts

MAX_ENTRIES = 1000  # authors or URLs read from one file, since aliases can repeat a list cheaply

_PERSON_WITH_EMAIL = re.compile(
    r"\s*(?P<name>[^<>()]*?)\s*(?:<(?P<email>[^<>]*)>)?\s*(?:\([^()]*\))?\s*"
)
_COPYRIGHT = re.compile(
    r"^[ \t#*/;-]*copyright[ \t]+"
    r"(?:(?:\(c\)|©)[ \t]*(?:\d{4}(?:[-,][ \t]*\d{4})*,?[ \t]+)?|\d{4}(?:[-,][ \t]*\d{4})*,?[ \t]+)"
    r"(?:by[ \t]+)?(?P<holder>[^\r\n]{2,160})",
    re.IGNORECASE | re.MULTILINE,
)
_RIGHTS_RESERVED = re.compile(r"[,.\s]*all rights reserved.*$", re.IGNORECASE)
_PLACEHOLDER_PEOPLE = frozenset(
    {
        "anonymous",
        "anonymous author",
        "anonymous authors",
        "anonymized",
        "author",
        "authors",
        "first last",
        "jane doe",
        "john doe",
        "maintainer",
        "n/a",
        "name",
        "none",
        "the authors",
        "tbd",
        "todo",
        "unknown",
        "your name",
    }
)
_PLACEHOLDER_HOLDERS = frozenset(
    {
        "free software foundation, inc.",
        "the python software foundation",
        "python software foundation",
        "the contributors",
        "contributors",
    }
)
_PLACEHOLDER_EMAIL_DOMAINS = frozenset({"example.com", "example.net", "example.org"})
_PLACEHOLDER_URL = re.compile(
    r"^(?:https?://)?(?:www\.)?(?:example\.(?:com|net|org)|localhost)(?:[/:]|$)", re.IGNORECASE
)
_LEGAL_PEOPLE_FILES = re.compile(r"(?:authors|contributors)(?:[._-].*)?", re.IGNORECASE)


class FieldKind(Enum):
    PERSON = "PERSON"
    EMAIL = "EMAIL"
    AFFILIATION = "AFFILIATION"
    URL = "URL"


@dataclass(frozen=True)
class ManifestField:
    kind: FieldKind
    value: str
    where: str  # such as `project.authors[0].name`


def _table(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _entries(value: object) -> list[Any]:
    return value[:MAX_ENTRIES] if isinstance(value, list) else []


def _field(kind: FieldKind, value: object, where: str) -> Iterator[ManifestField]:
    if isinstance(value, str) and value.strip():
        yield ManifestField(kind, value.strip(), where)


def _person_text(value: object, where: str) -> Iterator[ManifestField]:
    """Parse the common `Name <email> (url)` form."""
    if not isinstance(value, str):
        return
    match = _PERSON_WITH_EMAIL.fullmatch(value)
    if match is None:
        yield from _field(FieldKind.PERSON, value, where)
        return
    yield from _field(FieldKind.PERSON, match["name"], f"{where}.name")
    # Angle brackets also hold URLs, as in `Free Software Foundation, Inc. <https://fsf.org/>`.
    if "@" in (match["email"] or ""):
        yield from _field(FieldKind.EMAIL, match["email"], f"{where}.email")


def parse_pyproject(text: str) -> Iterator[ManifestField]:
    data = tomllib.loads(text)
    project = _table(data.get("project"))
    for key in ("authors", "maintainers"):
        for index, entry in enumerate(_entries(project.get(key))):
            person = _table(entry)
            where = f"project.{key}[{index}]"
            yield from _field(FieldKind.PERSON, person.get("name"), f"{where}.name")
            yield from _field(FieldKind.EMAIL, person.get("email"), f"{where}.email")
    for label, url in list(_table(project.get("urls")).items())[:MAX_ENTRIES]:
        yield from _field(FieldKind.URL, url, f"project.urls.{label}")
    poetry = _table(_table(data.get("tool")).get("poetry"))
    for key in ("authors", "maintainers"):
        for index, entry in enumerate(_entries(poetry.get(key))):
            yield from _person_text(entry, f"tool.poetry.{key}[{index}]")
    for key in ("homepage", "repository", "documentation"):
        yield from _field(FieldKind.URL, poetry.get(key), f"tool.poetry.{key}")


def _package_person(value: object, where: str) -> Iterator[ManifestField]:
    if isinstance(value, dict):
        yield from _field(FieldKind.PERSON, value.get("name"), f"{where}.name")
        yield from _field(FieldKind.EMAIL, value.get("email"), f"{where}.email")
        yield from _field(FieldKind.URL, value.get("url"), f"{where}.url")
    else:
        yield from _person_text(value, where)


def parse_package_json(text: str) -> Iterator[ManifestField]:
    data = _table(json.loads(text))
    yield from _package_person(data.get("author"), "author")
    for key in ("contributors", "maintainers"):
        for index, entry in enumerate(_entries(data.get(key))):
            yield from _package_person(entry, f"{key}[{index}]")
    yield from _field(FieldKind.URL, data.get("homepage"), "homepage")
    for key in ("repository", "bugs"):
        value = data.get(key)
        where = f"{key}.url" if isinstance(value, dict) else key
        yield from _field(FieldKind.URL, _table(value).get("url") or value, where)
    yield from _field(FieldKind.EMAIL, _table(data.get("bugs")).get("email"), "bugs.email")


def parse_setup_cfg(text: str) -> Iterator[ManifestField]:
    parser = configparser.RawConfigParser(strict=False)
    parser.read_string(text)
    if not parser.has_section("metadata"):
        return
    metadata = parser["metadata"]
    for key, kind in (
        ("author", FieldKind.PERSON),
        ("maintainer", FieldKind.PERSON),
        ("author_email", FieldKind.EMAIL),
        ("maintainer_email", FieldKind.EMAIL),
        ("url", FieldKind.URL),
        ("home_page", FieldKind.URL),
        ("download_url", FieldKind.URL),
    ):
        yield from _field(kind, metadata.get(key), f"metadata.{key}")
    urls = metadata.get("project_urls") or ""
    for line in urls.splitlines()[:MAX_ENTRIES]:
        label, separator, url = line.partition("=")
        if separator:
            yield from _field(FieldKind.URL, url, f"metadata.project_urls.{label.strip()}")


_SETUP_KEYWORDS = {
    "author": FieldKind.PERSON,
    "maintainer": FieldKind.PERSON,
    "author_email": FieldKind.EMAIL,
    "maintainer_email": FieldKind.EMAIL,
    "url": FieldKind.URL,
    "download_url": FieldKind.URL,
}
_MODULE_VARIABLES = {
    "__author__": FieldKind.PERSON,
    "__maintainer__": FieldKind.PERSON,
    "__email__": FieldKind.EMAIL,
    "__url__": FieldKind.URL,
}


def _literal(node: ast.expr) -> object:
    """A constant from the source, or `None`. Never evaluates anything else."""
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, RecursionError, MemoryError):
        return None


def parse_setup_py(text: str) -> Iterator[ManifestField]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # the file's own invalid escapes are not our concern
        tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in _MODULE_VARIABLES:
                    yield from _field(_MODULE_VARIABLES[target.id], _literal(node.value), target.id)
        elif isinstance(node, ast.Call):
            function = node.func
            name = (
                function.attr
                if isinstance(function, ast.Attribute)
                else getattr(function, "id", "")
            )
            if name != "setup":
                continue
            for keyword in node.keywords:
                if keyword.arg in _SETUP_KEYWORDS:
                    value = _literal(keyword.value)
                    yield from _field(_SETUP_KEYWORDS[keyword.arg], value, f"setup.{keyword.arg}")
                elif keyword.arg == "project_urls":
                    for label, url in list(_table(_literal(keyword.value)).items())[:MAX_ENTRIES]:
                        yield from _field(FieldKind.URL, url, f"setup.project_urls.{label}")


def _citation_person(entry: object, where: str) -> Iterator[ManifestField]:
    person = _table(entry)
    given = person.get("given-names")
    family = person.get("family-names")
    parts = [part for part in (given, family) if isinstance(part, str) and part.strip()]
    if parts:
        yield from _field(FieldKind.PERSON, " ".join(parts), f"{where}.name")
    yield from _field(FieldKind.PERSON, person.get("name"), f"{where}.name")
    yield from _field(FieldKind.PERSON, person.get("alias"), f"{where}.alias")
    yield from _field(FieldKind.EMAIL, person.get("email"), f"{where}.email")
    yield from _field(FieldKind.AFFILIATION, person.get("affiliation"), f"{where}.affiliation")
    yield from _field(FieldKind.URL, person.get("orcid"), f"{where}.orcid")
    yield from _field(FieldKind.URL, person.get("website"), f"{where}.website")


def parse_citation(text: str) -> Iterator[ManifestField]:
    data = _table(yaml.safe_load(text))
    for key in ("authors", "contact"):
        for index, entry in enumerate(_entries(data.get(key))):
            yield from _citation_person(entry, f"{key}[{index}]")
    preferred = _table(data.get("preferred-citation"))
    for index, entry in enumerate(_entries(preferred.get("authors"))):
        yield from _citation_person(entry, f"preferred-citation.authors[{index}]")
    for key in ("repository-code", "repository", "repository-artifact", "url"):
        yield from _field(FieldKind.URL, data.get(key), key)


def parse_legal(text: str) -> Iterator[ManifestField]:
    for index, match in enumerate(_COPYRIGHT.finditer(text)):
        if index >= MAX_ENTRIES:
            return
        holder = _RIGHTS_RESERVED.sub("", match["holder"]).strip()
        yield from _person_text(holder, f"copyright[{index}]")


def parse_people_file(text: str) -> Iterator[ManifestField]:
    index = 0
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith(("#", "//", "*", "=", "-")):
            yield from _person_text(stripped, f"line[{index}]")
            index += 1
            if index >= MAX_ENTRIES:
                return


_Parser = Callable[[str], Iterable[ManifestField]]
_RULES_FOR_PEOPLE_FILE = {
    FieldKind.PERSON: "RB304",
    FieldKind.EMAIL: "RB304",
    FieldKind.AFFILIATION: "RB304",
    FieldKind.URL: "RB304",
}
_RULES_FOR_PACKAGE = {
    FieldKind.PERSON: "RB301",
    FieldKind.EMAIL: "RB301",
    FieldKind.AFFILIATION: "RB302",
    FieldKind.URL: "RB302",
}
_RULES_FOR_CITATION = {
    FieldKind.PERSON: "RB303",
    FieldKind.EMAIL: "RB303",
    FieldKind.AFFILIATION: "RB303",
    FieldKind.URL: "RB302",
}
_PARSERS: dict[str, tuple[_Parser, dict[FieldKind, str]]] = {
    "pyproject.toml": (parse_pyproject, _RULES_FOR_PACKAGE),
    "package.json": (parse_package_json, _RULES_FOR_PACKAGE),
    "setup.cfg": (parse_setup_cfg, _RULES_FOR_PACKAGE),
    "setup.py": (parse_setup_py, _RULES_FOR_PACKAGE),
    "citation.cff": (parse_citation, _RULES_FOR_CITATION),
}
_PARSE_FAILURES = (ValueError, SyntaxError, RecursionError, yaml.YAMLError, configparser.Error)


def parser_for(name: str) -> tuple[_Parser, dict[FieldKind, str]]:
    """The parser and rules for a manifest's file name. Anything else is a legal or people file."""
    known = _PARSERS.get(name.lower())
    if known is not None:
        return known
    if _LEGAL_PEOPLE_FILES.fullmatch(name):
        return parse_people_file, _RULES_FOR_PEOPLE_FILE
    return parse_legal, _RULES_FOR_PEOPLE_FILE


def is_placeholder(field: ManifestField) -> bool:
    """A value that says nothing about who wrote the work, when it matches no confirmed identity."""
    key = comparison_key(field.value)
    if field.kind is FieldKind.URL:
        return _PLACEHOLDER_URL.match(field.value) is not None
    if field.kind is FieldKind.EMAIL:
        return key.rpartition("@")[2] in _PLACEHOLDER_EMAIL_DOMAINS
    if "[" in field.value or "<" in field.value or "{" in field.value:
        return True  # a template, such as `[name of copyright owner]`
    return key in _PLACEHOLDER_PEOPLE or key in _PLACEHOLDER_HOLDERS


class ManifestScanner:
    name = "manifests"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.kind is ArtifactKind.MANIFEST

    def scan(self, artifact: Artifact, context: ScanContext) -> Iterable[Detection]:
        text = read_text_artifact(artifact, context)
        if text is None:
            return []
        parser, rules = parser_for(artifact.relpath.rsplit("/", 1)[-1])
        try:
            fields = list(parser(text))
        except _PARSE_FAILURES as error:
            context.report_skip(artifact.relpath, SkipReason.CORRUPT, type(error).__name__)
            return []
        return self._detections(artifact.relpath, text, fields, rules, context)

    @staticmethod
    def _identity(field: ManifestField, context: ScanContext) -> str | None:
        if field.kind is FieldKind.URL:
            return confirmed_url_identity(field.value, context)
        matches = context.matcher.find(field.value)
        longest = max(matches, key=lambda match: match.end - match.start, default=None)
        return None if longest is None else longest.identity.value

    def _detections(
        self,
        relpath: str,
        text: str,
        fields: list[ManifestField],
        rules: dict[FieldKind, str],
        context: ScanContext,
    ) -> Iterator[Detection]:
        starts = line_starts(text)
        cursors: dict[str, int] = {}
        for field in fields:
            identity = self._identity(field, context)
            if identity is None and is_placeholder(field):
                continue
            kind = (
                EvidenceClass.INDIRECT
                if field.kind is FieldKind.AFFILIATION
                else EvidenceClass.DIRECT
            )
            located_by_field = Detection(
                rule_id=rules[field.kind],
                artifact=relpath,
                location=Location(relpath, field=field.where),
                matched=field.value,
                evidence=field.value,
                message="Found identifying metadata",
                identity=identity,
                evidence_class=kind,
            )
            # The raw text gives the line and span, so this finding can replace a plainer text
            # match of the same value. An escaped value may not be found, and then its field
            # name locates it instead.
            start = text.find(field.value, cursors.get(field.value, 0))
            if start == -1:
                yield located_by_field
                continue
            end = start + len(field.value)
            cursors[field.value] = end
            line, column = line_and_column(starts, start)
            yield replace(
                located_by_field,
                location=Location(relpath, line=line, column=column),
                evidence=excerpt(text, start, end),
                span=(start, end),
            )
