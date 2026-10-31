"""Identity candidates from the manifests at the top of a repository."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from reviewblind.discovery.candidates import Observation, SourceClass, person_kind
from reviewblind.discovery.git import email_local_part
from reviewblind.models import Confidence, IdentityKind
from reviewblind.scanners.manifests import (
    PARSE_FAILURES,
    FieldKind,
    ManifestField,
    is_placeholder,
    parser_for,
)
from reviewblind.signals import namespace_owner

_INDEX = re.compile(r"\[\d+\]")
_STRUCTURED_FILES = frozenset(
    {"pyproject.toml", "package.json", "setup.py", "setup.cfg", "citation.cff"}
)


def _url_label(name: str, where: str) -> str:
    """Such as `pyproject.toml repository URL`, from a field like `project.urls.Repository`."""
    parts = [part for part in _INDEX.sub("", where).split(".") if part.lower() != "url"]
    return f"{name} {parts[-1].lower()} URL" if parts else f"{name} URL"


def _person_label(name: str, where: str, structured: bool) -> str:
    if not structured:
        return f"{name} copyright holder" if where.startswith("copyright") else f"{name} file"
    return f"{name} maintainer" if "maintainer" in where else f"{name} author"


def _observe(name: str, field: ManifestField) -> Iterator[Observation]:
    structured = name.lower() in _STRUCTURED_FILES
    # A license may name someone other than the authors, such as the project it was forked from.
    strength = Confidence.HIGH if structured else Confidence.MEDIUM
    if field.kind is FieldKind.PERSON:
        label = _person_label(name, field.where, structured)
        yield Observation(
            field.value, person_kind(field.value), strength, label, SourceClass.MANIFEST
        )
    elif field.kind is FieldKind.EMAIL:
        yield Observation(
            field.value,
            IdentityKind.EMAIL,
            strength,
            f"{name} author email",
            SourceClass.MANIFEST,
        )
        local = email_local_part(field.value, SourceClass.MANIFEST)
        if local is not None:
            yield local
    elif field.kind is FieldKind.AFFILIATION:
        yield Observation(
            field.value,
            IdentityKind.AFFILIATION,
            Confidence.MEDIUM,
            f"{name} affiliation",
            SourceClass.MANIFEST,
        )
    else:
        owner = namespace_owner(field.value)
        yield Observation(
            owner or field.value,
            IdentityKind.USERNAME if owner else IdentityKind.URL,
            Confidence.MEDIUM,
            _url_label(name, field.where),
            SourceClass.MANIFEST,
        )


def from_manifest(name: str, text: str) -> tuple[list[Observation], list[str]]:
    """Observations from one manifest, and a note if it could not be parsed."""
    parser, _rules = parser_for(name)
    fields: Iterable[ManifestField]
    try:
        fields = list(parser(text))
    except PARSE_FAILURES as error:
        return [], [f"{name} could not be parsed: {type(error).__name__}"]
    observations = [
        observation
        for field in fields
        if not is_placeholder(field)
        for observation in _observe(name, field)
    ]
    return observations, []
