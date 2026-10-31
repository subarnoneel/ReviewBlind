"""Identity candidates from common LaTeX author macros. Read as text, and never compiled."""

from __future__ import annotations

import re
from collections.abc import Iterator

from reviewblind.discovery.candidates import Observation, SourceClass, person_kind
from reviewblind.discovery.git import email_local_part
from reviewblind.models import Confidence, IdentityKind
from reviewblind.scanners.manifests import FieldKind, ManifestField, is_placeholder

MAX_MACRO_LENGTH = 2000
MAX_MACROS_PER_FILE = 200

_MACRO = re.compile(
    r"\\(?P<name>author|IEEEauthorblockN|IEEEauthorblockA|institute|institution|affiliation|"
    r"email|icmlauthor|icmlaffiliation)\*?(?:\[[^\]\n]{0,200}\])?\{"
)
_COMMENT = re.compile(r"(?<!\\)%[^\n]*")
_DROPPED_COMMANDS = re.compile(
    r"\\(?:thanks|footnote|footnotemark|inst|orcid|orcidID|textsuperscript|affil|IEEEmembership)"
    r"\*?(?:\[[^\]]{0,50}\])?(?:\{[^{}]{0,300}\})?"
)
_WRAPPING_COMMAND = re.compile(r"\\[a-zA-Z]+\*?\s*\{([^{}]{0,300})\}")
_SEPARATOR = re.compile(r"\\and\b|\\AND\b|\\And\b|\\\\|\\par\b|\\newline\b|,|;|\n{2,}|\s+and\s+")
_ANY_COMMAND = re.compile(r"\\[a-zA-Z]+\*?|\$[^$]{0,50}\$|[{}^~&]")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_LETTER = re.compile(r"[^\W\d_]")


def _braced(text: str, start: int) -> str:
    """The text up to the brace closing the one before `start`, within a fixed bound."""
    depth = 1
    limit = min(len(text), start + MAX_MACRO_LENGTH)
    for index in range(start, limit):
        char = text[index]
        if char == "\\":
            continue
        if char == "{" and text[index - 1] != "\\":
            depth += 1
        elif char == "}" and text[index - 1] != "\\":
            depth -= 1
            if depth == 0:
                return text[start:index]
    return ""


def _second_argument(text: str, start: int, first: str) -> str | None:
    """The argument directly after the first one, for macros that take two."""
    after = start + len(first) + 1
    if text[after : after + 1] != "{":
        return None
    return _braced(text, after + 1)


def _plain(fragment: str) -> str:
    """Remove LaTeX commands, keeping the text they wrap."""
    text = _DROPPED_COMMANDS.sub(" ", fragment)
    for _ in range(4):  # nesting such as \textbf{\emph{x}}
        text, changed = _WRAPPING_COMMAND.subn(r"\1", text)
        if not changed:
            break
    text = _ANY_COMMAND.sub(" ", text)
    return " ".join(text.split())


def _parts(body: str) -> Iterator[str]:
    for part in _SEPARATOR.split(body):
        plain = _plain(part)
        if plain:
            yield plain


def _looks_like_a_name(value: str) -> bool:
    return 2 <= len(value) <= 80 and _LETTER.search(value) is not None and "@" not in value


def _email(value: str, source: str) -> Iterator[Observation]:
    yield Observation(
        value, IdentityKind.EMAIL, Confidence.HIGH, f"{source} email", SourceClass.LATEX
    )
    local = email_local_part(value, SourceClass.LATEX)
    if local is not None:
        yield local


def _person(value: str, source: str) -> Iterator[Observation]:
    field = ManifestField(FieldKind.PERSON, value, "latex")
    if _looks_like_a_name(value) and not is_placeholder(field):
        yield Observation(
            value,
            person_kind(value),
            Confidence.HIGH,
            f"{source} author",
            SourceClass.LATEX,
        )


def from_latex(name: str, text: str) -> list[Observation]:
    """Observations from one `.tex` file. Commented-out lines are ignored."""
    source = _COMMENT.sub("", text)
    observations: list[Observation] = []
    for index, macro in enumerate(_MACRO.finditer(source)):
        if index >= MAX_MACROS_PER_FILE:
            break
        kind = macro["name"]
        body = _braced(source, macro.end())
        second = _second_argument(source, macro.end(), body)
        if kind == "icmlaffiliation" and second is not None:
            body = second  # \\icmlaffiliation{key}{Institution}
        elif kind == "icmlauthor" and second is not None:
            observations.extend(
                found for email in _EMAIL.findall(second) for found in _email(email, name)
            )
        for email in _EMAIL.findall(body):
            observations.extend(_email(email, name))
        body = _EMAIL.sub(" ", body)
        if kind in {"author", "IEEEauthorblockN", "icmlauthor"}:
            for part in _parts(body):
                observations.extend(_person(part, name))
        elif kind == "IEEEauthorblockA":
            # Conventionally: department, then institution, then address.
            for part in list(_parts(body))[:2]:
                observations.append(_affiliation(part, name))
        elif kind in {"institute", "institution", "affiliation", "icmlaffiliation"}:
            observations.extend(_affiliation(part, name) for part in _whole_lines(body))
    return observations


def _whole_lines(body: str) -> Iterator[str]:
    # An institution's name can contain commas, so only line breaks and \and separate these.
    for part in re.split(r"\\and\b|\\AND\b|\\And\b|\\\\|\\newline\b|\n{2,}", body):
        plain = _plain(part)
        if plain and _LETTER.search(plain):
            yield plain


def _affiliation(value: str, source: str) -> Observation:
    return Observation(
        value,
        IdentityKind.AFFILIATION,
        Confidence.MEDIUM,
        f"{source} affiliation",
        SourceClass.LATEX,
    )
