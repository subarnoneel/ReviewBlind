"""The scanner interfaces, and what every scanner may read."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from reviewblind.config import Config
from reviewblind.inventory import Inventory
from reviewblind.matching import IdentityMatcher
from reviewblind.models import (
    Artifact,
    Detection,
    EvidenceClass,
    Location,
    SkippedArtifact,
    SkipReason,
    Target,
)
from reviewblind.signals import SignalKind, SignalMatcher
from reviewblind.utils.files import decode_text, read_limited
from reviewblind.utils.text import excerpt

# A file repeating an identity thousands of times gains nothing from listing each one, and a
# hostile one could otherwise exhaust memory. Passing a limit marks the scan incomplete, so it is
# never silent.
MAX_DETECTIONS_PER_ARTIFACT = 5000
DEFAULT_MAX_COMMITS = 5000


@dataclass
class ScanContext:
    """Read-only for scanners, except for reporting what could not be inspected."""

    root: Path
    config: Config
    target: Target
    matcher: IdentityMatcher
    signals: SignalMatcher
    inventory: Inventory
    max_commits: int = DEFAULT_MAX_COMMITS
    skipped: list[SkippedArtifact] = field(default_factory=list)

    def report_skip(self, path: str, reason: SkipReason, detail: str | None = None) -> None:
        self.skipped.append(SkippedArtifact(path, reason, detail))


def read_text_artifact(artifact: Artifact, context: ScanContext) -> str | None:
    """A text file's contents, within the size cap. On failure, records a skip and returns None."""
    limit = context.config.scan.max_text_bytes
    if artifact.size > limit:
        context.report_skip(artifact.relpath, SkipReason.TOO_LARGE, f"over {limit} bytes")
        return None
    try:
        content = read_limited(artifact.path, limit)
    except OSError as error:
        context.report_skip(artifact.relpath, SkipReason.UNREADABLE, error.strerror)
        return None
    if content is None:
        context.report_skip(artifact.relpath, SkipReason.TOO_LARGE, f"over {limit} bytes")
        return None
    try:
        return decode_text(content)
    except UnicodeDecodeError:
        context.report_skip(artifact.relpath, SkipReason.UNSUPPORTED_BINARY, "not valid UTF-8 text")
        return None


def read_binary_artifact(artifact: Artifact, context: ScanContext) -> bytes | None:
    """A file's bytes, within the binary size cap. On failure, records a skip and returns None."""
    limit = context.config.scan.max_binary_bytes
    if artifact.size > limit:
        context.report_skip(artifact.relpath, SkipReason.TOO_LARGE, f"over {limit} bytes")
        return None
    try:
        content = read_limited(artifact.path, limit)
    except OSError as error:
        context.report_skip(artifact.relpath, SkipReason.UNREADABLE, error.strerror)
        return None
    if content is None:
        context.report_skip(artifact.relpath, SkipReason.TOO_LARGE, f"over {limit} bytes")
    return content


def file_fact(
    rule_id: str, path: str, evidence: str, message: str, *, field: str | None = None
) -> Detection:
    """A detection about a file itself, which has no identity attached to it."""
    return Detection(
        rule_id=rule_id,
        artifact=path,
        location=Location(path, field=field),
        matched=f"{path}#{field}" if field else path,
        evidence=evidence,
        message=message,
        identity=None,
        evidence_class=EvidenceClass.DIRECT,
    )


def field_detections(
    text: str,
    *,
    rule_id: str,
    artifact: str,
    field: str,
    message: str,
    context: ScanContext,
    unconfirmed: frozenset[SignalKind] = frozenset(),
) -> Iterator[Detection]:
    """Identities and signals in one part of a structured file, each located by its field.

    A signal with no confirmed identity is only reported if its kind is listed in `unconfirmed`.
    """
    for match in context.matcher.find(text):
        yield Detection(
            rule_id=rule_id,
            artifact=artifact,
            location=Location(artifact, field=field),
            matched=match.matched,
            evidence=excerpt(text, match.start, match.end),
            message=message,
            identity=match.identity.value,
            evidence_class=match.evidence_class,
            span=(match.start, match.end),
        )
    for signal in context.signals.find(text, MAX_DETECTIONS_PER_ARTIFACT + 1):
        if signal.identity is not None or signal.kind in unconfirmed:
            yield Detection(
                rule_id=rule_id,
                artifact=artifact,
                location=Location(artifact, field=field),
                matched=signal.matched,
                evidence=excerpt(text, signal.start, signal.end),
                message=message,
                identity=signal.identity,
                evidence_class=signal.evidence_class,
                span=(signal.start, signal.end),
            )


def within_detection_limit(
    detections: Iterator[Detection], path: str, context: ScanContext
) -> list[Detection]:
    """Stop reading once a file passes the limit. Passing it is recorded, so nothing hides."""
    kept: list[Detection] = []
    for detection in detections:
        if len(kept) >= MAX_DETECTIONS_PER_ARTIFACT:
            context.report_skip(
                path,
                SkipReason.TOO_MANY_MATCHES,
                f"only the first {MAX_DETECTIONS_PER_ARTIFACT} matches were examined",
            )
            break
        kept.append(detection)
    return kept


def confirmed_url_identity(url: str, context: ScanContext) -> str | None:
    """The confirmed identity a URL corresponds to, whether by its namespace or by its text."""
    for signal in context.signals.find(url, limit=20):
        if signal.identity is not None:
            return signal.identity
    matches = context.matcher.find(url)
    return matches[0].identity.value if matches else None


class FileScanner(Protocol):
    name: str

    def supports(self, artifact: Artifact) -> bool: ...

    def scan(self, artifact: Artifact, context: ScanContext) -> Iterable[Detection]: ...


class RepositoryScanner(Protocol):
    name: str

    def scan(self, context: ScanContext) -> Iterable[Detection]: ...
