"""The scanner interfaces, and what every scanner may read."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from reviewblind.config import Config
from reviewblind.inventory import Inventory
from reviewblind.matching import IdentityMatcher
from reviewblind.models import Artifact, Detection, SkippedArtifact, SkipReason, Target
from reviewblind.signals import SignalMatcher
from reviewblind.utils.files import decode_text, read_limited

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
