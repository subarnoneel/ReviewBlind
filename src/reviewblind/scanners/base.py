"""The scanner interfaces, and what every scanner may read."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from reviewblind.config import Config
from reviewblind.matching import IdentityMatcher
from reviewblind.models import Artifact, Detection, SkippedArtifact, SkipReason, Target
from reviewblind.signals import SignalMatcher

# A file repeating an identity thousands of times gains nothing from listing each one, and a
# hostile one could otherwise exhaust memory. Passing a limit marks the scan incomplete, so it is
# never silent.
MAX_DETECTIONS_PER_ARTIFACT = 5000


@dataclass
class ScanContext:
    """Read-only for scanners, except for reporting what could not be inspected."""

    root: Path
    config: Config
    target: Target
    matcher: IdentityMatcher
    signals: SignalMatcher
    skipped: list[SkippedArtifact] = field(default_factory=list)

    def report_skip(self, path: str, reason: SkipReason, detail: str | None = None) -> None:
        self.skipped.append(SkippedArtifact(path, reason, detail))


class FileScanner(Protocol):
    name: str

    def supports(self, artifact: Artifact) -> bool: ...

    def scan(self, artifact: Artifact, context: ScanContext) -> Iterable[Detection]: ...


class RepositoryScanner(Protocol):
    name: str

    def scan(self, context: ScanContext) -> Iterable[Detection]: ...
