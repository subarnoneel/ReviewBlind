"""Confirmed identities in file and directory names."""

from __future__ import annotations

from collections.abc import Iterable

from reviewblind.matching import resolve_overlaps
from reviewblind.models import Artifact, Detection, Location, Severity
from reviewblind.scanners.base import ScanContext


class PathScanner:
    name = "paths"

    def supports(self, artifact: Artifact) -> bool:
        return True

    def scan(self, artifact: Artifact, context: ScanContext) -> Iterable[Detection]:
        relpath = artifact.relpath
        matches = resolve_overlaps(
            context.matcher.find(relpath),
            span=lambda match: (match.start, match.end),
            severity=lambda _match: Severity.BLOCKER,
            rule_id=lambda match: match.identity.value,
        )
        for match in matches:
            # A directory is reported once, not once for each file inside it. The engine merges
            # these, because every file under the directory produces the same detection.
            boundary = relpath.find("/", match.end)
            exposed = relpath if boundary == -1 else relpath[:boundary]
            yield Detection(
                rule_id="RB106",
                artifact=exposed,
                location=Location(exposed),
                matched=match.matched,
                evidence=exposed,
                message="Found a confirmed identity in a file or directory name",
                identity=match.identity.value,
                evidence_class=match.evidence_class,
            )
