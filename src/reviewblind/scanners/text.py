"""Confirmed identities and structural signals in text files."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from reviewblind.models import (
    Artifact,
    ArtifactKind,
    Detection,
    IdentityKind,
    Location,
    SkipReason,
)
from reviewblind.scanners.base import MAX_DETECTIONS_PER_ARTIFACT, ScanContext, read_text_artifact
from reviewblind.signals import SignalKind
from reviewblind.utils.text import excerpt, line_and_column, line_starts

_IDENTITY_RULES = {
    IdentityKind.NAME: ("RB101", "Found confirmed author name"),
    IdentityKind.ALIAS: ("RB101", "Found confirmed author alias"),
    IdentityKind.EMAIL: ("RB102", "Found confirmed email address"),
    IdentityKind.USERNAME: ("RB103", "Found confirmed username"),
    IdentityKind.AFFILIATION: ("RB104", "Found confirmed affiliation"),
    IdentityKind.URL: ("RB105", "Found confirmed personal URL"),
}
_SIGNAL_RULES = {
    SignalKind.HOME_PATH: ("RB201", "Found a personal home path"),
    SignalKind.INSTITUTION_DOMAIN: ("RB202", "Found an institutional hostname"),
    SignalKind.SERVICE_NAMESPACE: ("RB203", "Found a research-service namespace"),
    SignalKind.GIT_NAMESPACE: ("RB204", "Found a personal Git hosting namespace"),
    SignalKind.PROFILE_URL: ("RB105", "Found a personal profile URL"),
    SignalKind.SCHEDULER_ID: ("RB205", "Found a scheduler user or mail identifier"),
}


class TextScanner:
    name = "text"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.kind in {ArtifactKind.TEXT, ArtifactKind.MANIFEST}

    def scan(self, artifact: Artifact, context: ScanContext) -> Iterable[Detection]:
        text = read_text_artifact(artifact, context)
        if text is None:
            return ()
        detections = sorted(
            self._detect(artifact.relpath, text, context),
            key=lambda item: item.span or (0, 0),
        )
        if len(detections) > MAX_DETECTIONS_PER_ARTIFACT:
            context.report_skip(
                artifact.relpath,
                SkipReason.TOO_MANY_MATCHES,
                f"only the first {MAX_DETECTIONS_PER_ARTIFACT} matches were examined",
            )
        return detections[:MAX_DETECTIONS_PER_ARTIFACT]

    @staticmethod
    def _detect(relpath: str, text: str, context: ScanContext) -> Iterator[Detection]:
        starts = line_starts(text)

        def location(start: int) -> Location:
            line, column = line_and_column(starts, start)
            return Location(relpath, line=line, column=column)

        for match in context.matcher.find(text):
            rule_id, message = _IDENTITY_RULES[match.identity.kind]
            yield Detection(
                rule_id=rule_id,
                artifact=relpath,
                location=location(match.start),
                matched=match.matched,
                evidence=excerpt(text, match.start, match.end),
                message=message,
                identity=match.identity.value,
                evidence_class=match.evidence_class,
                span=(match.start, match.end),
            )
        for signal in context.signals.find(text, MAX_DETECTIONS_PER_ARTIFACT + 1):
            rule_id, message = _SIGNAL_RULES[signal.kind]
            yield Detection(
                rule_id=rule_id,
                artifact=relpath,
                location=location(signal.start),
                matched=signal.matched,
                evidence=excerpt(text, signal.start, signal.end),
                message=message,
                identity=signal.identity,
                evidence_class=signal.evidence_class,
                span=(signal.start, signal.end),
            )
