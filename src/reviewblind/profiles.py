"""The one place severity and confidence are decided. See docs/RULES.md."""

from __future__ import annotations

from dataclasses import dataclass

from reviewblind.fingerprints import fingerprint
from reviewblind.models import (
    Confidence,
    Detection,
    EvidenceClass,
    Finding,
    Rule,
    Severity,
    Target,
)
from reviewblind.rules.registry import get_rule
from reviewblind.utils.text import sanitize_evidence, sanitize_text


@dataclass(frozen=True)
class Resolution:
    severity: Severity
    confidence: Confidence


def resolve(
    rule: Rule,
    target: Target,
    evidence_class: EvidenceClass = EvidenceClass.DIRECT,
    *,
    confirmed: bool = True,
    git_packaged: bool = False,
    tracked: bool | None = None,
) -> Resolution | None:
    """Apply the steps in "How severity is resolved". `None` means no finding is raised.

    `confirmed` is ignored by rules about a fact rather than an identity. Git tracking that is
    unknown counts as tracked for RB805, since treating a leak as absent is the worse mistake.
    """
    if rule.identity_based and not confirmed:
        policy = rule.unconfirmed
        if policy is None or target not in policy.targets:
            return None
        return Resolution(policy.severity, policy.confidence)

    severity = rule.severity_for(target)
    if rule.blocker_if_git_packaged and git_packaged and target is Target.ARCHIVE:
        severity = Severity.BLOCKER
    if rule.blocker_if_tracked and tracked is not False:
        severity = Severity.BLOCKER

    if evidence_class is EvidenceClass.ACRONYM:
        return Resolution(min(severity, Severity.WARNING), Confidence.MEDIUM)
    if evidence_class is EvidenceClass.AMBIGUOUS:
        return Resolution(min(severity, Severity.REVIEW), Confidence.LOW)
    if evidence_class is EvidenceClass.INDIRECT and rule.container:
        severity = min(severity, Severity.WARNING)
    return Resolution(severity, rule.confidence)


def build_finding(
    detection: Detection,
    target: Target,
    *,
    git_packaged: bool = False,
    tracked: bool | None = None,
) -> Finding | None:
    """Combine what a scanner saw with the catalog. `None` means no finding is raised."""
    rule = get_rule(detection.rule_id)
    resolution = resolve(
        rule,
        target,
        detection.evidence_class,
        confirmed=detection.identity is not None,
        git_packaged=git_packaged,
        tracked=tracked,
    )
    if resolution is None:
        return None
    return Finding(
        rule_id=rule.id,
        severity=resolution.severity,
        confidence=resolution.confidence,
        artifact=detection.artifact,
        location=detection.location,
        matched=sanitize_text(detection.matched),
        evidence=sanitize_evidence(detection.evidence),
        message=sanitize_text(detection.message),
        reason=rule.reason,
        remediation=rule.remediation,
        identity=detection.identity,
        targets=rule.applicable_targets,
        fingerprint=fingerprint(rule.id, detection.artifact, detection.matched),
    )
