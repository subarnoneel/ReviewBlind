"""Severity and confidence for each rule, target and kind of evidence (FR-PIPE-1)."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from reviewblind.models import (
    Confidence,
    Detection,
    EvidenceClass,
    Location,
    Rule,
    Severity,
    Target,
)
from reviewblind.profiles import Resolution, build_finding, resolve
from reviewblind.rules.registry import all_rules, get_rule

B = Severity.BLOCKER
W = Severity.WARNING
R = Severity.REVIEW
I = Severity.INFO  # noqa: E741 - matches the letters in docs/RULES.md
ALL_THREE = [Target.MIRROR, Target.ARCHIVE, Target.REPOSITORY]


def _detection(rule_id: str = "RB101", **overrides: Any) -> Detection:
    detection = Detection(
        rule_id=rule_id,
        artifact="README.md",
        location=Location("README.md", line=3, column=1),
        matched="Alice Example",
        evidence="by Alice Example",
        message="Found confirmed author name",
        identity="Alice Example",
        evidence_class=EvidenceClass.DIRECT,
    )
    return replace(detection, **overrides)


def test_severity_and_confidence_are_ordered() -> None:
    assert Severity.BLOCKER > Severity.WARNING > Severity.REVIEW > Severity.INFO
    assert Severity.INFO < Severity.REVIEW < Severity.WARNING < Severity.BLOCKER
    assert Severity.BLOCKER >= Severity.BLOCKER
    assert Severity.INFO <= Severity.INFO
    assert Confidence.HIGH > Confidence.MEDIUM > Confidence.LOW
    assert min(Severity.BLOCKER, Severity.WARNING) is Severity.WARNING


def test_severity_and_confidence_cannot_be_compared_with_each_other() -> None:
    with pytest.raises(TypeError):
        _ = Severity.BLOCKER < Confidence.LOW
    with pytest.raises(TypeError):
        _ = Severity.BLOCKER <= Confidence.LOW
    with pytest.raises(TypeError):
        _ = Severity.BLOCKER > Confidence.LOW
    with pytest.raises(TypeError):
        _ = Severity.BLOCKER >= Confidence.LOW


@pytest.mark.parametrize("rule", all_rules(), ids=lambda rule: rule.id)
@pytest.mark.parametrize("target", ALL_THREE)
def test_direct_confirmed_evidence_gets_the_base_severity(rule: Rule, target: Target) -> None:
    # tracked=False keeps RB805 at its base severity.
    assert resolve(rule, target, tracked=False) == Resolution(
        rule.severity_for(target), rule.confidence
    )


@pytest.mark.parametrize(
    ("rule_id", "expected"),
    [
        ("RB402", [I, I, B]),
        ("RB601", [B, B, B]),
        ("RB801", [I, B, I]),
    ],
)
def test_severity_examples_from_the_specification(rule_id: str, expected: list[Severity]) -> None:
    rule = get_rule(rule_id)
    resolved = [resolve(rule, target) for target in ALL_THREE]
    assert [item.severity for item in resolved if item] == expected


@pytest.mark.parametrize("rule_id", ["RB401", "RB402", "RB403", "RB404"])
def test_git_rules_become_blockers_when_git_is_packaged_in_an_archive(rule_id: str) -> None:
    rule = get_rule(rule_id)
    assert resolve(rule, Target.ARCHIVE, git_packaged=True) == Resolution(B, Confidence.HIGH)
    assert resolve(rule, Target.MIRROR, git_packaged=True) == Resolution(I, Confidence.HIGH)


@pytest.mark.parametrize(
    ("target", "tracked", "expected"),
    [
        (Target.MIRROR, True, B),
        (Target.MIRROR, False, I),
        (Target.MIRROR, None, B),  # unknown tracking must not hide the leak
        (Target.REPOSITORY, True, B),
        (Target.REPOSITORY, False, I),
        (Target.ARCHIVE, False, B),
    ],
)
def test_reviewblind_config_in_the_artifact(
    target: Target, tracked: bool | None, expected: Severity
) -> None:
    resolved = resolve(get_rule("RB805"), target, tracked=tracked)
    assert resolved == Resolution(expected, Confidence.HIGH)


@pytest.mark.parametrize(
    "rule_id", ["RB106", "RB404", "RB501", "RB502", "RB503", "RB601", "RB602", "RB701"]
)
def test_container_rules_cap_indirect_evidence_at_warning(rule_id: str) -> None:
    resolved = resolve(get_rule(rule_id), Target.REPOSITORY, EvidenceClass.INDIRECT)
    assert resolved == Resolution(W, Confidence.HIGH)


def test_notebook_output_depends_on_what_was_found() -> None:
    rule = get_rule("RB502")
    name = resolve(rule, Target.MIRROR, EvidenceClass.DIRECT)
    home_path = resolve(rule, Target.MIRROR, EvidenceClass.INDIRECT)
    assert name is not None
    assert name.severity is B
    assert home_path is not None
    assert home_path.severity is W


def test_indirect_evidence_does_not_change_a_non_container_rule() -> None:
    resolved = resolve(get_rule("RB301"), Target.MIRROR, EvidenceClass.INDIRECT)
    assert resolved == Resolution(B, Confidence.HIGH)


@pytest.mark.parametrize("rule_id", ["RB101", "RB104"])
def test_acronym_in_exact_case_is_warning_medium(rule_id: str) -> None:
    resolved = resolve(get_rule(rule_id), Target.MIRROR, EvidenceClass.ACRONYM)
    assert resolved == Resolution(W, Confidence.MEDIUM)


@pytest.mark.parametrize("rule_id", ["RB101", "RB104"])
def test_acronym_in_another_case_is_review_low(rule_id: str) -> None:
    resolved = resolve(get_rule(rule_id), Target.MIRROR, EvidenceClass.AMBIGUOUS)
    assert resolved == Resolution(R, Confidence.LOW)


def test_evidence_class_can_lower_severity_but_never_raise_it() -> None:
    resolved = resolve(get_rule("RB404"), Target.MIRROR, EvidenceClass.ACRONYM)
    assert resolved == Resolution(I, Confidence.MEDIUM)


@pytest.mark.parametrize(
    ("rule_id", "expected"),
    [
        ("RB201", Resolution(R, Confidence.MEDIUM)),
        ("RB203", Resolution(R, Confidence.LOW)),
        ("RB205", Resolution(W, Confidence.MEDIUM)),
        ("RB301", Resolution(B, Confidence.MEDIUM)),
        ("RB302", Resolution(W, Confidence.MEDIUM)),
        ("RB601", Resolution(W, Confidence.MEDIUM)),
        ("RB101", None),
        ("RB204", None),
    ],
)
def test_unconfirmed_evidence(rule_id: str, expected: Resolution | None) -> None:
    assert resolve(get_rule(rule_id), Target.MIRROR, confirmed=False) == expected


@pytest.mark.parametrize("rule_id", ["RB402", "RB403"])
def test_unconfirmed_git_identity_only_matters_on_a_public_repository(rule_id: str) -> None:
    rule = get_rule(rule_id)
    assert resolve(rule, Target.MIRROR, confirmed=False) is None
    assert resolve(rule, Target.ARCHIVE, confirmed=False) is None
    assert resolve(rule, Target.REPOSITORY, confirmed=False) == Resolution(W, Confidence.MEDIUM)


def test_rules_about_a_fact_ignore_confirmation() -> None:
    resolved = resolve(get_rule("RB703"), Target.MIRROR, confirmed=False)
    assert resolved == Resolution(R, Confidence.HIGH)


def test_build_finding_combines_detection_and_catalog() -> None:
    finding = build_finding(_detection(), Target.MIRROR)
    assert finding is not None
    assert finding.rule_id == "RB101"
    assert finding.severity is B
    assert finding.confidence is Confidence.HIGH
    assert finding.artifact == "README.md"
    assert finding.location.line == 3
    assert finding.reason == get_rule("RB101").reason
    assert finding.remediation == get_rule("RB101").remediation
    assert finding.targets == frozenset(ALL_THREE)
    assert finding.fingerprint.startswith("rb1:")


def test_build_finding_returns_nothing_when_the_rule_says_so() -> None:
    assert build_finding(_detection("RB204", identity=None), Target.MIRROR) is None


def test_build_finding_rejects_an_unknown_rule() -> None:
    with pytest.raises(KeyError):
        build_finding(_detection("RB999"), Target.MIRROR)


def test_evidence_is_sanitized_before_it_reaches_a_reporter() -> None:
    # FR-PIPE-5
    finding = build_finding(
        _detection(evidence="\x1b[31mby Alice\x07\nExample\u202e", matched="Alice\nExample"),
        Target.MIRROR,
    )
    assert finding is not None
    assert finding.evidence == "[31mby Alice Example"
    assert finding.matched == "Alice Example"


def test_long_evidence_is_truncated_to_160_characters() -> None:
    # NFR-USE-3
    finding = build_finding(_detection(evidence="x" * 500), Target.MIRROR)
    assert finding is not None
    assert len(finding.evidence) == 160
    assert finding.evidence.endswith("\u2026")
