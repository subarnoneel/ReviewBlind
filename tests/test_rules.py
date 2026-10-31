"""The catalog must match docs/RULES.md field by field (FR-RULE-3)."""

from __future__ import annotations

import pytest

from _rules_doc import DocRule, load_rules
from reviewblind.models import ALL_TARGETS, Rule, Severity, Target
from reviewblind.rules.registry import all_rules, get_rule, is_known_rule

DOC_RULES = load_rules()
RULE_IDS = sorted(DOC_RULES)


def _first_upper(text: str) -> str:
    return text[0].upper() + text[1:]


def test_there_are_33_rules_with_the_same_ids_as_the_document() -> None:
    assert len(DOC_RULES) == 33
    assert [rule.id for rule in all_rules()] == RULE_IDS


@pytest.fixture(params=RULE_IDS)
def rule_pair(request: pytest.FixtureRequest) -> tuple[Rule, DocRule]:
    return get_rule(request.param), DOC_RULES[request.param]


def test_title_matches(rule_pair: tuple[Rule, DocRule]) -> None:
    rule, doc = rule_pair
    assert rule.title == doc.title


@pytest.mark.parametrize("target", list(Target))
def test_severity_matches_on_every_target(rule_pair: tuple[Rule, DocRule], target: Target) -> None:
    rule, doc = rule_pair
    assert rule.severity_for(target) is doc.severity[target]


def test_flags_match(rule_pair: tuple[Rule, DocRule]) -> None:
    rule, doc = rule_pair
    assert rule.confidence is doc.confidence
    assert rule.container == doc.container
    assert rule.identity_based == doc.identity_based
    assert rule.blocker_if_git_packaged == doc.git_packaged
    assert rule.blocker_if_tracked == doc.tracked


def test_unconfirmed_policy_matches(rule_pair: tuple[Rule, DocRule]) -> None:
    rule, doc = rule_pair
    if doc.unconfirmed is None:
        assert rule.unconfirmed is None
        return
    assert rule.unconfirmed is not None
    assert rule.unconfirmed.severity is doc.unconfirmed.severity
    assert rule.unconfirmed.confidence is doc.unconfirmed.confidence
    assert rule.unconfirmed.targets == doc.unconfirmed.targets


def test_text_matches_the_document(rule_pair: tuple[Rule, DocRule]) -> None:
    rule, doc = rule_pair
    assert _first_upper(rule.description) == doc.detects
    assert _first_upper(rule.reason) == doc.why
    assert _first_upper(rule.remediation) == doc.fix


def test_every_rule_applies_to_every_target() -> None:
    assert all(rule.applicable_targets == ALL_TARGETS for rule in all_rules())


def test_lookup() -> None:
    assert get_rule("RB601").default_severity is Severity.BLOCKER
    assert is_known_rule("RB601")
    assert not is_known_rule("RB999")
    with pytest.raises(KeyError):
        get_rule("RB999")
