"""Rule lookup."""

from __future__ import annotations

from reviewblind.models import Rule
from reviewblind.rules.catalog import CATALOG

_BY_ID = {rule.id: rule for rule in CATALOG}


def get_rule(rule_id: str) -> Rule:
    """Return a rule by ID. An unknown ID raises `KeyError`, since it is a bug in the caller."""
    return _BY_ID[rule_id]


def is_known_rule(rule_id: str) -> bool:
    return rule_id in _BY_ID


def all_rules() -> tuple[Rule, ...]:
    """Every rule, ordered by ID."""
    return CATALOG
