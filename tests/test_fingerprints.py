"""Fingerprints identify a leak, and must survive unrelated edits (FR-PIPE-3)."""

from __future__ import annotations

import hashlib

from reviewblind.fingerprints import fingerprint


def test_format_and_known_value() -> None:
    # A pinned value: changing the algorithm would invalidate every future baseline.
    expected = hashlib.sha256(b"RB101\0README.md\0alice example").hexdigest()
    assert fingerprint("RB101", "README.md", "Alice Example") == f"rb1:{expected}"


def test_case_and_whitespace_in_the_value_do_not_matter() -> None:
    reference = fingerprint("RB101", "README.md", "Alice Example")
    assert fingerprint("RB101", "README.md", "ALICE EXAMPLE") == reference
    assert fingerprint("RB101", "README.md", "Alice\n   Example") == reference


def test_unicode_form_of_the_value_does_not_matter() -> None:
    composed = fingerprint("RB101", "README.md", "Jos\u00e9")
    decomposed = fingerprint("RB101", "README.md", "Jose\u0301")
    assert composed == decomposed


def test_rule_path_and_value_all_change_it() -> None:
    reference = fingerprint("RB101", "README.md", "Alice Example")
    assert fingerprint("RB102", "README.md", "Alice Example") != reference
    assert fingerprint("RB101", "docs/README.md", "Alice Example") != reference
    assert fingerprint("RB101", "README.md", "Bob Example") != reference


def test_path_case_is_preserved_but_separators_are_normalized() -> None:
    reference = fingerprint("RB101", "docs/README.md", "Alice")
    assert fingerprint("RB101", "docs/readme.md", "Alice") != reference
    assert fingerprint("RB101", "docs\\README.md", "Alice") == reference


def test_fields_cannot_run_into_each_other() -> None:
    assert fingerprint("RB101", "ab", "c") != fingerprint("RB101", "a", "bc")
