"""Normalization, offsets, boundaries and overlaps (FR-MATCH-1 to FR-MATCH-7)."""

from __future__ import annotations

import sys
import unicodedata
from dataclasses import dataclass

import pytest

from reviewblind.matching import IdentityMatch, IdentityMatcher, is_acronym, resolve_overlaps
from reviewblind.models import Confidence, EvidenceClass, Identity, IdentityKind, Severity
from reviewblind.utils.text import (
    NormalizedText,
    line_and_column,
    line_starts,
    normalize_text,
    sanitize_evidence,
    sanitize_text,
)


def identity(value: str, kind: IdentityKind = IdentityKind.NAME) -> Identity:
    return Identity(value, kind, "config", Confidence.HIGH, confirmed=True)


def find(text: str, *values: str, kind: IdentityKind = IdentityKind.NAME) -> list[IdentityMatch]:
    return IdentityMatcher(identity(value, kind) for value in values).find(text)


def matched(text: str, *values: str, kind: IdentityKind = IdentityKind.NAME) -> list[str]:
    return [match.matched for match in find(text, *values, kind=kind)]


# Normalization and offsets


@pytest.mark.parametrize(
    ("needle", "text"),
    [("Jos\u00e9", "by Jose\u0301 today"), ("Jose\u0301", "by Jos\u00e9 today")],
)
def test_composed_and_decomposed_forms_match_each_other(needle: str, text: str) -> None:
    # FR-MATCH-1
    [match] = find(text, needle)
    assert match.matched == text[3 : len(text) - 6]
    assert match.column == 4


def test_casefolding_handles_a_change_in_length() -> None:
    # FR-MATCH-1 and FR-MATCH-4: ß folds to two characters, and columns still use the original.
    text = "\u00df\u00df Stra\u00dfe here"
    [match] = find(text, "STRASSE")
    assert match.matched == "Stra\u00dfe"
    assert match.column == 4
    assert text[match.start : match.end] == "Stra\u00dfe"


def test_offsets_after_a_length_change_stay_correct() -> None:
    text = "Stra\u00dfe, Jose\u0301, then Alice Example"
    [match] = find(text, "Alice Example")
    assert text[match.start : match.end] == "Alice Example"


def test_a_match_can_start_inside_a_segment_that_changed_length() -> None:
    text = "x \u00dfa y"
    [match] = find(text, "ssa")
    assert match.matched == "\u00dfa"
    assert match.column == 3


def test_a_match_can_end_at_a_length_change_at_the_very_end() -> None:
    assert matched("by stra\u00df", "STRASS") == ["stra\u00df"]


def test_needles_are_case_insensitive() -> None:
    assert matched("by ALICE example", "Alice Example") == ["ALICE example"]


def test_line_and_column_are_one_based_on_every_line_ending() -> None:
    # FR-MATCH-4
    [unix] = find("one\ntwo Alice", "Alice")
    [windows] = find("one\r\ntwo Alice", "Alice")
    [mac] = find("one\rtwo Alice", "Alice")
    assert (unix.line, unix.column) == (2, 5)
    assert (windows.line, windows.column) == (2, 5)
    assert (mac.line, mac.column) == (2, 5)


def test_no_nfc_composition_is_split_when_text_is_folded_piece_by_piece() -> None:
    # A length-changing character forces segment-by-segment folding. Every canonical composition
    # in this Python's Unicode must survive that, including ones whose second character is a
    # letter rather than a mark, such as Kirat Rai on Unicode 16.
    checked = 0
    for code_point in range(sys.maxunicode + 1):
        decomposition = unicodedata.decomposition(chr(code_point)).split()
        if len(decomposition) != 2 or decomposition[0].startswith("<"):
            continue
        first, second = (chr(int(part, 16)) for part in decomposition)
        text = f"\u00df{first}{second} z"
        expected = unicodedata.normalize("NFC", unicodedata.normalize("NFC", text).casefold())
        assert normalize_text(text) == expected, hex(code_point)
        checked += 1
    assert checked > 900


def test_hangul_jamo_compose_when_text_is_folded_piece_by_piece() -> None:
    text = "\u00df \u1100\u1161\u11a8"
    assert normalize_text(text) == "ss \uac01"


def test_a_mark_that_only_composes_after_lowercasing_maps_correctly() -> None:
    # J plus a caron has no composed form, but lowercase j plus a caron does.
    text = "J\u030c Alice"
    assert normalize_text(text) == "\u01f0 alice"
    [match] = find(text, "Alice")
    assert text[match.start : match.end] == "Alice"


def test_length_changes_that_cancel_out_still_map_correctly() -> None:
    # The sharp s grows by one and the decomposed vowel shrinks by one, so the total is unchanged.
    text = "\u00df\u0410\u0308 Alice"
    [match] = find(text, "Alice")
    assert text[match.start : match.end] == "Alice"
    assert match.column == 5


@pytest.mark.parametrize(
    "text",
    [
        "plain ascii",
        "Jose\u0301",
        "\u00df\u00df",
        "e\u0301\u0301x",
        "\u0301 starts with a mark",
        "\u09b0\u09b9\u09bf\u09ae",
        "\u1100\u1161\u11a8 hangul jamo",
        "\u0130stanbul",
        "",
    ],
)
def test_normalized_text_agrees_with_the_standard_library(text: str) -> None:
    expected = unicodedata.normalize("NFC", unicodedata.normalize("NFC", text).casefold())
    assert normalize_text(text) == expected


def test_a_span_covering_everything_maps_back_to_everything() -> None:
    text = "Stra\u00dfe Jose\u0301 \u0130x"
    index = NormalizedText(text)
    assert index.original_span(0, len(index.normalized)) == (0, len(text))


def test_line_helpers() -> None:
    starts = line_starts("a\nbb\n")
    assert starts == [0, 2, 5]
    assert line_and_column(starts, 3) == (2, 2)


# Boundaries


def test_a_name_does_not_match_inside_other_words() -> None:
    # FR-MATCH-2
    assert matched("MalicE Examples", "Alice Example") == []


@pytest.mark.parametrize(
    "text",
    [
        "aliceexample_data.csv",
        "aliceexample-v2",
        "aliceexample.tar",
        "/home/aliceexample/x",
        "@aliceexample,",
        "(aliceexample)",
    ],
)
def test_punctuation_counts_as_a_boundary(text: str) -> None:
    assert matched(text, "aliceexample") == ["aliceexample"]


def test_digits_are_not_a_boundary() -> None:
    assert matched("aliceexample2", "aliceexample") == []


def test_a_shorter_identity_is_found_when_a_longer_one_fails_its_boundary() -> None:
    assert matched("Alice Examples", "Alice Example", "Alice") == ["Alice"]


def test_a_failed_boundary_does_not_hide_a_later_match() -> None:
    assert matched("Xalice alice", "alice") == ["alice"]


def test_a_combining_mark_is_part_of_the_word() -> None:
    # A Bangla name must not match when a following vowel sign continues the syllable.
    name = "\u09b0\u09b9\u09bf\u09ae"
    assert matched(f"{name}\u09be", name) == []
    assert matched(f"by {name}.", name) == [name]


def test_a_decomposed_latin_mark_is_part_of_the_word() -> None:
    assert matched("Alice\u0301", "Alice") == []


@pytest.mark.parametrize("name", ["\u5f20\u4f1f", "\u3042\u308a\u3055", "\uae40\ucca0\uc218"])
def test_unspaced_scripts_skip_the_boundary_check(name: str) -> None:
    assert matched(f"\u7684{name}\u7684", name) == [name]


# Whitespace and literals


@pytest.mark.parametrize("gap", ["\n", "\r\n", "  ", "\t", "\u00a0", "\n    "])
def test_a_name_matches_across_any_whitespace(gap: str) -> None:
    # FR-MATCH-3
    text = f"\\author{{Alice{gap}Example}}"
    [match] = find(text, "Alice Example")
    assert match.matched == f"Alice{gap}Example"
    assert match.line == 1


def test_there_is_no_fuzzy_matching() -> None:
    # FR-MATCH-5
    assert matched("Alice Exmple, Alicia Example, Example Alice", "Alice Example") == []


def test_regex_characters_in_an_identity_are_literal() -> None:
    assert matched("by A. Example (PhD).", "A. Example (PhD)") == ["A. Example (PhD)"]
    assert matched("by AX Example (PhD)", "A. Example (PhD)") == []
    assert matched("a+b", "a+b") == ["a+b"]


def test_an_email_is_matched_whole() -> None:
    assert matched("mail alice@example.edu.", "alice@example.edu") == ["alice@example.edu"]
    assert matched("malice@example.edu", "alice@example.edu") == []


def test_every_occurrence_is_found_in_order() -> None:
    assert [match.column for match in find("Alice and Alice", "Alice")] == [1, 11]


def test_a_blank_identity_is_a_bug_in_the_caller() -> None:
    with pytest.raises(ValueError, match="whitespace"):
        IdentityMatcher([identity("   ")])


def test_duplicate_identities_give_one_match() -> None:
    assert matched("ALICE", "Alice", "alice") == ["ALICE"]


# Evidence classes


def test_full_names_are_direct_and_affiliations_are_indirect() -> None:
    assert find("Alice", "Alice")[0].evidence_class is EvidenceClass.DIRECT
    [match] = find("Example University", "Example University", kind=IdentityKind.AFFILIATION)
    assert match.evidence_class is EvidenceClass.INDIRECT


@pytest.mark.parametrize("kind", [IdentityKind.AFFILIATION, IdentityKind.ALIAS])
def test_an_acronym_depends_on_its_case(kind: IdentityKind) -> None:
    # FR-MATCH-7
    assert find("the EU lab", "EU", kind=kind)[0].evidence_class is EvidenceClass.ACRONYM
    assert find("the eu lab", "EU", kind=kind)[0].evidence_class is EvidenceClass.AMBIGUOUS


def test_a_short_username_is_not_treated_as_an_acronym() -> None:
    [match] = find("max", "MAX", kind=IdentityKind.USERNAME)
    assert match.evidence_class is EvidenceClass.DIRECT


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("EU", True),
        ("MIT", True),
        ("ABCDE", True),
        ("ABCDEF", False),
        ("Mit", False),
        ("A1", False),
        ("", False),
        ("\u09b0\u09b9", False),
    ],
)
def test_what_counts_as_an_acronym(value: str, expected: bool) -> None:
    assert is_acronym(value) is expected


# Overlaps


@dataclass(frozen=True)
class Candidate:
    rule_id: str
    span: tuple[int, int]
    severity: Severity


def resolved(*candidates: Candidate) -> list[str]:
    kept = resolve_overlaps(
        candidates,
        span=lambda item: item.span,
        severity=lambda item: item.severity,
        rule_id=lambda item: item.rule_id,
    )
    return [item.rule_id for item in kept]


def test_the_longest_span_wins_even_at_lower_severity() -> None:
    # FR-MATCH-6: /home/aliceexample/data is RB201, a WARNING, and not RB103.
    home_path = Candidate("RB201", (0, 18), Severity.WARNING)
    username = Candidate("RB103", (6, 18), Severity.BLOCKER)
    assert resolved(username, home_path) == ["RB201"]


def test_an_equal_span_goes_to_the_higher_severity() -> None:
    # --mail-user=alice@example.edu is RB102, a BLOCKER, and not RB205.
    assert resolved(
        Candidate("RB205", (12, 29), Severity.WARNING),
        Candidate("RB102", (12, 29), Severity.BLOCKER),
    ) == ["RB102"]


def test_an_equal_span_and_severity_goes_to_the_lower_rule_id() -> None:
    assert resolved(
        Candidate("RB205", (0, 5), Severity.WARNING),
        Candidate("RB202", (0, 5), Severity.WARNING),
    ) == ["RB202"]


def test_spans_that_only_partly_overlap_both_survive() -> None:
    # "Alice Example University": neither leak may hide the other.
    name = Candidate("RB101", (0, 13), Severity.BLOCKER)
    affiliation = Candidate("RB104", (6, 24), Severity.WARNING)
    assert resolved(name, affiliation) == ["RB101", "RB104"]


def test_separate_spans_both_survive() -> None:
    assert resolved(
        Candidate("RB101", (0, 5), Severity.BLOCKER),
        Candidate("RB102", (10, 15), Severity.BLOCKER),
    ) == ["RB101", "RB102"]


def test_something_nested_inside_a_partial_overlap_is_still_dropped() -> None:
    assert resolved(
        Candidate("RB101", (0, 10), Severity.BLOCKER),
        Candidate("RB104", (5, 20), Severity.WARNING),
        Candidate("RB103", (12, 15), Severity.BLOCKER),
    ) == ["RB101", "RB104"]


# Sanitizing (threats T-10 and T-11)


def test_terminal_and_bidirectional_controls_are_removed() -> None:
    assert sanitize_text("\x1b[31mred\x1b[0m") == "[31mred[0m"
    assert sanitize_text("a\u202eb\u2066c") == "abc"


def test_line_breaks_become_spaces() -> None:
    assert sanitize_text("a\nb\r\nc\u2028d") == "a b  c d"


def test_joiners_used_by_real_scripts_survive() -> None:
    word = "\u0995\u09cd\u200d\u09b7"
    assert sanitize_text(word) == word


def test_ordinary_text_is_returned_unchanged() -> None:
    assert sanitize_text("Jos\u00e9 \u5f20\u4f1f") == "Jos\u00e9 \u5f20\u4f1f"


def test_evidence_at_the_limit_is_not_truncated() -> None:
    assert sanitize_evidence("x" * 160) == "x" * 160
    assert len(sanitize_evidence("x" * 161)) == 160
