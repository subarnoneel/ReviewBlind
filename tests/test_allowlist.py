"""Exact suppressions (FR-PIPE-2, FR-CFG-4). A broad suppression could hide a different leak."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from _helpers import PERSONA, rules_found, scan, write_tree
from reviewblind.config import AllowEntry, Config
from reviewblind.engine import compute_exit_code, compute_verdict
from reviewblind.models import Severity, Verdict
from reviewblind.reporters.terminal import render_report

CITATION = AllowEntry("RB101", "references.bib", "Alice Example", "Neutral self-citation")


def with_allow(*entries: AllowEntry) -> Config:
    return replace(PERSONA, allow=entries)


def test_an_exact_entry_suppresses_the_finding(tmp_path: Path) -> None:
    write_tree(tmp_path, {"references.bib": "author = {Alice Example},\n"})
    report = scan(tmp_path, config=with_allow(CITATION))
    assert report.result.findings == []
    assert report.result.suppressed[0].finding.rule_id == "RB101"
    assert report.result.suppressed[0].reason == "Neutral self-citation"
    assert report.result.notes[:0] == []


def test_suppressed_findings_do_not_affect_the_verdict_or_exit_code(tmp_path: Path) -> None:
    write_tree(tmp_path, {"references.bib": "author = {Alice Example},\n"})
    result = scan(tmp_path, config=with_allow(CITATION)).result
    assert compute_verdict(result) is Verdict.NO_KNOWN_LEAKS
    assert compute_exit_code(result, Severity.INFO, strict=True) == 0


def test_value_comparison_ignores_case_whitespace_and_unicode_form(tmp_path: Path) -> None:
    write_tree(tmp_path, {"references.bib": "ALICE\n  EXAMPLE and Jose\u0301\n"})
    entry = replace(CITATION, value="alice example")
    identity = replace(PERSONA.identity, names=("Alice Example", "Jos\u00e9"))
    config = replace(
        PERSONA,
        identity=identity,
        allow=(entry, replace(CITATION, value="JOS\u00c9")),
    )
    report = scan(tmp_path, config=config)
    assert report.result.findings == []
    assert len(report.result.suppressed) == 2


def test_every_occurrence_of_the_value_in_that_file_is_covered(tmp_path: Path) -> None:
    write_tree(tmp_path, {"references.bib": "Alice Example\nAlice Example\n"})
    report = scan(tmp_path, config=with_allow(CITATION))
    assert report.result.findings == []
    assert len(report.result.suppressed) == 2


def test_another_file_is_not_covered(tmp_path: Path) -> None:
    write_tree(tmp_path, {"references.bib": "Alice Example\n", "README.md": "Alice Example\n"})
    report = scan(tmp_path, config=with_allow(CITATION))
    assert [item.artifact for item in report.result.findings] == ["README.md"]


def test_a_file_with_the_same_name_elsewhere_is_not_covered(tmp_path: Path) -> None:
    write_tree(tmp_path, {"sub/references.bib": "Alice Example\n"})
    assert rules_found(scan(tmp_path, config=with_allow(CITATION)).result.findings) == ["RB101"]


def test_another_rule_is_not_covered(tmp_path: Path) -> None:
    write_tree(tmp_path, {"references.bib": "alice@example.edu\n"})
    entry = replace(CITATION, value="alice@example.edu")
    assert rules_found(scan(tmp_path, config=with_allow(entry)).result.findings) == ["RB102"]


def test_another_value_is_not_covered(tmp_path: Path) -> None:
    write_tree(tmp_path, {"references.bib": "Alice Example and A. Example\n"})
    report = scan(tmp_path, config=with_allow(CITATION))
    assert [item.matched for item in report.result.findings] == ["A. Example"]


def test_a_file_name_can_be_allowed(tmp_path: Path) -> None:
    write_tree(tmp_path, {"aliceexample/a.txt": "x\n", "aliceexample/b.txt": "x\n"})
    entry = AllowEntry("RB106", "aliceexample", "aliceexample", "Renamed before submission")
    report = scan(tmp_path, config=with_allow(entry))
    assert report.result.findings == []
    assert len(report.result.suppressed) == 1


def test_a_stale_entry_produces_a_note(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.txt": "x\n"})
    report = scan(tmp_path, config=with_allow(CITATION))
    assert any(
        "[[allow]] entry matched nothing" in note and "references.bib" in note
        for note in report.result.notes
    )


def test_a_used_entry_produces_no_note(tmp_path: Path) -> None:
    write_tree(tmp_path, {"references.bib": "Alice Example\n"})
    report = scan(tmp_path, config=with_allow(CITATION))
    assert not any("[[allow]]" in note for note in report.result.notes)


def test_the_terminal_report_shows_the_suppressed_count(tmp_path: Path) -> None:
    write_tree(tmp_path, {"references.bib": "Alice Example\n"})
    report = scan(tmp_path, config=with_allow(CITATION))
    assert "Findings suppressed: 1" in render_report(report).plain


def test_suppressing_does_not_mark_the_scan_incomplete(tmp_path: Path) -> None:
    write_tree(tmp_path, {"references.bib": "Alice Example\n"})
    assert not scan(tmp_path, config=with_allow(CITATION)).result.incomplete
