"""JSON and Markdown reports (FR-REP-1 to FR-REP-5, threats T-10 and T-11)."""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from _helpers import PERSONA, git, init_repo, scan, write_tree
from reviewblind.config import AllowEntry
from reviewblind.models import (
    Confidence,
    Finding,
    Location,
    ScanReport,
    ScanResult,
    Severity,
    SkippedArtifact,
    SkipReason,
    SuppressedFinding,
    Target,
)
from reviewblind.reporters import display_config_path, display_root
from reviewblind.reporters.json import SCHEMA_VERSION, render_json
from reviewblind.reporters.markdown import MARKER, render_markdown
from reviewblind.reporters.terminal import render_report

SCHEMA_DOC = Path(__file__).resolve().parent.parent / "docs" / "REPORT_SCHEMA.md"


def documented_example() -> dict[str, Any]:
    block = re.search(r"```json\n(.*?)```", SCHEMA_DOC.read_text(encoding="utf-8"), re.DOTALL)
    assert block is not None
    return json.loads(block[1])  # type: ignore[no-any-return]


def finding(**overrides: Any) -> Finding:
    base = Finding(
        rule_id="RB101",
        severity=Severity.BLOCKER,
        confidence=Confidence.HIGH,
        artifact="README.md",
        location=Location("README.md", line=4, column=2),
        matched="Alice Example",
        evidence="by Alice Example",
        message="Found confirmed author name",
        reason="Direct author identity is visible.",
        remediation="Remove this name.",
        identity="Alice Example",
        targets=frozenset(Target),
        fingerprint="rb1:abc",
    )
    return replace(base, **overrides)


def report_of(*items: Finding, root: Path = Path("repo"), **result: Any) -> ScanReport:
    return ScanReport(
        result=ScanResult(findings=list(items), **result),
        target=Target.MIRROR,
        root=root,
        config_path=None,
        identities=PERSONA.identity.identities(),
        version="0.1.0",
    )


def rendered_outside_code_spans(document: str) -> str:
    """What is left of a Markdown document once its code spans are removed."""
    return re.sub(r"(?<!`)(`+)(?!`).*?(?<!`)\1(?!`)", "", document)


# JSON structure


@pytest.fixture
def real_report(tmp_path: Path) -> dict[str, Any]:
    write_tree(
        tmp_path,
        {
            "README.md": "by Alice Example\n",
            "references.bib": "Alice Example\n",
            "weights.bin": b"\x00\x01",
        },
    )
    allow = AllowEntry("RB101", "references.bib", "Alice Example", "Neutral self-citation")
    return json.loads(render_json(scan(tmp_path, config=replace(PERSONA, allow=(allow,)))))  # type: ignore[no-any-return]


def test_json_has_the_documented_top_level_keys_in_order(real_report: dict[str, Any]) -> None:
    assert list(real_report) == list(documented_example())


def test_json_nested_objects_have_the_documented_keys(real_report: dict[str, Any]) -> None:
    example = documented_example()
    for key in ("tool", "summary", "scan"):
        assert list(real_report[key]) == list(example[key])
    assert list(real_report["findings"][0]) == list(example["findings"][0])
    assert list(real_report["findings"][0]["location"]) == list(example["findings"][0]["location"])
    assert list(real_report["identities"][0]) == list(example["identities"][0])
    assert list(real_report["scan"]["skipped"][0]) == list(example["scan"]["skipped"][0])
    assert list(real_report["suppressed"][0]) == list(example["suppressed"][0])
    assert list(real_report["suppressed"][0]["finding"]) == list(example["findings"][0])


def test_json_values(real_report: dict[str, Any]) -> None:
    assert real_report["schema_version"] == SCHEMA_VERSION
    assert real_report["tool"]["name"] == "reviewblind"
    assert real_report["target"] == "mirror"
    assert real_report["verdict"] == "NOT_READY"
    assert real_report["summary"] == {
        "blocker": 1,
        "warning": 0,
        "review": 1,
        "info": 0,
        "suppressed": 1,
    }
    assert real_report["scan"]["complete"] is False
    assert real_report["scan"]["inspected"] == 2
    assert real_report["scan"]["skipped"][0]["reason"] == "UNSUPPORTED_BINARY"
    found = real_report["findings"][0]
    assert found["rule_id"] == "RB101"
    assert found["title"] == "Confirmed name in reviewer-visible text"
    assert found["severity"] == "BLOCKER"
    assert found["targets"] == ["ARCHIVE", "MIRROR", "REPOSITORY"]
    assert found["location"]["line"] == 1
    assert found["fingerprint"].startswith("rb1:")
    assert real_report["suppressed"][0]["reason"] == "Neutral self-citation"


def test_json_lists_confirmed_identities_for_export(real_report: dict[str, Any]) -> None:
    assert {"value": "Alice Example", "kind": "NAME", "source": "config"}.items() <= real_report[
        "identities"
    ][0].items()
    assert all(item["confirmed"] for item in real_report["identities"])


@pytest.mark.parametrize(
    ("items", "result", "verdict"),
    [
        ((finding(),), {}, "NOT_READY"),
        ((finding(severity=Severity.WARNING),), {}, "REVIEW_REQUIRED"),
        ((finding(severity=Severity.REVIEW),), {}, "REVIEW_REQUIRED"),
        ((finding(severity=Severity.INFO),), {}, "NO_KNOWN_LEAKS"),
        ((), {}, "NO_KNOWN_LEAKS"),
        ((), {"incomplete": True}, "NO_KNOWN_LEAKS_INCOMPLETE"),
    ],
)
def test_json_verdicts(items: tuple[Finding, ...], result: dict[str, Any], verdict: str) -> None:
    assert json.loads(render_json(report_of(*items, **result)))["verdict"] == verdict


def test_json_keeps_non_ascii_text_readable() -> None:
    document = render_json(report_of(finding(evidence="by Jos\u00e9 \u5f20\u4f1f")))
    assert "Jos\u00e9 \u5f20\u4f1f" in document


def test_json_can_always_be_encoded_as_utf8() -> None:
    # A file name with undecodable bytes reaches us with lone surrogates.
    bad = "data/\udcff.csv"
    item = finding(artifact=bad, location=Location(bad, field="a\udcff"))
    skipped = SkippedArtifact(bad, SkipReason.UNREADABLE, "bad\udcff")
    document = render_json(report_of(item, skipped=[skipped], notes=["n\udcff"]))
    document.encode("utf-8")
    assert json.loads(document)["findings"][0]["artifact"] == "data/.csv"


def test_json_removes_control_characters_from_paths() -> None:
    path = "a\x1b[31m\nb.txt"
    document = render_json(report_of(finding(artifact=path, location=Location(path))))
    loaded = json.loads(document)["findings"][0]
    assert loaded["artifact"] == "a[31m b.txt"
    assert loaded["location"]["path"] == "a[31m b.txt"


def test_json_ends_with_one_newline() -> None:
    document = render_json(report_of())
    assert document.endswith("}\n")
    assert "\r" not in document


# Determinism


@pytest.mark.parametrize("render", [render_json, render_markdown], ids=["json", "markdown"])
def test_reports_are_byte_identical_across_runs(tmp_path: Path, render: Any) -> None:
    # FR-REP-4 and NFR-DET-1
    init_repo(tmp_path, {"b.txt": "Alice Example\n", "a.txt": "/home/bob/x\n", "w.bin": b"\x00"})
    assert render(scan(tmp_path)) == render(scan(tmp_path))


def test_reports_contain_no_timestamps(tmp_path: Path) -> None:
    git_root = init_repo(tmp_path, {"a.txt": "Alice Example\n"})
    git(git_root, "status")
    for document in (render_json(scan(git_root)), render_markdown(scan(git_root))):
        assert not re.search(r"\b20\d\d-\d\d-\d\d\b", document)


# Paths in reports


def test_a_home_directory_is_abbreviated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    assert display_root(tmp_path / "research" / "paper") == "~/research/paper"


def test_a_path_outside_home_stays_absolute(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "somewhere")
    assert display_root(tmp_path / "x") == (tmp_path / "x").resolve().as_posix()


def test_a_config_inside_the_root_is_shown_relative_to_it(tmp_path: Path) -> None:
    report = replace(report_of(root=tmp_path), config_path=tmp_path / "sub" / "c.toml")
    assert display_config_path(report) == "sub/c.toml"


def test_a_missing_config_path_is_none(tmp_path: Path) -> None:
    assert display_config_path(report_of(root=tmp_path)) is None


# Markdown structure


def test_markdown_starts_with_the_marker(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.txt": "by Alice Example\n"})
    assert render_markdown(scan(tmp_path)).startswith(f"{MARKER}\n# ReviewBlind report\n")


def test_markdown_contains_every_section_in_order() -> None:
    document = render_markdown(
        report_of(
            finding(),
            finding(severity=Severity.WARNING),
            finding(severity=Severity.REVIEW),
            finding(severity=Severity.INFO),
            skipped=[SkippedArtifact("w.bin", SkipReason.UNSUPPORTED_BINARY, "unsupported")],
            notes=["A note"],
            suppressed=[SuppressedFinding(finding(), "A reason")],
            incomplete=True,
        )
    )
    headings = re.findall(r"^## (.+)$", document, re.MULTILINE)
    assert headings == [
        "Result: NOT READY FOR ANONYMOUS REVIEW",
        "Blockers",
        "Warnings",
        "Review",
        "Info",
        "Skipped",
        "Notes",
    ]
    assert "| Suppressed | 1 |" in document
    assert "--strict" in document


def test_markdown_shows_location_details() -> None:
    item = finding(location=Location("n.ipynb", field="output[7].traceback[3]", git_commit="a1b2"))
    document = render_markdown(report_of(item))
    assert "`n.ipynb`, `output[7].traceback[3]`, commit `a1b2`" in document


def test_markdown_omits_empty_sections() -> None:
    document = render_markdown(report_of())
    for heading in ("## Blockers", "## Skipped", "## Notes"):
        assert heading not in document


# Markdown injection (threat T-11)


@pytest.mark.parametrize(
    "payload",
    [
        "![tracker](http://attacker.example/pixel.png)",
        "[click me](http://attacker.example)",
        "<img src=x onerror=alert(1)>",
        "<script>alert(1)</script>",
        "# Fake heading",
        "| fake | row |",
    ],
)
@pytest.mark.parametrize(
    "where", ["evidence", "artifact", "field", "skipped", "skip_detail", "note"]
)
def test_repository_text_cannot_render_as_markdown(payload: str, where: str) -> None:
    item = finding()
    extra: dict[str, Any] = {}
    if where == "evidence":
        item = finding(evidence=payload)
    elif where == "artifact":
        item = finding(location=Location(payload))
    elif where == "field":
        item = finding(location=Location("a.txt", field=payload))
    elif where == "skipped":
        extra["skipped"] = [SkippedArtifact(payload, SkipReason.UNREADABLE, None)]
    elif where == "skip_detail":
        extra["skipped"] = [SkippedArtifact("a", SkipReason.UNREADABLE, payload)]
    else:
        extra["notes"] = [payload]
    outside = rendered_outside_code_spans(render_markdown(report_of(item, **extra)))
    # A backslash-escaped character renders as itself, so only unescaped markup is dangerous.
    assert not re.search(r"(?<!\\)<(img|script)|(?<!\\)\]\(http|!(?<!\\)\[|\n# Fake", outside)


@pytest.mark.parametrize("evidence", ["a`b", "``double``", "`starts", "ends`", "```", "x````y"])
def test_backticks_in_evidence_cannot_close_the_code_span(evidence: str) -> None:
    document = render_markdown(report_of(finding(evidence=f"{evidence} ![x](http://e/p.png)")))
    assert "![x]" not in rendered_outside_code_spans(document)


def test_line_breaks_cannot_escape_a_bullet() -> None:
    document = render_markdown(report_of(finding(evidence="safe\n\n## Injected heading")))
    assert "\n## Injected heading" not in document


def test_a_pipe_in_a_path_cannot_add_a_table_column() -> None:
    skipped = SkippedArtifact("a|b.bin", SkipReason.UNREADABLE, "c|d")
    document = render_markdown(report_of(skipped=[skipped]))
    row = next(line for line in document.splitlines() if "a\\|b.bin" in line)
    assert len(re.findall(r"(?<!\\)\|", row)) == 3


def test_markdown_prose_stays_readable() -> None:
    document = render_markdown(report_of(finding(reason="Visible to a reviewer-facing tool.")))
    assert "Visible to a reviewer-facing tool." in document


# Terminal


def test_terminal_shows_git_commit_and_field() -> None:
    item = finding(location=Location("a.ipynb", field="cell[1]", git_commit="a1b2"))
    plain = render_report(report_of(item)).plain
    assert "a.ipynb\ncommit a1b2\ncell[1]\n" in plain


@pytest.mark.parametrize(
    ("location", "expected"),
    [
        (Location("a.txt"), "a.txt\n"),
        (Location("a.txt", line=3), "a.txt:3\n"),
        (Location("a.txt", line=3, column=9), "a.txt:3:9\n"),
    ],
)
def test_terminal_location_formats(location: Location, expected: str) -> None:
    assert expected in render_report(report_of(finding(location=location))).plain


def test_terminal_sanitizes_what_scanners_do_not() -> None:
    plain = render_report(
        report_of(
            finding(location=Location("a\x1b[31mb.txt")),
            skipped=[SkippedArtifact("c\x1bd", SkipReason.UNREADABLE, "e\x1bf")],
            notes=["g\x1bh"],
        )
    ).plain
    assert "\x1b" not in plain
