"""Term lists (FR-EXP-1 to FR-EXP-7), and hostile reports (T-14)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from _helpers import PERSONA, scan, symlink_or_skip, write_tree
from reviewblind import cli
from reviewblind.exporters.terms import (
    SUPPORTED_SCHEMA_VERSION,
    ReportError,
    TermFormat,
    parse_report,
    render_terms,
)
from reviewblind.reporters.json import SCHEMA_VERSION, render_discovery_json, render_json

runner = CliRunner()


def identity(value: str, *, confirmed: bool = True, kind: str = "NAME") -> dict[str, Any]:
    return {
        "value": value,
        "kind": kind,
        "source": "config",
        "confidence": "HIGH",
        "confirmed": confirmed,
    }


def finding(rule_id: str, matched: str, owner: str | None = "aliceexample") -> dict[str, Any]:
    return {"rule_id": rule_id, "matched": matched, "identity": owner}


def report(
    identities: list[Any] | None = None,
    findings: list[Any] | None = None,
    *,
    complete: bool = True,
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "tool": {"name": "reviewblind", "version": "0.1.0"},
        "scan": {"complete": complete},
        "identities": [identity("Alice Example")] if identities is None else identities,
        "findings": findings or [],
    }


def encoded(document: object) -> bytes:
    return json.dumps(document).encode("utf-8")


def terms_of(document: object) -> tuple[str, ...]:
    return parse_report(encoded(document)).terms


@pytest.fixture
def saved(tmp_path: Path) -> Path:
    path = tmp_path / "report.json"
    path.write_bytes(encoded(report()))
    return path


# Which terms


def test_the_example_in_the_documentation() -> None:
    document = report(
        [
            identity("Alice Example"),
            identity("alice@example.edu", kind="EMAIL"),
            identity("aliceexample", kind="USERNAME"),
            identity("Example University", kind="AFFILIATION"),
        ],
        [finding("RB105", "github.com/aliceexample")],
    )
    source = parse_report(encoded(document))
    assert render_terms(source.terms, TermFormat.ANONYMOUS_GITHUB) == (
        "github\\.com/aliceexample\n"
        "Example University\n"
        "alice@example\\.edu\n"
        "Alice Example\n"
        "aliceexample\n"
    )


def test_all_three_url_rules_contribute_their_match() -> None:
    document = report(
        findings=[
            finding("RB105", "github.com/aliceexample"),
            finding("RB203", "wandb.ai/aliceexample/proj"),
            finding("RB204", "gitlab.com/aliceexample/tools"),
        ]
    )
    assert set(terms_of(document)) == {
        "Alice Example",
        "github.com/aliceexample",
        "wandb.ai/aliceexample/proj",
        "gitlab.com/aliceexample/tools",
    }


def test_an_unconfirmed_namespace_is_left_out() -> None:
    # It may belong to someone else, and replacing it would hide a third party's public work.
    document = report(findings=[finding("RB203", "wandb.ai/someone-else/proj", owner=None)])
    assert terms_of(document) == ("Alice Example",)


@pytest.mark.parametrize("rule_id", ["RB101", "RB201", "RB202", "RB205", "RB401", "RB602"])
def test_other_rules_add_no_terms(rule_id: str) -> None:
    document = report(findings=[finding(rule_id, "/home/aliceexample/some/path")])
    assert terms_of(document) == ("Alice Example",)


def test_an_unconfirmed_identity_is_left_out() -> None:
    document = report([identity("Alice Example"), identity("Bob Sample", confirmed=False)])
    assert terms_of(document) == ("Alice Example",)


def test_a_suppressed_finding_adds_no_term() -> None:
    document = report()
    document["suppressed"] = [
        {"finding": finding("RB204", "github.com/aliceexample/old"), "reason": "cited on purpose"}
    ]
    assert terms_of(document) == ("Alice Example",)


def test_terms_from_a_real_scan(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "a.md": "See https://github.com/aliceexample and https://alice.example.dev now.\n",
            "b.sh": "git clone https://gitlab.com/aliceexample/tools.git\n",
            "c.yaml": "a: https://wandb.ai/aliceexample/proj\nb: https://wandb.ai/someone/proj\n",
        },
    )
    terms = parse_report(render_json(scan(tmp_path)).encode("utf-8")).terms
    assert set(terms) == {
        "Alice Example",
        "alice@example.edu",
        "aliceexample",
        "Example University",
        "EU",
        "A. Example",
        "https://alice.example.dev",
        "github.com/aliceexample",
        "gitlab.com/aliceexample/tools.git",
        "wandb.ai/aliceexample/proj",
    }


# Order


def test_longest_first_and_ties_are_lexicographic() -> None:
    document = report([identity(value) for value in ("bb", "aaa", "ccc", "d", "dddd")])
    assert terms_of(document) == ("dddd", "aaa", "ccc", "bb", "d")


def test_a_short_term_cannot_come_before_one_it_is_part_of() -> None:
    terms = terms_of(
        report(
            [identity("aliceexample", kind="USERNAME")],
            [finding("RB204", "github.com/aliceexample/tools")],
        )
    )
    assert terms.index("github.com/aliceexample/tools") < terms.index("aliceexample")


def test_duplicates_are_removed_by_casefolded_value() -> None:
    document = report(
        [identity("Alice Example"), identity("ALICE EXAMPLE"), identity("alice example")],
        [finding("RB105", "Alice Example")],
    )
    assert len(terms_of(document)) == 1


def test_forms_that_are_different_bytes_are_both_kept() -> None:
    # A proxy compares text, so it needs both spellings even though they look the same.
    document = report([identity("Jos\u00e9"), identity("Jose\u0301")])
    assert len(terms_of(document)) == 2


def test_the_same_input_gives_the_same_order() -> None:
    values = ["Alice Example", "ALICE EXAMPLE", "Stra\u00dfe", "STRASSE", "zz", "aa"]
    forwards = terms_of(report([identity(value) for value in values]))
    backwards = terms_of(report([identity(value) for value in reversed(values)]))
    assert forwards == backwards


# Formats


@pytest.mark.parametrize(
    "term",
    [
        "A. Example (PhD)",
        "alice+tag@example.edu",
        "C++ [Lab] {Group}",
        "back\\slash",
        "a|b",
        "^start$",
        "what?*",
        "(a+)+",
    ],
)
def test_an_escaped_term_matches_exactly_itself(term: str) -> None:
    pattern = render_terms([term], TermFormat.ANONYMOUS_GITHUB).rstrip("\n")
    assert re.fullmatch(pattern, term)
    assert not re.fullmatch(pattern, term.replace(term[-2], "x") + "x")


@pytest.mark.parametrize(
    "term", ["Alice Example", "alice-example", "a/b", "alice@example", "Jos\u00e9"]
)
def test_only_regex_syntax_is_escaped(term: str) -> None:
    assert render_terms([term], TermFormat.ANONYMOUS_GITHUB) == f"{term}\n"


def test_a_replacement_arrow_cannot_split_a_term() -> None:
    # Anonymous GitHub reads `left=>right` as "replace left with right", which would publish `right`.
    rendered = render_terms(["Alice=>Example"], TermFormat.ANONYMOUS_GITHUB).rstrip("\n")
    assert "=>" not in rendered
    assert re.fullmatch(rendered, "Alice=>Example")


@pytest.mark.parametrize("term_format", [TermFormat.PLAIN, TermFormat.HIDO])
def test_literal_formats_change_nothing(term_format: TermFormat) -> None:
    terms = ("alice@example.edu", "A. Example (PhD)", "a=>b")
    assert render_terms(terms, term_format) == "alice@example.edu\nA. Example (PhD)\na=>b\n"


def test_output_is_only_terms(saved: Path) -> None:
    # FR-EXP-5: no Git rewrite rules, or anything else a proxy would read as a term.
    result = runner.invoke(cli.app, ["export", str(saved)])
    assert result.stdout == "Alice Example\n"


@pytest.mark.parametrize("option", ["anonymous-github", "hido", "plain"])
def test_each_format_is_available(saved: Path, option: str) -> None:
    assert runner.invoke(cli.app, ["export", str(saved), "--format", option]).exit_code == 0


def test_an_unknown_format_is_a_usage_error(saved: Path) -> None:
    assert runner.invoke(cli.app, ["export", str(saved), "--format", "sarif"]).exit_code == 2


# Incomplete scans (FR-EXP-7)


def test_an_incomplete_scan_warns_on_stderr_only(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_bytes(encoded(report(complete=False)))
    result = runner.invoke(cli.app, ["export", str(path)])
    assert result.exit_code == 0
    assert "incomplete" in result.stderr
    assert result.stdout == "Alice Example\n"


def test_a_complete_scan_does_not_warn(saved: Path) -> None:
    assert runner.invoke(cli.app, ["export", str(saved)]).stderr == ""


def test_blockers_do_not_prevent_an_export(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    document = report()
    document["verdict"] = "NOT_READY"
    path.write_bytes(encoded(document))
    assert runner.invoke(cli.app, ["export", str(path)]).exit_code == 0


# Reading a report


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-32"])
def test_a_report_saved_with_a_byte_order_mark_can_be_read(encoding: str) -> None:
    # Windows PowerShell's `>` writes UTF-16, and that is how many people will save a report.
    content = json.dumps(report([identity("Jos\u00e9")]), ensure_ascii=False).encode(encoding)
    assert parse_report(content).terms == ("Jos\u00e9",)


def test_the_reader_supports_the_version_the_reporter_writes() -> None:
    assert SUPPORTED_SCHEMA_VERSION == SCHEMA_VERSION


# Hostile or wrong reports (FR-EXP-6, T-14)


def _with(**changes: Any) -> dict[str, Any]:
    return {**report(), **changes}


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"", "not a JSON report"),
        (b"not json", "not a JSON report"),
        (b"\xff\xfe\xff", "not a JSON report"),
        (b"\xc3\x28", "not a JSON report"),
        (b"[" * 200_000, "not a JSON report"),
        (b'{"schema_version": ' + b"9" * 5000 + b"}", "not a JSON report"),
        (encoded([]), "the report must be an object"),
        (encoded("text"), "the report must be an object"),
        (encoded(None), "the report must be an object"),
    ],
)
def test_what_is_not_a_json_object_is_refused(content: bytes, message: str) -> None:
    with pytest.raises(ReportError, match=message):
        parse_report(content)


@pytest.mark.parametrize("version", [0, 2, 99, -1])
def test_an_unsupported_version_is_refused(version: int) -> None:
    with pytest.raises(ReportError, match=f"unsupported schema_version {version}"):
        parse_report(encoded(_with(schema_version=version)))


@pytest.mark.parametrize("version", ["1", 1.0, True, None, [1]])
def test_a_version_of_the_wrong_type_is_refused(version: object) -> None:
    with pytest.raises(ReportError, match="schema_version must be an integer"):
        parse_report(encoded(_with(schema_version=version)))


@pytest.mark.parametrize(
    "document",
    [
        _with(tool=None),
        _with(tool="reviewblind"),
        _with(tool={"name": "another-tool"}),
        _with(scan=None),
        _with(scan={"complete": "yes"}),
        _with(scan={}),
        _with(identities=None),
        _with(identities={}),
        _with(identities=["Alice Example"]),
        _with(identities=[{"value": "Alice Example"}]),
        _with(identities=[{"value": "Alice Example", "confirmed": 1}]),
        _with(findings=None),
        _with(findings=["RB105"]),
    ],
)
def test_a_report_of_the_wrong_shape_is_refused(document: dict[str, Any]) -> None:
    with pytest.raises(ReportError):
        parse_report(encoded(document))


def test_the_output_of_discover_is_refused() -> None:
    from reviewblind.discovery import Discovery

    content = render_discovery_json(Discovery(candidates=(), notes=())).encode("utf-8")
    with pytest.raises(ReportError):
        parse_report(content)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        None,
        7,
        ["Alice Example"],
        "Alice\nExample",  # would become two terms
        "Alice\rExample",
        "Alice\u2028Example",
        "Alice\x1b[31mExample",  # would reach the terminal
        "Alice\u202eExample",  # would reorder the text
        "Alice\x00Example",
        "\ud800",  # cannot even be written as UTF-8
    ],
)
def test_a_value_that_is_not_a_usable_term_is_refused(value: object) -> None:
    with pytest.raises(ReportError, match="not a usable term"):
        parse_report(encoded(report([identity("x") | {"value": value}])))
    with pytest.raises(ReportError, match="not a usable term"):
        parse_report(encoded(report(findings=[finding("RB204", "x") | {"matched": value}])))


def test_a_joiner_is_part_of_a_name_and_is_kept() -> None:
    name = "\u09b2\u0995\u09cd\u200d\u09b7\u09cd\u09ae\u09c0"
    assert terms_of(report([identity(name)])) == (name,)


def test_surrounding_space_is_removed() -> None:
    assert terms_of(report([identity("  Alice Example ")])) == ("Alice Example",)


def test_a_report_with_nothing_to_export_is_an_error_rather_than_an_empty_list() -> None:
    with pytest.raises(ReportError, match="no confirmed identities"):
        parse_report(encoded(report([])))
    with pytest.raises(ReportError, match="no confirmed identities"):
        parse_report(encoded(report([identity("Bob Sample", confirmed=False)])))


@pytest.mark.parametrize(
    "content",
    [b"not json", encoded(_with(schema_version=2)), encoded(_with(identities=[]))],
    ids=["malformed", "wrong-version", "empty"],
)
def test_the_cli_exits_2_and_writes_nothing(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "report.json"
    path.write_bytes(content)
    output = tmp_path / "terms.txt"
    result = runner.invoke(cli.app, ["export", str(path), "-o", str(output)])
    assert result.exit_code == 2
    assert result.stdout == ""
    assert not output.exists()


def test_a_missing_report_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(cli.app, ["export", str(tmp_path / "absent.json")])
    assert result.exit_code == 2
    assert "cannot read" in result.stderr


def test_a_directory_exits_2(tmp_path: Path) -> None:
    assert runner.invoke(cli.app, ["export", str(tmp_path)]).exit_code == 2


def test_a_report_over_the_cap_exits_2(saved: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from reviewblind.exporters import terms

    monkeypatch.setattr(terms, "MAX_REPORT_BYTES", 10)
    result = runner.invoke(cli.app, ["export", str(saved)])
    assert result.exit_code == 2
    assert "too large" in result.stderr


def test_an_unexpected_failure_exits_4(saved: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(_path: Path) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "read_report", fail)
    result = runner.invoke(cli.app, ["export", str(saved)])
    assert result.exit_code == 4
    assert "internal error" in result.stderr


# Writing a term list


def test_a_file_has_lf_line_endings_and_a_warning(saved: Path, tmp_path: Path) -> None:
    output = tmp_path / "terms.txt"
    result = runner.invoke(cli.app, ["export", str(saved), "-o", str(output)])
    assert result.exit_code == 0
    assert output.read_bytes() == b"Alice Example\n"
    assert result.stdout == ""
    assert "Do not include it in the artifact" in result.stderr


def test_stdout_has_lf_line_endings_on_every_platform(saved: Path) -> None:
    # Anonymous GitHub splits its input on LF, so a CR would become part of every term.
    environment = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    completed = subprocess.run(
        [sys.executable, "-m", "reviewblind", "export", str(saved)],
        capture_output=True,
        env=environment,
        check=True,
        timeout=60,
    )
    assert completed.stdout == b"Alice Example\n"


def test_non_ascii_terms_survive_stdout_on_any_console(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_bytes(encoded(report([identity("Jos\u00e9 \u0985\u09b2\u09bf\u09b8")])))
    environment = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    completed = subprocess.run(
        [sys.executable, "-m", "reviewblind", "export", str(path)],
        capture_output=True,
        env=environment,
        check=True,
        timeout=60,
    )
    assert completed.stdout.decode("utf-8") == "Jos\u00e9 \u0985\u09b2\u09bf\u09b8\n"


def test_a_term_list_is_not_written_through_a_symlink(saved: Path, tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("precious\n", "utf-8")
    link = tmp_path / "terms.txt"
    symlink_or_skip(link, victim)
    result = runner.invoke(cli.app, ["export", str(saved), "-o", str(link)])
    assert result.exit_code == 2
    assert victim.read_text("utf-8") == "precious\n"


def test_an_unwritable_destination_exits_2(saved: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        cli.app, ["export", str(saved), "-o", str(tmp_path / "no" / "terms.txt")]
    )
    assert result.exit_code == 2
    assert "cannot write" in result.stderr


def test_the_persona_in_the_helpers_can_be_exported(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.txt": "nothing\n"})
    terms = parse_report(render_json(scan(tmp_path)).encode("utf-8")).terms
    assert set(terms) == set(PERSONA.identity.names) | set(PERSONA.identity.emails) | set(
        PERSONA.identity.usernames
    ) | set(PERSONA.identity.affiliations) | set(PERSONA.identity.aliases) | set(
        PERSONA.identity.urls
    )
