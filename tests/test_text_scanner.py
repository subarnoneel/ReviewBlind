"""Text, signal and path detection, through the engine (FR-TEXT-1 to FR-TEXT-4, FR-PATH-1)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from _helpers import PERSONA, findings, rules_found, scan, write_tree
from reviewblind import engine
from reviewblind.config import Config, IdentityConfig, ScanSettings
from reviewblind.matching import IdentityMatcher
from reviewblind.models import Confidence, Finding, Severity, SkipReason, Target
from reviewblind.scanners import base as scanner_base
from reviewblind.scanners import text as text_scanner


def in_text(tmp_path: Path, text: str, name: str = "notes.txt") -> list[Finding]:
    write_tree(tmp_path, {name: text})
    return findings(tmp_path)


def only(items: list[Finding]) -> Finding:
    assert len(items) == 1, rules_found(items)
    return items[0]


# Confirmed identities


@pytest.mark.parametrize(
    ("text", "rule", "severity", "matched"),
    [
        ("by Alice Example\n", "RB101", Severity.BLOCKER, "Alice Example"),
        ("by A. Example\n", "RB101", Severity.BLOCKER, "A. Example"),
        ("mail alice@example.edu\n", "RB102", Severity.BLOCKER, "alice@example.edu"),
        ("# maintained by aliceexample\n", "RB103", Severity.BLOCKER, "aliceexample"),
        ("at Example University\n", "RB104", Severity.WARNING, "Example University"),
        (
            "see https://alice.example.dev/cv\n",
            "RB105",
            Severity.BLOCKER,
            "https://alice.example.dev",
        ),
    ],
)
def test_confirmed_identities(
    tmp_path: Path, text: str, rule: str, severity: Severity, matched: str
) -> None:
    finding = only(in_text(tmp_path, text))
    assert (finding.rule_id, finding.severity, finding.matched) == (rule, severity, matched)
    assert finding.confidence is Confidence.HIGH
    assert finding.identity is not None


def test_acronyms_follow_their_case(tmp_path: Path) -> None:
    exact = only(in_text(tmp_path, "the EU lab\n"))
    assert (exact.severity, exact.confidence) == (Severity.WARNING, Confidence.MEDIUM)
    other = only(in_text(tmp_path, "the eu lab\n"))
    assert (other.severity, other.confidence) == (Severity.REVIEW, Confidence.LOW)


def test_location_evidence_and_reason(tmp_path: Path) -> None:
    finding = only(in_text(tmp_path, "first\nMaintained by Alice Example at the lab\n", "doc.md"))
    assert finding.artifact == "doc.md"
    assert (finding.location.line, finding.location.column) == (2, 15)
    assert finding.evidence == "Maintained by Alice Example at the lab"
    assert finding.reason
    assert finding.remediation
    assert finding.fingerprint.startswith("rb1:")


def test_evidence_on_a_long_line_keeps_the_match_in_view(tmp_path: Path) -> None:
    finding = only(in_text(tmp_path, "x " * 500 + "Alice Example" + " y" * 500))
    assert "Alice Example" in finding.evidence
    assert len(finding.evidence) <= 160


def test_a_name_split_across_lines_is_found_once(tmp_path: Path) -> None:
    finding = only(in_text(tmp_path, "\\author{Alice\n  Example}\n", "paper.tex"))
    assert finding.matched == "Alice   Example"
    assert finding.evidence == "\\author{Alice   Example}"


# Home paths


@pytest.mark.parametrize(
    "path",
    [
        "/home/aliceexample/data",
        "/Users/aliceexample/data",
        "C:\\Users\\aliceexample\\data",
        "C:\\\\Users\\\\aliceexample\\\\data",
        "C:/Users/aliceexample/data",
        "d:\\users\\aliceexample\\data",
        "file:///home/aliceexample/data",
    ],
)
def test_home_path_with_a_confirmed_username(tmp_path: Path, path: str) -> None:
    finding = only(in_text(tmp_path, f'path = "{path}"\n'))
    assert finding.rule_id == "RB201"
    assert (finding.severity, finding.confidence) == (Severity.WARNING, Confidence.HIGH)
    assert finding.identity == "aliceexample"


def test_home_path_with_another_username_needs_review(tmp_path: Path) -> None:
    finding = only(in_text(tmp_path, "cd /home/bob/project\n"))
    assert finding.rule_id == "RB201"
    assert (finding.severity, finding.confidence) == (Severity.REVIEW, Confidence.MEDIUM)
    assert finding.identity is None


@pytest.mark.parametrize(
    "text",
    [
        "/home/user/project",
        "/home/ubuntu/project",
        "/home/runner/work/x",
        "/home/jovyan/work",
        "/Users/username/x",
        "C:\\Users\\runneradmin\\x",
        "/home/$USER/x",
        "/home/<user>/x",
        "https://example.org/home/about",
        "/var/www/home/page",
    ],
)
def test_placeholders_and_web_routes_are_not_home_paths(tmp_path: Path, text: str) -> None:
    assert in_text(tmp_path, f"{text}\n") == []


# Hostnames


@pytest.mark.parametrize(
    ("text", "matched"),
    [
        ("ssh cluster.cs.example.edu\n", "cluster.cs.example.edu"),
        ("https://www.example.edu/lab\n", "www.example.edu"),
        ("EXAMPLE.EDU\n", "EXAMPLE.EDU"),
        ("write to bob@cs.example.edu\n", "cs.example.edu"),
    ],
)
def test_institutional_hostnames(tmp_path: Path, text: str, matched: str) -> None:
    finding = only(in_text(tmp_path, text))
    assert (finding.rule_id, finding.severity) == ("RB202", Severity.WARNING)
    assert finding.matched == matched


@pytest.mark.parametrize("text", ["notexample.edu", "example.education", "example.edu-mirror"])
def test_lookalike_hostnames_do_not_match(tmp_path: Path, text: str) -> None:
    assert in_text(tmp_path, f"{text}\n") == []


def test_public_mail_providers_are_not_institutions(tmp_path: Path) -> None:
    config = Config(identity=IdentityConfig(emails=("alice.example@gmail.com",)))
    write_tree(tmp_path, {"a.txt": "see gmail.com and bob@gmail.com\n"})
    assert findings(tmp_path, config=config) == []


# Service namespaces


@pytest.mark.parametrize(
    "text",
    [
        "https://wandb.ai/aliceexample/proj",
        "huggingface.co/aliceexample/model",
        "https://huggingface.co/datasets/aliceexample/data",
        "s3://aliceexample/results",
        "gs://aliceexample-results/x",
        "wandb.ai/aliceexample-lab/proj",
    ],
)
def test_confirmed_research_service_namespaces(tmp_path: Path, text: str) -> None:
    finding = only(in_text(tmp_path, f"{text}\n"))
    assert finding.rule_id == "RB203"
    assert (finding.severity, finding.confidence) == (Severity.WARNING, Confidence.HIGH)


@pytest.mark.parametrize(
    "text", ["https://wandb.ai/bob/proj", "s3://some-bucket/x", "gs://other/y"]
)
def test_unconfirmed_accounts_and_buckets_need_review(tmp_path: Path, text: str) -> None:
    finding = only(in_text(tmp_path, f"{text}\n"))
    assert finding.rule_id == "RB203"
    assert (finding.severity, finding.confidence) == (Severity.REVIEW, Confidence.LOW)


@pytest.mark.parametrize(
    "text",
    [
        "github.com/pytorch/pytorch",
        "https://gitlab.com/inkscape/inkscape",
        "huggingface.co/bert-base-uncased",
        "https://huggingface.co/datasets/squad",
        "https://wandb.ai/site",
        "see github.com",
        "https://mygithub.com/aliceexample2",
    ],
)
def test_generic_urls_are_not_findings(tmp_path: Path, text: str) -> None:
    assert in_text(tmp_path, f"{text}\n") == []


@pytest.mark.parametrize(
    ("text", "matched"),
    [
        ("https://github.com/aliceexample/tools.git", "github.com/aliceexample/tools.git"),
        ("git@github.com:aliceexample/paper.git", "github.com:aliceexample/paper.git"),
        ("ssh://git@gitlab.com/aliceexample/paper", "gitlab.com/aliceexample/paper"),
        ("see github.com/aliceexample/tools.", "github.com/aliceexample/tools"),
    ],
)
def test_personal_git_namespaces(tmp_path: Path, text: str, matched: str) -> None:
    finding = only(in_text(tmp_path, f"{text}\n"))
    assert (finding.rule_id, finding.severity) == ("RB204", Severity.BLOCKER)
    assert finding.matched == matched


@pytest.mark.parametrize(
    "text",
    ["https://github.com/aliceexample", "gitlab.com/aliceexample/", "aliceexample.github.io/cv"],
)
def test_profile_urls(tmp_path: Path, text: str) -> None:
    finding = only(in_text(tmp_path, f"{text}\n"))
    assert (finding.rule_id, finding.severity) == ("RB105", Severity.BLOCKER)


# Scheduler directives


@pytest.mark.parametrize(
    "line",
    [
        "#SBATCH --mail-user=a.example@lab.example.org",
        "#SBATCH --mail-user a.example@lab.example.org",
        "#SBATCH --account=lab-account",
        "#SBATCH -A lab-account",
        "  #SBATCH --uid=someone",
        "#PBS -M a.example@lab.example.org",
        "#BSUB -u a.example@lab.example.org",
        "#$ -M a.example@lab.example.org",
    ],
)
def test_scheduler_directives(tmp_path: Path, line: str) -> None:
    finding = only(in_text(tmp_path, f"#!/bin/bash\n{line}\n", "train.sbatch"))
    assert finding.rule_id == "RB205"
    assert (finding.severity, finding.confidence) == (Severity.WARNING, Confidence.MEDIUM)


def test_a_scheduler_directive_read_from_the_environment_is_fine(tmp_path: Path) -> None:
    assert in_text(tmp_path, "#SBATCH --mail-user=$USER_EMAIL\n", "train.sbatch") == []


def test_a_comment_mentioning_sbatch_is_not_a_directive(tmp_path: Path) -> None:
    assert in_text(tmp_path, "# run with sbatch --account=lab\nx = 1\n") == []


# Overlaps, through the whole pipeline


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        ("alice@example.edu", "RB102"),
        ("aliceexample@example.edu", "RB103"),
        ("/home/aliceexample/data", "RB201"),
        ("wandb.ai/aliceexample/run", "RB203"),
        ("github.com/aliceexample/tools", "RB204"),
        ("#SBATCH --mail-user=alice@example.edu", "RB102"),
    ],
)
def test_one_finding_survives_when_one_match_contains_another(
    tmp_path: Path, text: str, rule: str
) -> None:
    items = in_text(tmp_path, f"{text}\n")
    assert rule in rules_found(items)
    if text != "aliceexample@example.edu":
        assert rules_found(items) == [rule]


def test_partly_overlapping_identities_are_both_reported(tmp_path: Path) -> None:
    assert sorted(rules_found(in_text(tmp_path, "Alice Example University\n"))) == [
        "RB101",
        "RB104",
    ]


def test_a_rule_that_raises_nothing_does_not_hide_what_it_contains(tmp_path: Path) -> None:
    # This URL raises no finding by itself, so the name inside it must still be found.
    finding = only(in_text(tmp_path, "huggingface.co/Alice Example\n"))
    assert finding.rule_id == "RB101"


# File names


def test_identity_in_a_file_name(tmp_path: Path) -> None:
    write_tree(tmp_path, {"data/aliceexample_results.csv": "1,2\n"})
    finding = only(findings(tmp_path))
    assert (finding.rule_id, finding.severity) == ("RB106", Severity.BLOCKER)
    assert finding.artifact == "data/aliceexample_results.csv"


def test_a_directory_is_reported_once_not_for_every_file(tmp_path: Path) -> None:
    write_tree(tmp_path, {f"aliceexample/{index}.txt": "x" for index in range(5)})
    finding = only(findings(tmp_path))
    assert finding.artifact == "aliceexample"


def test_an_affiliation_in_a_file_name_is_a_warning(tmp_path: Path) -> None:
    write_tree(tmp_path, {"Example University.txt": "x"})
    assert only(findings(tmp_path)).severity is Severity.WARNING


def test_binary_files_still_have_their_names_checked(tmp_path: Path) -> None:
    write_tree(tmp_path, {"aliceexample.bin": b"\x00\x01"})
    report = scan(tmp_path)
    assert rules_found(report.result.findings) == ["RB106", "RB803"]


# Encodings and limits


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "utf-32"])
def test_supported_encodings(tmp_path: Path, encoding: str) -> None:
    write_tree(tmp_path, {"a.txt": "by Alice Example\n".encode(encoding)})
    assert rules_found(findings(tmp_path)) == ["RB101"]


def test_invalid_utf8_after_the_sample_is_reported_not_guessed(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.txt": b"x" * 10_000 + b"\xff by Alice Example"})
    report = scan(tmp_path)
    assert report.result.findings == []
    assert report.result.skipped[0].reason is SkipReason.UNSUPPORTED_BINARY
    assert report.result.incomplete


def test_a_file_over_the_cap_is_skipped(tmp_path: Path) -> None:
    write_tree(tmp_path, {"big.txt": "Alice Example " * 10, "small.txt": "ok\n"})
    config = replace(PERSONA, scan=ScanSettings(max_text_bytes=20, exclude=()))
    report = scan(tmp_path, config=config)
    assert report.result.findings == []
    assert report.result.skipped[0].path == "big.txt"
    assert report.result.skipped[0].reason is SkipReason.TOO_LARGE
    assert report.result.incomplete
    assert report.result.inspected == 1


def test_a_file_that_grows_past_the_cap_is_still_caught(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(tmp_path, {"big.txt": "Alice Example " * 10})
    config = replace(PERSONA, scan=ScanSettings(max_text_bytes=20, exclude=()))
    real_scan = text_scanner.TextScanner.scan

    def understate_size(self, artifact, context):  # type: ignore[no-untyped-def]
        return real_scan(self, replace(artifact, size=1), context)

    monkeypatch.setattr(text_scanner.TextScanner, "scan", understate_size)
    report = scan(tmp_path, config=config)
    assert report.result.skipped[0].reason is SkipReason.TOO_LARGE


def test_too_many_matches_is_reported_as_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(text_scanner, "MAX_DETECTIONS_PER_ARTIFACT", 3)
    write_tree(tmp_path, {"a.txt": "Alice Example\n" * 10})
    report = scan(tmp_path)
    assert len(report.result.findings) == 3
    assert report.result.skipped[0].reason is SkipReason.TOO_MANY_MATCHES
    assert report.result.incomplete


def test_too_many_findings_keeps_the_most_severe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(engine, "MAX_FINDINGS_PER_ARTIFACT", 1)
    write_tree(tmp_path, {"a.txt": "Example University\nAlice Example\n"})
    report = scan(tmp_path)
    assert rules_found(report.result.findings) == ["RB101"]
    assert report.result.skipped[0].reason is SkipReason.TOO_MANY_MATCHES


def test_the_limit_constants_are_set() -> None:
    assert scanner_base.MAX_DETECTIONS_PER_ARTIFACT > engine.MAX_FINDINGS_PER_ARTIFACT


# Whole scans


@pytest.mark.parametrize(
    ("name", "content", "reason"),
    [
        ("analysis.ipynb", "{}", SkipReason.UNSUPPORTED_BINARY),
        ("figure.pdf", b"%PDF-1.7", SkipReason.UNSUPPORTED_BINARY),
        ("plot.png", b"\x89PNG", SkipReason.UNSUPPORTED_BINARY),
        ("weights.bin", b"\x00\x01", SkipReason.UNSUPPORTED_BINARY),
        ("data.zip", b"PK", SkipReason.ARCHIVE_NOT_INSPECTED),
    ],
)
def test_files_no_scanner_can_read_make_the_scan_incomplete(
    tmp_path: Path, name: str, content: str | bytes, reason: SkipReason
) -> None:
    # FR-COMP-2: never claim to have inspected something that was not.
    write_tree(tmp_path, {name: content})
    report = scan(tmp_path)
    assert report.result.incomplete
    assert report.result.skipped[0].reason is reason
    assert report.result.inspected == 0


def test_a_scanner_failure_is_contained_to_one_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # NFR-REL-1
    write_tree(tmp_path, {"bad.txt": "BOOM", "good.txt": "Alice Example\n"})
    real_find = IdentityMatcher.find

    def fail_on_boom(self, text):  # type: ignore[no-untyped-def]
        if "BOOM" in text:
            raise RecursionError("too deep")
        return real_find(self, text)

    monkeypatch.setattr(IdentityMatcher, "find", fail_on_boom)
    report = scan(tmp_path)
    assert rules_found(report.result.findings) == ["RB101"]
    assert report.result.skipped[0].path == "bad.txt"
    assert report.result.skipped[0].reason is SkipReason.SCANNER_ERROR
    assert "RecursionError" in (report.result.skipped[0].detail or "")
    assert report.result.incomplete


def test_findings_are_sorted_most_severe_first(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.txt": "at Example University\n", "b.txt": "by Alice Example\n"})
    assert rules_found(findings(tmp_path)) == ["RB101", "RB104"]


def test_two_scans_are_identical(tmp_path: Path) -> None:
    # NFR-DET-1
    write_tree(tmp_path, {"a.txt": "Alice Example\n/home/bob/x\n", "aliceexample.txt": "x"})
    assert scan(tmp_path).result == scan(tmp_path).result


def test_the_active_config_is_not_scanned_as_text(tmp_path: Path) -> None:
    write_tree(tmp_path, {".reviewblind.toml": 'names = ["Alice Example"]\n', "a.txt": "ok\n"})
    report = engine.run_scan(tmp_path, PERSONA, Target.MIRROR, tmp_path / ".reviewblind.toml")
    assert rules_found(report.result.findings) == ["RB805"]
    assert not report.result.incomplete


def test_a_scan_with_nothing_to_find_is_complete(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.py": "import os\n"})
    report = scan(tmp_path)
    assert report.result.findings == []
    assert not report.result.incomplete
    assert report.result.inspected == 1
