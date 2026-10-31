"""Files that should not ship, or cannot be read (FR-PKG-1 to FR-PKG-3, threats T-20 and T-21)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from _helpers import PERSONA, findings, git, init_repo, rules_found, scan, write_tree
from reviewblind.config import ScanSettings
from reviewblind.engine import run_scan
from reviewblind.models import ArtifactKind, Severity, SkipReason, Target
from reviewblind.reporters.json import render_json
from reviewblind.reporters.markdown import render_markdown
from reviewblind.reporters.terminal import render_report
from reviewblind.utils.files import classify


def only_rule(root: Path, rule_id: str, target: Target = Target.MIRROR) -> Severity:
    matching = [item for item in findings(root, target) if item.rule_id == rule_id]
    assert len(matching) == 1, rules_found(matching)
    return matching[0].severity


# RB801: .git


@pytest.mark.parametrize(
    ("target", "severity"),
    [
        (Target.MIRROR, Severity.INFO),
        (Target.ARCHIVE, Severity.BLOCKER),
        (Target.REPOSITORY, Severity.INFO),
    ],
)
def test_git_directory_severity_depends_on_target(
    tmp_path: Path, target: Target, severity: Severity
) -> None:
    init_repo(tmp_path)
    assert only_rule(tmp_path, "RB801", target) is severity


def test_no_git_directory_means_no_finding(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.txt": "x"})
    assert "RB801" not in rules_found(findings(tmp_path, Target.ARCHIVE))


def test_excluding_git_clears_the_finding(tmp_path: Path) -> None:
    # D-08: this is how an author states that .git will not be packaged.
    init_repo(tmp_path)
    config = PERSONA.__class__(identity=PERSONA.identity, scan=ScanSettings(exclude=(".git/**",)))
    assert "RB801" not in rules_found(findings(tmp_path, Target.ARCHIVE, config))


def test_a_git_file_counts_too(tmp_path: Path) -> None:
    # Worktrees and submodules use a file rather than a directory.
    write_tree(tmp_path, {".git": "gitdir: /elsewhere\n", "a.txt": "x"})
    assert only_rule(tmp_path, "RB801", Target.ARCHIVE) is Severity.BLOCKER


def test_a_nested_git_directory_in_an_archive_is_reported(tmp_path: Path) -> None:
    init_repo(tmp_path)
    init_repo(tmp_path / "vendor" / "lib")
    items = [item for item in findings(tmp_path, Target.ARCHIVE) if item.rule_id == "RB801"]
    assert sorted(item.artifact for item in items) == [".git", "vendor/lib/.git"]


# RB802: operating-system residue


@pytest.mark.parametrize("name", [".DS_Store", "sub/.DS_Store", "Thumbs.db", "pics/thumbs.db"])
def test_os_metadata_files(tmp_path: Path, name: str) -> None:
    write_tree(tmp_path, {name: b"\x00\x01binary"})
    report = scan(tmp_path)
    assert rules_found(report.result.findings) == ["RB802"]
    assert report.result.findings[0].severity is Severity.WARNING
    # Its only meaning is that it should not ship, so it is not also an unread binary.
    assert not report.result.incomplete


def test_macos_archive_residue_is_reported_once(tmp_path: Path) -> None:
    write_tree(tmp_path, {"__MACOSX/._a": b"\x00", "__MACOSX/sub/._b": b"\x00", "a.txt": "x"})
    report = scan(tmp_path)
    assert rules_found(report.result.findings) == ["RB802"]
    assert report.result.findings[0].artifact == "__MACOSX"
    assert not report.result.incomplete


def test_a_similar_name_is_not_residue(tmp_path: Path) -> None:
    write_tree(tmp_path, {"not.DS_Store.txt": "x", "MACOSX/a.txt": "x"})
    assert findings(tmp_path) == []


# RB803 and RB804: cannot look inside


def test_an_unknown_binary_needs_review_and_marks_the_scan_incomplete(tmp_path: Path) -> None:
    write_tree(tmp_path, {"results/model.bin": b"\x00\x01"})
    report = scan(tmp_path)
    assert rules_found(report.result.findings) == ["RB803"]
    assert report.result.findings[0].severity is Severity.REVIEW
    assert report.result.skipped[0].path == "results/model.bin"
    assert report.result.skipped[0].reason is SkipReason.UNSUPPORTED_BINARY
    assert report.result.incomplete


@pytest.mark.parametrize("name", ["data.zip", "data.tar", "data.tar.gz", "d.tgz", "d.7z", "d.rar"])
def test_an_archive_is_reported_and_never_unpacked(tmp_path: Path, name: str) -> None:
    # NFR-SAFE-6: even with a name inside it, the archive is opaque to ReviewBlind.
    write_tree(tmp_path, {name: b"PK Alice Example"})
    report = scan(tmp_path)
    assert rules_found(report.result.findings) == ["RB804"]
    assert report.result.skipped[0].reason is SkipReason.ARCHIVE_NOT_INSPECTED
    assert report.result.incomplete


# RB805: ReviewBlind's own files


def test_a_tracked_config_is_a_blocker_on_every_target(tmp_path: Path) -> None:
    # Threat T-20: the very file listing the identities, committed to the shared repository.
    init_repo(tmp_path, {".reviewblind.toml": 'names = ["Alice Example"]\n'})
    for target in Target:
        assert only_rule(tmp_path, "RB805", target) is Severity.BLOCKER


def test_an_untracked_config_only_matters_for_an_archive(tmp_path: Path) -> None:
    init_repo(tmp_path)
    write_tree(tmp_path, {".reviewblind.toml": "x"})
    assert only_rule(tmp_path, "RB805", Target.MIRROR) is Severity.INFO
    assert only_rule(tmp_path, "RB805", Target.REPOSITORY) is Severity.INFO
    assert only_rule(tmp_path, "RB805", Target.ARCHIVE) is Severity.BLOCKER


def test_outside_git_tracking_is_unknown_so_the_config_counts(tmp_path: Path) -> None:
    write_tree(tmp_path, {".reviewblind.toml": "x"})
    assert only_rule(tmp_path, "RB805", Target.MIRROR) is Severity.BLOCKER


def test_the_contents_of_a_config_are_not_scanned_as_text(tmp_path: Path) -> None:
    # FR-PKG-3: one finding about the file, not one for every identity it lists.
    write_tree(tmp_path, {".reviewblind.toml": 'names = ["Alice Example", "aliceexample"]\n'})
    assert rules_found(findings(tmp_path)) == ["RB805"]


def test_an_active_config_with_another_name_is_recognized(tmp_path: Path) -> None:
    write_tree(tmp_path, {"private.toml": 'names = ["Alice Example"]\n'})
    report = run_scan(tmp_path, PERSONA, Target.MIRROR, tmp_path / "private.toml")
    assert rules_found(report.result.findings) == ["RB805"]


def test_a_config_outside_the_root_raises_nothing(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {"a.txt": "x"})
    write_tree(tmp_path, {"private.toml": "x"})
    report = run_scan(root, PERSONA, Target.MIRROR, tmp_path / "private.toml")
    assert report.result.findings == []


def _real_report(tmp_path: Path) -> tuple[str, str, str]:
    source = tmp_path / "source"
    write_tree(source, {"a.txt": "by Alice Example\n"})
    report = scan(source)
    return render_json(report), render_markdown(report), render_report(report).plain


@pytest.mark.parametrize("index", [0, 1, 2], ids=["json", "markdown", "terminal"])
def test_a_saved_report_is_recognized_instead_of_flooding_the_scan(
    tmp_path: Path, index: int
) -> None:
    # Threat T-21: a re-scan must not list every name a saved report contains.
    document = _real_report(tmp_path)[index]
    root = tmp_path / "repo"
    write_tree(root, {"saved-report.txt": document})
    assert rules_found(findings(root)) == ["RB805"]


def test_a_report_saved_by_powershell_redirection_is_recognized(tmp_path: Path) -> None:
    # Windows PowerShell 5 writes `>` output as UTF-16 with a byte order mark.
    document = _real_report(tmp_path)[2]
    root = tmp_path / "repo"
    write_tree(root, {"report.txt": document.encode("utf-16")})
    assert rules_found(findings(root)) == ["RB805"]


@pytest.mark.parametrize(
    ("name", "head", "kind"),
    [
        (".reviewblind.toml", b"", ArtifactKind.REVIEWBLIND),
        ("sub/.reviewblind.toml", b"", ArtifactKind.REVIEWBLIND),
        (".reviewblind.example.toml", b"version = 1\n", ArtifactKind.TEXT),
        (
            "a.json",
            json.dumps({"schema_version": 1, "tool": {"name": "reviewblind"}}).encode(),
            ArtifactKind.REVIEWBLIND,
        ),
        (
            "a.json",
            json.dumps({"schema_version": 1, "tool": {"name": "other"}}).encode(),
            ArtifactKind.TEXT,
        ),
        ("a.json", b'{"name": "reviewblind"}', ArtifactKind.TEXT),
        ("a.md", b"<!-- reviewblind-report schema=1 -->\n# Title", ArtifactKind.REVIEWBLIND),
        ("a.md", b"# ReviewBlind report\n", ArtifactKind.TEXT),
        ("a.txt", b"ReviewBlind 0.1.0\nTarget: anonymous mirror\n", ArtifactKind.REVIEWBLIND),
        ("a.txt", b"ReviewBlind 0.1.0\r\nTarget: anonymous mirror\r\n", ArtifactKind.REVIEWBLIND),
        ("a.txt", b"ReviewBlind is a tool.\n", ArtifactKind.TEXT),
    ],
)
def test_what_counts_as_our_own_file(name: str, head: bytes, kind: ArtifactKind) -> None:
    assert classify(name, head) is kind


def test_a_tracked_report_is_a_blocker(tmp_path: Path) -> None:
    document = _real_report(tmp_path)[0]
    root = init_repo(tmp_path / "repo", {"report.json": document})
    git(root, "status")
    assert only_rule(root, "RB805") is Severity.BLOCKER
