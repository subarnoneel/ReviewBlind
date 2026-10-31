"""Identities in Git metadata (FR-GIT-1 to FR-GIT-3)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from _helpers import PERSONA, findings, git, init_repo, rules_found, scan, write_tree
from reviewblind.config import AllowEntry, ScanSettings
from reviewblind.engine import run_scan
from reviewblind.models import Confidence, Finding, Severity, SkipReason, Target
from reviewblind.reporters.terminal import render_report
from reviewblind.scanners import git as git_scanner
from reviewblind.utils.git import GitError, GitRepository

ALICE = ("Alice Example", "alice@example.edu")
BOB = ("Bob Coauthor", "bob@elsewhere.example.org")


def commit(
    root: Path,
    message: str = "Change something",
    author: tuple[str, str] = ALICE,
    committer: tuple[str, str] | None = None,
) -> None:
    name, email = committer or author
    git(
        root,
        "-c",
        f"user.name={name}",
        "-c",
        f"user.email={email}",
        "commit",
        "-q",
        "--allow-empty",
        f"--author={author[0]} <{author[1]}>",
        "-m",
        message,
    )


def by_rule(items: list[Finding], rule_id: str) -> list[Finding]:
    return [item for item in items if item.rule_id == rule_id]


def one(items: list[Finding], rule_id: str) -> Finding:
    # init_repo's own first commit is by a contributor who is not the persona.
    matching = [item for item in by_rule(items, rule_id) if "ixture" not in item.matched]
    assert len(matching) == 1, [item.matched for item in matching]
    return matching[0]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path / "repo", {"a.py": "import os\n"})


# Severity for each target


@pytest.mark.parametrize(
    ("target", "severity"),
    [
        (Target.MIRROR, Severity.INFO),
        (Target.ARCHIVE, Severity.BLOCKER),  # the .git directory would be packaged
        (Target.REPOSITORY, Severity.BLOCKER),
    ],
)
def test_git_identity_severity_depends_on_target(
    repo: Path, target: Target, severity: Severity
) -> None:
    commit(repo, "Work with Alice Example\n\nSigned-off-by: Alice Example")
    git(repo, "remote", "add", "origin", "git@github.com:aliceexample/paper.git")
    items = findings(repo, target)
    for rule_id in ("RB401", "RB402", "RB403", "RB404"):
        assert one(items, rule_id).severity is severity, rule_id


def test_an_archive_without_git_is_only_informational(repo: Path) -> None:
    # D-08: excluding .git states that it will not be packaged.
    commit(repo)
    config = replace(PERSONA, scan=ScanSettings(exclude=(".git/**",)))
    items = findings(repo, Target.ARCHIVE, config)
    assert one(items, "RB402").severity is Severity.INFO
    assert "RB801" not in rules_found(items)


# RB401: remotes


@pytest.mark.parametrize(
    "url",
    [
        "git@github.com:aliceexample/paper.git",
        "https://github.com/aliceexample/paper.git",
        "ssh://git@gitlab.com/aliceexample/paper.git",
        "https://aliceexample@bitbucket.example.net/team/paper.git",
        "https://git.example.edu/group/paper.git",
    ],
)
def test_a_remote_under_a_confirmed_namespace(repo: Path, url: str) -> None:
    git(repo, "remote", "add", "origin", url)
    found = one(findings(repo, Target.REPOSITORY), "RB401")
    assert found.severity is Severity.BLOCKER
    assert found.location.field == "remote origin"


def test_a_remote_under_another_namespace_is_not_a_finding(repo: Path) -> None:
    git(repo, "remote", "add", "origin", "https://github.com/pytorch/pytorch.git")
    assert by_rule(findings(repo, Target.REPOSITORY), "RB401") == []


def test_a_remote_is_reported_once_for_fetch_and_push(repo: Path) -> None:
    git(repo, "remote", "add", "origin", "git@github.com:aliceexample/paper.git")
    assert len(by_rule(findings(repo), "RB401")) == 1


def test_each_identifying_remote_is_reported(repo: Path) -> None:
    git(repo, "remote", "add", "origin", "git@github.com:aliceexample/a.git")
    git(repo, "remote", "add", "backup", "git@gitlab.com:aliceexample/a.git")
    assert len(by_rule(findings(repo), "RB401")) == 2


def test_a_token_in_a_remote_url_never_reaches_a_report(repo: Path) -> None:
    git(repo, "remote", "add", "origin", "https://aliceexample:SECRET123@github.com/x/paper.git")
    report = scan(repo)
    found = one(report.result.findings, "RB401")
    assert "SECRET123" not in found.matched
    assert "SECRET123" not in found.evidence
    assert found.matched == "https://***@github.com/x/paper.git"
    assert "SECRET123" not in render_report(report).plain


def test_redaction_keeps_the_ordinary_ssh_user() -> None:
    url = "ssh://git@gitlab.com/group/paper.git"
    assert git_scanner.redact_url(url) == url


# RB402 and RB403: authors, committers and emails


def test_author_and_email_are_reported(repo: Path) -> None:
    commit(repo)
    items = findings(repo, Target.REPOSITORY)
    assert one(items, "RB402").matched == "Alice Example"
    assert one(items, "RB403").matched == "alice@example.edu"
    assert one(items, "RB402").confidence is Confidence.HIGH
    assert one(items, "RB402").identity == "Alice Example"


def test_a_committer_is_inspected_as_well_as_the_author(repo: Path) -> None:
    commit(repo, author=BOB, committer=ALICE)
    items = findings(repo, Target.REPOSITORY)
    confirmed = [item for item in by_rule(items, "RB402") if item.identity]
    assert [item.matched for item in confirmed] == ["Alice Example"]


def test_each_identity_is_reported_once_with_a_count(repo: Path) -> None:
    # FR-GIT-3
    for _ in range(4):
        commit(repo)
    found = one(findings(repo), "RB402")
    assert "4 commits" in found.message
    assert found.location.git_commit is not None
    assert len(found.location.git_commit) == 12


def test_case_variants_are_one_identity(repo: Path) -> None:
    commit(repo, author=("ALICE EXAMPLE", "ALICE@EXAMPLE.EDU"))
    commit(repo)
    assert len(by_rule(findings(repo), "RB402")) == 1
    assert len(by_rule(findings(repo), "RB403")) == 1


def test_a_name_containing_a_confirmed_name_is_confirmed(repo: Path) -> None:
    commit(repo, author=("Dr. Alice Example", "other@lab.example.org"))
    assert one(findings(repo, Target.REPOSITORY), "RB402").identity == "Alice Example"


def test_a_github_noreply_address_counts_as_the_username(repo: Path) -> None:
    commit(repo, author=("Alice", "12345+aliceexample@users.noreply.github.com"))
    found = one(findings(repo, Target.REPOSITORY), "RB403")
    assert found.identity == "aliceexample"
    assert found.severity is Severity.BLOCKER


def test_a_mailmap_cannot_hide_an_identity(repo: Path) -> None:
    # FR-GIT-1: raw values are read, so history is reported as a reviewer would see it.
    write_tree(repo, {".mailmap": "Neutral Name <neutral@example.org> <alice@example.edu>\n"})
    git(repo, "add", "-A")
    commit(repo)
    assert one(findings(repo, Target.REPOSITORY), "RB402").matched == "Alice Example"


def test_another_contributor_only_matters_on_a_public_repository(repo: Path) -> None:
    commit(repo, author=BOB)
    public = [item for item in by_rule(findings(repo, Target.REPOSITORY), "RB402")]
    bob = next(item for item in public if item.matched == "Bob Coauthor")
    assert bob.identity is None
    assert (bob.severity, bob.confidence) == (Severity.WARNING, Confidence.MEDIUM)
    assert not any(
        item.matched == "Bob Coauthor" for item in by_rule(findings(repo, Target.MIRROR), "RB402")
    )
    assert not any(
        item.matched == "Bob Coauthor" for item in by_rule(findings(repo, Target.ARCHIVE), "RB402")
    )


@pytest.mark.parametrize(
    "bot",
    [
        ("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com"),
        ("github-actions", "action@github.com"),
        ("GitHub", "noreply@github.com"),
    ],
)
def test_bots_are_not_people(repo: Path, bot: tuple[str, str]) -> None:
    commit(repo, author=bot, committer=bot)
    items = findings(repo, Target.REPOSITORY)
    assert bot[0] not in [item.matched for item in by_rule(items, "RB402")]
    assert bot[1] not in [item.matched for item in by_rule(items, "RB403")]


def test_non_ascii_names_are_read_correctly(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo")
    commit(root, author=("Jos\u00e9 \u5f20\u4f1f", "jose@elsewhere.example.org"))
    names = [item.matched for item in by_rule(findings(root, Target.REPOSITORY), "RB402")]
    assert "Jos\u00e9 \u5f20\u4f1f" in names


# RB404: commit messages


@pytest.mark.parametrize(
    "message",
    [
        "Fix a bug\n\nSigned-off-by: Alice Example <other@example.org>",
        "Fix a bug\n\nCo-authored-by: Alice Example <other@example.org>",
        "Thanks to Alice Example for the idea",
    ],
)
def test_an_identity_in_a_commit_message(repo: Path, message: str) -> None:
    commit(repo, message, author=BOB)
    found = one(findings(repo, Target.REPOSITORY), "RB404")
    assert found.matched == "Alice Example"
    assert found.severity is Severity.BLOCKER
    assert "Alice Example" in found.evidence


def test_an_identity_in_many_messages_is_reported_once(repo: Path) -> None:
    # D-57: a thousand signed-off commits should not mean a thousand findings.
    for index in range(3):
        commit(repo, f"Change {index}\n\nSigned-off-by: Alice Example")
    found = one(findings(repo), "RB404")
    assert "3 commit messages" in found.message


def test_different_identities_in_a_message_are_each_reported(repo: Path) -> None:
    commit(repo, "From Alice Example and alice@example.edu", author=BOB)
    matched = {item.matched for item in by_rule(findings(repo), "RB404")}
    assert matched == {"Alice Example", "alice@example.edu"}


def test_an_affiliation_in_a_message_is_a_warning(repo: Path) -> None:
    # D-40
    commit(repo, "Data from Example University", author=BOB)
    found = one(findings(repo, Target.REPOSITORY), "RB404")
    assert found.severity is Severity.WARNING


def test_a_clean_message_raises_nothing(repo: Path) -> None:
    commit(repo, "Improve the training loop", author=BOB)
    assert by_rule(findings(repo, Target.REPOSITORY), "RB404") == []


# What history is read


def test_every_branch_is_inspected(repo: Path) -> None:
    git(repo, "branch", "side")
    git(repo, "switch", "-q", "side")
    commit(repo, author=("Alice Example", "alice@example.edu"))
    git(repo, "switch", "-q", "-")
    assert one(findings(repo), "RB402").matched == "Alice Example"


def test_an_empty_repository_is_fine(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    write_tree(root, {"a.txt": "x\n"})
    report = scan(root)
    assert not report.result.incomplete
    assert not [item for item in report.result.findings if item.rule_id.startswith("RB40")]


def test_a_truncated_history_is_reported_not_hidden(repo: Path) -> None:
    # FR-GIT-2
    commit(repo)
    commit(repo, "Newest", author=BOB)
    report = run_scan(repo, PERSONA, Target.MIRROR, max_commits=1)
    assert report.result.incomplete
    item = next(item for item in report.result.skipped if item.reason is SkipReason.GIT_TRUNCATED)
    assert item.path == ".git"
    assert "newest 1 of 3" in (item.detail or "")


def test_a_history_within_the_limit_is_complete(repo: Path) -> None:
    commit(repo)
    assert not run_scan(repo, PERSONA, Target.MIRROR, max_commits=2).result.incomplete


def test_outside_git_there_is_nothing_to_read(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.txt": "x\n"})
    assert not [item for item in findings(tmp_path) if item.rule_id.startswith("RB40")]


def test_a_failure_reading_history_marks_the_scan_incomplete(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(_self: GitRepository, _limit: int) -> None:
        raise GitError("history is unreadable")

    monkeypatch.setattr(GitRepository, "commits", fail)
    report = scan(repo)
    item = next(item for item in report.result.skipped if item.path == ".git")
    assert item.reason is SkipReason.GIT_UNAVAILABLE
    assert report.result.incomplete


# With the rest of the pipeline


def test_a_git_finding_can_be_allowed(repo: Path) -> None:
    commit(repo)
    entry = AllowEntry("RB402", ".git", "Alice Example", "Rewriting history before publishing")
    report = scan(repo, config=replace(PERSONA, allow=(entry,)))
    assert by_rule(report.result.findings, "RB402") == []
    assert report.result.suppressed[0].finding.rule_id == "RB402"


def test_the_terminal_report_names_the_commit(repo: Path) -> None:
    commit(repo)
    found = one(findings(repo), "RB402")
    assert f"commit {found.location.git_commit}" in render_report(scan(repo)).plain


def test_too_many_contributors_is_reported(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("reviewblind.engine.MAX_FINDINGS_PER_ARTIFACT", 2)
    for index in range(3):
        commit(repo, author=(f"Person {index}", f"p{index}@elsewhere.example.org"))
    report = scan(repo, Target.REPOSITORY)
    assert any(item.reason is SkipReason.TOO_MANY_MATCHES for item in report.result.skipped)
