"""The first-use workflow (FR-INIT-1 to FR-INIT-10, threats T-06 and T-20)."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from _helpers import git, init_repo, symlink_or_skip, write_tree
from reviewblind import cli
from reviewblind.config import load_config, parse_config

runner = CliRunner()

CITATION = """authors:
  - name: Alice Example
    email: alice@example.edu
    affiliation: Example University
"""


@pytest.fixture
def interactive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_stdin_is_interactive", lambda: True)


def init(root: Path, *args: str, answers: str | None = None):  # type: ignore[no-untyped-def]
    return runner.invoke(cli.app, ["init", str(root), *args], input=answers)


def written(root: Path) -> tuple[str, ...]:
    identity = load_config(root / ".reviewblind.toml").identity
    return (
        identity.names
        + identity.emails
        + identity.usernames
        + identity.affiliations
        + identity.aliases
    )


# Choosing


@pytest.mark.usefixtures("interactive")
def test_accepting_writes_only_high_confidence_candidates(tmp_path: Path) -> None:
    # FR-INIT-2
    write_tree(tmp_path, {"CITATION.cff": CITATION})
    result = init(tmp_path, answers="\n")
    assert result.exit_code == 0
    assert sorted(written(tmp_path)) == ["Alice Example", "alice@example.edu"]


@pytest.mark.usefixtures("interactive")
def test_candidates_show_their_sources_and_selection(tmp_path: Path) -> None:
    # FR-INIT-1
    write_tree(tmp_path, {"CITATION.cff": CITATION})
    output = init(tmp_path, answers="y\n").stdout
    assert "HIGH CONFIDENCE" in output
    assert "[1] [x] Alice Example (name)" in output
    assert "CITATION.cff author" in output
    assert "[ ] Example University (affiliation)" in output


@pytest.mark.usefixtures("interactive")
def test_a_candidate_can_be_added_by_number(tmp_path: Path) -> None:
    # FR-INIT-3. Numbers follow the list: name, email, affiliation, then low-confidence ones.
    write_tree(tmp_path, {"CITATION.cff": CITATION})
    result = init(tmp_path, answers="n\n3\ny\n")
    assert result.exit_code == 0
    assert "Example University" in written(tmp_path)
    assert result.stdout.count("HIGH CONFIDENCE") == 2


@pytest.mark.usefixtures("interactive")
def test_a_candidate_can_be_removed_by_number(tmp_path: Path) -> None:
    write_tree(tmp_path, {"CITATION.cff": CITATION})
    init(tmp_path, answers="n\n1\ny\n")
    assert written(tmp_path) == ("alice@example.edu",)


@pytest.mark.usefixtures("interactive")
def test_several_numbers_can_be_toggled_at_once(tmp_path: Path) -> None:
    write_tree(tmp_path, {"CITATION.cff": CITATION})
    init(tmp_path, answers="n\n2, 3\ny\n")
    assert sorted(written(tmp_path)) == ["Alice Example", "Example University"]


@pytest.mark.usefixtures("interactive")
def test_a_low_confidence_alias_is_chosen_only_by_a_person(tmp_path: Path) -> None:
    # FR-INIT-4
    write_tree(tmp_path, {"CITATION.cff": CITATION})
    init(tmp_path, answers="\n")
    assert "EU" not in written(tmp_path)
    assert "A. Example" not in written(tmp_path)


@pytest.mark.usefixtures("interactive")
@pytest.mark.parametrize("bad", ["99", "0", "abc", "1 x"])
def test_bad_numbers_change_nothing(tmp_path: Path, bad: str) -> None:
    write_tree(tmp_path, {"CITATION.cff": CITATION})
    result = init(tmp_path, answers=f"n\n{bad}\ny\n")
    assert result.exit_code == 0
    assert "please use numbers" in result.stderr
    assert sorted(written(tmp_path)) == ["Alice Example", "alice@example.edu"]


@pytest.mark.usefixtures("interactive")
def test_an_unclear_answer_is_asked_again(tmp_path: Path) -> None:
    write_tree(tmp_path, {"CITATION.cff": CITATION})
    result = init(tmp_path, answers="maybe\ny\n")
    assert result.exit_code == 0
    assert "please answer y or n" in result.stderr


@pytest.mark.usefixtures("interactive")
def test_accepting_nothing_is_not_allowed(tmp_path: Path) -> None:
    write_tree(tmp_path, {"CITATION.cff": CITATION})
    result = init(tmp_path, answers="n\n1 2\ny\n1\ny\n")
    assert "select at least one" in result.stderr
    assert result.exit_code == 0
    assert written(tmp_path) == ("Alice Example",)


@pytest.mark.usefixtures("interactive")
def test_cancelling_writes_nothing(tmp_path: Path) -> None:
    write_tree(tmp_path, {"CITATION.cff": CITATION})
    result = init(tmp_path, answers="")
    assert result.exit_code == 2
    assert "Nothing was written" in result.stderr
    assert not (tmp_path / ".reviewblind.toml").exists()


def test_prompts_go_to_stderr_so_stdout_can_be_redirected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "_stdin_is_interactive", lambda: True)
    write_tree(tmp_path, {"CITATION.cff": CITATION})
    result = init(tmp_path, answers="y\n")
    assert "Accept selected identities" in result.stderr
    assert "Accept selected identities" not in result.stdout


# Without a terminal


def test_no_terminal_without_yes_is_exit_2(tmp_path: Path) -> None:
    # FR-INIT-6
    write_tree(tmp_path, {"CITATION.cff": CITATION})
    result = init(tmp_path)
    assert result.exit_code == 2
    assert "--yes" in result.stderr
    assert not (tmp_path / ".reviewblind.toml").exists()


def test_yes_accepts_high_confidence_only(tmp_path: Path) -> None:
    write_tree(tmp_path, {"CITATION.cff": CITATION})
    assert init(tmp_path, "--yes").exit_code == 0
    assert sorted(written(tmp_path)) == ["Alice Example", "alice@example.edu"]


def test_yes_with_no_high_confidence_candidates_writes_nothing(tmp_path: Path) -> None:
    write_tree(tmp_path, {"LICENSE": "Copyright (c) 2026 Bob Coauthor\n"})
    result = init(tmp_path, "--yes")
    assert result.exit_code == 2
    assert not (tmp_path / ".reviewblind.toml").exists()


def test_no_candidates_at_all_writes_nothing(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.py": "import os\n"})
    result = init(tmp_path, "--yes")
    assert result.exit_code == 2
    assert "no likely identities" in result.stderr
    assert not (tmp_path / ".reviewblind.toml").exists()


# Writing the config


def test_an_existing_config_is_not_overwritten(tmp_path: Path) -> None:
    # FR-INIT-5
    write_tree(tmp_path, {"CITATION.cff": CITATION, ".reviewblind.toml": "keep me"})
    result = init(tmp_path, "--yes")
    assert result.exit_code == 2
    assert "--force" in result.stderr
    assert (tmp_path / ".reviewblind.toml").read_text(encoding="utf-8") == "keep me"


def test_force_overwrites(tmp_path: Path) -> None:
    write_tree(tmp_path, {"CITATION.cff": CITATION, ".reviewblind.toml": "old"})
    assert init(tmp_path, "--yes", "--force").exit_code == 0
    assert "Alice Example" in written(tmp_path)


def test_a_symlinked_config_is_refused(tmp_path: Path) -> None:
    # FR-INIT-10 and threat T-06
    root = tmp_path / "repo"
    write_tree(root, {"CITATION.cff": CITATION})
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched", encoding="utf-8")
    symlink_or_skip(root / ".reviewblind.toml", outside)
    for args in (("--yes",), ("--yes", "--force")):
        result = init(root, *args)
        assert result.exit_code == 2
        assert "symbolic link" in result.stderr
    assert outside.read_text(encoding="utf-8") == "untouched"


def test_config_can_be_written_elsewhere(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {"CITATION.cff": CITATION})
    outside = tmp_path / "private.toml"
    assert init(root, "--yes", "--config", str(outside)).exit_code == 0
    assert "Alice Example" in load_config(outside).identity.names
    assert not (root / ".reviewblind.toml").exists()


def test_an_unwritable_config_is_exit_2(tmp_path: Path) -> None:
    write_tree(tmp_path, {"CITATION.cff": CITATION})
    result = init(tmp_path, "--yes", "--config", str(tmp_path / "missing" / "c.toml"))
    assert result.exit_code == 2
    assert "cannot write" in result.stderr


def test_the_config_warns_about_itself(tmp_path: Path) -> None:
    write_tree(tmp_path, {"CITATION.cff": CITATION})
    init(tmp_path, "--yes")
    text = (tmp_path / ".reviewblind.toml").read_text(encoding="utf-8")
    assert "lists your identities in plain text" in text


def test_awkward_values_survive_into_the_config(tmp_path: Path) -> None:
    # FR-INIT-7
    write_tree(
        tmp_path, {"package.json": '{"author": {"name": "Jos\\u00e9 \\"Pepe\\" Garc\\u00eda\\\\"}}'}
    )
    assert init(tmp_path, "--yes").exit_code == 0
    assert load_config(tmp_path / ".reviewblind.toml").identity.names == (
        'Jos\u00e9 "Pepe" Garc\u00eda\\',
    )


def test_a_hostile_value_cannot_inject_config_lines(tmp_path: Path) -> None:
    # A quote and a newline in an author field must not let a repository rewrite the config.
    payload = 'Evil Name\\"\\nversion = 9\\nfollow_symlinks = true'
    write_tree(tmp_path, {"package.json": f'{{"author": {{"name": "{payload}"}}}}'})
    assert init(tmp_path, "--yes").exit_code == 0
    config = load_config(tmp_path / ".reviewblind.toml")
    assert config.identity.names == ('Evil Name" version = 9 follow_symlinks = true',)
    assert config.scan.follow_symlinks is False


def test_the_written_config_is_valid_and_complete(tmp_path: Path) -> None:
    import tomllib

    write_tree(tmp_path, {"CITATION.cff": CITATION})
    init(tmp_path, "--yes")
    data = tomllib.loads((tmp_path / ".reviewblind.toml").read_text(encoding="utf-8"))
    assert parse_config(data).has_identities


def test_init_needs_a_directory(tmp_path: Path) -> None:
    assert init(tmp_path / "missing", "--yes").exit_code == 2


# Keeping the config out of Git (threat T-20)


def exclude_lines(root: Path) -> list[str]:
    return (root / ".git" / "info" / "exclude").read_text(encoding="utf-8").splitlines()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return init_repo(tmp_path / "repo", {"CITATION.cff": CITATION})


def test_the_config_and_reports_are_excluded(repo: Path) -> None:
    # FR-INIT-8
    result = init(repo, "--yes")
    assert ".reviewblind.toml" in exclude_lines(repo)
    assert "reviewblind-report.*" in exclude_lines(repo)
    assert "Added .reviewblind.toml and reviewblind-report.*" in result.stderr


def test_git_really_ignores_them_afterwards(repo: Path) -> None:
    init(repo, "--yes")
    write_tree(repo, {"reviewblind-report.json": "{}"})
    assert git(repo, "status", "--porcelain") == ""


def test_no_tracked_file_is_changed_and_gitignore_is_not_created(repo: Path) -> None:
    init(repo, "--yes")
    assert git(repo, "status", "--porcelain") == ""
    assert not (repo / ".gitignore").exists()


def test_an_existing_gitignore_is_left_alone(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo", {"CITATION.cff": CITATION, ".gitignore": "*.log\n"})
    init(root, "--yes")
    assert (root / ".gitignore").read_text(encoding="utf-8") == "*.log\n"


def test_excluding_twice_adds_nothing(repo: Path) -> None:
    init(repo, "--yes")
    before = exclude_lines(repo)
    result = init(repo, "--yes", "--force")
    assert exclude_lines(repo) == before
    assert "Added" not in result.stderr


def test_existing_exclude_rules_are_kept(repo: Path) -> None:
    path = repo / ".git" / "info" / "exclude"
    path.write_bytes(b"my-own-rule")  # no final newline
    init(repo, "--yes")
    assert exclude_lines(repo)[:2] == ["my-own-rule", ".reviewblind.toml"]


def test_a_missing_exclude_file_is_created(repo: Path) -> None:
    (repo / ".git" / "info" / "exclude").unlink()
    (repo / ".git" / "info").rmdir()
    init(repo, "--yes")
    assert ".reviewblind.toml" in exclude_lines(repo)


def test_no_exclude_leaves_git_alone(repo: Path) -> None:
    before = (repo / ".git" / "info" / "exclude").read_bytes()
    init(repo, "--yes", "--no-exclude")
    assert (repo / ".git" / "info" / "exclude").read_bytes() == before


def test_a_custom_config_name_inside_the_repository_is_excluded(repo: Path) -> None:
    init(repo, "--yes", "--config", str(repo / "private.toml"))
    assert "private.toml" in exclude_lines(repo)


def test_a_config_outside_the_repository_is_not_listed(tmp_path: Path, repo: Path) -> None:
    init(repo, "--yes", "--config", str(tmp_path / "private.toml"))
    assert "private.toml" not in exclude_lines(repo)
    assert "reviewblind-report.*" in exclude_lines(repo)


def test_a_tracked_config_gets_a_warning(repo: Path) -> None:
    # FR-INIT-9
    write_tree(repo, {".reviewblind.toml": "version = 1\n"})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "Add config")
    result = init(repo, "--yes", "--force")
    assert "already tracked by Git" in result.stderr


def test_a_tracked_config_gets_a_warning_with_no_exclude_too(repo: Path) -> None:
    write_tree(repo, {".reviewblind.toml": "version = 1\n"})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "Add config")
    result = init(repo, "--yes", "--force", "--no-exclude")
    assert "already tracked by Git" in result.stderr


def test_outside_git_it_says_so(tmp_path: Path) -> None:
    write_tree(tmp_path, {"CITATION.cff": CITATION})
    result = init(tmp_path, "--yes")
    assert "not a Git repository" in result.stderr


@pytest.mark.parametrize("linked", ["file", "directory"])
def test_a_symlink_in_git_cannot_redirect_the_write(tmp_path: Path, linked: str) -> None:
    # Threat T-06: a repository controls what is inside its own .git directory.
    root = init_repo(tmp_path / "repo", {"CITATION.cff": CITATION})
    info = root / ".git" / "info"
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "exclude").write_text("untouched", encoding="utf-8")
    (info / "exclude").unlink()
    if linked == "file":
        symlink_or_skip(info / "exclude", outside / "exclude")
    else:
        info.rmdir()
        symlink_or_skip(info, outside, directory=True)
    result = init(root, "--yes")
    assert result.exit_code == 0  # the config itself is fine, and RB805 still protects it
    assert "could not update" in result.stderr
    assert (outside / "exclude").read_text(encoding="utf-8") == "untouched"


# The whole workflow


def test_init_then_scan_works_with_nothing_else(repo: Path) -> None:
    assert init(repo, "--yes").exit_code == 0
    result = runner.invoke(cli.app, ["scan", str(repo), "--target", "mirror"])
    assert result.exit_code == 1
    assert "RB303" in result.stdout
    assert "RB805" not in result.stdout  # git now ignores the config


def test_after_init_an_archive_still_warns_about_the_config(repo: Path) -> None:
    # Zipping a folder would include it, whatever .git/info/exclude says.
    init(repo, "--yes")
    result = runner.invoke(cli.app, ["scan", str(repo), "--target", "archive"])
    assert "BLOCKER  RB805" in result.stdout
