"""Security properties on hostile input. Each maps to a threat in docs/THREAT_MODEL.md.

Attacks are checked with a positive control where possible: first proving that plain Git really does
run the planted command, so that a passing test means the hardening stopped it.
"""

from __future__ import annotations

import ast
import hashlib
import os
import socket
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

import reviewblind
from _helpers import (
    PERSONA,
    findings,
    git,
    git_input,
    init_repo,
    rules_found,
    scan,
    symlink_or_skip,
    write_tree,
)
from reviewblind.config import ScanSettings
from reviewblind.matching import IdentityMatcher
from reviewblind.models import SkipReason, Target
from reviewblind.scanners import base as scanner_base
from reviewblind.signals import SignalMatcher
from reviewblind.utils import git as git_module
from reviewblind.utils.git import (
    ALLOWED_COMMANDS,
    ForbiddenGitCommandError,
    GitError,
    GitRepository,
    find_git,
    is_allowed_command,
    open_repository,
)

SOURCE_ROOT = Path(reviewblind.__file__).parent
ALL_TARGETS = list(Target)


def marker_command(marker: Path, label: str = "ran") -> str:
    """A shell command that leaves evidence that it ran, on every platform CI uses."""
    return f"sh -c 'echo {label} >> \"{marker.as_posix()}\"; cat' --"


def fired(marker: Path) -> bool:
    return marker.exists()


def touch_later(path: Path) -> None:
    """Change a file's timestamp, which makes Git re-read it even when its size is unchanged."""
    future = time.time() + 100
    os.utime(path, (future, future))


# T-02: code execution through Git configuration


def test_the_fsmonitor_attack_is_real_and_is_stopped(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo", {"a.txt": "hello\n"})
    marker = tmp_path / "marker"
    git(root, "config", "core.fsmonitor", marker_command(marker))

    git(root, "status", "--porcelain")
    assert fired(marker), "control failed: plain git did not run core.fsmonitor"

    marker.unlink()
    for target in ALL_TARGETS:
        scan(root, target)
    assert not fired(marker)


@pytest.mark.parametrize(
    "key", ["core.pager", "core.sshCommand", "core.editor", "core.askPass", "diff.external"]
)
def test_other_config_commands_do_not_run(tmp_path: Path, key: str) -> None:
    root = init_repo(tmp_path / "repo", {"a.txt": "hello\n"})
    marker = tmp_path / "marker"
    git(root, "config", key, marker_command(marker))
    write_tree(root, {"a.txt": "HELLO\n"})
    scan(root)
    assert not fired(marker)


def test_hooks_do_not_run(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo", {"a.txt": "hello\n"})
    marker = tmp_path / "marker"
    hooks = tmp_path / "hooks"
    for name in ("post-index-change", "pre-commit", "post-checkout", "reference-transaction"):
        write_tree(hooks, {name: f"#!/bin/sh\necho ran >> '{marker.as_posix()}'\n"})
        (hooks / name).chmod(0o755)
    git(root, "config", "core.hooksPath", hooks.as_posix())
    marker.unlink(missing_ok=True)
    scan(root)
    assert not fired(marker)


# T-03: code execution through Git filters


def test_the_filter_attack_is_real_and_is_stopped(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo", {"a.txt": "hello\n", ".gitattributes": "*.txt filter=x\n"})
    marker = tmp_path / "marker"
    git(root, "config", "filter.x.clean", marker_command(marker))

    # A same-size edit forces Git to run the filter to find out whether the content changed.
    write_tree(root, {"a.txt": "HELLO\n"})
    touch_later(root / "a.txt")
    git(root, "status", "--porcelain")
    assert fired(marker), "control failed: plain git did not run the clean filter"

    marker.unlink()
    touch_later(root / "a.txt")
    for target in ALL_TARGETS:
        report = scan(root, target)
    assert not fired(marker)
    assert report.result.inspected > 0


def test_a_change_is_still_noticed_without_running_the_filter(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo", {"a.txt": "hello\n", ".gitattributes": "*.txt filter=x\n"})
    marker = tmp_path / "marker"
    git(root, "config", "filter.x.clean", marker_command(marker))
    write_tree(root, {"a.txt": "HELLO\n"})
    touch_later(root / "a.txt")
    notes = scan(root).result.notes
    assert any("differ from the index" in note for note in notes)
    assert not fired(marker)


@pytest.mark.parametrize(
    "command",
    [
        ("status",),
        ("status", "--porcelain"),
        ("diff",),
        ("ls-files", "--modified"),
        ("ls-files", "-m"),
        ("fetch",),
        ("pull",),
        ("ls-remote",),
        ("submodule", "update"),
        ("checkout", "."),
        ("config", "--list"),
    ],
)
def test_commands_that_can_run_repository_code_are_rejected(
    tmp_path: Path, command: tuple[str, ...]
) -> None:
    repository = GitRepository(tmp_path, "git")
    with pytest.raises(ForbiddenGitCommandError):
        repository._run(*command)


def test_the_allowlist_contains_only_reviewed_commands() -> None:
    # Adding to this set needs a test showing the command cannot run repository-defined code.
    assert {command[0] for command in ALLOWED_COMMANDS} == {
        "rev-parse",
        "ls-files",
        "remote",
        "rev-list",
    }
    assert not any("--modified" in command or "-m" in command for command in ALLOWED_COMMANDS)


# T-02: code execution through `git log`


def _signed_commit(root: Path) -> None:
    """Add a commit with a signature header, which is all that `git log` needs to verify one."""
    tree = git(root, "rev-parse", "HEAD^{tree}").strip()
    body = (
        f"tree {tree}\n"
        "author Fixture <fixture@example.org> 1700000000 +0000\n"
        "committer Fixture <fixture@example.org> 1700000000 +0000\n"
        "gpgsig -----BEGIN PGP SIGNATURE-----\n"
        " \n"
        " abcdef\n"
        " -----END PGP SIGNATURE-----\n"
        "\n"
        "Signed commit\n"
    )
    object_id = git_input(root, body, "hash-object", "-t", "commit", "-w", "--stdin").strip()
    git(root, "update-ref", "HEAD", object_id)


def _hostile_gpg(root: Path, marker: Path) -> None:
    program = root.parent / "evil-gpg"
    write_tree(root.parent, {"evil-gpg": f"#!/bin/sh\necho ran >> '{marker.as_posix()}'\n"})
    program.chmod(0o755)
    git(root, "config", "gpg.program", program.as_posix())
    git(root, "config", "log.showSignature", "true")


def test_the_signature_attack_is_real_and_is_stopped(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo", {"a.txt": "hello\n"})
    marker = tmp_path / "marker"
    _signed_commit(root)
    _hostile_gpg(root, marker)

    git(root, "log", "-1", "--format=%H")
    assert fired(marker), "control failed: plain git log did not run gpg.program"

    marker.unlink()
    for target in ALL_TARGETS:
        report = scan(root, target)
        assert not report.result.incomplete
    assert not fired(marker)
    # The signed commit was still read, so nothing was skipped to achieve this.
    assert "RB402" in rules_found(scan(root, Target.REPOSITORY).result.findings)


@pytest.mark.parametrize(
    "key",
    ["diff.external", "core.pager", "pager.log", "core.sshCommand", "gpg.ssh.program", "alias.log"],
)
def test_history_reading_ignores_other_config_commands(tmp_path: Path, key: str) -> None:
    root = init_repo(tmp_path / "repo", {"a.txt": "hello\n"})
    write_tree(root, {"a.txt": "changed\n"})
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "Second")
    marker = tmp_path / "marker"
    git(root, "config", key, "!" + marker_command(marker))
    scan(root, Target.REPOSITORY)
    assert not fired(marker)


def test_a_textconv_driver_does_not_run(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo", {"a.txt": "hello\n", ".gitattributes": "*.txt diff=x\n"})
    write_tree(root, {"a.txt": "changed\n"})
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "Second")
    marker = tmp_path / "marker"
    git(root, "config", "diff.x.textconv", marker_command(marker))
    git(root, "config", "diff.x.command", marker_command(marker))
    scan(root, Target.REPOSITORY)
    assert not fired(marker)


def test_a_partial_clone_cannot_reach_its_remote(tmp_path: Path) -> None:
    # A promisor remote would otherwise be contacted for missing objects, through any transport.
    root = init_repo(tmp_path / "repo", {"a.txt": "hello\n"})
    marker = tmp_path / "marker"
    git(root, "config", "core.repositoryformatversion", "1")
    git(root, "config", "extensions.partialClone", "origin")
    git(root, "config", "remote.origin.promisor", "true")
    git(root, "config", "remote.origin.url", "ext::" + marker_command(marker))
    scan(root, Target.REPOSITORY)
    assert not fired(marker)
    environment = git_module._environment()
    assert environment["GIT_NO_LAZY_FETCH"] == "1"


@pytest.mark.parametrize(
    "extra",
    [
        ("--max-count=5", "--output=stolen.txt"),
        ("--patch",),
        ("--max-count=5; rm -rf /",),
        ("--max-count=-1",),
        ("--show-signature",),
    ],
)
def test_only_the_exact_log_command_is_allowed(extra: tuple[str, ...]) -> None:
    base = (
        "log",
        "--all",
        "--no-mailmap",
        "--no-show-signature",
        "--no-notes",
        "--no-patch",
        git_module._LOG_FORMAT,
    )
    assert is_allowed_command((*base, "--max-count=5"))
    assert not is_allowed_command((*base, *extra))
    assert not is_allowed_command(("log", *extra))


def test_a_hostile_amount_of_git_output_is_contained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = init_repo(tmp_path / "repo", {"a.txt": "hello\n"})
    git(root, "commit", "-q", "--allow-empty", "-m", "x" * 5000)
    monkeypatch.setattr(git_module, "MAX_GIT_OUTPUT_BYTES", 1000)
    report = scan(root)
    assert report.result.incomplete
    assert any(
        item.reason is SkipReason.GIT_UNAVAILABLE and "too much output" in (item.detail or "")
        for item in report.result.skipped
    )


def test_hanging_git_is_stopped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = init_repo(tmp_path / "repo", {"a.txt": "hello\n"})
    monkeypatch.setattr(git_module, "GIT_TIMEOUT_SECONDS", 0)
    with pytest.raises(GitError, match="timed out"):
        open_repository(root)


# T-01: code execution through Python files


@pytest.mark.parametrize("name", ["setup.py", "conftest.py", "__init__.py", "train.py"])
def test_python_files_are_never_run_or_imported(tmp_path: Path, name: str) -> None:
    marker = tmp_path / "marker"
    payload = (
        "import pathlib\n"
        f"pathlib.Path({marker.as_posix()!r}).write_text('ran')\n"
        "from setuptools import setup\n"
        "setup(author=__import__('os').system('echo ran'))\n"
    )
    root = tmp_path / "repo"
    write_tree(root, {name: payload})
    for target in ALL_TARGETS:
        scan(root, target)
    assert not fired(marker)


def test_scanning_does_not_add_the_repository_to_the_import_path(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {"setup.py": "setup()\n"})
    before = list(sys.path)
    scan(root)
    assert sys.path == before


# T-04: a nested bare repository


def test_a_bare_repository_is_refused_and_its_config_does_not_run(tmp_path: Path) -> None:
    bare = tmp_path / "evil.git"
    bare.mkdir()
    git(bare, "init", "-q", "--bare")
    marker = tmp_path / "marker"
    git(bare, "config", "core.fsmonitor", marker_command(marker))
    report = scan(bare)
    assert not fired(marker)
    assert any(item.reason is SkipReason.GIT_UNAVAILABLE for item in report.result.skipped)
    assert report.result.incomplete


def test_a_bare_repository_nested_in_a_project_does_not_run(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo")
    bare = root / "vendor" / "evil.git"
    bare.mkdir(parents=True)
    git(bare, "init", "-q", "--bare")
    marker = tmp_path / "marker"
    git(bare, "config", "core.fsmonitor", marker_command(marker))
    for target in ALL_TARGETS:
        scan(root, target)
    assert not fired(marker)


# T-05: reading outside the scan root


def test_a_symlink_cannot_pull_outside_content_into_a_report(tmp_path: Path) -> None:
    write_tree(tmp_path, {"secret.txt": "Alice Example secret\n"})
    root = tmp_path / "repo"
    write_tree(root, {"a.txt": "ok\n"})
    symlink_or_skip(root / "link.txt", tmp_path / "secret.txt")
    report = scan(
        root, config=replace(PERSONA, scan=ScanSettings(follow_symlinks=True, exclude=()))
    )
    assert report.result.findings == []
    assert report.result.incomplete


# T-07 and T-08: resource exhaustion


def test_an_oversized_file_is_never_opened(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_tree(tmp_path, {"big.txt": "x" * 100})

    def must_not_read(_path: Path, _limit: int) -> bytes:
        raise AssertionError("an oversized file was read")

    monkeypatch.setattr(scanner_base, "read_limited", must_not_read)
    config = replace(PERSONA, scan=ScanSettings(max_text_bytes=10, exclude=()))
    report = scan(tmp_path, config=config)
    assert report.result.skipped[0].reason is SkipReason.TOO_LARGE


@pytest.mark.parametrize(
    "fragment",
    [
        "/home/",
        "/home/a ",
        "a.",
        "a-",
        "alice ",
        " ",
        "s3://",
        "#SBATCH ",
        "github.com/",
        "C:\\Users\\",
        "aliceexamplex",
        "\u00df",
        "example.edu.",
    ],
)
def test_hostile_text_at_the_size_cap_finishes_quickly(fragment: str) -> None:
    # Threat T-08: quadratic matching would take hours at this size, not seconds.
    text = (fragment * (2_000_000 // len(fragment) + 1))[:2_000_000]
    identities = PERSONA.identity.identities()
    started = time.perf_counter()
    IdentityMatcher(identities).find(text)
    SignalMatcher(identities).find(text, 5001)
    assert time.perf_counter() - started < 30


def test_a_flood_of_matches_does_not_exhaust_the_scan(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.txt": "Alice Example\n" * 200_000})
    report = scan(tmp_path)
    assert len(report.result.findings) <= 1000
    assert report.result.incomplete


# T-13: no network, and T-15: no planted executables


def test_a_scan_opens_no_network_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("a network connection was attempted")

    monkeypatch.setattr(socket, "socket", no_network)
    root = init_repo(tmp_path / "repo", {"a.txt": "Alice Example\n"})
    git(root, "remote", "add", "origin", "https://example.org/repo.git")
    assert "RB101" in rules_found(findings(root))


def test_git_planted_in_the_repository_is_never_chosen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Windows searches the current directory first, so scanning here could run this file.
    root = tmp_path / "repo"
    write_tree(root, {"git": "planted", "git.exe": "planted", "bin/git": "x", "bin/git.exe": "x"})
    for name in ("git", "git.exe", "bin/git", "bin/git.exe"):
        (root / name).chmod(0o755)
    real_path = os.environ["PATH"]
    monkeypatch.setenv("PATH", os.pathsep.join([str(root), str(root / "bin"), ".", real_path]))
    monkeypatch.chdir(root)
    chosen = find_git(root)
    assert chosen is not None
    assert Path(chosen).is_absolute()
    assert not Path(chosen).resolve().is_relative_to(root.resolve())


def test_a_relative_path_entry_is_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_tree(tmp_path, {"git": "planted", "git.exe": "planted"})
    (tmp_path / "git").chmod(0o755)
    (tmp_path / "git.exe").chmod(0o755)
    monkeypatch.setenv("PATH", ".")
    monkeypatch.chdir(tmp_path)
    assert find_git(tmp_path / "elsewhere") is None


def test_inherited_git_variables_cannot_redirect_git(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = init_repo(tmp_path / "other", {"other.txt": "o\n"})
    root = init_repo(tmp_path / "repo", {"a.txt": "a\n"})
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(other))
    repository = open_repository(root)
    assert repository is not None
    assert repository.tracked_files() == ["a.txt"]


def test_an_unusable_repository_raises_rather_than_passing(tmp_path: Path) -> None:
    write_tree(tmp_path, {".git": "not a real gitfile\n"})
    with pytest.raises(GitError):
        open_repository(tmp_path)


# NFR-SAFE-5: nothing is modified


def _snapshot(root: Path) -> dict[str, tuple[str, int]]:
    return {
        path.relative_to(root).as_posix(): (
            hashlib.sha256(path.read_bytes()).hexdigest(),
            path.stat().st_mtime_ns,
        )
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


@pytest.mark.parametrize("target", ALL_TARGETS)
def test_a_scan_changes_nothing_including_inside_git(tmp_path: Path, target: Target) -> None:
    root = init_repo(tmp_path / "repo", {"a.txt": "Alice Example\n"})
    write_tree(root, {"a.txt": "Bob Example!\n", "new.txt": "n\n"})
    before = _snapshot(root)
    scan(root, target)
    assert _snapshot(root) == before


# NFR-SAFE-1 and NFR-SAFE-4: checked in the source itself


def _imports_and_calls(path: Path) -> tuple[set[str], set[str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            function = node.func
            if isinstance(function, ast.Name):
                calls.add(function.id)
            elif isinstance(function, ast.Attribute):
                calls.add(function.attr)
    return imports, calls


SOURCE_FILES = sorted(SOURCE_ROOT.rglob("*.py"))


@pytest.mark.parametrize("path", SOURCE_FILES, ids=lambda path: path.name)
def test_source_has_no_network_or_dynamic_code(path: Path) -> None:
    imports, calls = _imports_and_calls(path)
    assert not imports & {"socket", "http", "urllib", "requests", "ftplib", "smtplib", "ssl"}
    assert not imports & {"importlib", "runpy", "pickle", "marshal", "shelve"}
    assert not calls & {"eval", "exec", "compile_module", "__import__", "system", "popen"}


def test_only_the_git_module_may_start_a_process() -> None:
    users = {path for path in SOURCE_FILES if "subprocess" in _imports_and_calls(path)[0]}
    assert users == {SOURCE_ROOT / "utils" / "git.py"}


def test_the_git_runner_never_uses_a_shell() -> None:
    source = (SOURCE_ROOT / "utils" / "git.py").read_text(encoding="utf-8")
    assert "shell=" not in source
