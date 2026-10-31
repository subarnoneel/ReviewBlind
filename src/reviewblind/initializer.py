"""Keeps a new config out of Git, without touching any tracked file (threat T-20)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from reviewblind.utils.files import atomic_write
from reviewblind.utils.git import GitError, GitRepository, open_repository

REPORT_PATTERN = "reviewblind-report.*"


@dataclass(frozen=True)
class ExcludeResult:
    added: tuple[str, ...] = ()
    not_a_repository: bool = False
    config_is_tracked: bool = False
    problem: str | None = None


def _relative_inside(root: Path, path: Path) -> str | None:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return None


def _tracked(repository: GitRepository, root: Path, config_path: Path) -> bool:
    relative = _relative_inside(root, config_path)
    return relative is not None and relative in repository.tracked_files()


def is_tracked(root: Path, config_path: Path) -> bool:
    """Whether the config is committed, which `.git/info/exclude` cannot undo (FR-INIT-9)."""
    try:
        repository = open_repository(root)
        return repository is not None and _tracked(repository, root, config_path)
    except GitError:
        return False


def _append_lines(path: Path, patterns: list[str]) -> tuple[str, ...]:
    """Add whichever patterns are missing. Running `init` twice changes nothing the second time."""
    # A symlink planted in `.git` could otherwise redirect this write (threat T-06).
    if path.is_symlink() or path.parent.is_symlink():
        raise OSError("it is a symbolic link")
    existing = path.read_bytes() if path.exists() else b""
    lines = {line.strip() for line in existing.decode("utf-8", "replace").splitlines()}
    missing = tuple(pattern for pattern in patterns if pattern not in lines)
    if not missing:
        return ()
    separator = b"" if not existing or existing.endswith(b"\n") else b"\n"
    addition = "".join(f"{pattern}\n" for pattern in missing).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, existing + separator + addition)
    return missing


def add_to_exclude_file(root: Path, config_path: Path) -> ExcludeResult:
    """Add the config and default report names to `.git/info/exclude`.

    That file is local and untracked, so this keeps the promise never to modify source files.
    `.gitignore` is never edited (FR-INIT-8).
    """
    try:
        repository = open_repository(root)
        if repository is None:
            return ExcludeResult(not_a_repository=True)
        exclude_file = repository.exclude_file()
        tracked = _tracked(repository, root, config_path)
    except GitError as error:
        return ExcludeResult(problem=str(error))
    patterns = [REPORT_PATTERN]
    if _relative_inside(root, config_path) is not None:
        patterns.insert(0, config_path.name)
    try:
        added = _append_lines(exclude_file, patterns)
    except OSError as error:
        return ExcludeResult(config_is_tracked=tracked, problem=error.strerror or str(error))
    return ExcludeResult(added=added, config_is_tracked=tracked)
