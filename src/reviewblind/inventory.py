"""Decides what is inspected for each target. See docs/ARCHITECTURE.md, section 5."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

import pathspec

from reviewblind.config import ConfigError, ScanSettings
from reviewblind.models import Artifact, SkippedArtifact, SkipReason, Target
from reviewblind.utils.files import classify, read_head, read_limited
from reviewblind.utils.git import GitError, GitRepository, differs_from_index, open_repository

_REGULAR_FILE_MODES = frozenset({"100644", "100755"})


@dataclass(frozen=True)
class Inventory:
    artifacts: tuple[Artifact, ...]
    skipped: tuple[SkippedArtifact, ...]
    excluded: int
    notes: tuple[str, ...]
    git_present: bool  # a .git directory or file at the scan root
    git_packaged: bool  # the archive will include it: see RB801
    git_entries: tuple[str, ...]  # every .git in the tree that is not excluded


def compile_excludes(patterns: tuple[str, ...]) -> pathspec.GitIgnoreSpec:
    try:
        return pathspec.GitIgnoreSpec.from_lines(patterns)
    except ValueError as error:
        raise ConfigError(f"scan.exclude contains an invalid pattern: {error}") from error


class _Collector:
    """Visits paths without following anything out of the scan root (threat T-05)."""

    def __init__(
        self,
        root: Path,
        settings: ScanSettings,
        excludes: pathspec.GitIgnoreSpec,
        tracked: frozenset[str] | None,
    ) -> None:
        self._root = root
        self._real_root = os.path.normcase(os.path.realpath(root))
        self._settings = settings
        self._excludes = excludes
        self._tracked = tracked
        self._visited: set[str] = {self._real_root}
        self._pending: list[str] = []
        self.artifacts: list[Artifact] = []
        self.skipped: list[SkippedArtifact] = []
        self.excluded = 0
        self.git_entries: list[str] = []

    def _skip(self, relpath: str, reason: SkipReason, detail: str) -> None:
        self.skipped.append(SkippedArtifact(relpath, reason, detail))

    def _is_inside_root(self, real_path: str) -> bool:
        normalized = os.path.normcase(real_path)
        return normalized == self._real_root or normalized.startswith(self._real_root + os.sep)

    def walk(self) -> None:
        self._pending.append("")
        self._drain()

    def visit_listed(self, paths: list[str]) -> None:
        """Visit paths reported by Git. A directory here is a submodule or nested repository."""
        for relpath in sorted(set(paths)):
            self._visit(relpath.rstrip("/"), listed_by_git=True)
        self._drain()

    def _drain(self) -> None:
        while self._pending:
            directory = self._pending.pop()
            try:
                with os.scandir(self._root / directory) as entries:
                    names = sorted(entry.name for entry in entries)
            except OSError as error:
                self._skip(directory or ".", SkipReason.UNREADABLE, error.strerror or str(error))
                continue
            for name in names:
                relpath = f"{directory}/{name}" if directory else name
                if name == ".git":  # never descended into, whatever the target
                    self.git_entries.append(relpath)
                else:
                    self._visit(relpath, listed_by_git=False)

    def _visit(self, relpath: str, *, listed_by_git: bool) -> None:
        path = self._root / relpath
        try:
            status = os.lstat(path)
        except OSError as error:
            detail = "tracked by Git but missing" if listed_by_git else str(error.strerror)
            self._skip(relpath, SkipReason.UNREADABLE, detail)
            return
        if stat.S_ISDIR(status.st_mode) and not stat.S_ISLNK(status.st_mode):
            self._visit_directory(relpath, listed_by_git=listed_by_git)
        elif self._excludes.match_file(relpath):
            self.excluded += 1
        elif stat.S_ISLNK(status.st_mode):
            self._visit_symlink(relpath)
        elif stat.S_ISREG(status.st_mode):
            self._add_file(relpath, status.st_size)
        else:
            # Reading a FIFO would hang the scan forever.
            self._skip(relpath, SkipReason.UNREADABLE, "not a regular file")

    def _visit_directory(self, relpath: str, *, listed_by_git: bool) -> None:
        if listed_by_git:
            self._skip(relpath, SkipReason.SUBMODULE_NOT_INSPECTED, "a nested Git repository")
            return
        # A Windows junction reports as a directory, so containment is checked for every one.
        real_path = os.path.realpath(self._root / relpath)
        if not self._is_inside_root(real_path):
            self._skip(relpath, SkipReason.SYMLINK_NOT_FOLLOWED, "it leads outside the scan root")
            return
        normalized = os.path.normcase(real_path)
        if normalized not in self._visited:
            self._visited.add(normalized)
            self._pending.append(relpath)

    def _visit_symlink(self, relpath: str) -> None:
        real_path = os.path.realpath(self._root / relpath)
        resolved = Path(real_path)
        if not self._is_inside_root(real_path):
            self._skip(relpath, SkipReason.SYMLINK_NOT_FOLLOWED, "it leads outside the scan root")
        elif not self._settings.follow_symlinks:
            self._skip(relpath, SkipReason.SYMLINK_NOT_FOLLOWED, "follow_symlinks is off")
        elif not resolved.exists():
            self._skip(relpath, SkipReason.SYMLINK_NOT_FOLLOWED, "its target does not exist")
        elif resolved.is_dir():
            normalized = os.path.normcase(real_path)
            if normalized not in self._visited:
                self._visited.add(normalized)
                self._pending.append(relpath)
        else:
            self._add_file(relpath, resolved.stat().st_size)

    def _add_file(self, relpath: str, size: int) -> None:
        path = self._root / relpath
        try:
            head = read_head(path)
        except OSError as error:
            self._skip(relpath, SkipReason.UNREADABLE, error.strerror or str(error))
            return
        tracked = None if self._tracked is None else relpath in self._tracked
        self.artifacts.append(Artifact(path, relpath, classify(relpath, head), size, tracked))


def _count_uncommitted(repository: GitRepository, root: Path, limit: int) -> int:
    """How many tracked files differ from the index. Never runs a repository-defined filter."""
    count = 0
    for entry in repository.index_entries():
        path = root / entry.path
        if entry.mode not in _REGULAR_FILE_MODES or path.is_symlink():
            continue
        try:
            content = read_limited(path, limit)
        except OSError:
            continue  # a missing file is already reported as skipped
        if content is not None and differs_from_index(content, entry.object_id):
            count += 1
    return count


def build_inventory(root: Path, target: Target, settings: ScanSettings) -> Inventory:
    """List what a reviewer could see for this target. Raises `ConfigError` on bad patterns."""
    excludes = compile_excludes(settings.exclude)
    notes: list[str] = []
    git_failure: str | None = None
    repository: GitRepository | None = None
    tracked: list[str] = []
    untracked: list[str] = []
    try:
        repository = open_repository(root)
        if repository is not None:
            tracked = repository.tracked_files()
            untracked = repository.untracked_files()
    except GitError as error:
        repository = None
        git_failure = str(error)

    collector = _Collector(
        root, settings, excludes, None if repository is None else frozenset(tracked)
    )
    if repository is not None and target is not Target.ARCHIVE:
        collector.visit_listed(tracked + untracked)
        uncommitted = _count_uncommitted(repository, root, settings.max_binary_bytes)
        if uncommitted:
            notes.append(
                f"Results reflect the working tree; {uncommitted} tracked file(s) differ from "
                "the index. A reviewer sees what was pushed."
            )
    else:
        # Zipping a folder does not honour .gitignore, so an archive covers every file.
        collector.walk()
        if repository is None and git_failure is None and target is not Target.ARCHIVE:
            notes.append("Not a Git repository, so every file under the root was inspected.")

    if git_failure is not None:
        collector.skipped.append(SkippedArtifact(".git", SkipReason.GIT_UNAVAILABLE, git_failure))
        notes.append("Git could not read this repository, so every file was inspected.")

    git_present = os.path.lexists(root / ".git")
    git_entries = {".git"} if git_present else set()
    git_entries.update(collector.git_entries)
    return Inventory(
        artifacts=tuple(sorted(collector.artifacts, key=lambda item: item.relpath)),
        skipped=tuple(sorted(collector.skipped, key=lambda item: item.path)),
        excluded=collector.excluded,
        notes=tuple(notes),
        git_present=git_present,
        git_packaged=(
            target is Target.ARCHIVE and git_present and not excludes.match_file(".git/config")
        ),
        git_entries=tuple(
            sorted(entry for entry in git_entries if not excludes.match_file(f"{entry}/config"))
        ),
    )
