"""The only place ReviewBlind starts a subprocess. See docs/ARCHITECTURE.md, section 8.

A repository's `.git/config` is attacker-controlled input, and some of its keys run commands.
The flags below disable the ones that can be disabled. They do not cover everything: `git status`
and `git ls-files --modified` run a repo-defined clean filter even with these flags, and filter
names cannot be disabled from the command line. So only exact, tested commands are allowed.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

GIT_TIMEOUT_SECONDS = 60
MAX_GIT_OUTPUT_BYTES = 256 * 1024 * 1024  # a hostile commit message could be any size
_READ_CHUNK_BYTES = 64 * 1024

_HARDENING = (
    "--no-pager",
    "--no-optional-locks",
    "--no-replace-objects",
    "-c",
    "core.fsmonitor=false",
    "-c",
    f"core.hooksPath={os.devnull}",
    "-c",
    "protocol.allow=never",
    "-c",
    "safe.bareRepository=explicit",
    "-c",
    "i18n.logOutputEncoding=UTF-8",
)

# Raw names and emails, so that a `.mailmap` cannot hide an identity. The flags turn off what
# `git log` could otherwise be configured to do: `log.showSignature` with `gpg.program` runs a
# program chosen by the repository, and patches could run an external diff or textconv driver.
_LOG_FORMAT = "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B%x00"
_LOG_COMMAND = (
    "log",
    "--all",
    "--no-mailmap",
    "--no-show-signature",
    "--no-notes",
    "--no-patch",
    _LOG_FORMAT,
)
_MAX_COUNT = re.compile(r"--max-count=[0-9]+")
_LOG_FIELDS = 6

ALLOWED_COMMANDS = frozenset(
    {
        ("rev-parse", "--is-inside-work-tree"),
        ("rev-parse", "--git-path", "info/exclude"),
        ("ls-files", "--cached", "-z"),
        ("ls-files", "--others", "--exclude-standard", "-z"),
        ("ls-files", "-s", "-z"),
        ("remote", "-v"),
        ("rev-list", "--all", "--count"),
    }
)


def is_allowed_command(command: tuple[str, ...]) -> bool:
    """Exact matches only. Every command here has an attack test in tests/test_safety.py."""
    if command in ALLOWED_COMMANDS:
        return True
    return (
        len(command) == len(_LOG_COMMAND) + 1
        and command[:-1] == _LOG_COMMAND
        and _MAX_COUNT.fullmatch(command[-1]) is not None
    )


class GitError(Exception):
    """Git is missing, refused the repository, or failed. The scan is marked incomplete."""


class ForbiddenGitCommandError(Exception):
    """A bug in ReviewBlind: this command is not known to be safe on a hostile repository."""


@dataclass(frozen=True)
class IndexEntry:
    mode: str
    object_id: str
    path: str


@dataclass(frozen=True)
class Commit:
    sha: str
    author_name: str
    author_email: str
    committer_name: str
    committer_email: str
    message: str


@dataclass(frozen=True)
class _Completed:
    returncode: int
    stdout: bytes
    stderr: bytes


def find_git(root: Path) -> str | None:
    """Locate Git without ever choosing a copy planted in the scanned repository.

    Windows searches the current directory first, so a repository could otherwise run its own
    `git.exe` as soon as it is scanned (threat T-15). Only absolute PATH entries outside the scan
    root are considered, and an absolute path is what gets executed.
    """
    name = "git.exe" if os.name == "nt" else "git"
    real_root = os.path.normcase(os.path.realpath(root))
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry or not Path(entry).is_absolute():
            continue
        directory = os.path.normcase(os.path.realpath(entry))
        if directory == real_root or directory.startswith(real_root + os.sep):
            continue
        candidate = Path(entry) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _environment() -> dict[str, str]:
    # Inherited GIT_* variables could redirect Git to another repository or config.
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_LAZY_FETCH": "1",  # a partial clone would otherwise contact its remote
            "LC_ALL": "C",  # error messages are matched below
            "LANGUAGE": "C",
        }
    )
    return environment


def _read_within_limit(process: subprocess.Popen[bytes], name: str) -> bytes:
    """Read in pieces, because `read(limit + 1)` allocates the whole limit before reading."""
    received = bytearray()
    pipe = process.stdout
    while pipe is not None and (chunk := pipe.read(_READ_CHUNK_BYTES)):
        received += chunk
        if len(received) > MAX_GIT_OUTPUT_BYTES:
            process.kill()
            raise GitError(f"git {name} produced too much output")
    return bytes(received)


class GitRepository:
    """Read-only access to the repository containing a directory."""

    def __init__(self, root: Path, executable: str) -> None:
        self._root = root
        self._executable = executable

    def _run(self, *command: str) -> _Completed:
        if not is_allowed_command(command):
            raise ForbiddenGitCommandError(" ".join(command))
        timed_out = threading.Event()
        try:
            with (
                tempfile.TemporaryFile() as stderr,
                subprocess.Popen(  # noqa: S603 - absolute path, no shell, allowlisted arguments
                    [self._executable, *_HARDENING, *command],
                    cwd=self._root,
                    env=_environment(),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=stderr,
                ) as process,
            ):

                def stop() -> None:
                    timed_out.set()
                    process.kill()

                timer = threading.Timer(GIT_TIMEOUT_SECONDS, stop)
                timer.start()
                try:
                    stdout = _read_within_limit(process, command[0])
                    process.wait()
                finally:
                    timer.cancel()
                stderr.seek(0)
                errors = stderr.read(64 * 1024)
        except OSError as error:
            raise GitError(f"could not run git: {error.strerror or error}") from error
        if timed_out.is_set():
            raise GitError(f"git {command[0]} timed out")
        return _Completed(process.returncode, stdout, errors)

    def _output(self, *command: str) -> bytes:
        completed = self._run(*command)
        if completed.returncode != 0:
            raise GitError(completed.stderr.decode("utf-8", "replace").strip())
        return completed.stdout

    def is_work_tree(self) -> bool:
        """True inside a working tree. Raises `GitError` if this is not a usable repository."""
        return self._output("rev-parse", "--is-inside-work-tree").strip() == b"true"

    def exclude_file(self) -> Path:
        """Where this repository keeps its local, untracked ignore rules."""
        reported = self._output("rev-parse", "--git-path", "info/exclude").strip()
        return self._root / os.fsdecode(reported)

    def tracked_files(self) -> list[str]:
        return _split_paths(self._output("ls-files", "--cached", "-z"))

    def untracked_files(self) -> list[str]:
        """Untracked files that are not ignored. A nested repository appears as `name/`."""
        return _split_paths(self._output("ls-files", "--others", "--exclude-standard", "-z"))

    def index_entries(self) -> list[IndexEntry]:
        entries = []
        for record in self._output("ls-files", "-s", "-z").split(b"\0"):
            if record:
                header, _, path = record.partition(b"\t")
                mode, object_id, _stage = header.decode("ascii").split(" ")
                entries.append(IndexEntry(mode, object_id, os.fsdecode(path)))
        return entries

    def remotes(self) -> list[tuple[str, str]]:
        """Each remote name and URL, once. Reads local config and never contacts a remote."""
        found: dict[tuple[str, str], None] = {}
        output = self._output("remote", "-v").decode("utf-8", "replace")
        for line in output.splitlines():
            name, _, rest = line.partition("\t")
            url = rest.rsplit(" (", 1)[0]
            if name and url:
                found[(name, url)] = None
        return list(found)

    def commit_count(self) -> int:
        return int(self._output("rev-list", "--all", "--count").strip() or b"0")

    def commits(self, limit: int) -> list[Commit]:
        """Up to `limit` commits from every ref, newest first."""
        output = self._output(*_LOG_COMMAND, f"--max-count={limit}")
        fields = output.decode("utf-8", "replace").split("\0")
        return [
            Commit(
                sha=fields[start].strip(),
                author_name=fields[start + 1],
                author_email=fields[start + 2],
                committer_name=fields[start + 3],
                committer_email=fields[start + 4],
                message=fields[start + 5],
            )
            for start in range(0, len(fields) - _LOG_FIELDS + 1, _LOG_FIELDS)
        ]


def _split_paths(output: bytes) -> list[str]:
    return [os.fsdecode(path) for path in output.split(b"\0") if path]


def open_repository(root: Path) -> GitRepository | None:
    """The repository containing `root`, or `None` if it is not in one.

    Raises `GitError` when a repository is present but cannot be read, because Git is missing or
    refuses it. `safe.directory` is never changed on the user's behalf.
    """
    has_git_entry = os.path.lexists(root / ".git")
    executable = find_git(root)
    if executable is None:
        if has_git_entry:
            raise GitError("this is a Git repository, but no Git executable was found")
        return None
    repository = GitRepository(root, executable)
    try:
        return repository if repository.is_work_tree() else None
    except GitError as error:
        if not has_git_entry and "not a git repository" in str(error).lower():
            return None
        raise


def blob_id(content: bytes, length: int) -> str:
    """Git's object ID for file content. `length` is 40 for SHA-1 and 64 for SHA-256."""
    header = f"blob {len(content)}\0".encode("ascii")
    algorithm = "sha256" if length == 64 else "sha1"
    return hashlib.new(algorithm, header + content, usedforsecurity=False).hexdigest()


def differs_from_index(content: bytes, object_id: str) -> bool:
    """Compare file content with the index without running any repository-defined filter.

    This replaces `git status`, which is banned. Content is also compared with CRLF converted to
    LF, the most common cause of a file looking changed on Windows when it is not.
    """
    if blob_id(content, len(object_id)) == object_id:
        return False
    return blob_id(content.replace(b"\r\n", b"\n"), len(object_id)) != object_id
