"""Shared test helpers. Every identity here is the fictional persona in CONTRIBUTING.md."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping
from pathlib import Path

import pytest

from reviewblind.config import Config, IdentityConfig, ScanSettings
from reviewblind.engine import run_scan
from reviewblind.models import Finding, ScanReport, Target

PERSONA = Config(
    identity=IdentityConfig(
        names=("Alice Example",),
        emails=("alice@example.edu",),
        usernames=("aliceexample",),
        affiliations=("Example University", "EU"),
        aliases=("A. Example",),
        urls=("https://alice.example.dev",),
    ),
    scan=ScanSettings(exclude=()),
)


def write_tree(root: Path, files: Mapping[str, str | bytes]) -> None:
    for relpath, content in files.items():
        path = root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_bytes(content.encode("utf-8"))


def _git_environment() -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    # Tests must not depend on the developer's own Git configuration.
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    return environment


def git(root: Path, *args: str) -> str:
    """Plain Git for building fixtures. This is deliberately not the hardened runner."""
    completed = subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.org",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.autocrlf=false",
            *args,
        ],
        cwd=root,
        env=_git_environment(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    return completed.stdout


def init_repo(root: Path, files: Mapping[str, str | bytes] | None = None) -> Path:
    """Create a repository with one commit containing `files`."""
    root.mkdir(parents=True, exist_ok=True)
    git(root, "init", "-q")
    write_tree(root, files or {"README.md": "A project\n"})
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "Initial commit")
    return root


def symlink_or_skip(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError:
        pytest.skip("this process cannot create symbolic links")


def scan(root: Path, target: Target = Target.MIRROR, config: Config = PERSONA) -> ScanReport:
    return run_scan(root, config, target)


def findings(root: Path, target: Target = Target.MIRROR, config: Config = PERSONA) -> list[Finding]:
    return scan(root, target, config).result.findings


def rules_found(items: list[Finding]) -> list[str]:
    return [item.rule_id for item in items]
