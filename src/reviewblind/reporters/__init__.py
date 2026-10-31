"""Reporters turn a finished scan into text. They read results and change nothing."""

from __future__ import annotations

from pathlib import Path

from reviewblind.models import ScanReport


def display_root(root: Path) -> str:
    """Show a home directory as `~`, so a shared capture reveals less."""
    resolved = root.resolve()
    try:
        return "~/" + resolved.relative_to(Path.home().resolve()).as_posix()
    except (ValueError, RuntimeError):
        return resolved.as_posix()


def display_config_path(report: ScanReport) -> str | None:
    """The config used: relative to the root when inside it, otherwise like `display_root`."""
    if report.config_path is None:
        return None
    resolved = report.config_path.resolve()
    try:
        return resolved.relative_to(report.root.resolve()).as_posix()
    except ValueError:
        return display_root(resolved)
