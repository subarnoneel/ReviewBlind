"""Finding likely author identities. Reads and never writes (FR-DISC-10)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from reviewblind.config import ScanSettings
from reviewblind.discovery.candidates import (
    Candidate,
    Observation,
    SourceClass,
    derived_aliases,
    merge,
)
from reviewblind.discovery.git import from_git
from reviewblind.discovery.latex import from_latex
from reviewblind.discovery.manifests import from_manifest
from reviewblind.inventory import build_inventory
from reviewblind.models import Artifact, ArtifactKind, Confidence, IdentityKind, SkipReason, Target
from reviewblind.scanners.base import DEFAULT_MAX_COMMITS
from reviewblind.signals import is_placeholder_user
from reviewblind.utils.files import decode_text, read_limited
from reviewblind.utils.git import GitError
from reviewblind.utils.text import comparison_key

MAX_LATEX_FILES = 200


@dataclass(frozen=True)
class Discovery:
    candidates: tuple[Candidate, ...]
    notes: tuple[str, ...]


def _read(artifact: Artifact, limit: int) -> str | None:
    try:
        content = read_limited(artifact.path, limit)
        return None if content is None else decode_text(content)
    except (OSError, UnicodeDecodeError):
        return None


def _from_environment() -> list[Observation]:
    """The local account, read only when asked for: it may have nothing to do with the work."""
    names = [os.environ.get("USER"), os.environ.get("USERNAME"), Path.home().name]
    return [
        Observation(
            name,
            IdentityKind.USERNAME,
            Confidence.LOW,
            "environment username",
            SourceClass.ENVIRONMENT,
        )
        for name in dict.fromkeys(names)
        if name and not is_placeholder_user(name)
    ]


def _from_files(artifacts: tuple[Artifact, ...], limit: int) -> tuple[list[Observation], list[str]]:
    """Only top-level manifests count, because a nested one usually describes vendored code."""
    observations: list[Observation] = []
    notes: list[str] = []
    latex_read = 0
    for artifact in artifacts:
        is_top_level_manifest = (
            artifact.kind is ArtifactKind.MANIFEST and "/" not in artifact.relpath
        )
        is_latex = artifact.kind is ArtifactKind.TEXT and artifact.relpath.lower().endswith(".tex")
        if is_latex and latex_read >= MAX_LATEX_FILES:
            continue
        if not is_top_level_manifest and not is_latex:
            continue
        text = _read(artifact, limit)
        if text is None:
            notes.append(f"{artifact.relpath} could not be read.")
            continue
        if is_latex:
            latex_read += 1
            observations.extend(from_latex(artifact.relpath, text))
        else:
            found, file_notes = from_manifest(artifact.relpath, text)
            observations.extend(found)
            notes.extend(file_notes)
    return observations, notes


def discover(
    root: Path, *, include_env: bool = False, max_commits: int = DEFAULT_MAX_COMMITS
) -> Discovery:
    """Find likely identities in a directory. Nothing is confirmed until a person says so."""
    settings = ScanSettings()
    inventory = build_inventory(root, Target.MIRROR, settings)
    observations, notes = _from_files(inventory.artifacts, settings.max_text_bytes)
    notes.extend(
        f"Git could not read this repository: {item.detail}"
        for item in inventory.skipped
        if item.reason is SkipReason.GIT_UNAVAILABLE
    )
    if inventory.repository is not None:
        try:
            from_history, history_notes = from_git(inventory.repository, max_commits)
            observations.extend(from_history)
            notes.extend(history_notes)
        except GitError as error:
            notes.append(f"Git history could not be read: {error}")
    if include_env:
        observations.extend(_from_environment())

    merged = merge(observations)
    aliases = derived_aliases(merged)
    known = {comparison_key(candidate.value) for candidate in merged}
    fresh = [alias for alias in aliases if comparison_key(alias.value) not in known]
    return Discovery(tuple(merge([*observations, *fresh])), tuple(notes))


__all__ = ["Candidate", "Discovery", "discover"]
