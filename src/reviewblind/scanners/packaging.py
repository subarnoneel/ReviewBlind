"""Things that should not ship at all, or that ReviewBlind cannot look inside."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from reviewblind.models import Artifact, ArtifactKind, Detection, SkipReason
from reviewblind.scanners.base import ScanContext, file_fact

_OS_FILE_NAMES = frozenset({".ds_store", "thumbs.db"})
_MACOS_ARCHIVE_DIRECTORY = "__MACOSX"


def _os_metadata_path(relpath: str) -> str | None:
    """The path to report if this is operating-system residue. A directory is reported once."""
    parts = relpath.split("/")
    if _MACOS_ARCHIVE_DIRECTORY in parts:
        return "/".join(parts[: parts.index(_MACOS_ARCHIVE_DIRECTORY) + 1])
    return relpath if parts[-1].lower() in _OS_FILE_NAMES else None


class PackagingScanner:
    name = "packaging"

    def supports(self, artifact: Artifact) -> bool:
        return (
            artifact.kind in {ArtifactKind.BINARY, ArtifactKind.ARCHIVE, ArtifactKind.REVIEWBLIND}
            or _os_metadata_path(artifact.relpath) is not None
        )

    def scan(self, artifact: Artifact, context: ScanContext) -> Iterator[Detection]:
        relpath = artifact.relpath
        if artifact.kind is ArtifactKind.REVIEWBLIND:
            yield file_fact(
                "RB805",
                relpath,
                "This file lists author identities in plain text.",
                "Found a ReviewBlind config or report",
            )
            return
        os_path = _os_metadata_path(relpath)
        if os_path is not None:
            # Its only meaning is that it should not ship, so it is not also an unreadable binary.
            yield file_fact("RB802", os_path, os_path, "Found operating-system metadata")
        elif artifact.kind is ArtifactKind.BINARY:
            context.report_skip(relpath, SkipReason.UNSUPPORTED_BINARY, "unsupported binary format")
            yield file_fact(
                "RB803", relpath, "Binary contents were not inspected.", "Found an unreadable file"
            )
        elif artifact.kind is ArtifactKind.ARCHIVE:
            context.report_skip(
                relpath, SkipReason.ARCHIVE_NOT_INSPECTED, "archives are not unpacked"
            )
            yield file_fact(
                "RB804", relpath, "Archive contents were not inspected.", "Found an archive"
            )


class GitDirectoryScanner:
    name = "git-directory"

    def scan(self, context: ScanContext) -> Iterable[Detection]:
        return [
            file_fact("RB801", path, path, "Found a Git directory")
            for path in context.inventory.git_entries
        ]
