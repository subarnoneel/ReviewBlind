"""Scanner registration. Adding a scanner means adding it here, with no change to the engine."""

from __future__ import annotations

from reviewblind.scanners.base import FileScanner, RepositoryScanner
from reviewblind.scanners.git import GitScanner
from reviewblind.scanners.manifests import ManifestScanner
from reviewblind.scanners.packaging import GitDirectoryScanner, PackagingScanner
from reviewblind.scanners.paths import PathScanner
from reviewblind.scanners.text import TextScanner

PATH_SCANNER: FileScanner = PathScanner()
CONTENT_SCANNERS: tuple[FileScanner, ...] = (TextScanner(), ManifestScanner(), PackagingScanner())
REPOSITORY_SCANNERS: tuple[RepositoryScanner, ...] = (GitDirectoryScanner(), GitScanner())
