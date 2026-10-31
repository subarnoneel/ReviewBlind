"""Scanner registration. Adding a scanner means adding it here, with no change to the engine."""

from __future__ import annotations

from reviewblind.scanners.base import FileScanner, RepositoryScanner
from reviewblind.scanners.paths import PathScanner
from reviewblind.scanners.text import TextScanner

PATH_SCANNER: FileScanner = PathScanner()
CONTENT_SCANNERS: tuple[FileScanner, ...] = (TextScanner(),)
REPOSITORY_SCANNERS: tuple[RepositoryScanner, ...] = ()
