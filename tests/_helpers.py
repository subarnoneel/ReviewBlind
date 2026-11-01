"""Shared test helpers. Every identity here is the fictional persona in CONTRIBUTING.md."""

from __future__ import annotations

import io
import os
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from PIL import ExifTags, Image

from reviewblind.config import Config, IdentityConfig, ScanSettings
from reviewblind.engine import run_scan
from reviewblind.models import Finding, ScanReport, Target
from reviewblind.scanners.pdf import load_pymupdf

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


def git_input(root: Path, text: str, *args: str) -> str:
    """Plain Git, with `text` on its standard input."""
    return subprocess.run(
        ["git", *args],
        cwd=root,
        env=_git_environment(),
        input=text.encode("utf-8"),  # as bytes, so Windows does not rewrite the line endings
        capture_output=True,
        check=True,
        timeout=60,
    ).stdout.decode("utf-8")


def init_repo(root: Path, files: Mapping[str, str | bytes] | None = None) -> Path:
    """Create a repository with one commit containing `files`."""
    root.mkdir(parents=True, exist_ok=True)
    git(root, "init", "-q")
    write_tree(root, files or {"README.md": "A project\n"})
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "Initial commit")
    return root


def make_pdf(
    *,
    metadata: dict[str, str] | None = None,
    xmp: str | None = None,
    pages: tuple[str, ...] = ("Some ordinary content",),
    link: str | None = None,
    encrypted: bool = False,
) -> bytes:
    pymupdf: Any = load_pymupdf()
    document = pymupdf.open()
    for text in pages:
        page = document.new_page()
        page.insert_text((72, 72), text)
        if link:
            page.insert_link(
                {"kind": pymupdf.LINK_URI, "from": pymupdf.Rect(72, 80, 200, 100), "uri": link}
            )
    document.set_metadata(metadata or {})
    if xmp:
        document.set_xml_metadata(xmp)
    options = {"encryption": pymupdf.PDF_ENCRYPT_AES_256, "user_pw": "u", "owner_pw": "o"}
    content: bytes = document.tobytes(**(options if encrypted else {}))
    document.close()
    return content


def jpeg(
    tags: dict[int, str | bytes] | None = None,
    exif_ifd: dict[int, str | bytes] | None = None,
    *,
    gps: bool = False,
    comment: bytes | None = None,
) -> bytes:
    exif = Image.Exif()
    for tag, value in (tags or {}).items():
        exif[tag] = value
    if exif_ifd:
        details = exif.get_ifd(ExifTags.IFD.Exif)
        details.update(exif_ifd)
    if gps:
        location = exif.get_ifd(ExifTags.IFD.GPSInfo)
        location[ExifTags.GPS.GPSLatitudeRef] = "N"
    buffer = io.BytesIO()
    options = {"comment": comment} if comment else {}
    Image.new("RGB", (4, 4)).save(buffer, format="JPEG", exif=exif, **options)
    return buffer.getvalue()


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
