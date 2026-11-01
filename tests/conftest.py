"""The benchmark repositories. What cannot be committed is built here (docs/TEST_PLAN.md).

Git history cannot sit inside this repository, `.DS_Store` is ignored by it, and PDFs, images and other
binaries are generated so that it holds nothing opaque.
"""

from __future__ import annotations

import io
import shutil
import zipfile
from pathlib import Path

import pytest
from PIL import Image

from _helpers import git, jpeg, make_pdf, write_tree

FIXTURES = Path(__file__).parent / "fixtures"
_ALICE = ("-c", "user.name=Alice Example", "-c", "user.email=alice@example.edu")


def _zip_archive() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("raw/graph.csv", "source,target\n1,2\n")
    return buffer.getvalue()


def _png() -> bytes:
    buffer = io.BytesIO()
    Image.new("RGB", (4, 4)).save(buffer, format="PNG")
    return buffer.getvalue()


@pytest.fixture(scope="session")
def leaking_repo(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Every planted leak in tests/fixtures/leaking_repo/expected.toml. Copy it to change it."""
    root = tmp_path_factory.mktemp("benchmark") / "repo"
    shutil.copytree(FIXTURES / "leaking_repo", root, ignore=shutil.ignore_patterns("expected.toml"))
    write_tree(
        root,
        {
            "figures/architecture.pdf": make_pdf(metadata={"author": "Alice Example"}),
            "figures/poster.pdf": make_pdf(pages=("Poster by Alice Example",)),
            "figures/plot.jpg": jpeg({0x013B: "Alice Example"}),
            "figures/field-site.jpg": jpeg({0x0131: "Camera"}, gps=True),
            "figures/team-photo.png": _png(),
            ".DS_Store": b"\x00\x00\x00\x01Bud1\x00\x00",
            "results/model-output.bin": b"\x00\x01weights\xff\xfe",
            "data/raw.zip": _zip_archive(),
        },
    )
    git(root, "init", "-q")
    git(root, "remote", "add", "origin", "git@github.com:aliceexample/paper.git")
    git(root, "add", "-A")
    git(
        root,
        *_ALICE,
        "commit",
        "-q",
        "-m",
        "Add the first experiments\n\nSigned-off-by: Alice Example <alice@example.edu>",
    )
    return root


@pytest.fixture
def clean_repo(tmp_path: Path) -> Path:
    """Ordinary research code full of lookalikes, with no Git history and no binary files."""
    root = tmp_path / "clean"
    shutil.copytree(FIXTURES / "clean_repo", root)
    return root
