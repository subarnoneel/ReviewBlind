"""PDF metadata and text (FR-PDF-1 to FR-PDF-3). PDFs are built at test time (D-33)."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from _helpers import PERSONA, findings, rules_found, scan, write_tree
from reviewblind.config import ScanSettings, write_config
from reviewblind.models import Confidence, Finding, Severity, SkipReason, Target
from reviewblind.scanners import pdf as pdf_module
from reviewblind.scanners.pdf import load_pymupdf


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


def scan_pdf(root: Path, content: bytes) -> list[Finding]:
    write_tree(root, {"figure.pdf": content})
    return findings(root)


def only(items: list[Finding]) -> Finding:
    assert len(items) == 1, [(item.rule_id, item.matched) for item in items]
    return items[0]


# RB601: metadata


@pytest.mark.parametrize(
    ("key", "label"),
    [
        ("author", "Author"),
        ("title", "Title"),
        ("subject", "Subject"),
        ("keywords", "Keywords"),
        ("creator", "Creator"),
        ("producer", "Producer"),
    ],
)
def test_identity_in_each_metadata_field(tmp_path: Path, key: str, label: str) -> None:
    found = only(scan_pdf(tmp_path, make_pdf(metadata={key: "Alice Example"})))
    assert (found.rule_id, found.severity) == ("RB601", Severity.BLOCKER)
    assert found.confidence is Confidence.HIGH
    assert found.location.field == f"PDF metadata: {label}"
    assert found.matched == "Alice Example"


def test_identity_in_xmp_metadata(tmp_path: Path) -> None:
    xmp = (
        '<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        '<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Alice Example</dc:creator>'
        "</rdf:Description></rdf:RDF></x:xmpmeta>"
    )
    found = only(scan_pdf(tmp_path, make_pdf(xmp=xmp)))
    assert found.location.field == "PDF metadata: XMP"


def test_a_metadata_author_outside_the_config_is_a_warning(tmp_path: Path) -> None:
    # The figure may be someone else's, but it may also be a co-author missing from the config.
    found = only(scan_pdf(tmp_path, make_pdf(metadata={"author": "Bob Coauthor"})))
    assert (found.severity, found.confidence) == (Severity.WARNING, Confidence.MEDIUM)
    assert found.identity is None


@pytest.mark.parametrize("author", ["Anonymous Authors", "anonymous", "", "   ", "Unknown"])
def test_a_placeholder_author_is_not_a_finding(tmp_path: Path, author: str) -> None:
    assert scan_pdf(tmp_path, make_pdf(metadata={"author": author})) == []


@pytest.mark.parametrize("key", ["creator", "producer", "title"])
def test_other_unconfirmed_metadata_is_not_a_finding(tmp_path: Path, key: str) -> None:
    assert scan_pdf(tmp_path, make_pdf(metadata={key: "LaTeX with hyperref"})) == []


def test_a_home_path_in_metadata_is_a_warning(tmp_path: Path) -> None:
    content = make_pdf(metadata={"title": "/home/aliceexample/figure.tex"})
    found = only(scan_pdf(tmp_path, content))
    assert (found.rule_id, found.severity) == ("RB601", Severity.WARNING)
    assert found.identity == "aliceexample"


def test_an_affiliation_in_metadata_is_a_warning(tmp_path: Path) -> None:
    found = only(scan_pdf(tmp_path, make_pdf(metadata={"subject": "Example University"})))
    assert found.severity is Severity.WARNING


@pytest.mark.parametrize("target", list(Target))
def test_metadata_is_a_blocker_on_every_target(tmp_path: Path, target: Target) -> None:
    # A mirror cannot rewrite binary files, so it offers no protection here (D-22).
    write_tree(tmp_path, {"figure.pdf": make_pdf(metadata={"author": "Alice Example"})})
    assert findings(tmp_path, target)[0].severity is Severity.BLOCKER


# RB602: text and links


def test_identity_in_page_text(tmp_path: Path) -> None:
    found = only(scan_pdf(tmp_path, make_pdf(pages=("A poster by Alice Example",))))
    assert (found.rule_id, found.severity) == ("RB602", Severity.BLOCKER)
    assert found.location.field == "page 1"
    assert "Alice Example" in found.evidence


def test_each_page_is_located(tmp_path: Path) -> None:
    content = make_pdf(pages=("nothing", "by Alice Example", "nothing", "by Alice Example"))
    fields = sorted(item.location.field or "" for item in scan_pdf(tmp_path, content))
    assert fields == ["page 2", "page 4"]


def test_an_affiliation_in_text_is_a_warning(tmp_path: Path) -> None:
    found = only(scan_pdf(tmp_path, make_pdf(pages=("At Example University",))))
    assert found.severity is Severity.WARNING


def test_identity_in_a_link(tmp_path: Path) -> None:
    found = only(scan_pdf(tmp_path, make_pdf(link="https://github.com/aliceexample/tools")))
    assert (found.rule_id, found.location.field) == ("RB602", "page 1 link")
    assert found.matched == "github.com/aliceexample/tools"


def test_an_ordinary_link_is_not_a_finding(tmp_path: Path) -> None:
    assert scan_pdf(tmp_path, make_pdf(link="https://github.com/pytorch/pytorch")) == []


def test_unconfirmed_paths_in_text_are_not_findings(tmp_path: Path) -> None:
    assert scan_pdf(tmp_path, make_pdf(pages=("See /home/bob/out",))) == []


def test_a_clean_pdf_is_complete(tmp_path: Path) -> None:
    write_tree(tmp_path, {"figure.pdf": make_pdf()})
    report = scan(tmp_path)
    assert report.result.findings == []
    assert not report.result.incomplete
    assert report.result.inspected == 1


def test_an_empty_page_is_fine(tmp_path: Path) -> None:
    assert scan_pdf(tmp_path, make_pdf(pages=("",))) == []


# Files that cannot be read (FR-PDF-3)


def test_an_encrypted_pdf_is_reported(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {"figure.pdf": make_pdf(metadata={"author": "Alice Example"}, encrypted=True)},
    )
    report = scan(tmp_path)
    assert report.result.skipped[0].reason is SkipReason.ENCRYPTED
    assert report.result.incomplete


@pytest.mark.parametrize(
    "content",
    [b"", b"%PDF-1.7 not really a pdf", b"not a pdf at all", b"%PDF-1.4\n" + b"\x00" * 500],
)
def test_a_corrupt_pdf_is_reported(tmp_path: Path, content: bytes) -> None:
    write_tree(tmp_path, {"figure.pdf": content})
    report = scan(tmp_path)
    assert report.result.incomplete
    assert report.result.findings == []
    assert report.result.skipped[0].reason is SkipReason.CORRUPT


def test_a_truncated_pdf_does_not_stop_the_scan(tmp_path: Path) -> None:
    full = make_pdf(metadata={"author": "Alice Example"})
    write_tree(tmp_path, {"figure.pdf": full[: len(full) // 2], "a.txt": "Alice Example\n"})
    assert "RB101" in rules_found(scan(tmp_path).result.findings)


def test_mupdf_messages_do_not_reach_the_terminal(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    write_tree(tmp_path, {"figure.pdf": b"%PDF-1.7\n1 0 obj\n<<\nendobj\ntrailer\n<<>>\n"})
    scan(tmp_path)
    captured = capfd.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_an_oversized_pdf_is_never_parsed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def must_not_load() -> None:
        raise AssertionError("an oversized PDF reached the parser")

    write_tree(tmp_path, {"figure.pdf": make_pdf()})
    monkeypatch.setattr(pdf_module, "load_pymupdf", must_not_load)
    config = replace(PERSONA, scan=ScanSettings(max_binary_bytes=10, exclude=()))
    report = scan(tmp_path, config=config)
    assert report.result.skipped[0].reason is SkipReason.TOO_LARGE


def test_only_the_first_pages_are_read_and_that_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pdf_module, "MAX_PAGES", 1)
    content = make_pdf(pages=("nothing", "by Alice Example"))
    write_tree(tmp_path, {"figure.pdf": content})
    report = scan(tmp_path)
    assert report.result.findings == []
    assert report.result.skipped[0].reason is SkipReason.TOO_LARGE
    assert "first 1 pages" in (report.result.skipped[0].detail or "")


def test_a_text_flood_stops_and_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pdf_module, "MAX_TEXT_CHARACTERS", 5)
    write_tree(tmp_path, {"figure.pdf": make_pdf(pages=("first page text", "Alice Example"))})
    report = scan(tmp_path)
    assert report.result.skipped[0].reason is SkipReason.TOO_LARGE
    assert report.result.incomplete


def test_a_failure_on_one_page_keeps_the_others(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(tmp_path, {"figure.pdf": make_pdf(pages=("first", "by Alice Example"))})
    pymupdf = load_pymupdf()
    real_load = pymupdf.Document.load_page

    def fail_first(self: Any, number: int = 0) -> Any:
        if number == 0:
            raise RuntimeError("bad page")
        return real_load(self, number)

    monkeypatch.setattr(pymupdf.Document, "load_page", fail_first)
    report = scan(tmp_path)
    assert rules_found(report.result.findings) == ["RB602"]
    assert report.result.skipped[0].reason is SkipReason.CORRUPT
    assert "page 1" in (report.result.skipped[0].detail or "")


# Safety


def test_a_pdf_is_never_modified(tmp_path: Path) -> None:
    # FR-PDF-2
    content = make_pdf(metadata={"author": "Alice Example"})
    write_tree(tmp_path, {"figure.pdf": content})
    before = hashlib.sha256(content).hexdigest()
    scan(tmp_path)
    assert hashlib.sha256((tmp_path / "figure.pdf").read_bytes()).hexdigest() == before


def test_pymupdf_is_not_loaded_until_a_pdf_appears() -> None:
    code = "import sys, reviewblind.cli; raise SystemExit(1 if 'pymupdf' in sys.modules else 0)"
    completed = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_warnings_as_errors_cannot_crash_a_scan(tmp_path: Path) -> None:
    # D-39: on macOS, PyMuPDF segfaults if its import-time warnings become errors. The guard must
    # hold even here, since a crash is something the scan engine could not contain.
    root = tmp_path / "repo"
    write_tree(root, {"figure.pdf": make_pdf(metadata={"author": "Alice Example"})})
    config = tmp_path / "private.toml"
    write_config(PERSONA, config)
    completed = subprocess.run(
        [
            sys.executable,
            "-W",
            "error",
            "-m",
            "reviewblind",
            "scan",
            str(root),
            "--config",
            str(config),
        ],
        capture_output=True,
        env={**os.environ, "PYTHONWARNINGS": "error"},
        stdin=subprocess.DEVNULL,
        timeout=120,
        check=False,
    )
    assert completed.returncode == 1, completed.stderr
    assert b"RB601" in completed.stdout
