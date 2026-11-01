"""Image metadata (FR-IMG-1 to FR-IMG-3). Images are built at test time (D-33)."""

from __future__ import annotations

import io
import struct
import zlib
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from PIL import ExifTags, Image, ImageFile, PngImagePlugin

from _helpers import PERSONA, findings, rules_found, scan, write_tree
from reviewblind.config import ScanSettings
from reviewblind.models import Confidence, Finding, Severity, SkipReason, Target
from reviewblind.scanners import image as image_module
from reviewblind.scanners.image import png_text_chunks


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


def png(*chunks: tuple[str, str]) -> bytes:
    info = PngImagePlugin.PngInfo()
    for key, value in chunks:
        info.add_text(key, value)
    buffer = io.BytesIO()
    Image.new("RGB", (4, 4)).save(buffer, format="PNG", pnginfo=info)
    return buffer.getvalue()


def chunk(kind: bytes, body: bytes) -> bytes:
    crc = zlib.crc32(kind + body)
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", crc)


SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _png_with(*chunks: bytes) -> bytes:
    header = struct.pack(">IIBBBBB", 4, 4, 8, 2, 0, 0, 0)
    return SIGNATURE + chunk(b"IHDR", header) + b"".join(chunks) + chunk(b"IEND", b"")


def scan_image(root: Path, content: bytes, name: str = "plot.jpg") -> list[Finding]:
    write_tree(root, {name: content})
    return findings(root)


def by_rule(items: list[Finding], rule_id: str) -> list[Finding]:
    return [item for item in items if item.rule_id == rule_id]


# RB703: every image


@pytest.mark.parametrize(
    ("name", "content"),
    [("a.jpg", jpeg()), ("a.png", png()), ("corrupt.png", b"not an image"), ("empty.gif", b"")],
)
def test_every_image_needs_a_visual_review(tmp_path: Path, name: str, content: bytes) -> None:
    # FR-IMG-2: even one that cannot be read at all.
    found = by_rule(scan_image(tmp_path, content, name), "RB703")
    assert len(found) == 1
    assert found[0].severity is Severity.REVIEW
    assert found[0].artifact == name


def test_visual_review_does_not_make_a_scan_incomplete(tmp_path: Path) -> None:
    # FR-COMP-3: otherwise every repository with a plot would be incomplete.
    write_tree(tmp_path, {"plot.png": png()})
    report = scan(tmp_path)
    assert rules_found(report.result.findings) == ["RB703"]
    assert not report.result.incomplete
    assert report.result.inspected == 1


# RB701: metadata


@pytest.mark.parametrize(
    ("tag", "field"),
    [
        (ExifTags.Base.Artist, "EXIF Artist"),
        (ExifTags.Base.Copyright, "EXIF Copyright"),
        (ExifTags.Base.ImageDescription, "EXIF ImageDescription"),
        (ExifTags.Base.Software, "EXIF Software"),
        (ExifTags.Base.HostComputer, "EXIF HostComputer"),
    ],
)
def test_identity_in_exif_fields(tmp_path: Path, tag: int, field: str) -> None:
    found = by_rule(scan_image(tmp_path, jpeg({tag: "Alice Example"})), "RB701")[0]
    assert (found.severity, found.confidence) == (Severity.BLOCKER, Confidence.HIGH)
    assert found.location.field == field
    assert found.matched == "Alice Example"


def test_identity_in_a_windows_field(tmp_path: Path) -> None:
    content = jpeg({ExifTags.Base.XPAuthor: "Alice Example\x00".encode("utf-16-le")})
    found = by_rule(scan_image(tmp_path, content), "RB701")[0]
    assert found.location.field == "EXIF XPAuthor"
    assert found.matched == "Alice Example"


@pytest.mark.parametrize(
    "comment",
    [
        b"ASCII\x00\x00\x00Alice Example",
        b"UNICODE\x00" + "Alice Example".encode("utf-16"),
        b"\x00\x00\x00\x00\x00\x00\x00\x00Alice Example",
    ],
)
def test_identity_in_a_user_comment(tmp_path: Path, comment: bytes) -> None:
    content = jpeg(exif_ifd={ExifTags.Base.UserComment: comment})
    found = by_rule(scan_image(tmp_path, content), "RB701")[0]
    assert found.location.field == "EXIF UserComment"


def test_identity_in_camera_owner(tmp_path: Path) -> None:
    content = jpeg(exif_ifd={ExifTags.Base.CameraOwnerName: "Alice Example"})
    assert (
        by_rule(scan_image(tmp_path, content), "RB701")[0].location.field == "EXIF CameraOwnerName"
    )


def test_identity_in_a_jpeg_comment(tmp_path: Path) -> None:
    found = by_rule(scan_image(tmp_path, jpeg(comment=b"By Alice Example")), "RB701")[0]
    assert found.location.field == "Image text: comment"


@pytest.mark.parametrize(
    "key", ["Author", "Comment", "Description", "Software", "XML:com.adobe.xmp"]
)
def test_identity_in_png_text(tmp_path: Path, key: str) -> None:
    content = png((key, "by Alice Example"))
    found = by_rule(scan_image(tmp_path, content, "plot.png"), "RB701")[0]
    assert found.location.field == f"Image text: {key}"


def test_a_home_path_in_metadata_is_a_warning(tmp_path: Path) -> None:
    content = png(("Source", "/Users/aliceexample/figure.ai"))
    found = by_rule(scan_image(tmp_path, content, "plot.png"), "RB701")[0]
    assert found.severity is Severity.WARNING
    assert found.identity == "aliceexample"


def test_an_affiliation_in_metadata_is_a_warning(tmp_path: Path) -> None:
    found = by_rule(
        scan_image(tmp_path, jpeg({ExifTags.Base.Copyright: "Example University"})), "RB701"
    )[0]
    assert found.severity is Severity.WARNING


@pytest.mark.parametrize(
    "tag",
    [ExifTags.Base.Artist, ExifTags.Base.Copyright],
)
def test_an_owner_outside_the_config_is_a_warning(tmp_path: Path, tag: int) -> None:
    found = by_rule(scan_image(tmp_path, jpeg({tag: "Bob Coauthor"})), "RB701")[0]
    assert (found.severity, found.confidence) == (Severity.WARNING, Confidence.MEDIUM)
    assert found.identity is None


def test_a_png_author_outside_the_config_is_a_warning(tmp_path: Path) -> None:
    found = by_rule(scan_image(tmp_path, png(("Author", "Bob Coauthor")), "plot.png"), "RB701")[0]
    assert found.severity is Severity.WARNING


@pytest.mark.parametrize(
    "tag",
    [ExifTags.Base.Software, ExifTags.Base.ImageDescription],
)
def test_other_unconfirmed_fields_are_not_findings(tmp_path: Path, tag: int) -> None:
    assert by_rule(scan_image(tmp_path, jpeg({tag: "Adobe Photoshop"})), "RB701") == []


@pytest.mark.parametrize("artist", ["Anonymous Authors", "unknown", "   "])
def test_a_placeholder_owner_is_not_a_finding(tmp_path: Path, artist: str) -> None:
    assert by_rule(scan_image(tmp_path, jpeg({ExifTags.Base.Artist: artist})), "RB701") == []


@pytest.mark.parametrize("target", list(Target))
def test_metadata_is_a_blocker_on_every_target(tmp_path: Path, target: Target) -> None:
    write_tree(tmp_path, {"plot.jpg": jpeg({ExifTags.Base.Artist: "Alice Example"})})
    assert by_rule(findings(tmp_path, target), "RB701")[0].severity is Severity.BLOCKER


# RB702: GPS


def test_gps_metadata_is_a_warning(tmp_path: Path) -> None:
    found = by_rule(scan_image(tmp_path, jpeg(gps=True)), "RB702")[0]
    assert (found.severity, found.confidence) == (Severity.WARNING, Confidence.HIGH)
    assert found.location.field == "EXIF GPS"


def test_no_gps_means_no_finding(tmp_path: Path) -> None:
    assert by_rule(scan_image(tmp_path, jpeg()), "RB702") == []


# Other formats


@pytest.mark.parametrize(("name", "image_format"), [("a.tif", "TIFF"), ("a.webp", "WEBP")])
def test_exif_in_other_formats(tmp_path: Path, name: str, image_format: str) -> None:
    exif = Image.Exif()
    exif[ExifTags.Base.Artist] = "Alice Example"
    buffer = io.BytesIO()
    Image.new("RGB", (4, 4)).save(buffer, format=image_format, exif=exif)
    assert by_rule(scan_image(tmp_path, buffer.getvalue(), name), "RB701")


def test_a_gif_comment_is_read(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    Image.new("P", (4, 4)).save(buffer, format="GIF", comment=b"By Alice Example")
    assert by_rule(scan_image(tmp_path, buffer.getvalue(), "a.gif"), "RB701")


def test_a_bmp_has_nothing_to_read(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    Image.new("RGB", (4, 4)).save(buffer, format="BMP")
    assert rules_found(scan_image(tmp_path, buffer.getvalue(), "a.bmp")) == ["RB703"]


def test_an_extension_that_lies_is_still_read(tmp_path: Path) -> None:
    content = jpeg({ExifTags.Base.Artist: "Alice Example"})
    assert by_rule(scan_image(tmp_path, content, "actually-a-jpeg.png"), "RB701")


# Pixels are never decoded (FR-IMG-3)


def _encoded(image_format: str, **options: object) -> bytes:
    exif = Image.Exif()
    exif[ExifTags.Base.Artist] = "Alice Example"
    buffer = io.BytesIO()
    Image.new("RGB", (4, 4)).save(buffer, format=image_format, exif=exif, **options)
    return buffer.getvalue()


@pytest.mark.parametrize(
    ("name", "image_format"),
    [("a.jpg", "JPEG"), ("a.png", "PNG"), ("a.tif", "TIFF"), ("a.webp", "WEBP")],
)
def test_exif_is_read_without_decoding_pixels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, image_format: str
) -> None:
    # Built first, because saving an image does need to load it.
    write_tree(tmp_path, {name: _encoded(image_format)})

    def must_not_load(_self: Image.Image) -> None:
        raise AssertionError("pixels were decoded")

    # ImageFile.load is the real decoder for every format opened from a file.
    monkeypatch.setattr(ImageFile.ImageFile, "load", must_not_load)
    monkeypatch.setattr(Image.Image, "load", must_not_load)
    report = scan(tmp_path)
    assert not report.result.skipped, report.result.skipped
    assert by_rule(report.result.findings, "RB701")[0].location.field == "EXIF Artist"


@pytest.mark.parametrize(
    ("name", "build"),
    [
        ("a.png", lambda: png(("Author", "Alice Example"))),
        ("a.jpg", lambda: jpeg(comment=b"By Alice Example")),
    ],
)
def test_text_is_read_without_decoding_pixels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, build: Any
) -> None:
    write_tree(tmp_path, {name: build()})

    def must_not_load(_self: Image.Image) -> None:
        raise AssertionError("pixels were decoded")

    monkeypatch.setattr(ImageFile.ImageFile, "load", must_not_load)
    monkeypatch.setattr(Image.Image, "load", must_not_load)
    report = scan(tmp_path)
    assert not report.result.skipped, report.result.skipped
    assert by_rule(report.result.findings, "RB701")


def test_gps_in_a_png_is_found(tmp_path: Path) -> None:
    exif = Image.Exif()
    exif[ExifTags.Base.Software] = "x"  # Pillow does not write EXIF holding only a sub-directory
    location = exif.get_ifd(ExifTags.IFD.GPSInfo)
    location[ExifTags.GPS.GPSLatitudeRef] = "N"
    buffer = io.BytesIO()
    Image.new("RGB", (4, 4)).save(buffer, format="PNG", exif=exif)
    assert by_rule(scan_image(tmp_path, buffer.getvalue(), "a.png"), "RB702")


def test_broken_exif_in_a_png_is_reported(tmp_path: Path) -> None:
    content = _png_with(chunk(b"eXIf", b"not a tiff header"))
    write_tree(tmp_path, {"a.png": content})
    report = scan(tmp_path)
    assert rules_found(report.result.findings) == ["RB703"]


def _bomb_png(*extra: bytes) -> bytes:
    """A tiny file claiming to be 60,000 by 60,000 pixels."""
    header = struct.pack(">IIBBBBB", 60_000, 60_000, 8, 2, 0, 0, 0)
    return SIGNATURE + chunk(b"IHDR", header) + b"".join(extra) + chunk(b"IEND", b"")


def test_a_decompression_bomb_costs_nothing(tmp_path: Path) -> None:
    # Threat T-07: its metadata is still read, because nothing tries to allocate those pixels.
    content = _bomb_png(chunk(b"tEXt", b"Author\x00Alice Example"))
    write_tree(tmp_path, {"bomb.png": content})
    found = findings(tmp_path)
    assert by_rule(found, "RB701")[0].matched == "Alice Example"


def test_the_pixel_limit_is_restored_afterwards(tmp_path: Path) -> None:
    before = Image.MAX_IMAGE_PIXELS
    write_tree(tmp_path, {"bomb.png": _bomb_png()})
    scan(tmp_path)
    assert before == Image.MAX_IMAGE_PIXELS


# PNG text chunks, read directly


def test_text_after_the_image_data_is_found(tmp_path: Path) -> None:
    # Pillow reports this only once pixels are decoded, so reading the chunks is the only way.
    data = chunk(b"IDAT", zlib.compress(b"\x00" * 52))
    content = _png_with(data, chunk(b"tEXt", b"Author\x00Alice Example"))
    assert by_rule(scan_image(tmp_path, content, "late.png"), "RB701")


def test_compressed_text_is_read() -> None:
    compressed = chunk(b"zTXt", b"Author\x00\x00" + zlib.compress(b"Alice Example"))
    assert list(png_text_chunks(_png_with(compressed))) == [("Author", "Alice Example")]


def test_international_text_is_read() -> None:
    plain = chunk(b"iTXt", b"Author\x00\x00\x00en\x00\x00Jos\xc3\xa9")
    packed = chunk(b"iTXt", b"Title\x00\x01\x00en\x00\x00" + zlib.compress(b"Alice"))
    assert list(png_text_chunks(_png_with(plain, packed))) == [
        ("Author", "Jos\u00e9"),
        ("Title", "Alice"),
    ]


def test_a_text_bomb_is_bounded() -> None:
    bomb = chunk(b"zTXt", b"Comment\x00\x00" + zlib.compress(b"x" * 50_000_000))
    [(_key, text)] = list(png_text_chunks(_png_with(bomb)))
    assert len(text) == image_module.MAX_DECOMPRESSED_TEXT


@pytest.mark.parametrize(
    "bad",
    [
        chunk(b"zTXt", b"Comment\x00\x00not zlib data"),
        chunk(b"tEXt", b"no separator"),
        chunk(b"zTXt", b"Comment\x00"),
        chunk(b"iTXt", b"Comment\x00"),
        chunk(b"iTXt", b"Comment\x00\x01\x00\x00\x00not zlib"),
    ],
)
def test_broken_chunks_are_ignored(bad: bytes) -> None:
    assert list(png_text_chunks(_png_with(bad))) == []


def test_a_truncated_chunk_ends_reading() -> None:
    content = SIGNATURE + struct.pack(">I", 1_000_000) + b"tEXt" + b"Author\x00x"
    assert [key for key, _ in png_text_chunks(content)] == ["Author"]


def test_endless_empty_chunks_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(image_module, "MAX_PNG_CHUNKS", 3)
    many = chunk(b"tEXt", b"A\x00b") * 10
    assert len(list(png_text_chunks(_png_with(many)))) == 2


# Files that cannot be read


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("a.png", b"not an image"),
        ("a.jpg", b"\xff\xd8\xff garbage"),
        ("a.png", b""),
        ("a.tif", b"II*\x00garbage"),
        ("a.gif", b"GIF89a"),
    ],
)
def test_a_corrupt_image_is_reported(tmp_path: Path, name: str, content: bytes) -> None:
    write_tree(tmp_path, {name: content})
    report = scan(tmp_path)
    assert rules_found(report.result.findings) == ["RB703"]
    assert report.result.incomplete
    assert report.result.skipped[0].reason is SkipReason.CORRUPT


def test_an_oversized_image_still_needs_a_visual_review(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.jpg": jpeg({ExifTags.Base.Artist: "Alice Example"})})
    config = replace(PERSONA, scan=ScanSettings(max_binary_bytes=5, exclude=()))
    report = scan(tmp_path, config=config)
    assert rules_found(report.result.findings) == ["RB703"]
    assert report.result.skipped[0].reason is SkipReason.TOO_LARGE
