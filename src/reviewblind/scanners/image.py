"""Image metadata. Pixels are never decoded, so a decompression bomb costs nothing."""

from __future__ import annotations

import io
import struct
import warnings
import zlib
from collections.abc import Iterable, Iterator

from PIL import ExifTags, Image, UnidentifiedImageError

from reviewblind.models import (
    Artifact,
    ArtifactKind,
    Detection,
    EvidenceClass,
    Location,
    SkipReason,
)
from reviewblind.scanners.base import (
    ScanContext,
    field_detections,
    file_fact,
    read_binary_artifact,
    within_detection_limit,
)
from reviewblind.scanners.manifests import FieldKind, ManifestField, is_placeholder
from reviewblind.utils.text import sanitize_evidence

MAX_PNG_CHUNKS = 10_000
MAX_DECOMPRESSED_TEXT = 1024 * 1024

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_EXIF_TAGS = {
    int(ExifTags.Base.Artist): "Artist",
    int(ExifTags.Base.Copyright): "Copyright",
    int(ExifTags.Base.ImageDescription): "ImageDescription",
    int(ExifTags.Base.Software): "Software",
    int(ExifTags.Base.HostComputer): "HostComputer",
    int(ExifTags.Base.XPAuthor): "XPAuthor",
    int(ExifTags.Base.XPComment): "XPComment",
    int(ExifTags.Base.XPSubject): "XPSubject",
    int(ExifTags.Base.XPTitle): "XPTitle",
    int(ExifTags.Base.XPKeywords): "XPKeywords",
}
_EXIF_IFD_TAGS = {
    int(ExifTags.Base.UserComment): "UserComment",
    int(ExifTags.Base.CameraOwnerName): "CameraOwnerName",
}
_OWNER_FIELDS = frozenset(
    {"artist", "author", "cameraownername", "copyright", "creator", "xpauthor"}
)
_USER_COMMENT_CODES = {
    b"ASCII\x00\x00\x00": "ascii",
    b"UNICODE\x00": "utf-16",
    b"JIS\x00\x00\x00\x00\x00": "shift_jis",
}


def _decoded(key: str, value: object) -> str | None:
    if isinstance(value, str):
        return value
    if not isinstance(value, bytes):
        return None
    if key.startswith("XP"):  # Windows stores these as UTF-16
        return value.decode("utf-16-le", "replace").rstrip("\x00")
    if key == "UserComment" and len(value) >= 8:
        encoding = _USER_COMMENT_CODES.get(value[:8], "utf-8")
        return value[8:].decode(encoding, "replace").rstrip("\x00")
    return value.decode("utf-8", "replace").rstrip("\x00")


def _exif_fields(exif: Image.Exif) -> tuple[list[tuple[str, str]], bool]:
    """The text fields in EXIF, and whether there is any GPS data."""
    fields = []
    for tag, name in _EXIF_TAGS.items():
        value = _decoded(name, exif.get(tag))
        if value:
            fields.append((name, value))
    details = exif.get_ifd(ExifTags.IFD.Exif)
    for tag, name in _EXIF_IFD_TAGS.items():
        value = _decoded(name, details.get(tag))
        if value:
            fields.append((name, value))
    return fields, bool(exif.get_ifd(ExifTags.IFD.GPSInfo))


def _inflate(data: bytes) -> str | None:
    """Decompress a text chunk, with a limit, since a small chunk can inflate enormously."""
    try:
        return (
            zlib.decompressobj().decompress(data, MAX_DECOMPRESSED_TEXT).decode("utf-8", "replace")
        )
    except zlib.error:
        return None


def _png_chunks(data: bytes) -> Iterator[tuple[bytes, bytes]]:
    """Each chunk's kind and body, read straight from the file.

    Pillow must not be asked for a PNG's metadata. Its `getexif()` and `text` decode the whole image
    first, in order to reach chunks stored after the pixels, and a small file can claim to be
    enormous. Reading the chunks needs no pixels at all (FR-IMG-3).
    """
    position = len(_PNG_SIGNATURE)
    for _ in range(MAX_PNG_CHUNKS):
        header = data[position : position + 8]
        if len(header) < 8:
            return
        length, kind = struct.unpack(">I4s", header)
        if kind == b"IEND":
            return
        yield kind, data[position + 8 : position + 8 + length]
        position += 12 + length


def png_exif(data: bytes) -> Image.Exif:
    """The EXIF data in a PNG file, which is empty if it has none."""
    exif = Image.Exif()
    for kind, body in _png_chunks(data):
        if kind == b"eXIf":
            exif.load(body)
            break
    return exif


def png_text_chunks(data: bytes) -> Iterator[tuple[str, str]]:
    """Every text chunk in a PNG file, wherever it is stored."""
    for kind, body in _png_chunks(data):
        keyword, separator, rest = body.partition(b"\x00")
        if not separator:
            continue
        name = keyword.decode("latin-1")
        text: str | None = None
        if kind == b"tEXt":
            text = rest.decode("latin-1")
        elif kind == b"zTXt" and rest:
            text = _inflate(rest[1:])
        elif kind == b"iTXt" and len(rest) >= 2:
            compressed = rest[0] == 1
            _language, _, after = rest[2:].partition(b"\x00")
            _translated, _, content = after.partition(b"\x00")
            text = _inflate(content) if compressed else content.decode("utf-8", "replace")
        if text:
            yield name, text


def _info_fields(image: Image.Image) -> Iterator[tuple[str, str]]:
    """Comments and XMP that other formats expose without decoding anything."""
    for key in ("comment", "xmp", "XML:com.adobe.xmp", "description", "Author", "Title"):
        text = _decoded(key, image.info.get(key))
        if text:
            yield key, text


class ImageScanner:
    name = "image"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.kind is ArtifactKind.IMAGE

    def scan(self, artifact: Artifact, context: ScanContext) -> Iterable[Detection]:
        relpath = artifact.relpath
        # Reported first and whatever else happens: ReviewBlind cannot see what is in the picture.
        visual = file_fact(
            "RB703",
            relpath,
            "Visual content was not inspected.",
            "Found an image",
        )
        content = read_binary_artifact(artifact, context)
        if content is None:
            return [visual]
        try:
            found = list(self._metadata(relpath, content, context))
        except (
            UnidentifiedImageError,
            OSError,
            ValueError,
            SyntaxError,
            struct.error,
            EOFError,
            TypeError,
            KeyError,
            IndexError,
            RecursionError,
        ) as error:
            context.report_skip(relpath, SkipReason.CORRUPT, type(error).__name__)
            return [visual]
        return [visual, *within_detection_limit(iter(found), relpath, context)]

    def _metadata(self, relpath: str, content: bytes, context: ScanContext) -> Iterator[Detection]:
        pixel_limit = Image.MAX_IMAGE_PIXELS
        # The limit guards against decoding, and nothing here decodes. Without this, a large image
        # would stop us reading the metadata that is the only thing we can check.
        Image.MAX_IMAGE_PIXELS = None
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                with Image.open(io.BytesIO(content)) as image:
                    if content.startswith(_PNG_SIGNATURE):
                        fields, has_gps = _exif_fields(png_exif(content))
                        extra = list(png_text_chunks(content))
                    else:
                        fields, has_gps = _exif_fields(image.getexif())
                        extra = list(_info_fields(image))
        finally:
            Image.MAX_IMAGE_PIXELS = pixel_limit

        if has_gps:
            yield file_fact(
                "RB702",
                relpath,
                "This image contains GPS coordinates.",
                "Found GPS metadata",
                field="EXIF GPS",
            )
        labelled = [(f"EXIF {name}", name, value) for name, value in fields]
        labelled += [(f"Image text: {name}", name, value) for name, value in extra]
        for label, name, value in labelled:
            yield from self._field(relpath, label, name, value, context)

    @staticmethod
    def _field(
        relpath: str, label: str, name: str, value: str, context: ScanContext
    ) -> Iterator[Detection]:
        found = list(
            field_detections(
                value,
                rule_id="RB701",
                artifact=relpath,
                field=label,
                message="Found an identity in image metadata",
                context=context,
            )
        )
        yield from found
        person = ManifestField(FieldKind.PERSON, value.strip(), label)
        if (
            not found
            and name.lower() in _OWNER_FIELDS
            and value.strip()
            and not is_placeholder(person)
        ):
            # A co-author may be missing from the config, so a named owner is worth reporting.
            yield Detection(
                rule_id="RB701",
                artifact=relpath,
                location=Location(relpath, field=label),
                matched=value.strip(),
                evidence=sanitize_evidence(value.strip()),
                message="Found an owner in image metadata",
                identity=None,
                evidence_class=EvidenceClass.DIRECT,
            )
