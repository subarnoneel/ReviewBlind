"""PDF metadata and extractable text. Nothing is rendered or modified."""

from __future__ import annotations

import functools
import warnings
from collections.abc import Iterable, Iterator
from typing import Any

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
    read_binary_artifact,
    within_detection_limit,
)
from reviewblind.scanners.manifests import FieldKind, ManifestField, is_placeholder
from reviewblind.utils.text import sanitize_evidence

MAX_PAGES = 5000
MAX_TEXT_CHARACTERS = 64 * 1024 * 1024

_METADATA_FIELDS = {
    "author": "Author",
    "title": "Title",
    "subject": "Subject",
    "keywords": "Keywords",
    "creator": "Creator",
    "producer": "Producer",
}


@functools.cache
def load_pymupdf() -> Any:
    """Import PyMuPDF only when a PDF appears, and survive `PYTHONWARNINGS=error`.

    On macOS its native module raises deprecation warnings while loading. If those become errors,
    the process segfaults, which nothing here could contain (D-39).
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import pymupdf

    # Its own messages about a malformed file would otherwise appear in the middle of a report.
    tools: Any = pymupdf.TOOLS
    tools.mupdf_display_errors(False)
    tools.mupdf_display_warnings(False)
    return pymupdf


class PdfScanner:
    name = "pdf"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.kind is ArtifactKind.PDF

    def scan(self, artifact: Artifact, context: ScanContext) -> Iterable[Detection]:
        content = read_binary_artifact(artifact, context)
        if content is None:
            return []
        pymupdf = load_pymupdf()
        try:
            document = pymupdf.open(stream=content, filetype="pdf")
        except Exception as error:  # MuPDF raises several kinds on malformed input
            context.report_skip(artifact.relpath, SkipReason.CORRUPT, type(error).__name__)
            return []
        with document:
            if document.needs_pass:
                context.report_skip(artifact.relpath, SkipReason.ENCRYPTED, "password protected")
                return []
            return within_detection_limit(
                self._detections(artifact.relpath, document, context),
                artifact.relpath,
                context,
            )

    def _detections(self, relpath: str, document: Any, context: ScanContext) -> Iterator[Detection]:
        yield from self._metadata(relpath, document, context)
        yield from self._pages(relpath, document, context)

    @staticmethod
    def _metadata(relpath: str, document: Any, context: ScanContext) -> Iterator[Detection]:
        metadata = document.metadata or {}
        for key, label in _METADATA_FIELDS.items():
            value = metadata.get(key)
            if not isinstance(value, str) or not value.strip():
                continue
            field = f"PDF metadata: {label}"
            found = list(
                field_detections(
                    value,
                    rule_id="RB601",
                    artifact=relpath,
                    field=field,
                    message="Found an identity in PDF metadata",
                    context=context,
                )
            )
            yield from found
            person = ManifestField(FieldKind.PERSON, value.strip(), field)
            if key == "author" and not found and not is_placeholder(person):
                # A co-author may be missing from the config, so a named author is worth reporting.
                yield Detection(
                    rule_id="RB601",
                    artifact=relpath,
                    location=Location(relpath, field=field),
                    matched=value.strip(),
                    evidence=sanitize_evidence(value.strip()),
                    message="Found an author in PDF metadata",
                    identity=None,
                    evidence_class=EvidenceClass.DIRECT,
                )
        xmp = document.get_xml_metadata()
        if isinstance(xmp, str) and xmp.strip():
            yield from field_detections(
                xmp,
                rule_id="RB601",
                artifact=relpath,
                field="PDF metadata: XMP",
                message="Found an identity in PDF metadata",
                context=context,
            )

    @staticmethod
    def _pages(relpath: str, document: Any, context: ScanContext) -> Iterator[Detection]:
        page_count = document.page_count
        if page_count > MAX_PAGES:
            context.report_skip(
                relpath, SkipReason.TOO_LARGE, f"only the first {MAX_PAGES} pages were read"
            )
        characters = 0
        for index in range(min(page_count, MAX_PAGES)):
            number = index + 1
            try:
                page = document.load_page(index)
                text = page.get_text()
                links = [link.get("uri") for link in page.get_links()]
            except Exception as error:  # one bad page should not lose the rest of the document
                context.report_skip(
                    relpath, SkipReason.CORRUPT, f"page {number}: {type(error).__name__}"
                )
                continue
            characters += len(text)
            if characters > MAX_TEXT_CHARACTERS:
                context.report_skip(
                    relpath, SkipReason.TOO_LARGE, f"text was only read up to page {number}"
                )
                return
            yield from field_detections(
                text,
                rule_id="RB602",
                artifact=relpath,
                field=f"page {number}",
                message="Found an identity in PDF text",
                context=context,
            )
            for link in links:
                if isinstance(link, str):
                    yield from field_detections(
                        link,
                        rule_id="RB602",
                        artifact=relpath,
                        field=f"page {number} link",
                        message="Found an identity in a PDF link",
                        context=context,
                    )
