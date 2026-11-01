"""Jupyter notebooks, parsed as JSON and never executed.

Each part is inspected separately, because a clean cell can still have a name in its saved output.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from typing import Any

from reviewblind.models import Artifact, ArtifactKind, Detection, SkipReason
from reviewblind.scanners.base import (
    ScanContext,
    field_detections,
    file_fact,
    read_binary_artifact,
    within_detection_limit,
)
from reviewblind.signals import SignalKind

MAX_METADATA_NODES = 100_000

# IPython colours its tracebacks, and a colour code can fall in the middle of a path or name.
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_HOME_PATHS = frozenset({SignalKind.HOME_PATH})
_TEXT_MIME_PREFIXES = ("text/", "application/json", "application/javascript", "image/svg")


def _text(value: object) -> str | None:
    """A notebook stores text as one string or as a list of lines."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(item for item in value if isinstance(item, str))
    return None


def _strings(root: object, prefix: str) -> Iterator[tuple[str, str]]:
    """Every string in a metadata tree, without recursion, and with a limit on hostile input."""
    stack = [(root, prefix)]
    visited = 0
    while stack and visited < MAX_METADATA_NODES:
        node, path = stack.pop()
        visited += 1
        if isinstance(node, str):
            yield path, node
        elif isinstance(node, dict):
            for key, value in node.items():
                child = f"{path}.{key}"
                yield child, str(key)
                stack.append((value, child))
        elif isinstance(node, list):
            stack.extend((value, f"{path}[{index}]") for index, value in enumerate(node))


class NotebookScanner:
    name = "notebook"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.kind is ArtifactKind.NOTEBOOK

    def scan(self, artifact: Artifact, context: ScanContext) -> Iterable[Detection]:
        content = read_binary_artifact(artifact, context)
        if content is None:
            return []
        try:
            notebook = json.loads(content.decode("utf-8-sig"))
        except (ValueError, RecursionError) as error:
            context.report_skip(artifact.relpath, SkipReason.CORRUPT, type(error).__name__)
            return []
        if not isinstance(notebook, dict) or not isinstance(notebook.get("cells"), list):
            # Older formats keep cells elsewhere, and saying so is better than finding nothing.
            context.report_skip(artifact.relpath, SkipReason.CORRUPT, "not a version 4 notebook")
            return []
        return within_detection_limit(
            self._detections(artifact.relpath, notebook, context), artifact.relpath, context
        )

    def _detections(
        self, relpath: str, notebook: dict[str, Any], context: ScanContext
    ) -> Iterator[Detection]:
        yield from self._metadata(relpath, notebook.get("metadata"), "metadata", context)
        for index, cell in enumerate(notebook["cells"]):
            if isinstance(cell, dict):
                yield from self._cell(relpath, cell, f"cell[{index}]", context)

    @staticmethod
    def _metadata(
        relpath: str, metadata: object, prefix: str, context: ScanContext
    ) -> Iterator[Detection]:
        for field, value in _strings(metadata, prefix):
            yield from field_detections(
                value,
                rule_id="RB503",
                artifact=relpath,
                field=field,
                message="Found an identity in notebook metadata",
                context=context,
                unconfirmed=_HOME_PATHS,
            )

    def _cell(
        self, relpath: str, cell: dict[str, Any], prefix: str, context: ScanContext
    ) -> Iterator[Detection]:
        source = _text(cell.get("source"))
        if source is not None:
            yield from field_detections(
                _ANSI_ESCAPE.sub("", source),
                rule_id="RB501",
                artifact=relpath,
                field=f"{prefix}.source",
                message="Found an identity in a notebook cell",
                context=context,
            )
        yield from self._metadata(relpath, cell.get("metadata"), f"{prefix}.metadata", context)
        attachments = cell.get("attachments")
        if isinstance(attachments, dict) and attachments:
            yield _binary_output(relpath, f"{prefix}.attachments")
        outputs = cell.get("outputs")
        if isinstance(outputs, list):
            for index, output in enumerate(outputs):
                if isinstance(output, dict):
                    yield from self._output(relpath, output, f"{prefix}.output[{index}]", context)

    def _output(
        self, relpath: str, output: dict[str, Any], prefix: str, context: ScanContext
    ) -> Iterator[Detection]:
        for field, value in _output_strings(output, prefix):
            yield from field_detections(
                _ANSI_ESCAPE.sub("", value),
                rule_id="RB502",
                artifact=relpath,
                field=field,
                message="Found an identity in notebook output",
                context=context,
                unconfirmed=_HOME_PATHS,
            )
        data = output.get("data")
        if isinstance(data, dict) and any(_is_binary_mime(mime) for mime in data):
            yield _binary_output(relpath, f"{prefix}.data")
        yield from self._metadata(relpath, output.get("metadata"), f"{prefix}.metadata", context)


def _is_binary_mime(mime: object) -> bool:
    return isinstance(mime, str) and not mime.startswith(_TEXT_MIME_PREFIXES)


def _binary_output(relpath: str, field: str) -> Detection:
    return file_fact(
        "RB504",
        relpath,
        "Binary notebook output was not inspected.",
        "Found embedded binary output",
        field=field,
    )


def _output_strings(output: dict[str, Any], prefix: str) -> Iterator[tuple[str, str]]:
    """The text a notebook keeps from running a cell: streams, errors and rich results."""
    text = _text(output.get("text"))
    if text is not None:
        yield f"{prefix}.text", text
    for key in ("ename", "evalue"):
        value = output.get(key)
        if isinstance(value, str):
            yield f"{prefix}.{key}", value
    traceback = output.get("traceback")
    if isinstance(traceback, list):
        for index, line in enumerate(traceback):
            if isinstance(line, str):
                yield f"{prefix}.traceback[{index}]", line
    data = output.get("data")
    if isinstance(data, dict):
        for mime, value in data.items():
            if not _is_binary_mime(mime):
                rendered = _text(value)
                if rendered is None:  # application/json holds a structure rather than text
                    yield from _strings(value, f"{prefix}.data[{mime}]")
                else:
                    yield f"{prefix}.data[{mime}]", rendered
