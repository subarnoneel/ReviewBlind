"""Jupyter notebooks (FR-NB-1 to FR-NB-3)."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from _helpers import PERSONA, findings, rules_found, scan, write_tree
from reviewblind.config import ScanSettings
from reviewblind.models import Confidence, Finding, Severity, SkipReason, Target
from reviewblind.scanners import base as scanner_base
from reviewblind.scanners import notebook as notebook_module


def notebook(*cells: dict[str, Any], metadata: dict[str, Any] | None = None) -> str:
    return json.dumps(
        {"nbformat": 4, "nbformat_minor": 5, "metadata": metadata or {}, "cells": list(cells)}
    )


def code_cell(*outputs: dict[str, Any], source: str = "run()\n") -> dict[str, Any]:
    return {"cell_type": "code", "metadata": {}, "source": source, "outputs": list(outputs)}


def scan_notebook(root: Path, content: str) -> list[Finding]:
    write_tree(root, {"n.ipynb": content})
    return findings(root)


def only(items: list[Finding]) -> Finding:
    assert len(items) == 1, [(item.rule_id, item.matched) for item in items]
    return items[0]


# RB501: source


@pytest.mark.parametrize("cell_type", ["markdown", "code", "raw"])
def test_identity_in_cell_source(tmp_path: Path, cell_type: str) -> None:
    content = notebook({"cell_type": cell_type, "metadata": {}, "source": "By Alice Example\n"})
    found = only(scan_notebook(tmp_path, content))
    assert (found.rule_id, found.severity) == ("RB501", Severity.BLOCKER)
    assert found.location.field == "cell[0].source"
    assert found.matched == "Alice Example"
    assert found.location.line is None


def test_source_stored_as_a_list_of_lines(tmp_path: Path) -> None:
    # A name can be split across two of the stored lines.
    content = notebook(
        {"cell_type": "markdown", "metadata": {}, "source": ["By Alice\n", "Example\n"]}
    )
    assert only(scan_notebook(tmp_path, content)).rule_id == "RB501"


def test_an_affiliation_in_source_is_a_warning(tmp_path: Path) -> None:
    content = notebook({"cell_type": "markdown", "metadata": {}, "source": "At Example University"})
    assert only(scan_notebook(tmp_path, content)).severity is Severity.WARNING


def test_a_namespace_in_source_is_a_blocker(tmp_path: Path) -> None:
    content = notebook(code_cell(source="!git clone https://github.com/aliceexample/tools\n"))
    found = only(scan_notebook(tmp_path, content))
    assert found.severity is Severity.BLOCKER
    assert found.matched == "github.com/aliceexample/tools"


@pytest.mark.parametrize(
    "path", ["/home/bob/x", "/kaggle/input/datasets/bob/x", "/kaggle/input/notebooks/bob/x"]
)
def test_an_unconfirmed_account_path_in_source_needs_review(tmp_path: Path, path: str) -> None:
    # The same path in a .py file is reported, and a cell should be no different.
    found = only(scan_notebook(tmp_path, notebook(code_cell(source=f"open('{path}')\n"))))
    assert found.rule_id == "RB501"
    assert (found.severity, found.confidence) == (Severity.REVIEW, Confidence.MEDIUM)


def test_a_confirmed_kaggle_path_in_source_is_a_warning(tmp_path: Path) -> None:
    source = "open('/kaggle/input/datasets/aliceexample/x')\n"
    found = only(scan_notebook(tmp_path, notebook(code_cell(source=source))))
    assert (found.severity, found.confidence) == (Severity.WARNING, Confidence.HIGH)
    assert found.identity == "aliceexample"
    assert found.matched == "kaggle/input/datasets/aliceexample"


@pytest.mark.parametrize(
    "path",
    ["s3://other/x", "https://wandb.ai/bob/p", "/home/user/x", "/kaggle/input/some-data/x"],
)
def test_other_unconfirmed_signals_in_source_are_not_reported(tmp_path: Path, path: str) -> None:
    assert scan_notebook(tmp_path, notebook(code_cell(source=f"open('{path}')\n"))) == []


# RB502: outputs


@pytest.mark.parametrize(
    ("output", "field"),
    [
        ({"output_type": "stream", "name": "stdout", "text": "by Alice Example\n"}, "text"),
        ({"output_type": "stream", "name": "stdout", "text": ["by Alice ", "Example\n"]}, "text"),
        (
            {"output_type": "error", "ename": "E", "evalue": "by Alice Example", "traceback": []},
            "evalue",
        ),
        (
            {"output_type": "error", "ename": "Alice Example", "evalue": "", "traceback": []},
            "ename",
        ),
        (
            {
                "output_type": "execute_result",
                "metadata": {},
                "data": {"text/plain": "by Alice Example"},
            },
            "data[text/plain]",
        ),
        (
            {
                "output_type": "display_data",
                "metadata": {},
                "data": {"text/html": ["<b>Alice Example</b>"]},
            },
            "data[text/html]",
        ),
        (
            {
                "output_type": "display_data",
                "metadata": {},
                "data": {"text/markdown": "Alice Example"},
            },
            "data[text/markdown]",
        ),
    ],
)
def test_identity_in_an_output(tmp_path: Path, output: dict[str, Any], field: str) -> None:
    found = only(scan_notebook(tmp_path, notebook(code_cell(output))))
    assert (found.rule_id, found.severity) == ("RB502", Severity.BLOCKER)
    assert found.location.field == f"cell[0].output[0].{field}"


def test_a_structured_json_output_is_read(tmp_path: Path) -> None:
    output = {
        "output_type": "display_data",
        "metadata": {},
        "data": {"application/json": {"author": {"name": "Alice Example"}}},
    }
    found = only(scan_notebook(tmp_path, notebook(code_cell(output))))
    assert found.location.field == "cell[0].output[0].data[application/json].author.name"


def test_a_home_path_in_a_traceback_is_a_warning(tmp_path: Path) -> None:
    output = {
        "output_type": "error",
        "ename": "E",
        "evalue": "x",
        "traceback": ["first", "File /home/aliceexample/miniconda3/x.py:1"],
    }
    found = only(scan_notebook(tmp_path, notebook(code_cell(output))))
    assert (found.rule_id, found.severity) == ("RB502", Severity.WARNING)
    assert found.location.field == "cell[0].output[0].traceback[1]"
    assert found.identity == "aliceexample"


def test_colour_codes_cannot_split_a_path_or_a_name(tmp_path: Path) -> None:
    # IPython colours tracebacks, and a code can fall in the middle of what we need to match.
    output = {
        "output_type": "error",
        "ename": "E",
        "evalue": "x",
        "traceback": [
            "File \x1b[1;32m/home/\x1b[0m\x1b[1;32maliceexample/x.py\x1b[0m",
            "\x1b[0;31mAlice\x1b[0m \x1b[0;31mExample\x1b[0m",
        ],
    }
    items = scan_notebook(tmp_path, notebook(code_cell(output)))
    assert {item.matched for item in items} == {"/home/aliceexample", "Alice Example"}
    assert all("\x1b" not in item.evidence for item in items)


@pytest.mark.parametrize("path", ["/home/bob/out", "/kaggle/input/notebooks/bob/out"])
def test_another_users_account_path_in_output_needs_review(tmp_path: Path, path: str) -> None:
    output = {"output_type": "stream", "name": "stdout", "text": f"saved in {path}\n"}
    found = only(scan_notebook(tmp_path, notebook(code_cell(output))))
    assert found.rule_id == "RB502"
    assert (found.severity, found.confidence) == (Severity.REVIEW, Confidence.MEDIUM)


@pytest.mark.parametrize("text", ["s3://other/x", "https://wandb.ai/bob/p", "/home/user/x"])
def test_other_unconfirmed_signals_in_output_are_not_reported(tmp_path: Path, text: str) -> None:
    output = {"output_type": "stream", "name": "stdout", "text": text}
    assert scan_notebook(tmp_path, notebook(code_cell(output))) == []


def test_a_clean_source_cell_can_still_have_a_leaking_output(tmp_path: Path) -> None:
    # This is the case RB502 exists for.
    output = {"output_type": "stream", "name": "stdout", "text": "Alice Example\n"}
    assert rules_found(scan_notebook(tmp_path, notebook(code_cell(output)))) == ["RB502"]


# RB503: metadata


@pytest.mark.parametrize(
    "metadata",
    [
        {"kernelspec": {"display_name": "Python (aliceexample)"}},
        {"vscode": {"interpreter": {"path": "/home/aliceexample/bin/python"}}},
        {"colab": {"name": "aliceexample.ipynb", "authorship_tag": "x"}},
        {"authors": [{"name": "Alice Example"}]},
    ],
)
def test_identity_in_notebook_metadata(tmp_path: Path, metadata: dict[str, Any]) -> None:
    items = scan_notebook(tmp_path, notebook(metadata=metadata))
    assert rules_found(items) == ["RB503"]
    assert items[0].location.field is not None
    assert items[0].location.field.startswith("metadata.")


def test_a_field_name_is_read_too(tmp_path: Path) -> None:
    assert rules_found(scan_notebook(tmp_path, notebook(metadata={"aliceexample": 1}))) == ["RB503"]


def test_identity_in_cell_metadata(tmp_path: Path) -> None:
    cell = {"cell_type": "code", "metadata": {"colab": {"owner": "Alice Example"}}, "source": ""}
    found = only(scan_notebook(tmp_path, notebook(cell)))
    assert (found.rule_id, found.location.field) == ("RB503", "cell[0].metadata.colab.owner")


def test_a_home_path_in_metadata_is_a_warning(tmp_path: Path) -> None:
    content = notebook(metadata={"vscode": {"path": "/home/aliceexample/x"}})
    assert only(scan_notebook(tmp_path, content)).severity is Severity.WARNING


def test_another_users_home_path_in_metadata_needs_review(tmp_path: Path) -> None:
    found = only(scan_notebook(tmp_path, notebook(metadata={"path": "/home/bob/x"})))
    assert found.severity is Severity.REVIEW


def test_metadata_walking_is_limited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(notebook_module, "MAX_METADATA_NODES", 3)
    content = notebook(metadata={f"k{index}": index for index in range(100)})
    assert scan_notebook(tmp_path, content) == []


# RB504: embedded binary output


@pytest.mark.parametrize("mime", ["image/png", "image/jpeg", "application/pdf", "video/mp4"])
def test_binary_output_needs_review(tmp_path: Path, mime: str) -> None:
    output = {"output_type": "display_data", "metadata": {}, "data": {mime: "QUJD"}}
    write_tree(tmp_path, {"n.ipynb": notebook(code_cell(output))})
    report = scan(tmp_path)
    found = only(report.result.findings)
    assert (found.rule_id, found.severity) == ("RB504", Severity.REVIEW)
    assert found.location.field == "cell[0].output[0].data"
    # FR-COMP-3: this is a stated limit, and every notebook with a plot would otherwise be incomplete.
    assert not report.result.incomplete


def test_svg_is_text_and_is_read(tmp_path: Path) -> None:
    output = {
        "output_type": "display_data",
        "metadata": {},
        "data": {"image/svg+xml": "<svg>Alice Example</svg>"},
    }
    assert rules_found(scan_notebook(tmp_path, notebook(code_cell(output)))) == ["RB502"]


def test_a_cell_attachment_needs_review(tmp_path: Path) -> None:
    cell = {
        "cell_type": "markdown",
        "metadata": {},
        "source": "",
        "attachments": {"a.png": {"image/png": "QUJD"}},
    }
    found = only(scan_notebook(tmp_path, notebook(cell)))
    assert (found.rule_id, found.location.field) == ("RB504", "cell[0].attachments")


def test_each_output_with_binary_data_is_reported_once(tmp_path: Path) -> None:
    output = {
        "output_type": "display_data",
        "metadata": {},
        "data": {"image/png": "A", "image/jpeg": "B"},
    }
    other = {"output_type": "display_data", "metadata": {}, "data": {"image/png": "C"}}
    items = scan_notebook(tmp_path, notebook(code_cell(output, other)))
    assert sorted(item.location.field or "" for item in items) == [
        "cell[0].output[0].data",
        "cell[0].output[1].data",
    ]


# In the pipeline


def test_severity_is_the_same_on_every_target(tmp_path: Path) -> None:
    content = notebook({"cell_type": "markdown", "metadata": {}, "source": "Alice Example"})
    write_tree(tmp_path, {"n.ipynb": content})
    for target in Target:
        assert findings(tmp_path, target)[0].severity is Severity.BLOCKER


def test_overlaps_resolve_inside_each_field_only(tmp_path: Path) -> None:
    # The same offsets in two different cells must not cancel each other out.
    first = {"cell_type": "markdown", "metadata": {}, "source": "Alice Example"}
    second = {"cell_type": "markdown", "metadata": {}, "source": "alice@example.edu"}
    third = {"cell_type": "markdown", "metadata": {}, "source": "/home/aliceexample/x"}
    items = scan_notebook(tmp_path, notebook(first, second, third))
    assert len(items) == 3
    assert {item.location.field for item in items} == {
        "cell[0].source",
        "cell[1].source",
        "cell[2].source",
    }


def test_a_name_inside_a_longer_match_gives_one_finding(tmp_path: Path) -> None:
    content = notebook(code_cell(source="p = '/home/aliceexample/data'\n"))
    assert only(scan_notebook(tmp_path, content)).matched == "/home/aliceexample"


def test_a_notebook_is_not_also_scanned_as_plain_text(tmp_path: Path) -> None:
    content = notebook({"cell_type": "markdown", "metadata": {}, "source": "Alice Example"})
    assert rules_found(scan_notebook(tmp_path, content)) == ["RB501"]


def test_a_clean_notebook_is_complete(tmp_path: Path) -> None:
    write_tree(tmp_path, {"n.ipynb": notebook(code_cell())})
    report = scan(tmp_path)
    assert report.result.findings == []
    assert not report.result.incomplete
    assert report.result.inspected == 1


def test_a_byte_order_mark_is_tolerated(tmp_path: Path) -> None:
    content = notebook({"cell_type": "markdown", "metadata": {}, "source": "Alice Example"})
    write_tree(tmp_path, {"n.ipynb": b"\xef\xbb\xbf" + content.encode("utf-8")})
    assert rules_found(findings(tmp_path)) == ["RB501"]


def test_too_many_matches_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scanner_base, "MAX_DETECTIONS_PER_ARTIFACT", 2)
    cells = [{"cell_type": "markdown", "metadata": {}, "source": "Alice Example"} for _ in range(5)]
    write_tree(tmp_path, {"n.ipynb": notebook(*cells)})
    report = scan(tmp_path)
    assert len(report.result.findings) == 2
    assert report.result.skipped[0].reason is SkipReason.TOO_MANY_MATCHES


# Malformed notebooks


@pytest.mark.parametrize(
    "content",
    [
        '{"cells": [',
        "not json at all",
        b"\xff\xfe invalid utf-8",
        "[]",
        '"text"',
        "{}",
        '{"cells": "nope"}',
        '{"worksheets": [{"cells": []}]}',
        "[" * 200_000,
    ],
)
def test_a_notebook_that_cannot_be_read_is_reported(tmp_path: Path, content: str | bytes) -> None:
    write_tree(tmp_path, {"n.ipynb": content})
    report = scan(tmp_path)
    assert report.result.findings == []
    assert report.result.skipped[0].reason is SkipReason.CORRUPT
    assert report.result.incomplete


@pytest.mark.parametrize(
    "content",
    [
        '{"cells": [1, "x", null, []]}',
        '{"cells": [{"source": 5, "outputs": "x", "metadata": 3, "attachments": []}]}',
        '{"cells": [{"source": [1, null], "outputs": [1, {"text": 5, "traceback": "x", "data": 5}]}]}',
        '{"cells": [{"outputs": [{"traceback": [1, null], "data": {"text/plain": 5}}]}]}',
        '{"cells": [], "metadata": [1, 2, {"a": null}]}',
    ],
)
def test_wrong_types_are_ignored(tmp_path: Path, content: str) -> None:
    write_tree(tmp_path, {"n.ipynb": content})
    report = scan(tmp_path)
    assert report.result.findings == []
    assert not report.result.incomplete


def test_an_oversized_notebook_is_skipped_by_the_binary_cap(tmp_path: Path) -> None:
    # D-34: notebooks with plots are large, so they use the larger cap.
    content = notebook({"cell_type": "markdown", "metadata": {}, "source": "Alice Example"})
    write_tree(tmp_path, {"n.ipynb": content})
    fits = replace(PERSONA, scan=ScanSettings(max_text_bytes=1, exclude=()))
    assert rules_found(scan(tmp_path, config=fits).result.findings) == ["RB501"]
    too_small = replace(PERSONA, scan=ScanSettings(max_binary_bytes=5, exclude=()))
    report = scan(tmp_path, config=too_small)
    assert report.result.skipped[0].reason is SkipReason.TOO_LARGE
    assert report.result.findings == []


# Found on real repositories


def _colab_cell(name: str) -> dict[str, Any]:
    user = {"displayName": name, "userId": "1234567890"}
    return {
        "cell_type": "code",
        "metadata": {"executionInfo": {"user": user, "user_tz": -360}},
        "source": "run()\n",
        "outputs": [],
    }


def test_a_progress_bar_is_not_an_embedded_image(tmp_path: Path) -> None:
    # tqdm in a notebook saves one of these per bar, which raised 179 findings in one real file.
    widget = {"model_id": "abc123", "version_major": 2, "version_minor": 0}
    output = {
        "output_type": "display_data",
        "metadata": {},
        "data": {"application/vnd.jupyter.widget-view+json": widget, "text/plain": "0%|  |"},
    }
    assert scan_notebook(tmp_path, notebook(code_cell(output))) == []


def test_text_inside_a_json_output_is_read(tmp_path: Path) -> None:
    figure = {"layout": {"title": {"text": "Results by Alice Example"}}}
    output = {
        "output_type": "display_data",
        "metadata": {},
        "data": {"application/vnd.plotly.v1+json": figure},
    }
    assert only(scan_notebook(tmp_path, notebook(code_cell(output)))).rule_id == "RB502"


def test_a_colab_account_with_a_confirmed_name_is_a_blocker(tmp_path: Path) -> None:
    found = only(scan_notebook(tmp_path, notebook(_colab_cell("ALICE EXAMPLE 12345"))))
    assert (found.rule_id, found.severity) == ("RB503", Severity.BLOCKER)
    assert found.location.field == "cell[0].metadata.executionInfo.user.displayName"


def test_a_colab_account_missing_from_the_config_needs_review(tmp_path: Path) -> None:
    # A co-author may not be in the config at all, and this is the only place they would show.
    found = only(scan_notebook(tmp_path, notebook(_colab_cell("Bob Coauthor"))))
    assert (found.rule_id, found.severity) == ("RB503", Severity.REVIEW)
    assert found.confidence is Confidence.MEDIUM
    assert found.identity is None
    assert found.matched == "Bob Coauthor"


@pytest.mark.parametrize("name", ["Anonymous", "", "  "])
def test_a_neutral_colab_account_is_not_reported(tmp_path: Path, name: str) -> None:
    assert scan_notebook(tmp_path, notebook(_colab_cell(name))) == []


def test_a_display_name_elsewhere_is_not_a_colab_account(tmp_path: Path) -> None:
    metadata = {"kernelspec": {"displayName": "Bob Coauthor", "name": "python3"}}
    assert scan_notebook(tmp_path, notebook(metadata=metadata)) == []
