"""End to end through the CLI, including the planted-leak benchmark (docs/TEST_PLAN.md)."""

from __future__ import annotations

import json
import os
import random
import re
import shutil
import tomllib
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from _helpers import PERSONA, git, jpeg, make_pdf, write_tree
from reviewblind import cli
from reviewblind.config import ScanSettings, write_config
from reviewblind.rules.registry import all_rules

FIXTURES = Path(__file__).parent / "fixtures"
TEST_PLAN = Path(__file__).parent.parent / "docs" / "TEST_PLAN.md"
TARGETS = ("mirror", "archive", "repository")
LEAKS = tomllib.loads((FIXTURES / "leaking_repo" / "expected.toml").read_text("utf-8"))["leak"]
runner = CliRunner()


def scan_json(root: Path, *args: str) -> tuple[int, dict[str, Any]]:
    result = runner.invoke(cli.app, ["scan", str(root), "--format", "json", *args])
    return result.exit_code, json.loads(result.stdout)


def locate(finding: dict[str, Any]) -> tuple[str, str]:
    return finding["rule_id"], finding["location"]["path"]


@pytest.fixture(scope="module")
def reports(leaking_repo: Path) -> dict[str, dict[str, Any]]:
    """One report for each target, read back from the JSON that `export` would be given."""
    found = {}
    for target in TARGETS:
        exit_code, report = scan_json(leaking_repo, "--target", target)
        assert exit_code == 1
        found[target] = report
    return found


# The benchmark


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("leak", LEAKS, ids=lambda leak: f"{leak['id']}-{leak['rule']}")
def test_a_planted_leak_is_found_at_its_severity(
    reports: dict[str, dict[str, Any]], leak: dict[str, str], target: str
) -> None:
    candidates = [
        finding
        for finding in reports[target]["findings"]
        if locate(finding) == (leak["rule"], leak["path"])
    ]
    assert candidates, f"{leak['id']} was missed on {target}"
    matching = [finding for finding in candidates if leak.get("matched", "") in finding["matched"]]
    assert matching, [finding["matched"] for finding in candidates]
    assert {finding["severity"] for finding in matching} == {leak[target]}


def test_every_rule_is_planted_exactly_once() -> None:
    assert sorted(leak["rule"] for leak in LEAKS) == sorted(rule.id for rule in all_rules())
    assert len(LEAKS) == 33


def test_the_manifest_matches_the_test_plan() -> None:
    row = re.compile(r"^\| (L\d\d) \| (RB\d{3}) \| `?([^`|]+?)`? \|", re.MULTILINE)
    planned = {
        match[1]: (match[2], match[3]) for match in row.finditer(TEST_PLAN.read_text("utf-8"))
    }
    for leak in LEAKS:
        rule, place = planned[leak["id"]]
        assert rule == leak["rule"]
        # The plan describes Git's leaks in words, such as "Git history".
        assert place == leak["path"] or (leak["path"] == ".git" and place.startswith("Git"))
    assert len(planned) == len(LEAKS)


@pytest.mark.parametrize("target", TARGETS)
def test_nothing_is_found_that_was_not_planted(
    reports: dict[str, dict[str, Any]], target: str
) -> None:
    planted = {(leak["rule"], leak["path"]) for leak in LEAKS}
    # RB703 is raised for every image, and the plan assigns it to just one of them.
    other_images = {("RB703", "figures/plot.jpg"), ("RB703", "figures/field-site.jpg")}
    assert {locate(finding) for finding in reports[target]["findings"]} == planted | other_images


@pytest.mark.parametrize("target", TARGETS)
def test_the_benchmark_is_reported_as_incomplete(
    reports: dict[str, dict[str, Any]], target: str
) -> None:
    report = reports[target]
    assert report["verdict"] == "NOT_READY"
    assert report["scan"]["complete"] is False
    assert {item["path"]: item["reason"] for item in report["scan"]["skipped"]} == {
        "data/raw.zip": "ARCHIVE_NOT_INSPECTED",
        "results/model-output.bin": "UNSUPPORTED_BINARY",
    }


def test_strict_takes_precedence_over_blockers(leaking_repo: Path) -> None:
    exit_code, _report = scan_json(leaking_repo, "--strict")
    assert exit_code == 3


# False positives


@pytest.fixture
def clean_config(tmp_path: Path) -> Path:
    path = tmp_path / "private.toml"
    write_config(PERSONA, path)
    return path


@pytest.mark.parametrize("target", TARGETS)
def test_lookalikes_raise_nothing_at_warning_or_above(
    clean_repo: Path, clean_config: Path, target: str
) -> None:
    exit_code, report = scan_json(
        clean_repo, "--target", target, "--config", str(clean_config), "--fail-on", "warning"
    )
    assert exit_code == 0, [(item["rule_id"], item["matched"]) for item in report["findings"]]
    assert report["summary"]["blocker"] == report["summary"]["warning"] == 0
    assert report["scan"]["complete"] is True


def test_the_only_thing_lookalikes_raise_is_a_possible_acronym(
    clean_repo: Path, clean_config: Path
) -> None:
    # `eu` in `eu-west-1` may be the persona's EU in the wrong case, which is exactly a review.
    _exit_code, report = scan_json(clean_repo, "--config", str(clean_config))
    assert [
        (item["rule_id"], item["severity"], item["confidence"], item["matched"])
        for item in report["findings"]
    ] == [("RB104", "REVIEW", "LOW", "eu")]


def test_the_corpus_still_contains_its_lookalikes(clean_repo: Path) -> None:
    corpus = "\n".join(path.read_text("utf-8") for path in clean_repo.rglob("*") if path.is_file())
    for lookalike in (
        "Alicia Examples",
        "malice example",
        "github.com/pytorch/pytorch",
        "huggingface.co/bert-base-uncased",
        "/home/user/",
        "C:\\Users\\runner\\",
        "Anonymous Authors",
    ):
        assert lookalike in corpus


def test_no_acronym_means_no_finding_at_all(clean_repo: Path, tmp_path: Path) -> None:
    identity = replace(PERSONA.identity, affiliations=("Example University",))
    write_config(replace(PERSONA, identity=identity), tmp_path / "exact.toml")
    result = runner.invoke(
        cli.app, ["scan", str(clean_repo), "--config", str(tmp_path / "exact.toml")]
    )
    assert result.exit_code == 0
    assert "RESULT: NO KNOWN LEAKS DETECTED\n" in result.stdout
    assert "Scan complete: YES" in result.stdout


@pytest.mark.parametrize("target", TARGETS)
def test_a_neutral_history_and_neutral_binaries_stay_quiet(
    clean_repo: Path, tmp_path: Path, target: str
) -> None:
    write_tree(
        clean_repo,
        {
            "figures/loss.pdf": make_pdf(pages=("Loss curve",), metadata={"author": "Anonymous"}),
            "figures/loss.jpg": jpeg({0x0131: "Plotting software"}),
        },
    )
    git(clean_repo, "init", "-q")
    git(clean_repo, "add", "-A")
    git(
        clean_repo,
        "-c",
        "user.name=Anonymous Authors",
        "-c",
        "user.email=anonymous@example.org",
        "commit",
        "-q",
        "-m",
        "Add the review copy",
    )
    settings = ScanSettings(exclude=(".git/**",))  # how an archive is told .git will not be packed
    write_config(replace(PERSONA, scan=settings), tmp_path / "private.toml")
    _exit_code, report = scan_json(
        clean_repo, "--target", target, "--config", str(tmp_path / "private.toml")
    )
    loud = [item for item in report["findings"] if item["severity"] in {"BLOCKER", "WARNING"}]
    assert not loud, [(item["rule_id"], item["matched"]) for item in loud]


# The whole workflow


def test_init_scan_fix_and_scan_again(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    write_tree(
        root,
        {
            "pyproject.toml": '[project]\nname = "x"\nversion = "1"\n'
            'authors = [{ name = "Alice Example", email = "alice@example.edu" }]\n',
            "train.py": "import os\n",
        },
    )
    git(root, "add", "-A")
    alice = ("-c", "user.name=Alice Example", "-c", "user.email=alice@example.edu")
    for message in ("First", "Second"):
        git(root, *alice, "commit", "-q", "--allow-empty", "-m", message)

    created = runner.invoke(cli.app, ["init", str(root), "--yes"])
    assert created.exit_code == 0, created.stderr
    assert "Added .reviewblind.toml" in created.stderr

    before = runner.invoke(cli.app, ["scan", str(root)])
    assert before.exit_code == 1
    assert "RB301" in before.stdout

    write_tree(root, {"pyproject.toml": '[project]\nname = "x"\nversion = "1"\n'})
    git(root, *alice, "commit", "-q", "-am", "Remove the author")

    # A mirror hides history, so the source is now fine. A public repository still shows it all.
    assert runner.invoke(cli.app, ["scan", str(root)]).exit_code == 0
    assert runner.invoke(cli.app, ["scan", str(root), "--target", "repository"]).exit_code == 1


def _apply_terms(root: Path, terms: list[str]) -> None:
    """What Anonymous GitHub does to each text file: every pattern in order, ignoring case.

    Binary files pass through unchanged, including an ASCII-only PDF.
    """
    binary = {".pdf", ".jpg", ".png", ".zip", ".bin", ".DS_Store"}
    for path in root.rglob("*"):
        parts = path.relative_to(root).parts
        if ".git" in parts or not path.is_file() or path.suffix in binary or path.name in binary:
            continue
        text = path.read_text("utf-8")
        for number, term in enumerate(terms, start=1):
            # A boundary only where the term has a word character at that edge.
            before = r"\b" if re.match(r"\w", term, re.ASCII) else ""
            after = r"\b" if re.search(r"\w$", term, re.ASCII) else ""
            text = re.sub(f"{before}{term}{after}", f"XXXX-{number}", text, flags=re.IGNORECASE)
        path.write_text(text, "utf-8", newline="")


def test_an_exported_list_removes_direct_identities_from_text(
    leaking_repo: Path, tmp_path: Path
) -> None:
    root = tmp_path / "mirror"
    shutil.copytree(leaking_repo, root)
    config = tmp_path / "private.toml"
    shutil.move(root / ".reviewblind.toml", config)
    report_path = tmp_path / "report.json"
    scanned = runner.invoke(
        cli.app,
        ["scan", str(root), "--config", str(config), "--format", "json", "-o", str(report_path)],
    )
    assert scanned.exit_code == 1

    exported = runner.invoke(cli.app, ["export", str(report_path)])
    assert exported.exit_code == 0, exported.stderr
    _apply_terms(root, exported.stdout.splitlines())

    _exit_code, after = scan_json(root, "--config", str(config))
    # Everything a term list cannot fix, as CLI.md says. Anything else confirmed has been replaced.
    assert {item["rule_id"] for item in after["findings"] if item["identity"]} == {
        "RB106",  # a file name, since this test rewrites only contents
        "RB202",  # a hostname is not a term
        "RB303",  # a name split across given-names and family-names is not a term
        "RB401",  # Git metadata is for the mirror to hide
        "RB402",
        "RB403",
        "RB404",
        "RB601",  # binary files pass through unchanged
        "RB602",
        "RB701",
    }


def test_a_term_list_left_in_the_repository_is_itself_a_leak(
    leaking_repo: Path, tmp_path: Path
) -> None:
    root = tmp_path / "repo"
    shutil.copytree(leaking_repo, root)
    report_path = tmp_path / "report.json"
    runner.invoke(cli.app, ["scan", str(root), "--format", "json", "-o", str(report_path)])
    terms = root / "terms.txt"
    exported = runner.invoke(cli.app, ["export", str(report_path), "-o", str(terms)])
    assert exported.exit_code == 0
    assert "Do not include it in the artifact" in exported.stderr
    _exit_code, report = scan_json(root)
    assert ("RB101", "terms.txt") in {locate(item) for item in report["findings"]}


# Determinism


class _Shuffled:
    """`os.scandir`, in an order that changes every time."""

    def __init__(self, entries: Iterator[Any], order: random.Random) -> None:
        self._entries = list(entries)
        order.shuffle(self._entries)

    def __enter__(self) -> _Shuffled:
        return self

    def __exit__(self, *_details: object) -> None:
        return None

    def __iter__(self) -> Iterator[Any]:
        return iter(self._entries)


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_file_system_order_does_not_change_a_report(
    leaking_repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, seed: int
) -> None:
    # Without Git, since Git supplies its own list of files and the walk would never happen.
    root = tmp_path / "repo"
    shutil.copytree(leaking_repo, root, ignore=shutil.ignore_patterns(".git"))
    expected = runner.invoke(cli.app, ["scan", str(root), "--format", "json"]).stdout
    real_scandir = os.scandir
    order = random.Random(seed)  # noqa: S311
    calls = []

    def shuffled(path: Any) -> _Shuffled:
        calls.append(path)
        with real_scandir(path) as entries:
            return _Shuffled(iter(list(entries)), order)

    monkeypatch.setattr(os, "scandir", shuffled)
    assert runner.invoke(cli.app, ["scan", str(root), "--format", "json"]).stdout == expected
    assert calls, "the shuffle was never used"


@pytest.mark.parametrize("output_format", ["json", "markdown", "terminal"])
def test_every_format_is_byte_identical_between_runs(
    leaking_repo: Path, output_format: str
) -> None:
    arguments = ["scan", str(leaking_repo), "--format", output_format]
    first = runner.invoke(cli.app, arguments).stdout
    assert runner.invoke(cli.app, arguments).stdout == first
