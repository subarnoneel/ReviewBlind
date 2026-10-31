"""Structured author and project metadata (FR-MAN-1 to FR-MAN-4)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from _helpers import findings, rules_found, scan, write_tree
from reviewblind.models import Confidence, Finding, Severity, SkipReason
from reviewblind.scanners.manifests import (
    FieldKind,
    ManifestField,
    is_placeholder,
    parse_citation,
    parse_legal,
    parse_package_json,
    parse_people_file,
    parse_pyproject,
    parse_setup_cfg,
    parse_setup_py,
)


def values(fields: object, kind: FieldKind | None = None) -> list[str]:
    return [
        field.value
        for field in fields  # type: ignore[attr-defined]
        if kind is None or field.kind is kind
    ]


def scan_file(root: Path, name: str, content: str) -> list[Finding]:
    write_tree(root, {name: content})
    return findings(root)


def by_rule(items: list[Finding], rule_id: str) -> list[Finding]:
    return [item for item in items if item.rule_id == rule_id]


# pyproject.toml


PYPROJECT = """[project]
name = "pruning"
authors = [{ name = "Alice Example", email = "alice@example.edu" }]
maintainers = [{ name = "Bob Coauthor" }]

[project.urls]
Homepage = "https://aliceexample.github.io/pruning"
Repository = "https://github.com/pytorch/pytorch"
"""


def test_pyproject_fields() -> None:
    fields = list(parse_pyproject(PYPROJECT))
    assert values(fields, FieldKind.PERSON) == ["Alice Example", "Bob Coauthor"]
    assert values(fields, FieldKind.EMAIL) == ["alice@example.edu"]
    assert len(values(fields, FieldKind.URL)) == 2
    assert fields[0].where == "project.authors[0].name"


def test_poetry_authors_are_parsed() -> None:
    text = """[tool.poetry]
authors = ["Alice Example <alice@example.edu>", "Bob"]
homepage = "https://example.edu/x"
"""
    fields = list(parse_pyproject(text))
    assert values(fields, FieldKind.PERSON) == ["Alice Example", "Bob"]
    assert values(fields, FieldKind.EMAIL) == ["alice@example.edu"]
    assert values(fields, FieldKind.URL) == ["https://example.edu/x"]


def test_a_confirmed_author_is_a_high_confidence_blocker_on_its_line(tmp_path: Path) -> None:
    items = scan_file(tmp_path, "pyproject.toml", PYPROJECT)
    found = next(item for item in by_rule(items, "RB301") if item.matched == "Alice Example")
    assert (found.severity, found.confidence) == (Severity.BLOCKER, Confidence.HIGH)
    assert found.location.line == 3
    assert found.evidence.startswith("authors = [")


def test_an_unconfirmed_author_is_still_a_blocker_at_medium_confidence(tmp_path: Path) -> None:
    # FR-MAN-3: a co-author may simply be missing from the config.
    items = scan_file(tmp_path, "pyproject.toml", PYPROJECT)
    found = next(item for item in by_rule(items, "RB301") if item.matched == "Bob Coauthor")
    assert (found.severity, found.confidence) == (Severity.BLOCKER, Confidence.MEDIUM)
    assert found.identity is None


def test_the_manifest_rule_replaces_the_plain_text_match(tmp_path: Path) -> None:
    # D-58: RB301 and RB101 tie on span and severity, and RB301 says more.
    items = scan_file(
        tmp_path,
        "pyproject.toml",
        'authors = 1\n[project]\nauthors = [{ name = "Alice Example" }]\n',
    )
    assert rules_found(items) == ["RB301"]


def test_a_second_mention_elsewhere_in_the_file_is_still_a_text_match(tmp_path: Path) -> None:
    text = '[project]\nauthors = [{ name = "Alice Example" }]\n# Alice Example wrote this\n'
    assert sorted(rules_found(scan_file(tmp_path, "pyproject.toml", text))) == ["RB101", "RB301"]


def test_the_same_author_twice_gives_two_locations(tmp_path: Path) -> None:
    text = """[project]
authors = [{ name = "Alice Example" }]
maintainers = [{ name = "Alice Example" }]
"""
    items = by_rule(scan_file(tmp_path, "pyproject.toml", text), "RB301")
    assert [item.location.line for item in items] == [2, 3]


def test_project_urls_follow_their_namespace(tmp_path: Path) -> None:
    items = by_rule(scan_file(tmp_path, "pyproject.toml", PYPROJECT), "RB302")
    severity = {item.matched: item.severity for item in items}
    assert severity["https://aliceexample.github.io/pruning"] is Severity.BLOCKER
    assert severity["https://github.com/pytorch/pytorch"] is Severity.WARNING


def test_a_url_finding_replaces_the_namespace_match_inside_it(tmp_path: Path) -> None:
    text = '[project.urls]\nRepository = "https://github.com/aliceexample/tools"\n'
    assert rules_found(scan_file(tmp_path, "pyproject.toml", text)) == ["RB302"]


# package.json


def test_package_json_fields() -> None:
    text = json.dumps(
        {
            "author": "Alice Example <alice@example.edu> (https://example.edu)",
            "contributors": [{"name": "Bob", "email": "bob@x.example.org", "url": "https://x"}],
            "maintainers": ["Carol <carol@x.example.org>"],
            "homepage": "https://aliceexample.github.io/p",
            "repository": {"url": "git+https://github.com/aliceexample/p.git"},
            "bugs": {"url": "https://example.edu/bugs", "email": "bugs@example.edu"},
        }
    )
    fields = list(parse_package_json(text))
    assert values(fields, FieldKind.PERSON) == ["Alice Example", "Bob", "Carol"]
    assert "alice@example.edu" in values(fields, FieldKind.EMAIL)
    assert "bugs@example.edu" in values(fields, FieldKind.EMAIL)
    assert "git+https://github.com/aliceexample/p.git" in values(fields, FieldKind.URL)


def test_a_string_repository_is_read(tmp_path: Path) -> None:
    items = scan_file(tmp_path, "package.json", '{"repository": "github:aliceexample/p"}')
    assert rules_found(items) == ["RB302"]


def test_a_value_with_a_json_escape_is_located_by_its_field(tmp_path: Path) -> None:
    items = scan_file(tmp_path, "package.json", '{"author": {"name": "Alice\\u0020Example"}}')
    found = by_rule(items, "RB301")[0]
    assert found.location.line is None
    assert found.location.field == "author.name"
    assert found.severity is Severity.BLOCKER


# setup.cfg


def test_setup_cfg_fields() -> None:
    text = """[metadata]
author = Alice Example
author_email = alice@example.edu
maintainer = Bob
url = https://github.com/aliceexample/p
project_urls =
    Source = https://github.com/aliceexample/p
    Docs = https://docs.example.org
"""
    fields = list(parse_setup_cfg(text))
    assert values(fields, FieldKind.PERSON) == ["Alice Example", "Bob"]
    assert values(fields, FieldKind.EMAIL) == ["alice@example.edu"]
    assert len(values(fields, FieldKind.URL)) == 3


def test_setup_cfg_percent_signs_are_not_interpolated() -> None:
    assert values(parse_setup_cfg("[metadata]\nauthor = 100%(x)s Alice\n")) == ["100%(x)s Alice"]


def test_setup_cfg_without_metadata_is_empty() -> None:
    assert values(parse_setup_cfg("[options]\nzip_safe = false\n")) == []


# setup.py


def test_setup_py_literals_are_read() -> None:
    text = """
from setuptools import setup
__author__ = "Alice Example"
setup(
    name="p",
    author="Alice Example",
    author_email="alice@example.edu",
    maintainer="Bob",
    url="https://github.com/aliceexample/p",
    project_urls={"Docs": "https://docs.example.org"},
)
"""
    fields = list(parse_setup_py(text))
    assert values(fields, FieldKind.PERSON) == ["Alice Example", "Alice Example", "Bob"]
    assert values(fields, FieldKind.EMAIL) == ["alice@example.edu"]
    assert len(values(fields, FieldKind.URL)) == 2


def test_setuptools_dot_setup_is_recognized() -> None:
    assert values(parse_setup_py('import setuptools\nsetuptools.setup(author="A B")\n')) == ["A B"]


def test_computed_values_are_ignored_rather_than_evaluated() -> None:
    # FR-MAN-2
    text = 'setup(author=open("/etc/passwd").read(), author_email=NAME, url=f"{x}")\n'
    assert values(parse_setup_py(text)) == []


def test_other_calls_named_like_arguments_are_ignored() -> None:
    assert values(parse_setup_py('configure(author="Not Metadata")\n')) == []


# CITATION.cff


CITATION = """cff-version: 1.2.0
title: Pruning
authors:
  - family-names: Example
    given-names: Alice
    email: alice@example.edu
    affiliation: Example University
    orcid: https://orcid.org/0000-0000-0000-0001
  - name: Vision Lab
preferred-citation:
  authors:
    - family-names: Coauthor
      given-names: Bob
repository-code: https://github.com/aliceexample/p
"""


def test_citation_fields() -> None:
    fields = list(parse_citation(CITATION))
    assert values(fields, FieldKind.PERSON) == ["Alice Example", "Vision Lab", "Bob Coauthor"]
    assert values(fields, FieldKind.EMAIL) == ["alice@example.edu"]
    assert values(fields, FieldKind.AFFILIATION) == ["Example University"]
    assert "https://github.com/aliceexample/p" in values(fields, FieldKind.URL)


def test_a_citation_uses_its_own_rules(tmp_path: Path) -> None:
    items = scan_file(tmp_path, "CITATION.cff", CITATION)
    assert {item.matched for item in by_rule(items, "RB303")} >= {
        "alice@example.edu",
        "Example University",
        "Vision Lab",
    }
    assert "https://github.com/aliceexample/p" in {item.matched for item in by_rule(items, "RB302")}


def test_a_citation_name_split_across_fields_is_still_confirmed(tmp_path: Path) -> None:
    # The two parts never appear together in the file, so they are located by field name.
    items = by_rule(scan_file(tmp_path, "CITATION.cff", CITATION), "RB303")
    found = next(item for item in items if item.matched == "Alice Example")
    assert found.identity == "Alice Example"
    assert found.confidence is Confidence.HIGH
    assert found.location.field == "authors[0].name"


def test_yaml_aliases_do_not_expand_the_work() -> None:
    # A YAML bomb only costs anything if it is walked, and only named fields are read.
    bomb = "a: &a [x, x]\nb: &b [*a, *a]\nc: &c [*b, *b]\nd: &d [*c, *c]\nauthors: [*d, *d]\n"
    assert values(parse_citation(bomb)) == []


def test_yaml_cannot_construct_python_objects(tmp_path: Path) -> None:
    marker = tmp_path / "marker"
    text = f"authors: !!python/object/apply:os.system ['echo x > {marker.as_posix()}']\n"
    write_tree(tmp_path, {"CITATION.cff": text})
    report = scan(tmp_path)
    assert not marker.exists()
    assert report.result.skipped[0].reason is SkipReason.CORRUPT


# Legal and people files


@pytest.mark.parametrize(
    ("line", "holder"),
    [
        ("Copyright (c) 2026 Alice Example", "Alice Example"),
        ("Copyright (C) 2020-2026 Alice Example", "Alice Example"),
        ("Copyright 2026 Alice Example", "Alice Example"),
        ("Copyright \u00a9 2026, 2027 Alice Example", "Alice Example"),
        ("Copyright (c) Alice Example", "Alice Example"),
        ("  # Copyright (c) 2026 by Alice Example", "Alice Example"),
        ("Copyright (c) 2026 Alice Example. All rights reserved.", "Alice Example"),
        ("Copyright (c) 2026 Alice Example <alice@example.edu>", "Alice Example"),
    ],
)
def test_copyright_holders(line: str, holder: str) -> None:
    assert values(parse_legal(f"MIT License\n\n{line}\n"), FieldKind.PERSON) == [holder]


@pytest.mark.parametrize(
    "line",
    ["Copyright law applies.", "the copyright holder may", "Copyright notice and permission"],
)
def test_prose_about_copyright_is_not_a_holder(line: str) -> None:
    assert values(parse_legal(f"{line}\n")) == []


def test_a_confirmed_copyright_holder_is_a_blocker(tmp_path: Path) -> None:
    items = scan_file(tmp_path, "LICENSE", "MIT\n\nCopyright (c) 2026 Alice Example\n")
    assert rules_found(items) == ["RB304"]
    assert items[0].severity is Severity.BLOCKER
    assert items[0].location.line == 3


def test_another_copyright_holder_is_a_warning(tmp_path: Path) -> None:
    items = scan_file(tmp_path, "LICENSE.txt", "Copyright (c) 2026 Bob Coauthor\n")
    assert (items[0].rule_id, items[0].severity) == ("RB304", Severity.WARNING)
    assert items[0].confidence is Confidence.MEDIUM


@pytest.mark.parametrize(
    "text",
    [
        "Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>",
        "Copyright [yyyy] [name of copyright owner]",
        "Copyright (c) <year> <copyright holders>",
        "Copyright (C) <year>  <name of author>",
        "Copyright (c) 2026 Anonymous Authors",
        "Copyright (c) {year} {fullname}",
    ],
)
def test_standard_license_text_and_placeholders_are_not_findings(tmp_path: Path, text: str) -> None:
    assert scan_file(tmp_path, "LICENSE", f"{text}\n") == []


def test_an_authors_file_lists_people() -> None:
    text = "# Our authors\n\nAlice Example <alice@example.edu>\nBob Coauthor\n"
    fields = list(parse_people_file(text))
    assert values(fields, FieldKind.PERSON) == ["Alice Example", "Bob Coauthor"]
    assert values(fields, FieldKind.EMAIL) == ["alice@example.edu"]


def test_an_authors_file_uses_the_legal_rule(tmp_path: Path) -> None:
    items = scan_file(tmp_path, "AUTHORS", "Bob Coauthor\n")
    assert rules_found(items) == ["RB304"]


@pytest.mark.parametrize("name", ["NOTICE", "COPYING", "LICENCE-MIT"])
def test_other_legal_files(tmp_path: Path, name: str) -> None:
    assert rules_found(scan_file(tmp_path, name, "Copyright 2026 Alice Example\n")) == ["RB304"]


# Placeholders


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        (FieldKind.PERSON, "Anonymous Authors", True),
        (FieldKind.PERSON, "anonymous", True),
        (FieldKind.PERSON, "TODO", True),
        (FieldKind.PERSON, "Bob Coauthor", False),
        (FieldKind.PERSON, "SomeProject contributors", True),
        (FieldKind.PERSON, "The SomeProject Authors", True),
        (FieldKind.PERSON, "SomeProject Developers", True),
        (FieldKind.PERSON, "Vision Lab Team", False),
        (FieldKind.PERSON, "Bob Contributor", False),
        (FieldKind.EMAIL, "anon@example.com", True),
        (FieldKind.EMAIL, "bob@example.org", True),
        (FieldKind.EMAIL, "bob@example.edu", False),
        (FieldKind.URL, "https://example.com/project", True),
        (FieldKind.URL, "http://localhost:8000", True),
        (FieldKind.URL, "https://github.com/pytorch/pytorch", False),
        (FieldKind.URL, "https://notexample.com", False),
    ],
)
def test_what_counts_as_a_placeholder(kind: FieldKind, value: str, expected: bool) -> None:
    assert is_placeholder(ManifestField(kind, value, "x")) is expected


def test_a_placeholder_author_is_not_a_finding(tmp_path: Path) -> None:
    text = '[project]\nauthors = [{ name = "Anonymous Authors", email = "anon@example.com" }]\n'
    assert scan_file(tmp_path, "pyproject.toml", text) == []


def test_a_confirmed_identity_is_never_treated_as_a_placeholder(tmp_path: Path) -> None:
    # example.edu is the persona's institution, and the name always counts.
    text = '[project]\nauthors = [{ email = "alice@example.edu" }]\n'
    assert rules_found(scan_file(tmp_path, "pyproject.toml", text)) == ["RB301"]


# Malformed and hostile files


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("pyproject.toml", "[project\nname = "),
        ("package.json", '{"author": '),
        ("setup.cfg", "no section header\n[broken\n"),
        ("setup.py", "def broken(:\n"),
        ("setup.py", "x = 1\0\n"),
        ("CITATION.cff", "authors: [unclosed\n  - : :\n"),
    ],
)
def test_a_corrupt_manifest_is_reported_and_its_text_is_still_scanned(
    tmp_path: Path, name: str, content: str
) -> None:
    write_tree(tmp_path, {name: f"{content}\n# Alice Example\n"})
    report = scan(tmp_path)
    assert report.result.incomplete
    assert any(item.reason is SkipReason.CORRUPT for item in report.result.skipped)
    assert "RB101" in rules_found(report.result.findings)


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("pyproject.toml", 'project = "text"\n'),
        ("pyproject.toml", "[project]\nauthors = 5\n"),
        ("pyproject.toml", '[project]\nauthors = ["not a table", 5]\nurls = "x"\n'),
        ("pyproject.toml", "[project]\nauthors = [{ name = 5, email = [] }]\n"),
        ("package.json", "[1, 2, 3]"),
        ("package.json", '"just a string"'),
        ("package.json", '{"author": 5, "contributors": "x", "repository": 5, "bugs": []}'),
        ("CITATION.cff", "just text\n"),
        ("CITATION.cff", "authors: 5\n"),
        ("CITATION.cff", "authors: [1, [2], text]\ncontact: {}\n"),
        ("setup.py", "setup(author=5, project_urls=3)\n"),
    ],
)
def test_wrong_types_are_ignored_without_failing(tmp_path: Path, name: str, content: str) -> None:
    write_tree(tmp_path, {name: content})
    report = scan(tmp_path)
    assert report.result.findings == []
    assert not report.result.incomplete


def test_deeply_nested_json_is_contained(tmp_path: Path) -> None:
    write_tree(tmp_path, {"package.json": "[" * 200_000})
    report = scan(tmp_path)
    assert report.result.incomplete
    assert report.result.skipped[0].reason in {SkipReason.CORRUPT, SkipReason.SCANNER_ERROR}


def test_deeply_nested_python_is_contained(tmp_path: Path) -> None:
    write_tree(tmp_path, {"setup.py": "x = " + "(" * 100_000})
    report = scan(tmp_path)
    assert report.result.incomplete


def test_a_binary_file_named_like_a_manifest_is_reported(tmp_path: Path) -> None:
    write_tree(tmp_path, {"package.json": b"\xff\xfe\x00\x00garbage\xff"})
    assert scan(tmp_path).result.incomplete


def test_only_manifest_names_are_parsed_as_manifests(tmp_path: Path) -> None:
    text = '[project]\nauthors = [{ name = "Bob Coauthor" }]\n'
    assert scan_file(tmp_path, "other.toml", text) == []


def test_a_manifest_in_a_subdirectory_counts(tmp_path: Path) -> None:
    text = '[project]\nauthors = [{ name = "Bob Coauthor" }]\n'
    assert rules_found(scan_file(tmp_path, "pkg/pyproject.toml", text)) == ["RB301"]
