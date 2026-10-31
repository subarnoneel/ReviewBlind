"""Finding likely identities (FR-DISC-1 to FR-DISC-11)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from _helpers import git, init_repo, write_tree
from reviewblind import cli
from reviewblind.discovery import Candidate, Discovery, discover
from reviewblind.discovery.candidates import (
    MAX_VALUE_LENGTH,
    Observation,
    SourceClass,
    derived_aliases,
    merge,
)
from reviewblind.discovery.latex import from_latex
from reviewblind.models import Confidence, IdentityKind
from reviewblind.signals import namespace_owner

runner = CliRunner()
HIGH = Confidence.HIGH
MEDIUM = Confidence.MEDIUM
LOW = Confidence.LOW


def commit(root: Path, name: str, email: str, message: str = "Change") -> None:
    git(
        root,
        "-c",
        f"user.name={name}",
        "-c",
        f"user.email={email}",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        message,
    )


def empty_repo(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    git(root, "init", "-q")
    return root


def find(found: Discovery, value: str) -> Candidate:
    matches = [item for item in found.candidates if item.value == value]
    assert len(matches) == 1, [item.value for item in found.candidates]
    return matches[0]


def values(found: Discovery) -> list[str]:
    return [item.value for item in found.candidates]


# Git history (FR-DISC-1)


def test_a_repeated_git_identity_is_high_confidence(tmp_path: Path) -> None:
    root = empty_repo(tmp_path / "repo")
    commit(root, "Alice Example", "alice@example.edu")
    commit(root, "Alice Example", "alice@example.edu")
    found = discover(root)
    name = find(found, "Alice Example")
    assert name.kind is IdentityKind.NAME
    assert name.confidence is HIGH
    assert "Git author (2 commits)" in name.sources
    assert find(found, "alice@example.edu").confidence is HIGH


def test_a_single_commit_identity_is_medium_confidence(tmp_path: Path) -> None:
    root = empty_repo(tmp_path / "repo")
    commit(root, "Bob Coauthor", "bob@elsewhere.example.org")
    found = discover(root)
    assert find(found, "Bob Coauthor").confidence is MEDIUM
    assert find(found, "bob@elsewhere.example.org").confidence is MEDIUM


def test_an_emails_local_part_cannot_promote_its_own_commit(tmp_path: Path) -> None:
    # They come from one commit, so they are not independent evidence (D-63).
    root = empty_repo(tmp_path / "repo")
    commit(root, "bob", "bob@elsewhere.example.org")
    assert find(discover(root), "bob").confidence is MEDIUM


def test_the_same_email_in_two_places_does_not_promote_its_local_part(tmp_path: Path) -> None:
    # Spec section 9: a local part alone is LOW, however many places repeat the address.
    root = empty_repo(tmp_path / "repo")
    commit(root, "Alice Example", "alice@example.edu")
    write_tree(root, {"CITATION.cff": "authors:\n  - email: alice@example.edu\n"})
    assert find(discover(root), "alice").confidence is LOW


def test_a_local_part_supports_independent_evidence(tmp_path: Path) -> None:
    # The example in docs/CLI.md: a remote and a local part from history agree on a username.
    root = empty_repo(tmp_path / "repo")
    commit(root, "Alice Example", "aliceexample@example.edu")
    git(root, "remote", "add", "origin", "git@github.com:aliceexample/paper.git")
    candidate = find(discover(root), "aliceexample")
    assert candidate.confidence is HIGH
    assert candidate.sources == ("email local part", "GitHub remote")


def test_a_one_word_author_is_treated_as_a_username(tmp_path: Path) -> None:
    root = empty_repo(tmp_path / "repo")
    commit(root, "aliceexample", "other@elsewhere.example.org")
    assert find(discover(root), "aliceexample").kind is IdentityKind.USERNAME


def test_a_committer_is_read_as_well_as_the_author(tmp_path: Path) -> None:
    root = init_repo(tmp_path / "repo")
    git(
        root,
        "-c",
        "user.name=Carol Committer",
        "-c",
        "user.email=carol@elsewhere.example.org",
        "commit",
        "-q",
        "--allow-empty",
        "--author=Bob Coauthor <bob@elsewhere.example.org>",
        "-m",
        "Change",
    )
    found = values(discover(root))
    assert "Carol Committer" in found
    assert "Bob Coauthor" in found
    assert "carol@elsewhere.example.org" in found


def test_case_variants_are_one_candidate(tmp_path: Path) -> None:
    root = empty_repo(tmp_path / "repo")
    commit(root, "Alice Example", "alice@example.edu")
    commit(root, "ALICE EXAMPLE", "ALICE@EXAMPLE.EDU")
    found = discover(root)
    names = [item for item in found.candidates if item.kind is IdentityKind.NAME]
    assert len(names) == 1
    assert names[0].confidence is HIGH


@pytest.mark.parametrize(
    ("name", "email"),
    [
        ("dependabot[bot]", "49699333+dependabot[bot]@users.noreply.github.com"),
        ("github-actions", "action@github.com"),
        ("GitHub", "noreply@github.com"),
    ],
)
def test_bots_are_filtered(tmp_path: Path, name: str, email: str) -> None:
    # FR-DISC-7
    root = empty_repo(tmp_path / "repo")
    commit(root, name, email)
    assert discover(root).candidates == ()


@pytest.mark.parametrize(
    "email",
    ["12345+aliceexample@users.noreply.github.com", "aliceexample@users.noreply.github.com"],
)
def test_a_noreply_address_gives_the_username(tmp_path: Path, email: str) -> None:
    # FR-DISC-7
    root = empty_repo(tmp_path / "repo")
    commit(root, "Alice Example", email)
    commit(root, "Alice Example", email)
    found = discover(root)
    assert find(found, "aliceexample").kind is IdentityKind.USERNAME
    assert find(found, "aliceexample").confidence is HIGH
    assert email not in values(found)


def test_every_source_is_listed(tmp_path: Path) -> None:
    # FR-DISC-8
    root = init_repo(
        tmp_path / "repo", {"pyproject.toml": '[project]\nauthors = [{name = "Alice Example"}]\n'}
    )
    commit(root, "Alice Example", "alice@example.edu")
    sources = find(discover(root), "Alice Example").sources
    assert "pyproject.toml author" in sources
    assert "Git author (1 commit)" in sources


def test_truncated_history_is_stated(tmp_path: Path) -> None:
    # FR-DISC-9
    root = empty_repo(tmp_path / "repo")
    commit(root, "Old Author", "old@elsewhere.example.org")
    commit(root, "New Author", "new@elsewhere.example.org")
    found = discover(root, max_commits=1)
    assert "New Author" in values(found)
    assert "Old Author" not in values(found)
    assert any("newest 1 of 2" in note for note in found.notes)


def test_an_empty_repository_has_no_candidates(tmp_path: Path) -> None:
    assert discover(empty_repo(tmp_path / "repo")).candidates == ()


def test_outside_git_only_files_are_read(tmp_path: Path) -> None:
    write_tree(tmp_path, {"pyproject.toml": '[project]\nauthors = [{name = "Alice Example"}]\n'})
    found = discover(tmp_path)
    assert find(found, "Alice Example").confidence is HIGH


# Remotes


@pytest.mark.parametrize(
    "url",
    [
        "git@github.com:aliceexample/paper.git",
        "https://github.com/aliceexample/paper.git",
        "ssh://git@gitlab.com/aliceexample/paper.git",
        "https://user:SECRET123@github.com/aliceexample/paper.git",
    ],
)
def test_a_remote_owner_is_medium_confidence(tmp_path: Path, url: str) -> None:
    root = empty_repo(tmp_path / "repo")
    git(root, "remote", "add", "origin", url)
    found = discover(root)
    owner = find(found, "aliceexample")
    assert owner.confidence is MEDIUM
    assert owner.kind is IdentityKind.USERNAME
    assert "SECRET123" not in json.dumps([item.sources for item in found.candidates])
    assert not any("SECRET123" in value for value in values(found))


def test_a_remote_on_an_unknown_host_gives_no_owner(tmp_path: Path) -> None:
    root = empty_repo(tmp_path / "repo")
    git(root, "remote", "add", "origin", "https://git.example.org/team/paper.git")
    assert discover(root).candidates == ()


def test_two_source_classes_raise_confidence(tmp_path: Path) -> None:
    # The remote and a manifest URL agree, as in the example in docs/CLI.md.
    root = empty_repo(tmp_path / "repo")
    git(root, "remote", "add", "origin", "git@github.com:aliceexample/paper.git")
    write_tree(
        root,
        {"pyproject.toml": '[project.urls]\nRepository = "https://github.com/aliceexample/p"\n'},
    )
    owner = find(discover(root), "aliceexample")
    assert owner.confidence is HIGH
    assert owner.sources == ("pyproject.toml repository URL", "GitHub remote")


@pytest.mark.parametrize(
    ("url", "owner"),
    [
        ("https://github.com/aliceexample/x", "aliceexample"),
        ("https://aliceexample.github.io/x", "aliceexample"),
        ("https://huggingface.co/datasets/aliceexample/x", "aliceexample"),
        ("https://wandb.ai/aliceexample/x", "aliceexample"),
        ("https://wandb.ai/site", None),
        ("https://github.com/orgs/acme/people", None),
        ("https://example.edu/x", None),
    ],
)
def test_namespace_owner(url: str, owner: str | None) -> None:
    assert namespace_owner(url) == owner


# Manifests (FR-DISC-2)


@pytest.mark.parametrize(
    ("name", "content", "label"),
    [
        (
            "pyproject.toml",
            '[project]\nauthors = [{name = "Alice Example"}]\n',
            "pyproject.toml author",
        ),
        ("package.json", '{"author": "Alice Example"}', "package.json author"),
        ("setup.cfg", "[metadata]\nauthor = Alice Example\n", "setup.cfg author"),
        ("setup.py", 'setup(author="Alice Example")\n', "setup.py author"),
        (
            "CITATION.cff",
            "authors:\n  - given-names: Alice\n    family-names: Example\n",
            "CITATION.cff author",
        ),
    ],
)
def test_structured_author_fields_are_high_confidence(
    tmp_path: Path, name: str, content: str, label: str
) -> None:
    write_tree(tmp_path, {name: content})
    candidate = find(discover(tmp_path), "Alice Example")
    assert candidate.confidence is HIGH
    assert candidate.sources == (label,)


def test_maintainers_are_labelled(tmp_path: Path) -> None:
    write_tree(tmp_path, {"pyproject.toml": '[project]\nmaintainers = [{name = "Bob Coauthor"}]\n'})
    assert find(discover(tmp_path), "Bob Coauthor").sources == ("pyproject.toml maintainer",)


def test_a_license_holder_is_only_medium_confidence(tmp_path: Path) -> None:
    # It may be the project this one was forked from.
    write_tree(tmp_path, {"LICENSE": "Copyright (c) 2026 Bob Coauthor\n"})
    candidate = find(discover(tmp_path), "Bob Coauthor")
    assert candidate.confidence is MEDIUM
    assert candidate.sources == ("LICENSE copyright holder",)


def test_an_authors_file_is_only_medium_confidence(tmp_path: Path) -> None:
    write_tree(tmp_path, {"AUTHORS": "Bob Coauthor <bob@elsewhere.example.org>\n"})
    assert find(discover(tmp_path), "Bob Coauthor").confidence is MEDIUM


def test_an_affiliation_is_medium_confidence(tmp_path: Path) -> None:
    write_tree(tmp_path, {"CITATION.cff": "authors:\n  - affiliation: Example University\n"})
    candidate = find(discover(tmp_path), "Example University")
    assert candidate.kind is IdentityKind.AFFILIATION
    assert candidate.confidence is MEDIUM


def test_a_url_with_no_known_owner_is_a_url_candidate(tmp_path: Path) -> None:
    write_tree(
        tmp_path, {"pyproject.toml": '[project.urls]\nHomepage = "https://alice.example.dev"\n'}
    )
    candidate = find(discover(tmp_path), "https://alice.example.dev")
    assert candidate.kind is IdentityKind.URL
    assert candidate.confidence is MEDIUM


def test_placeholders_are_not_candidates(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "pyproject.toml": '[project]\nauthors = [{name = "Anonymous Authors", email = "a@example.com"}]\n'
        },
    )
    assert discover(tmp_path).candidates == ()


def test_a_collective_label_is_not_a_person(tmp_path: Path) -> None:
    write_tree(
        tmp_path, {"pyproject.toml": '[project]\nauthors = [{name = "SomeProject contributors"}]\n'}
    )
    assert discover(tmp_path).candidates == ()


def test_nested_manifests_are_ignored(tmp_path: Path) -> None:
    # A nested one usually describes vendored code, whose authors are not this project's (D-62).
    write_tree(
        tmp_path, {"vendor/lib/pyproject.toml": '[project]\nauthors = [{name = "Someone Else"}]\n'}
    )
    assert discover(tmp_path).candidates == ()


def test_a_broken_manifest_is_a_note_not_a_failure(tmp_path: Path) -> None:
    write_tree(
        tmp_path, {"pyproject.toml": "[project\n", "setup.py": 'setup(author="Alice Example")\n'}
    )
    found = discover(tmp_path)
    assert "Alice Example" in values(found)
    assert any("pyproject.toml could not be parsed" in note for note in found.notes)


def test_excluded_directories_are_not_read(tmp_path: Path) -> None:
    write_tree(tmp_path, {"node_modules/x/paper.tex": "\\author{Someone Else}\n"})
    assert discover(tmp_path).candidates == ()


# LaTeX (FR-DISC-3)


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("\\author{Alice Example}", ["Alice Example"]),
        ("\\author{Alice Example \\and Bob Coauthor}", ["Alice Example", "Bob Coauthor"]),
        ("\\author{Alice Example, Bob Coauthor}", ["Alice Example", "Bob Coauthor"]),
        ("\\author{Alice Example and Bob Coauthor}", ["Alice Example", "Bob Coauthor"]),
        ("\\author{Alice Example\\\\Bob Coauthor}", ["Alice Example", "Bob Coauthor"]),
        ("\\author{Alice Example\\thanks{Funded by a grant}}", ["Alice Example"]),
        ("\\author{\\textbf{Alice Example}}", ["Alice Example"]),
        ("\\author{\\textbf{\\emph{Alice Example}}}", ["Alice Example"]),
        ("\\author[1]{Alice Example}", ["Alice Example"]),
        ("\\author*{Alice Example}", ["Alice Example"]),
        ("\\author{Alice Example\\inst{1}}", ["Alice Example"]),
        ("\\author{Alice Example$^{1}$}", ["Alice Example"]),
        ("\\IEEEauthorblockN{Alice Example}", ["Alice Example"]),
        ("\\icmlauthor{Alice Example}{alice@example.edu}", ["Alice Example"]),
    ],
)
def test_author_macros(source: str, expected: list[str]) -> None:
    people = [item.value for item in from_latex("p.tex", source) if item.kind is IdentityKind.NAME]
    assert people == expected


def test_emails_in_macros() -> None:
    found = from_latex(
        "p.tex", "\\email{alice@example.edu}\n\\author{Alice Example alice@example.edu}\n"
    )
    emails = {item.value for item in found if item.kind is IdentityKind.EMAIL}
    assert emails == {"alice@example.edu"}


@pytest.mark.parametrize(
    "source",
    [
        "\\institute{Example University}",
        "\\affiliation{\\institution{Example University}}",
        "\\institution{Example University}",
        "\\icmlaffiliation{Example University}",
        "\\IEEEauthorblockA{Example University\\\\Somewhere}",
    ],
)
def test_affiliation_macros(source: str) -> None:
    found = [item for item in from_latex("p.tex", source) if item.kind is IdentityKind.AFFILIATION]
    assert "Example University" in [item.value for item in found]
    assert all(item.confidence is MEDIUM for item in found)


def test_an_institution_name_with_a_comma_stays_whole() -> None:
    found = from_latex("p.tex", "\\institute{University of Example, Anytown}")
    assert [item.value for item in found] == ["University of Example, Anytown"]


@pytest.mark.parametrize(
    "source",
    [
        "% \\author{Commented Out}",
        "  %\\author{Commented Out}",
        "\\author{Anonymous Authors}",
        "\\author{Your Name}",
        "\\author{}",
        "\\author{\\textbf{}}",
        "\\author{1234}",
        "\\newcommand{\\foo}{bar}",
        "\\author{unclosed",
    ],
)
def test_things_that_are_not_authors(source: str) -> None:
    assert from_latex("p.tex", source) == []


def test_an_escaped_percent_is_not_a_comment() -> None:
    found = from_latex("p.tex", "\\author{Alice 100\\% Example}")
    assert found


def test_latex_files_are_found_anywhere(tmp_path: Path) -> None:
    write_tree(tmp_path, {"paper/main.tex": "\\author{Alice Example}\n"})
    candidate = find(discover(tmp_path), "Alice Example")
    assert candidate.confidence is HIGH
    assert candidate.sources == ("paper/main.tex author",)


def test_hostile_latex_is_fast() -> None:
    from_latex("p.tex", "\\author{" * 200_000)
    from_latex("p.tex", "\\author{" + "{" * 1_000_000)
    from_latex("p.tex", "\\author" + "[" * 1_000_000)


# The environment (FR-DISC-4)


def _set_user(monkeypatch: pytest.MonkeyPatch, name: str, tmp_path: Path) -> None:
    home = tmp_path / "home" / name
    home.mkdir(parents=True)
    monkeypatch.setenv("USER", name)
    monkeypatch.setenv("USERNAME", name)
    monkeypatch.setattr(Path, "home", lambda: home)


def test_the_environment_is_read_only_when_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_user(monkeypatch, "aliceexample", tmp_path)
    root = tmp_path / "repo"
    root.mkdir()
    assert discover(root).candidates == ()
    candidate = find(discover(root, include_env=True), "aliceexample")
    assert candidate.confidence is LOW
    assert candidate.sources == ("environment username",)


def test_a_generic_account_is_not_a_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_user(monkeypatch, "runner", tmp_path)
    root = tmp_path / "repo"
    root.mkdir()
    assert discover(root, include_env=True).candidates == ()


# Confidence and merging (FR-DISC-5, FR-DISC-6)


def observation(
    value: str,
    confidence: Confidence,
    source_class: SourceClass = SourceClass.MANIFEST,
    kind: IdentityKind = IdentityKind.NAME,
) -> Observation:
    return Observation(
        value, kind, confidence, f"{source_class.value} {confidence.value}", source_class
    )


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        (MEDIUM, LOW, HIGH),
        (LOW, LOW, MEDIUM),
        (HIGH, LOW, HIGH),
    ],
)
def test_two_classes_raise_the_highest_by_one_level(
    first: Confidence, second: Confidence, expected: Confidence
) -> None:
    merged = merge(
        [
            observation("A B", first, SourceClass.GIT_REMOTE),
            observation("a  b", second, SourceClass.MANIFEST),
        ]
    )
    assert [item.confidence for item in merged] == [expected]


def test_one_class_does_not_raise_confidence() -> None:
    merged = merge([observation("A B", MEDIUM), observation("A B", MEDIUM)])
    assert merged[0].confidence is MEDIUM


def test_merged_candidates_are_sorted_by_confidence_kind_and_value() -> None:
    merged = merge(
        [
            observation("z@example.edu", HIGH, kind=IdentityKind.EMAIL),
            observation("Zed Name", HIGH),
            observation("Abe Name", HIGH),
            observation("Mid Name", MEDIUM),
            observation("Low Name", LOW),
        ]
    )
    assert [item.value for item in merged] == [
        "Abe Name",
        "Zed Name",
        "z@example.edu",
        "Mid Name",
        "Low Name",
    ]


def test_hostile_values_are_cleaned() -> None:
    merged = merge([observation("Alice\x1b[31m\nExample\u202e", HIGH)])
    assert merged[0].value == "Alice[31m Example"


def test_absurdly_long_or_empty_values_are_dropped() -> None:
    assert merge([observation("x" * (MAX_VALUE_LENGTH + 1), HIGH)]) == []
    assert merge([observation("   ", HIGH), observation("\x07", HIGH)]) == []


# Derived aliases


def aliases_of(value: str, kind: IdentityKind, confidence: Confidence = HIGH) -> list[str]:
    candidate = Candidate(value, kind, confidence, ("x",))
    return [item.value for item in derived_aliases([candidate])]


def test_name_aliases() -> None:
    assert aliases_of("Alice Example", IdentityKind.NAME) == [
        "A. Example",
        "Example, Alice",
        "Example, A.",
    ]


def test_a_middle_name_uses_the_outer_names() -> None:
    assert "A. Example" in aliases_of("Alice B. Example", IdentityKind.NAME)


def test_a_name_with_diacritics_gets_a_plain_form() -> None:
    assert "Jose Garcia" in aliases_of("Jos\u00e9 Garc\u00eda", IdentityKind.NAME)


@pytest.mark.parametrize(
    ("affiliation", "expected"),
    [
        ("Example University", ["EU"]),
        ("University of Example at Anytown", ["UEA"]),
        ("Massachusetts Institute of Technology", ["MIT"]),
        ("Example", []),
        ("\u5317\u4eac\u5927\u5b66", []),
    ],
)
def test_affiliation_acronyms(affiliation: str, expected: list[str]) -> None:
    assert aliases_of(affiliation, IdentityKind.AFFILIATION, MEDIUM) == expected


def test_weak_names_are_not_expanded() -> None:
    # A fork can list hundreds of one-time contributors.
    assert aliases_of("Bob Coauthor", IdentityKind.NAME, MEDIUM) == []


def test_aliases_are_always_low_confidence(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "CITATION.cff": "authors:\n  - name: Alice Example\n    affiliation: Example University\n"
        },
    )
    found = discover(tmp_path)
    for value in ("A. Example", "Example, Alice", "EU"):
        assert find(found, value).confidence is LOW
        assert find(found, value).kind is IdentityKind.ALIAS


def test_an_alias_already_found_directly_is_not_repeated(tmp_path: Path) -> None:
    write_tree(
        tmp_path, {"CITATION.cff": "authors:\n  - name: Alice Example\n  - name: A. Example\n"}
    )
    found = discover(tmp_path)
    assert find(found, "A. Example").kind is IdentityKind.NAME


# The command


def test_discover_prints_candidates_by_confidence(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            "CITATION.cff": "authors:\n  - name: Alice Example\n    affiliation: Example University\n"
        },
    )
    result = runner.invoke(cli.app, ["discover", str(tmp_path)])
    assert result.exit_code == 0
    output = result.stdout
    assert output.index("HIGH CONFIDENCE") < output.index("MEDIUM CONFIDENCE")
    assert output.index("MEDIUM CONFIDENCE") < output.index("LOW CONFIDENCE")
    assert "[1] Alice Example (name)" in output
    assert "Source:\n      CITATION.cff author" in output


def test_discover_json_matches_the_documented_shape(tmp_path: Path) -> None:
    # FR-DISC-11
    write_tree(tmp_path, {"pyproject.toml": '[project]\nauthors = [{name = "Alice Example"}]\n'})
    result = runner.invoke(cli.app, ["discover", str(tmp_path), "--json"])
    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert list(document) == ["schema_version", "candidates", "notes"]
    assert document["schema_version"] == 1
    first = document["candidates"][0]
    assert first == {
        "value": "Alice Example",
        "kind": "NAME",
        "confidence": "HIGH",
        "sources": ["pyproject.toml author"],
    }


def test_discover_says_when_nothing_was_found(tmp_path: Path) -> None:
    result = runner.invoke(cli.app, ["discover", str(tmp_path)])
    assert result.exit_code == 0
    assert "No likely identities" in result.stdout


def test_discover_needs_a_directory(tmp_path: Path) -> None:
    assert runner.invoke(cli.app, ["discover", str(tmp_path / "missing")]).exit_code == 2


def test_discover_notes_go_to_stderr(tmp_path: Path) -> None:
    write_tree(tmp_path, {"pyproject.toml": "[project\n"})
    result = runner.invoke(cli.app, ["discover", str(tmp_path)])
    assert "could not be parsed" in result.stderr


def test_discover_max_commits_is_validated(tmp_path: Path) -> None:
    assert runner.invoke(cli.app, ["discover", str(tmp_path), "--max-commits", "0"]).exit_code == 2


def test_discover_exit_4_on_an_internal_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("broke")

    monkeypatch.setattr(cli, "discover", explode)
    result = runner.invoke(cli.app, ["discover", str(tmp_path)])
    assert result.exit_code == 4
    assert "internal error" in result.stderr


def test_discover_writes_nothing(tmp_path: Path) -> None:
    # FR-DISC-10
    root = init_repo(
        tmp_path / "repo", {"pyproject.toml": '[project]\nauthors = [{name = "A B"}]\n'}
    )

    def snapshot() -> dict[str, bytes]:
        return {str(path): path.read_bytes() for path in root.rglob("*") if path.is_file()}

    before = snapshot()
    runner.invoke(cli.app, ["discover", str(root), "--include-env"])
    assert snapshot() == before
