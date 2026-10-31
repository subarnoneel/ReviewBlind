"""Reading, validating and writing .reviewblind.toml (FR-CFG-1 to FR-CFG-4, FR-INIT-7)."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

import pytest

from reviewblind.config import (
    DEFAULT_EXCLUDE,
    DEFAULT_MAX_BINARY_BYTES,
    DEFAULT_MAX_TEXT_BYTES,
    MAX_CONFIG_BYTES,
    AllowEntry,
    Config,
    ConfigError,
    IdentityConfig,
    ScanSettings,
    dumps_config,
    find_config,
    load_config,
    parse_config,
    write_config,
)
from reviewblind.models import IdentityKind

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / ".reviewblind.example.toml"

VALID: dict[str, Any] = {"version": 1, "identity": {"names": ["Alice Example"]}}


def allow_entry(**overrides: Any) -> dict[str, Any]:
    entry = {"rule": "RB101", "path": "references.bib", "value": "Alice", "reason": "A citation"}
    return {key: value for key, value in (entry | overrides).items() if value is not None}


def test_the_published_example_is_valid() -> None:
    config = load_config(EXAMPLE)
    assert config.identity.names == ("Alice Example",)
    assert config.identity.emails == ("alice@example.edu",)
    assert config.scan.max_text_bytes == DEFAULT_MAX_TEXT_BYTES
    assert config.allow[0].rule == "RB101"
    assert config.has_identities


def test_every_listed_value_is_a_confirmed_identity() -> None:
    config = parse_config(
        {
            "version": 1,
            "identity": {
                "names": ["Alice Example"],
                "emails": ["alice@example.edu"],
                "usernames": ["aliceexample"],
                "affiliations": ["Example University"],
                "aliases": ["A. Example"],
                "urls": ["https://alice.example.edu"],
            },
        }
    )
    identities = config.identity.identities()
    assert {item.kind for item in identities} == set(IdentityKind)
    assert all(item.confirmed and item.source == "config" for item in identities)


def test_defaults_apply_when_scan_is_omitted() -> None:
    scan = parse_config(VALID).scan
    assert scan.max_text_bytes == DEFAULT_MAX_TEXT_BYTES
    assert scan.max_binary_bytes == DEFAULT_MAX_BINARY_BYTES
    assert scan.follow_symlinks is False
    assert scan.exclude == DEFAULT_EXCLUDE
    assert parse_config(VALID).allow == ()


def test_setting_exclude_replaces_the_defaults() -> None:
    config = parse_config(VALID | {"scan": {"exclude": ["data/**"]}})
    assert config.scan.exclude == ("data/**",)


def test_no_identities_parses_but_is_reported() -> None:
    # `scan` turns this into exit code 2, but `init` must be able to read such a file.
    assert not parse_config({"version": 1}).has_identities


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({}, "version is missing"),
        ({"version": 2}, "unsupported version"),
        ({"version": "1"}, "unsupported version"),
        ({"version": True}, "unsupported version"),
        (VALID | {"extra": 1}, "unknown key"),
        ({"version": 1, "identity": {"emials": ["a@example.edu"]}}, "unknown key.*emials"),
        (VALID | {"scan": {"max_bytes": 1}}, "unknown key"),
        ({"version": 1, "identity": "Alice"}, "identity must be a table"),
        ({"version": 1, "identity": {"names": "Alice"}}, "identity.names must be a list"),
        ({"version": 1, "identity": {"names": [1]}}, r"identity.names\[0\] must be a string"),
        ({"version": 1, "identity": {"names": [""]}}, "must not be empty"),
        ({"version": 1, "identity": {"names": ["   "]}}, "must not be empty"),
        (VALID | {"scan": {"max_text_bytes": 0}}, "greater than zero"),
        (VALID | {"scan": {"max_binary_bytes": -1}}, "greater than zero"),
        (VALID | {"scan": {"max_text_bytes": True}}, "must be an integer"),
        (VALID | {"scan": {"max_text_bytes": "8"}}, "must be an integer"),
        (VALID | {"scan": {"follow_symlinks": "no"}}, "true or false"),
        (VALID | {"scan": {"exclude": "data"}}, "must be a list"),
        (VALID | {"allow": {}}, r"\[\[allow\]\]"),
        (VALID | {"allow": ["RB101"]}, "must be a table"),
    ],
)
def test_invalid_configs_are_rejected(data: dict[str, Any], message: str) -> None:
    # FR-CFG-2
    with pytest.raises(ConfigError, match=message):
        parse_config(data)


@pytest.mark.parametrize("key", ["rule", "path", "value", "reason"])
def test_an_allow_entry_needs_all_four_keys(key: str) -> None:
    with pytest.raises(ConfigError, match=f"missing: {key}"):
        parse_config(VALID | {"allow": [allow_entry(**{key: None})]})


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"rule": "RB999"}, "not a known rule"),
        ({"reason": ""}, "must not be empty"),
        ({"reason": "   "}, "must not be empty"),
        ({"path": "*.bib"}, "no wildcards"),
        ({"path": "ref?.bib"}, "no wildcards"),
        ({"path": "docs\\references.bib"}, "forward slashes"),
        ({"path": "/references.bib"}, "relative"),
        ({"regex": ".*"}, "unknown key"),
    ],
)
def test_allow_entries_stay_exact(overrides: dict[str, str], message: str) -> None:
    # FR-CFG-4: a broad suppression could silently hide a different leak.
    with pytest.raises(ConfigError, match=message):
        parse_config(VALID | {"allow": [allow_entry(**overrides)]})


def test_a_valid_allow_entry_is_kept() -> None:
    config = parse_config(VALID | {"allow": [allow_entry()]})
    assert config.allow == (AllowEntry("RB101", "references.bib", "Alice", "A citation"),)


# Reading files


def test_malformed_toml_is_a_config_error(tmp_path: Path) -> None:
    path = tmp_path / ".reviewblind.toml"
    path.write_text("version = = 1", encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid TOML"):
        load_config(path)


def test_invalid_utf8_is_a_config_error(tmp_path: Path) -> None:
    path = tmp_path / ".reviewblind.toml"
    path.write_bytes(b'version = 1\nname = "\xff"\n')
    with pytest.raises(ConfigError, match="not valid TOML"):
        load_config(path)


def test_deeply_nested_toml_does_not_crash(tmp_path: Path) -> None:
    path = tmp_path / ".reviewblind.toml"
    path.write_text("x = " + "[" * 100_000, encoding="utf-8")
    with pytest.raises(ConfigError, match="not valid TOML"):
        load_config(path)


def test_an_oversized_config_is_rejected_before_parsing(tmp_path: Path) -> None:
    path = tmp_path / ".reviewblind.toml"
    path.write_bytes(b"#" * (MAX_CONFIG_BYTES + 1))
    with pytest.raises(ConfigError, match="too large"):
        load_config(path)


def test_a_missing_file_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "missing.toml")


def test_errors_name_the_file(tmp_path: Path) -> None:
    path = tmp_path / ".reviewblind.toml"
    path.write_text("version = 9\n", encoding="utf-8")
    with pytest.raises(ConfigError, match=r"\.reviewblind\.toml: unsupported version"):
        load_config(path)


# Lookup


def test_the_default_location_is_the_scan_root(tmp_path: Path) -> None:
    path = tmp_path / ".reviewblind.toml"
    path.write_text("version = 1\n", encoding="utf-8")
    assert find_config(tmp_path) == path


def test_an_explicit_path_takes_priority(tmp_path: Path) -> None:
    (tmp_path / ".reviewblind.toml").write_text("version = 1\n", encoding="utf-8")
    explicit = tmp_path / "elsewhere.toml"
    explicit.write_text("version = 1\n", encoding="utf-8")
    assert find_config(tmp_path, explicit) == explicit


def test_a_missing_explicit_path_does_not_fall_back(tmp_path: Path) -> None:
    (tmp_path / ".reviewblind.toml").write_text("version = 1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="not found"):
        find_config(tmp_path, tmp_path / "missing.toml")


def test_a_missing_config_suggests_init(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="reviewblind init"):
        find_config(tmp_path)


def test_parent_directories_are_not_searched(tmp_path: Path) -> None:
    (tmp_path / ".reviewblind.toml").write_text("version = 1\n", encoding="utf-8")
    child = tmp_path / "child"
    child.mkdir()
    with pytest.raises(ConfigError):
        find_config(child)


# Writing


FULL = Config(
    identity=IdentityConfig(
        names=("Alice Example",),
        emails=("alice@example.edu",),
        usernames=("aliceexample",),
        affiliations=("Example University", "EU"),
        aliases=("A. Example",),
        urls=("https://alice.example.edu",),
    ),
    scan=ScanSettings(
        max_text_bytes=10, max_binary_bytes=20, follow_symlinks=True, exclude=("a/**",)
    ),
    allow=(AllowEntry("RB101", "references.bib", "Alice Example", "A citation"),),
)


def test_a_full_config_round_trips() -> None:
    assert parse_config(tomllib.loads(dumps_config(FULL))) == FULL


def test_an_empty_config_round_trips() -> None:
    assert parse_config(tomllib.loads(dumps_config(Config()))) == Config()


@pytest.mark.parametrize(
    "value",
    [
        'Alice "Ace" Example',
        "C:\\Users\\alice",
        "Jos\u00e9 Garc\u00eda",
        "\u09b0\u09b9\u09bf\u09ae",
        "\u5f20\u4f1f",
        "tab\there",
        "line\nbreak",
        "return\rhere",
        "bell\x07",
        "delete\x7f",
        "# not a comment",
        "[not.a.table]",
        '"""',
        "'single'",
        "trailing\\",
        "\U0001f600",
    ],
)
def test_awkward_values_round_trip(value: str) -> None:
    # FR-INIT-7
    config = Config(identity=IdentityConfig(names=(value,)))
    assert parse_config(tomllib.loads(dumps_config(config))) == config


def test_writing_creates_a_file_that_loads(tmp_path: Path) -> None:
    path = tmp_path / ".reviewblind.toml"
    write_config(FULL, path)
    assert load_config(path) == FULL
    assert b"\r" not in path.read_bytes()


def test_writing_does_not_leave_temporary_files(tmp_path: Path) -> None:
    write_config(FULL, tmp_path / ".reviewblind.toml")
    assert [item.name for item in tmp_path.iterdir()] == [".reviewblind.toml"]


def test_an_existing_config_is_not_overwritten(tmp_path: Path) -> None:
    # FR-INIT-5
    path = tmp_path / ".reviewblind.toml"
    path.write_text("keep me", encoding="utf-8")
    with pytest.raises(ConfigError, match="--force"):
        write_config(FULL, path)
    assert path.read_text(encoding="utf-8") == "keep me"


def test_force_overwrites(tmp_path: Path) -> None:
    path = tmp_path / ".reviewblind.toml"
    path.write_text("old", encoding="utf-8")
    write_config(FULL, path, force=True)
    assert load_config(path) == FULL


def test_an_unwritable_location_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot write"):
        write_config(FULL, tmp_path / "missing" / ".reviewblind.toml")


def test_a_failed_write_leaves_nothing_behind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(self: Path, target: Path) -> None:
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(Path, "replace", fail)
    with pytest.raises(ConfigError, match="Permission denied"):
        write_config(FULL, tmp_path / ".reviewblind.toml")
    assert list(tmp_path.iterdir()) == []


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("this process cannot create symbolic links")


@pytest.mark.parametrize("force", [False, True])
def test_writing_never_follows_a_symlink(tmp_path: Path, force: bool) -> None:
    # FR-INIT-10 and threat T-06
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched", encoding="utf-8")
    link = tmp_path / ".reviewblind.toml"
    _symlink_or_skip(link, outside)
    with pytest.raises(ConfigError, match="symbolic link"):
        write_config(FULL, link, force=force)
    assert outside.read_text(encoding="utf-8") == "untouched"


def test_writing_refuses_a_dangling_symlink(tmp_path: Path) -> None:
    missing = tmp_path / "created-by-accident.txt"
    link = tmp_path / ".reviewblind.toml"
    _symlink_or_skip(link, missing)
    with pytest.raises(ConfigError, match="symbolic link"):
        write_config(FULL, link)
    assert not missing.exists()
