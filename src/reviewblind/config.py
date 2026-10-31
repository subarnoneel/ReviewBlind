"""Reading, validating and writing `.reviewblind.toml`. See docs/CONFIG.md."""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reviewblind.models import Confidence, Identity, IdentityKind
from reviewblind.rules.registry import is_known_rule
from reviewblind.utils.files import CONFIG_FILE_NAME, atomic_write

CONFIG_VERSION = 1
MAX_CONFIG_BYTES = 1024 * 1024
DEFAULT_MAX_TEXT_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_BINARY_BYTES = 50 * 1024 * 1024
DEFAULT_EXCLUDE = (
    ".venv/**",
    "node_modules/**",
    "__pycache__/**",
    ".pytest_cache/**",
    ".mypy_cache/**",
)

_IDENTITY_KEYS = {
    "names": IdentityKind.NAME,
    "emails": IdentityKind.EMAIL,
    "usernames": IdentityKind.USERNAME,
    "affiliations": IdentityKind.AFFILIATION,
    "aliases": IdentityKind.ALIAS,
    "urls": IdentityKind.URL,
}
_TOP_LEVEL_KEYS = {"version", "identity", "scan", "allow"}
_SCAN_KEYS = {"max_text_bytes", "max_binary_bytes", "follow_symlinks", "exclude"}
_ALLOW_KEYS = {"rule", "path", "value", "reason"}
_TOML_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}


class ConfigError(Exception):
    """The configuration cannot be used. The CLI reports this and exits with code 2."""


@dataclass(frozen=True)
class IdentityConfig:
    names: tuple[str, ...] = ()
    emails: tuple[str, ...] = ()
    usernames: tuple[str, ...] = ()
    affiliations: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    urls: tuple[str, ...] = ()

    def identities(self) -> tuple[Identity, ...]:
        """Every value here is confirmed: listing it in the config is the confirmation."""
        return tuple(
            Identity(value, kind, "config", Confidence.HIGH, confirmed=True)
            for key, kind in _IDENTITY_KEYS.items()
            for value in getattr(self, key)
        )


@dataclass(frozen=True)
class ScanSettings:
    max_text_bytes: int = DEFAULT_MAX_TEXT_BYTES
    max_binary_bytes: int = DEFAULT_MAX_BINARY_BYTES
    follow_symlinks: bool = False
    exclude: tuple[str, ...] = DEFAULT_EXCLUDE


@dataclass(frozen=True)
class AllowEntry:
    rule: str
    path: str
    value: str
    reason: str


@dataclass(frozen=True)
class Config:
    identity: IdentityConfig = field(default_factory=IdentityConfig)
    scan: ScanSettings = field(default_factory=ScanSettings)
    allow: tuple[AllowEntry, ...] = ()

    @property
    def has_identities(self) -> bool:
        return bool(self.identity.identities())


def _check_keys(table: Mapping[str, Any], allowed: set[str], where: str) -> None:
    # An ignored `emials` would look like a passing scan, so unknown keys are errors.
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ConfigError(f"unknown key in {where}: {', '.join(unknown)}")


def _table(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"{key} must be a table")
    return value


def _text(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{where} must be a string")
    if not value.strip():
        raise ConfigError(f"{where} must not be empty")
    return value


def _text_list(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError(f"{where} must be a list of strings")
    return tuple(_text(item, f"{where}[{index}]") for index, item in enumerate(value))


def _positive_int(value: object, where: str) -> int:
    # bool is a subclass of int, and `max_text_bytes = true` is a mistake.
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"{where} must be an integer")
    if value <= 0:
        raise ConfigError(f"{where} must be greater than zero")
    return value


def _parse_identity(table: Mapping[str, Any]) -> IdentityConfig:
    _check_keys(table, set(_IDENTITY_KEYS), "[identity]")
    return IdentityConfig(
        **{key: _text_list(value, f"identity.{key}") for key, value in table.items()}
    )


def _parse_scan(table: Mapping[str, Any]) -> ScanSettings:
    _check_keys(table, _SCAN_KEYS, "[scan]")
    follow_symlinks = table.get("follow_symlinks", False)
    if not isinstance(follow_symlinks, bool):
        raise ConfigError("scan.follow_symlinks must be true or false")
    return ScanSettings(
        max_text_bytes=_positive_int(
            table.get("max_text_bytes", DEFAULT_MAX_TEXT_BYTES), "scan.max_text_bytes"
        ),
        max_binary_bytes=_positive_int(
            table.get("max_binary_bytes", DEFAULT_MAX_BINARY_BYTES), "scan.max_binary_bytes"
        ),
        follow_symlinks=follow_symlinks,
        exclude=_text_list(table.get("exclude", list(DEFAULT_EXCLUDE)), "scan.exclude"),
    )


def _parse_allow_entry(entry: object, index: int) -> AllowEntry:
    where = f"allow[{index}]"
    if not isinstance(entry, dict):
        raise ConfigError(f"{where} must be a table")
    _check_keys(entry, _ALLOW_KEYS, f"[[allow]] entry {index}")
    missing = sorted(_ALLOW_KEYS - set(entry))
    if missing:
        raise ConfigError(f"{where} is missing: {', '.join(missing)}")
    rule = _text(entry["rule"], f"{where}.rule")
    if not is_known_rule(rule):
        raise ConfigError(f"{where}.rule is not a known rule: {rule}")
    path = _text(entry["path"], f"{where}.path")
    if "\\" in path or path.startswith("/") or "*" in path or "?" in path:
        raise ConfigError(
            f"{where}.path must be an exact relative path with forward slashes and no wildcards"
        )
    return AllowEntry(
        rule=rule,
        path=path,
        value=_text(entry["value"], f"{where}.value"),
        reason=_text(entry["reason"], f"{where}.reason"),
    )


def parse_config(data: Mapping[str, Any]) -> Config:
    """Validate parsed TOML. Raises `ConfigError` naming the first problem found."""
    _check_keys(data, _TOP_LEVEL_KEYS, "the top level")
    if "version" not in data:
        raise ConfigError("version is missing")
    version = data["version"]
    if isinstance(version, bool) or version != CONFIG_VERSION:
        raise ConfigError(f"unsupported version: {version!r}. This release reads version 1")
    allow = data.get("allow", [])
    if not isinstance(allow, list):
        raise ConfigError("allow must be written as [[allow]] entries")
    return Config(
        identity=_parse_identity(_table(data, "identity")),
        scan=_parse_scan(_table(data, "scan")),
        allow=tuple(_parse_allow_entry(entry, index) for index, entry in enumerate(allow)),
    )


def load_config(path: Path) -> Config:
    """Read and validate a config file."""
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigError(f"{path} is too large to be a ReviewBlind config")
        with path.open("rb") as file:
            data = tomllib.load(file)
    except OSError as error:
        raise ConfigError(f"cannot read {path}: {error.strerror or error}") from error
    except (tomllib.TOMLDecodeError, UnicodeDecodeError, RecursionError) as error:
        raise ConfigError(f"{path} is not valid TOML: {error}") from error
    try:
        return parse_config(data)
    except ConfigError as error:
        raise ConfigError(f"{path}: {error}") from error


def find_config(root: Path, explicit: Path | None = None) -> Path:
    """Apply the lookup order in docs/CONFIG.md. Parent directories are never searched."""
    if explicit is not None:
        if not explicit.is_file():
            raise ConfigError(f"config file not found: {explicit}")
        return explicit
    candidate = root / CONFIG_FILE_NAME
    if not candidate.is_file():
        raise ConfigError(f"no {CONFIG_FILE_NAME} in {root}. Run `reviewblind init` to create one")
    return candidate


def _toml_string(value: str) -> str:
    escaped: list[str] = []
    for char in value:
        if char in _TOML_ESCAPES:
            escaped.append(_TOML_ESCAPES[char])
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            escaped.append(f"\\u{ord(char):04X}")
        else:
            escaped.append(char)
    return '"' + "".join(escaped) + '"'


def _toml_list(key: str, values: tuple[str, ...]) -> str:
    if not values:
        return f"{key} = []"
    lines = "".join(f"  {_toml_string(value)},\n" for value in values)
    return f"{key} = [\n{lines}]"


def dumps_config(config: Config) -> str:
    """Render a config as TOML. `tomllib` only reads, so this covers our one fixed schema."""
    sections = [f"version = {CONFIG_VERSION}"]
    identity = ["[identity]"]
    identity.extend(_toml_list(key, getattr(config.identity, key)) for key in _IDENTITY_KEYS)
    sections.append("\n".join(identity))
    scan = config.scan
    sections.append(
        "\n".join(
            (
                "[scan]",
                f"max_text_bytes = {scan.max_text_bytes}",
                f"max_binary_bytes = {scan.max_binary_bytes}",
                f"follow_symlinks = {'true' if scan.follow_symlinks else 'false'}",
                _toml_list("exclude", scan.exclude),
            )
        )
    )
    sections.extend(
        "\n".join(
            (
                "[[allow]]",
                f"rule = {_toml_string(entry.rule)}",
                f"path = {_toml_string(entry.path)}",
                f"value = {_toml_string(entry.value)}",
                f"reason = {_toml_string(entry.reason)}",
            )
        )
        for entry in config.allow
    )
    return "\n\n".join(sections) + "\n"


def write_config(config: Config, path: Path, *, force: bool = False) -> None:
    """Write a config without ever following a symlink (threat T-06)."""
    if path.is_symlink():
        raise ConfigError(f"refusing to write through a symbolic link: {path}")
    if path.exists() and not force:
        raise ConfigError(f"{path} already exists. Use --force to overwrite it")
    try:
        atomic_write(path, dumps_config(config).encode("utf-8"))
    except OSError as error:
        raise ConfigError(f"cannot write {path}: {error.strerror or error}") from error
