"""The command line. Exit codes are defined in docs/CLI.md."""

from __future__ import annotations

import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.text import Text

from reviewblind import __version__
from reviewblind.config import (
    Config,
    ConfigError,
    IdentityConfig,
    find_config,
    load_config,
    write_config,
)
from reviewblind.discovery import Candidate, Discovery, discover
from reviewblind.engine import compute_exit_code, run_scan
from reviewblind.initializer import ExcludeResult, add_to_exclude_file, is_tracked
from reviewblind.models import Confidence, IdentityKind, ScanReport, Severity, Target
from reviewblind.reporters.json import render_discovery_json, render_json
from reviewblind.reporters.markdown import render_markdown
from reviewblind.reporters.terminal import (
    render_candidates,
    render_report,
    render_rule,
    render_rule_list,
)
from reviewblind.rules.registry import all_rules, get_rule, is_known_rule
from reviewblind.scanners.base import DEFAULT_MAX_COMMITS
from reviewblind.utils.files import CONFIG_FILE_NAME, atomic_write

EXIT_USAGE = 2
EXIT_INTERNAL = 4

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    help="Preflight a research repository for identity leaks before double-anonymous review.",
)


class TargetOption(StrEnum):
    MIRROR = "mirror"
    ARCHIVE = "archive"
    REPOSITORY = "repository"


class FormatOption(StrEnum):
    TERMINAL = "terminal"
    JSON = "json"
    MARKDOWN = "markdown"


class FailOnOption(StrEnum):
    BLOCKER = "blocker"
    WARNING = "warning"
    REVIEW = "review"
    INFO = "info"


def _prepare_streams() -> None:
    # A name on a Windows code page must not crash the report that was meant to show it.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")


def _print(text: Text) -> None:
    Console(highlight=False, markup=False, emoji=False).print(text, soft_wrap=True, end="")


def _error(message: str) -> None:
    Console(stderr=True, highlight=False, markup=False, emoji=False).print(
        Text(f"reviewblind: {message}"), soft_wrap=True
    )


def _exit_with_error(message: str, code: int = EXIT_USAGE) -> NoReturn:
    _error(message)
    raise typer.Exit(code)


def _render(report: ScanReport, output_format: FormatOption) -> str | Text:
    if output_format is FormatOption.JSON:
        return render_json(report)
    if output_format is FormatOption.MARKDOWN:
        return render_markdown(report)
    return render_report(report)


def _write_stdout(document: str) -> None:
    # A machine-readable format must not depend on the console's code page or line endings.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(encoding="utf-8", newline="\n")
    sys.stdout.write(document)
    sys.stdout.flush()


def _write_report(path: Path, document: str, root: Path) -> None:
    """Write a report file. It lists author identities, so a path inside the scan is flagged."""
    # A symlink planted in the repository could otherwise redirect the write (threat T-06).
    if path.is_symlink():
        _exit_with_error(f"refusing to write through a symbolic link: {path}")
    try:
        atomic_write(path, document.encode("utf-8"))
    except OSError as error:
        _exit_with_error(f"cannot write {path}: {error.strerror or error}")
    _error(f"wrote the report to {path}")
    if path.resolve().is_relative_to(root):
        _error(
            "warning: the report is inside the scanned directory, and it lists your identities. "
            "Keep it out of the artifact you share."
        )


def _show_version(value: bool) -> None:
    if value:
        typer.echo(f"reviewblind {__version__}")
        raise typer.Exit


@app.callback()
def _main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_show_version, is_eager=True, help="Show the version."),
    ] = False,
) -> None:
    """Preflight a research repository for identity leaks before double-anonymous review."""


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Directory to scan.")] = Path(),
    target: Annotated[
        TargetOption, typer.Option(help="How the artifact will be shared.")
    ] = TargetOption.MIRROR,
    config: Annotated[
        Path | None, typer.Option(help="Config to use. Default: PATH/.reviewblind.toml")
    ] = None,
    fail_on: Annotated[
        FailOnOption, typer.Option(help="Lowest severity that causes exit code 1.")
    ] = FailOnOption.BLOCKER,
    strict: Annotated[
        bool, typer.Option("--strict", help="An incomplete scan causes exit code 3.")
    ] = False,
    output_format: Annotated[
        FormatOption, typer.Option("--format", help="Report format.")
    ] = FormatOption.TERMINAL,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report to a file.")
    ] = None,
    max_commits: Annotated[
        int, typer.Option(min=1, help="Newest commits to inspect, from all branches.")
    ] = DEFAULT_MAX_COMMITS,
) -> None:
    """Inspect an artifact and report what could identify its authors."""
    _prepare_streams()
    if not path.is_dir():
        _exit_with_error(f"not a directory: {path}")
    try:
        config_path = find_config(path, config)
        loaded = load_config(config_path)
        if not loaded.has_identities:
            _exit_with_error(
                f"{config_path} lists no identities, so a scan could not find anything. "
                "Run `reviewblind init`, or add them by hand."
            )
        report = run_scan(
            path.resolve(), loaded, Target[target.name], config_path, max_commits=max_commits
        )
        rendered = _render(report, output_format)
    except typer.Exit:
        raise  # Typer's own exit signal is an Exception, and is not a failure
    except ConfigError as error:
        _exit_with_error(str(error))
    except Exception as error:
        _exit_with_error(
            f"internal error: {type(error).__name__}: {error}. This is a bug in ReviewBlind. "
            "If you report it, please reproduce it without your real identities.",
            EXIT_INTERNAL,
        )
    if output is not None:
        plain = rendered.plain if isinstance(rendered, Text) else rendered
        _write_report(output, plain, report.root)
    elif isinstance(rendered, Text):
        _print(rendered)
    else:
        _write_stdout(rendered)
    raise typer.Exit(compute_exit_code(report.result, Severity[fail_on.name], strict=strict))


@app.command()
def rules(
    rule_id: Annotated[str | None, typer.Argument(help="Show one rule in detail.")] = None,
) -> None:
    """Explain what each rule detects, why it matters and how to fix it."""
    _prepare_streams()
    if rule_id is None:
        _print(render_rule_list(all_rules()))
        return
    normalized = rule_id.upper()
    if not is_known_rule(normalized):
        _exit_with_error(f"unknown rule: {rule_id}. Run `reviewblind rules` to list them.")
    _print(render_rule(get_rule(normalized)))


_CONFIG_KEYS = {
    IdentityKind.NAME: "names",
    IdentityKind.EMAIL: "emails",
    IdentityKind.USERNAME: "usernames",
    IdentityKind.AFFILIATION: "affiliations",
    IdentityKind.ALIAS: "aliases",
    IdentityKind.URL: "urls",
}


def _run_discovery(path: Path, *, include_env: bool, max_commits: int) -> Discovery:
    if not path.is_dir():
        _exit_with_error(f"not a directory: {path}")
    try:
        return discover(path.resolve(), include_env=include_env, max_commits=max_commits)
    except ConfigError as error:
        _exit_with_error(str(error))
    except Exception as error:
        _exit_with_error(
            f"internal error: {type(error).__name__}: {error}. This is a bug in ReviewBlind. "
            "If you report it, please reproduce it without your real identities.",
            EXIT_INTERNAL,
        )


@app.command(name="discover")
def discover_command(
    path: Annotated[Path, typer.Argument(help="Directory to inspect.")] = Path(),
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
    include_env: Annotated[
        bool, typer.Option("--include-env", help="Also inspect USER and the home directory.")
    ] = False,
    max_commits: Annotated[
        int, typer.Option(min=1, help="Newest commits to read, from all branches.")
    ] = DEFAULT_MAX_COMMITS,
) -> None:
    """List likely author identities. Writes nothing."""
    _prepare_streams()
    found = _run_discovery(path, include_env=include_env, max_commits=max_commits)
    if as_json:
        _write_stdout(render_discovery_json(found))
        return
    _print(render_candidates(found.candidates))
    if not found.candidates:
        _print(Text("\nNo likely identities were found.\n"))
    for note in found.notes:
        _error(note)


def _stdin_is_interactive() -> bool:
    return sys.stdin is not None and sys.stdin.isatty()


def _ask(question: str, default: str = "") -> str:
    """Prompts go to stderr, so stdout stays clean if it is redirected."""
    try:
        answer: str = typer.prompt(question, default=default, show_default=False, err=True)
    except typer.Abort:
        _exit_with_error("cancelled. Nothing was written.")
    return answer.strip()


def _parse_numbers(answer: str, count: int) -> set[int] | None:
    numbers = set()
    for word in answer.replace(",", " ").split():
        if not word.isdigit() or not 1 <= int(word) <= count:
            return None
        numbers.add(int(word))
    return numbers


def _choose(candidates: tuple[Candidate, ...], selected: set[int]) -> set[int]:
    """Let a person review the list. Nothing is written until they accept it."""
    while True:
        _print(render_candidates(candidates, selected))
        answer = _ask("Accept selected identities? [Y/n]", default="y").lower()
        if answer in {"y", "yes"}:
            if selected:
                return selected
            _error("select at least one identity, or press Ctrl+C to cancel.")
        elif answer not in {"n", "no"}:
            _error("please answer y or n.")
            continue
        answer = _ask("Numbers to select or unselect (for example: 4 5). Enter to go back")
        numbers = _parse_numbers(answer, len(candidates))
        if numbers is None:
            _error(f"please use numbers from 1 to {len(candidates)}.")
        else:
            selected ^= numbers


def _build_config(chosen: list[Candidate]) -> Config:
    values: dict[str, list[str]] = {key: [] for key in _CONFIG_KEYS.values()}
    for candidate in chosen:
        values[_CONFIG_KEYS[candidate.kind]].append(candidate.value)
    return Config(identity=IdentityConfig(**{key: tuple(items) for key, items in values.items()}))


def _report_exclude(result: ExcludeResult, config_path: Path) -> None:
    if result.not_a_repository:
        _error(
            "This is not a Git repository, so nothing keeps the config out of what you share. "
            "Keep it out yourself."
        )
    elif result.problem is not None:
        _error(f"warning: could not update .git/info/exclude: {result.problem}")
    elif result.added:
        _error(f"Added {' and '.join(result.added)} to .git/info/exclude")
    if result.config_is_tracked:
        _error(
            f"warning: {config_path} is already tracked by Git, so excluding it has no effect. "
            "Run `git rm --cached` on it, or keep your config outside the repository."
        )


@app.command()
def init(
    path: Annotated[Path, typer.Argument(help="Directory to inspect.")] = Path(),
    config: Annotated[
        Path | None, typer.Option(help="Where to write. Default: PATH/.reviewblind.toml")
    ] = None,
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing config.")] = False,
    yes: Annotated[
        bool, typer.Option("--yes", help="Accept high-confidence candidates without asking.")
    ] = False,
    include_env: Annotated[
        bool, typer.Option("--include-env", help="Also inspect USER and the home directory.")
    ] = False,
    max_commits: Annotated[
        int, typer.Option(min=1, help="Newest commits to read, from all branches.")
    ] = DEFAULT_MAX_COMMITS,
    no_exclude: Annotated[
        bool, typer.Option("--no-exclude", help="Do not add entries to .git/info/exclude.")
    ] = False,
) -> None:
    """Find likely identities, confirm them, and write the config."""
    _prepare_streams()
    config_path = config if config is not None else path / CONFIG_FILE_NAME
    if config_path.is_symlink():
        _exit_with_error(f"refusing to write through a symbolic link: {config_path}")
    if config_path.exists() and not force:
        _exit_with_error(f"{config_path} already exists. Use --force to overwrite it.")
    if not yes and not _stdin_is_interactive():
        _exit_with_error(
            "no terminal to ask you on. Use --yes to accept high-confidence candidates."
        )

    found = _run_discovery(path, include_env=include_env, max_commits=max_commits)
    for note in found.notes:
        _error(note)
    candidates = found.candidates
    if not candidates:
        _exit_with_error(
            "no likely identities were found, so no config was written. "
            "Create one by hand: see docs/CONFIG.md."
        )
    # Only HIGH is preselected. Anything weaker needs a person's choice (FR-INIT-2, FR-INIT-4).
    selected = {
        number
        for number, candidate in enumerate(candidates, start=1)
        if candidate.confidence is Confidence.HIGH
    }
    if yes:
        _print(render_candidates(candidates, selected))
        if not selected:
            _exit_with_error(
                "no high-confidence candidates, so no config was written. "
                "Run without --yes to choose from the others."
            )
    else:
        selected = _choose(candidates, selected)

    chosen = [candidates[number - 1] for number in sorted(selected)]
    try:
        write_config(_build_config(chosen), config_path, force=force)
    except ConfigError as error:
        _exit_with_error(str(error))
    _error(f"Created {config_path}")
    if not no_exclude:
        _report_exclude(add_to_exclude_file(path.resolve(), config_path.resolve()), config_path)
    elif is_tracked(path.resolve(), config_path.resolve()):
        _report_exclude(ExcludeResult(config_is_tracked=True), config_path)
    _error("This file lists your identities. Do not include it in the artifact you share.")


def main() -> None:
    app()
