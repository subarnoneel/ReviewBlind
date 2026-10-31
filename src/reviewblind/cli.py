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
from reviewblind.config import ConfigError, find_config, load_config
from reviewblind.engine import compute_exit_code, run_scan
from reviewblind.models import ScanReport, Severity, Target
from reviewblind.reporters.json import render_json
from reviewblind.reporters.markdown import render_markdown
from reviewblind.reporters.terminal import render_report, render_rule, render_rule_list
from reviewblind.rules.registry import all_rules, get_rule, is_known_rule
from reviewblind.scanners.base import DEFAULT_MAX_COMMITS
from reviewblind.utils.files import atomic_write

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


def main() -> None:
    app()
