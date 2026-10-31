"""Commands, flags, exit codes and verdicts (FR-SCAN-1, FR-SCAN-2, FR-SCAN-5 to FR-SCAN-7)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from _helpers import PERSONA, write_tree
from reviewblind import __version__, cli
from reviewblind.config import Config, write_config

runner = CliRunner()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    write_config(PERSONA, root / ".reviewblind.toml")
    return root


def scan(*args: str | Path):  # type: ignore[no-untyped-def]
    return runner.invoke(cli.app, ["scan", *map(str, args)])


# Exit codes


def test_exit_0_when_nothing_reaches_the_threshold(repo: Path) -> None:
    write_tree(repo, {"a.py": "import os\n"})
    result = scan(repo)
    assert result.exit_code == 0
    assert "RESULT: NO KNOWN LEAKS DETECTED\n" in result.stdout
    assert "Scan complete: YES" in result.stdout


def test_exit_1_when_a_blocker_is_found(repo: Path) -> None:
    write_tree(repo, {"a.txt": "by Alice Example\n"})
    result = scan(repo)
    assert result.exit_code == 1
    assert "RESULT: NOT READY FOR ANONYMOUS REVIEW" in result.stdout
    assert "BLOCKER  RB101  HIGH" in result.stdout
    assert "a.txt:1:4" in result.stdout


def test_a_warning_does_not_fail_by_default_but_can(repo: Path) -> None:
    write_tree(repo, {"a.txt": "at Example University\n"})
    assert scan(repo).exit_code == 0
    assert "RESULT: MANUAL REVIEW REQUIRED" in scan(repo).stdout
    assert scan(repo, "--fail-on", "warning").exit_code == 1


@pytest.mark.parametrize(
    ("fail_on", "expected"), [("blocker", 0), ("warning", 0), ("review", 1), ("info", 1)]
)
def test_fail_on_shifts_the_threshold(repo: Path, fail_on: str, expected: int) -> None:
    write_tree(repo, {"a.txt": "cd /home/bob/x\n"})  # REVIEW
    assert scan(repo, "--fail-on", fail_on).exit_code == expected


def test_verdict_does_not_depend_on_fail_on(repo: Path) -> None:
    write_tree(repo, {"a.txt": "at Example University\n"})
    assert "MANUAL REVIEW REQUIRED" in scan(repo, "--fail-on", "warning").stdout


@pytest.mark.parametrize(
    "args",
    [
        ("--target", "conference"),
        ("--fail-on", "panic"),
        ("--no-such-flag",),
    ],
)
def test_exit_2_for_bad_usage(repo: Path, args: tuple[str, ...]) -> None:
    assert scan(repo, *args).exit_code == 2


def test_exit_2_when_the_path_is_not_a_directory(tmp_path: Path) -> None:
    result = scan(tmp_path / "missing")
    assert result.exit_code == 2
    assert "not a directory" in result.stderr


def test_exit_2_when_no_config_exists(tmp_path: Path) -> None:
    # D-16: running without identities would produce a misleading pass.
    result = scan(tmp_path)
    assert result.exit_code == 2
    assert "reviewblind init" in result.stderr
    assert "RESULT" not in result.stdout


def test_exit_2_when_the_config_has_no_identities(tmp_path: Path) -> None:
    write_config(Config(), tmp_path / ".reviewblind.toml")
    result = scan(tmp_path)
    assert result.exit_code == 2
    assert "no identities" in result.stderr
    assert "RESULT" not in result.stdout


def test_exit_2_for_a_misspelled_config_key(tmp_path: Path) -> None:
    write_tree(tmp_path, {".reviewblind.toml": 'version = 1\n[identity]\nemials = ["a@b.c"]\n'})
    result = scan(tmp_path)
    assert result.exit_code == 2
    assert "emials" in result.stderr


def test_exit_2_for_an_invalid_exclude_pattern(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {
            ".reviewblind.toml": 'version = 1\n[identity]\nnames = ["Alice"]\n'
            '[scan]\nexclude = ["\\\\"]\n'
        },
    )
    result = scan(tmp_path)
    assert result.exit_code == 2
    assert "invalid pattern" in result.stderr


def test_exit_3_only_with_strict(repo: Path) -> None:
    write_tree(repo, {"weights.bin": b"\x00\x01"})
    relaxed = scan(repo)
    assert relaxed.exit_code == 0
    assert "Scan complete: NO" in relaxed.stdout
    assert "RESULT: NO KNOWN LEAKS DETECTED - SCAN INCOMPLETE" in relaxed.stdout
    assert "--strict" in relaxed.stdout
    assert scan(repo, "--strict").exit_code == 3


def test_strict_incomplete_outranks_findings(repo: Path) -> None:
    # D-15
    write_tree(repo, {"weights.bin": b"\x00\x01", "a.txt": "Alice Example\n"})
    assert scan(repo).exit_code == 1
    assert scan(repo, "--strict").exit_code == 3


def test_strict_does_not_change_a_complete_scan(repo: Path) -> None:
    write_tree(repo, {"a.txt": "Alice Example\n"})
    assert scan(repo, "--strict").exit_code == 1


def test_exit_4_for_an_internal_failure_with_no_passing_verdict(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # NFR-REL-2
    def explode(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("something broke")

    monkeypatch.setattr(cli, "run_scan", explode)
    result = scan(repo)
    assert result.exit_code == 4
    assert "internal error" in result.stderr
    assert "RESULT" not in result.stdout


# Options


def test_config_can_live_outside_the_scanned_tree(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    write_tree(root, {"a.txt": "Alice Example\n"})
    outside = tmp_path / "private.toml"
    write_config(PERSONA, outside)
    assert scan(root, "--config", outside).exit_code == 1


def test_a_missing_explicit_config_does_not_fall_back(repo: Path, tmp_path: Path) -> None:
    result = scan(repo, "--config", tmp_path / "missing.toml")
    assert result.exit_code == 2


def test_the_config_in_the_root_is_not_scanned_when_relative(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(repo)
    result = runner.invoke(cli.app, ["scan"])
    assert result.exit_code == 0
    assert "RB10" not in result.stdout


@pytest.mark.parametrize(
    ("target", "label"),
    [
        ("mirror", "anonymous mirror"),
        ("archive", "supplementary archive"),
        ("repository", "public anonymous repository"),
    ],
)
def test_target_is_shown(repo: Path, target: str, label: str) -> None:
    assert f"Target: {label}" in scan(repo, "--target", target).stdout


def test_mirror_is_the_default_target(repo: Path) -> None:
    assert "Target: anonymous mirror" in scan(repo).stdout


# Output


def test_report_contains_what_the_specification_requires(repo: Path) -> None:
    write_tree(repo, {"a.txt": "by Alice Example\n"})
    output = scan(repo).stdout
    for expected in (
        f"ReviewBlind {__version__}",
        "Identities: 7 confirmed",
        "Files inspected: 2",
        "Files skipped: 0",
        "Found confirmed author name:",
        "by Alice Example",
        "Reason:",
        "Direct author identity is visible",
        "Suggested action:",
        "BLOCKERS    1",
        "WARNINGS    0",
        "REVIEW      0",
        "INFO        0",
    ):
        assert expected in output


@pytest.mark.parametrize("word", ["clean", "compliant"])
def test_results_never_claim_too_much(repo: Path, word: str) -> None:
    # FR-SCAN-7
    write_tree(repo, {"a.py": "import os\n"})
    assert word not in scan(repo).stdout.lower()


def test_results_never_say_the_artifact_is_anonymous(repo: Path) -> None:
    write_tree(repo, {"a.py": "import os\n"})
    output = scan(repo).stdout.lower().replace("target: anonymous mirror", "")
    assert "anonymous" not in output


def test_markup_in_repository_text_is_not_interpreted(repo: Path) -> None:
    # Threat T-10
    write_tree(repo, {"a.txt": "[bold red]Alice Example[/bold red] \x1b[31mx\n"})
    output = scan(repo).stdout
    assert "[bold red]Alice Example[/bold red]" in output
    assert "\x1b" not in output


def test_a_hostile_file_name_cannot_inject_lines(repo: Path) -> None:
    if os.name == "nt":
        pytest.skip("Windows does not allow control characters in file names")
    write_tree(repo, {"a\nRESULT: fake\x1b[0m.txt": "Alice Example\n"})
    output = scan(repo).stdout
    assert "\nRESULT: fake" not in output
    assert "\x1b" not in output


def test_notes_are_shown(repo: Path) -> None:
    assert "Not a Git repository" in scan(repo).stdout


def test_home_directory_is_abbreviated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path / "research" / "paper"
    root.mkdir(parents=True)
    write_config(PERSONA, root / ".reviewblind.toml")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    assert "Root: ~/research/paper" in scan(root).stdout


# rules and --version


def test_version() -> None:
    result = runner.invoke(cli.app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_rules_lists_all_33() -> None:
    result = runner.invoke(cli.app, ["rules"])
    assert result.exit_code == 0
    assert sum(line.startswith("RB") for line in result.stdout.splitlines()) == 33


def test_one_rule_is_explained() -> None:
    result = runner.invoke(cli.app, ["rules", "RB502"])
    assert result.exit_code == 0
    for expected in (
        "RB502 - Identity in notebook output/traceback",
        "mirror      BLOCKER",
        "Indirect evidence such as a home path: WARNING",
        "Detects:",
        "Why:",
        "Fix:",
    ):
        assert expected in result.stdout


@pytest.mark.parametrize(
    ("rule", "expected"),
    [
        ("RB402", "BLOCKER on archive when .git will be packaged"),
        ("RB402", "repository only"),
        ("RB805", "BLOCKER when the file is tracked by Git"),
    ],
)
def test_rule_conditions_are_explained(rule: str, expected: str) -> None:
    assert expected in runner.invoke(cli.app, ["rules", rule]).stdout


def test_rule_ids_are_case_insensitive() -> None:
    assert runner.invoke(cli.app, ["rules", "rb101"]).exit_code == 0


def test_an_unknown_rule_is_exit_2() -> None:
    # FR-RULE-2
    result = runner.invoke(cli.app, ["rules", "RB999"])
    assert result.exit_code == 2
    assert "unknown rule" in result.stderr


def test_no_arguments_shows_help() -> None:
    result = runner.invoke(cli.app, [])
    assert "scan" in result.output
    assert "rules" in result.output


# Real processes


def run_module(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, "-m", "reviewblind", *args],
        capture_output=True,
        env={**os.environ, **(env or {})},
        stdin=subprocess.DEVNULL,
        timeout=120,
        check=False,
    )


def test_running_as_a_module_passes_through_the_exit_code(repo: Path) -> None:
    write_tree(repo, {"a.txt": "Alice Example\n"})
    completed = run_module("scan", str(repo))
    assert completed.returncode == 1
    assert b"RB101" in completed.stdout


def test_a_name_the_console_cannot_encode_does_not_crash_the_report(repo: Path) -> None:
    write_config(
        Config(identity=PERSONA.identity.__class__(names=("\u5f20\u4f1f",))),
        repo / ".reviewblind.toml",
        force=True,
    )
    write_tree(repo, {"a.txt": "by \u5f20\u4f1f\n"})
    completed = run_module("scan", str(repo), env={"PYTHONIOENCODING": "cp1252"})
    assert completed.returncode == 1
    assert b"RESULT:" in completed.stdout


def test_no_color_is_honoured_and_redirected_output_is_plain(repo: Path) -> None:
    # NFR-USE-2
    write_tree(repo, {"a.txt": "Alice Example\n"})
    assert b"\x1b[" not in run_module("scan", str(repo)).stdout
    assert b"\x1b[" not in run_module("scan", str(repo), env={"NO_COLOR": "1"}).stdout
