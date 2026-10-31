"""The Markdown report. Repository text is kept in code spans, so it cannot render (threat T-11)."""

from __future__ import annotations

import re

from reviewblind.engine import compute_verdict
from reviewblind.models import Finding, ScanReport, Severity
from reviewblind.reporters import display_config_path, display_root
from reviewblind.rules.registry import get_rule
from reviewblind.utils.text import sanitize_text

MARKER = "<!-- reviewblind-report schema=1 -->"

_SECTION_TITLES = {
    Severity.BLOCKER: "Blockers",
    Severity.WARNING: "Warnings",
    Severity.REVIEW: "Review",
    Severity.INFO: "Info",
}
_BACKTICK_RUN = re.compile(r"`+")
_MARKDOWN_SPECIALS = re.compile(r"([\\`*_{}\[\]()#|<>~&])")


def _code(value: str) -> str:
    """A code span that cannot be closed from inside. Its fence outgrows any run of backticks."""
    text = sanitize_text(value)
    longest = max((len(run) for run in _BACKTICK_RUN.findall(text)), default=0)
    fence = "`" * (longest + 1)
    padding = " " if text.startswith("`") or text.endswith("`") or not text.strip() else ""
    return f"{fence}{padding}{text}{padding}{fence}"


def _table_code(value: str) -> str:
    # In a table, a pipe ends the cell even inside a code span unless it is escaped.
    return _code(value).replace("|", "\\|")


def _escape(value: str) -> str:
    """Plain prose with every Markdown character escaped."""
    return _MARKDOWN_SPECIALS.sub(r"\\\1", sanitize_text(value))


def _location(finding: Finding) -> str:
    location = finding.location
    position = location.path
    if location.line is not None:
        position += f":{location.line}"
        if location.column is not None:
            position += f":{location.column}"
    parts = [_code(position)]
    if location.field:
        parts.append(_code(location.field))
    if location.git_commit:
        parts.append(f"commit {_code(location.git_commit)}")
    return ", ".join(parts)


def _finding_lines(finding: Finding) -> list[str]:
    return [
        f"### {finding.rule_id} - {_escape(get_rule(finding.rule_id).title)}",
        "",
        f"- **Location:** {_location(finding)}",
        f"- **Confidence:** {finding.confidence.value}",
        f"- **Evidence:** {_code(finding.evidence)}",
        f"- **Reason:** {_escape(finding.reason)}",
        f"- **Suggested action:** {_escape(finding.remediation)}",
        f"- **Fingerprint:** {_code(finding.fingerprint)}",
        "",
    ]


def render_markdown(report: ScanReport) -> str:
    result = report.result
    config = display_config_path(report)
    lines = [
        MARKER,
        "# ReviewBlind report",
        "",
        "| | |",
        "|---|---|",
        f"| **Version** | {_table_code(report.version)} |",
        f"| **Target** | {report.target.value.lower()} |",
        f"| **Root** | {_table_code(display_root(report.root))} |",
    ]
    if config is not None:
        lines.append(f"| **Config** | {_table_code(config)} |")
    lines += [
        f"| **Identities** | {len(report.identities)} confirmed |",
        f"| **Files inspected** | {result.inspected} |",
        f"| **Files excluded** | {result.excluded} |",
        f"| **Files skipped** | {len(result.skipped)} |",
        f"| **Scan complete** | {'NO' if result.incomplete else 'YES'} |",
        "",
        f"## Result: {compute_verdict(result).line}",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for severity in Severity:
        count = sum(1 for finding in result.findings if finding.severity is severity)
        lines.append(f"| {_SECTION_TITLES[severity]} | {count} |")
    lines += [f"| Suppressed | {len(result.suppressed)} |", ""]

    for severity in Severity:
        group = [finding for finding in result.findings if finding.severity is severity]
        if group:
            lines += [f"## {_SECTION_TITLES[severity]}", ""]
            for finding in group:
                lines += _finding_lines(finding)

    if result.skipped:
        lines += ["## Skipped", "", "| Path | Reason |", "|---|---|"]
        for item in result.skipped:
            reason = item.reason.value.replace("_", " ").lower()
            detail = f": {_escape(item.detail)}".replace("|", "\\|") if item.detail else ""
            lines.append(f"| {_table_code(item.path)} | {reason}{detail} |")
        lines += ["", "Use `--strict` to treat incomplete scanning as CI failure.", ""]

    if result.notes:
        lines += ["## Notes", ""]
        lines += [f"- {_escape(note)}" for note in result.notes]
        lines.append("")
    return "\n".join(lines)
