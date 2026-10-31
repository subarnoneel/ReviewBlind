"""The terminal report, and `reviewblind rules`. Layout is for people and may change."""

from __future__ import annotations

from pathlib import Path

from rich.text import Text

from reviewblind.engine import compute_verdict
from reviewblind.models import Finding, Rule, ScanReport, Severity, Target
from reviewblind.utils.text import sanitize_text

_TARGET_LABELS = {
    Target.MIRROR: "anonymous mirror",
    Target.ARCHIVE: "supplementary archive",
    Target.REPOSITORY: "public anonymous repository",
}
_STYLES = {
    Severity.BLOCKER: "bold red",
    Severity.WARNING: "yellow",
    Severity.REVIEW: "cyan",
    Severity.INFO: "dim",
}
_SUMMARY_LABELS = {
    Severity.BLOCKER: "BLOCKERS",
    Severity.WARNING: "WARNINGS",
    Severity.REVIEW: "REVIEW",
    Severity.INFO: "INFO",
}
_SEPARATOR = "-" * 36


def display_root(root: Path) -> str:
    """Show a home directory as `~`, so a shared terminal capture reveals less."""
    resolved = root.resolve()
    try:
        return "~/" + resolved.relative_to(Path.home().resolve()).as_posix()
    except (ValueError, RuntimeError):
        return resolved.as_posix()


def _location_lines(finding: Finding) -> list[str]:
    location = finding.location
    if location.line is None:
        heading = sanitize_text(location.path)
    elif location.column is None:
        heading = f"{sanitize_text(location.path)}:{location.line}"
    else:
        heading = f"{sanitize_text(location.path)}:{location.line}:{location.column}"
    lines = [heading]
    if location.git_commit:
        lines.append(f"commit {sanitize_text(location.git_commit)}")
    if location.field:
        lines.append(sanitize_text(location.field))
    return lines


def _append_finding(output: Text, finding: Finding) -> None:
    output.append(f"{finding.severity.value}  {finding.rule_id}", style=_STYLES[finding.severity])
    output.append(f"  {finding.confidence.value}\n")
    output.append("\n".join(_location_lines(finding)) + "\n\n")
    output.append(f"{finding.message}:\n")
    output.append(f"{finding.evidence}\n\n")
    output.append(f"Reason:\n{finding.reason}\n\n")
    output.append(f"Suggested action:\n{finding.remediation}\n\n\n")


def render_report(report: ScanReport) -> Text:
    """Build the report. Repository text is added as plain text, so it is never read as markup."""
    result = report.result
    output = Text()
    output.append(f"ReviewBlind {report.version}\n", style="bold")
    output.append(f"Target: {_TARGET_LABELS[report.target]}\n")
    output.append(f"Root: {sanitize_text(display_root(report.root))}\n\n")
    output.append(f"Identities: {len(report.identities)} confirmed\n")
    output.append(f"Files inspected: {result.inspected}\n")
    output.append(f"Files excluded: {result.excluded}\n")
    output.append(f"Files skipped: {len(result.skipped)}\n")
    output.append(f"Scan complete: {'NO' if result.incomplete else 'YES'}\n\n")

    for finding in result.findings:
        _append_finding(output, finding)

    if result.skipped:
        output.append("Skipped:\n")
        for item in result.skipped:
            output.append(f"{sanitize_text(item.path)}\n")
            reason = item.reason.value.replace("_", " ").lower()
            detail = f": {sanitize_text(item.detail)}" if item.detail else ""
            output.append(f"  {reason}{detail}\n")
        output.append("\nUse --strict to treat incomplete scanning as CI failure.\n\n")

    if result.notes:
        output.append("Notes:\n")
        for note in result.notes:
            output.append(f"{sanitize_text(note)}\n")
        output.append("\n")

    output.append(f"{_SEPARATOR}\n\n")
    for severity in Severity:
        count = sum(1 for finding in result.findings if finding.severity is severity)
        output.append(f"{_SUMMARY_LABELS[severity]:<11} {count}\n")
    output.append(f"\nRESULT: {compute_verdict(result).line}\n", style="bold")
    return output


def render_rule_list(rules: tuple[Rule, ...]) -> Text:
    output = Text()
    output.append(f"{'ID':<7}{'Mirror':<9}{'Archive':<9}{'Repo':<9}Title\n", style="bold")
    for rule in rules:
        severities = "".join(f"{rule.severity_for(target).value:<9}" for target in Target)
        output.append(f"{rule.id:<7}{severities}{rule.title}\n")
    return output


def render_rule(rule: Rule) -> Text:
    output = Text()
    output.append(f"{rule.id} - {rule.title}\n\n", style="bold")
    output.append("Severity:\n")
    for target in Target:
        output.append(f"  {target.value.lower():<12}{rule.severity_for(target).value}\n")
    if rule.blocker_if_git_packaged:
        output.append("  BLOCKER on archive when .git will be packaged\n")
    if rule.blocker_if_tracked:
        output.append("  BLOCKER when the file is tracked by Git\n")
    if rule.container:
        output.append("  Indirect evidence such as a home path: WARNING\n")
    if rule.unconfirmed is not None:
        policy = rule.unconfirmed
        scope = "" if len(policy.targets) == len(Target) else " (repository only)"
        output.append(
            f"  Not tied to a confirmed identity: {policy.severity.value}, "
            f"{policy.confidence.value} confidence{scope}\n"
        )
    output.append(f"\nDetects:\n{rule.description}\n\n")
    output.append(f"Why:\n{rule.reason}\n\n")
    output.append(f"Fix:\n{rule.remediation}\n")
    return output
