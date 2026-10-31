"""Orchestrates one scan: inventory, scanners, then the finding pipeline."""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path

from reviewblind import __version__
from reviewblind.config import AllowEntry, Config
from reviewblind.inventory import build_inventory
from reviewblind.matching import IdentityMatcher, resolve_overlaps
from reviewblind.models import (
    Artifact,
    ArtifactKind,
    Detection,
    Finding,
    ScanReport,
    ScanResult,
    Severity,
    SkipReason,
    SuppressedFinding,
    Target,
    Verdict,
)
from reviewblind.profiles import build_finding
from reviewblind.scanners import CONTENT_SCANNERS, PATH_SCANNER, REPOSITORY_SCANNERS
from reviewblind.scanners.base import (
    DEFAULT_MAX_COMMITS,
    FileScanner,
    RepositoryScanner,
    ScanContext,
)
from reviewblind.signals import SignalMatcher
from reviewblind.utils.text import comparison_key

MAX_FINDINGS_PER_ARTIFACT = 1000


def _run_file_scanner(
    scanner: FileScanner, artifact: Artifact, context: ScanContext
) -> list[Detection]:
    try:
        return list(scanner.scan(artifact, context))
    except Exception as error:
        context.report_skip(
            artifact.relpath, SkipReason.SCANNER_ERROR, f"{scanner.name}: {type(error).__name__}"
        )
        return []


def _run_repository_scanner(scanner: RepositoryScanner, context: ScanContext) -> list[Detection]:
    try:
        return list(scanner.scan(context))
    except Exception as error:
        context.report_skip(
            ".", SkipReason.SCANNER_ERROR, f"{scanner.name}: {type(error).__name__}"
        )
        return []


def _overlap_rule_key(rule_id: str) -> str:
    # A manifest rule says more than a plain text match of the same value (D-58).
    return ("0" if rule_id.startswith("RB3") else "1") + rule_id


def _resolve_spans(
    pairs: Iterable[tuple[Finding, tuple[int, int] | None, str | None]],
) -> list[Finding]:
    """Apply overlap resolution within each field, since spans in different ones are unrelated."""
    spanless: list[Finding] = []
    by_field: dict[str | None, list[tuple[Finding, tuple[int, int]]]] = {}
    for finding, span, field in pairs:
        if span is None:
            spanless.append(finding)
        else:
            by_field.setdefault(field, []).append((finding, span))
    for group in by_field.values():
        kept = resolve_overlaps(
            group,
            span=lambda pair: pair[1],
            severity=lambda pair: pair[0].severity,
            rule_id=lambda pair: _overlap_rule_key(pair[0].rule_id),
        )
        spanless.extend(finding for finding, _span in kept)
    return spanless


def _build_findings(
    detections: Iterable[Detection],
    target: Target,
    *,
    git_packaged: bool,
    tracked: bool | None,
) -> list[Finding]:
    pairs = []
    for detection in detections:
        # A rule may decline to raise a finding, and then it must not hide anything nested in it.
        finding = build_finding(detection, target, git_packaged=git_packaged, tracked=tracked)
        if finding is not None:
            pairs.append((finding, detection.span, detection.location.field))
    return _resolve_spans(pairs)


def _sort_key(finding: Finding) -> tuple[int, str, int, int, str, str]:
    location = finding.location
    return (
        finding.severity.rank,
        finding.artifact,
        location.line if location.line is not None else -1,
        location.column if location.column is not None else -1,
        finding.rule_id,
        finding.fingerprint,
    )


class _Allowlist:
    """Exact suppressions. A broad pattern could silently hide a different leak (FR-CFG-4)."""

    def __init__(self, entries: Iterable[AllowEntry]) -> None:
        self._entries = {
            (entry.rule, entry.path, comparison_key(entry.value)): entry for entry in entries
        }
        self._used: set[tuple[str, str, str]] = set()
        self.suppressed: list[SuppressedFinding] = []

    def keep(self, findings: Iterable[Finding]) -> list[Finding]:
        """Return the findings that stand, and remember the rest for the report."""
        kept = []
        for finding in findings:
            key = (finding.rule_id, finding.artifact, comparison_key(finding.matched))
            entry = self._entries.get(key)
            if entry is None:
                kept.append(finding)
            else:
                self._used.add(key)
                self.suppressed.append(SuppressedFinding(finding, entry.reason))
        return kept

    def stale_notes(self) -> list[str]:
        stale = sorted(key for key in self._entries if key not in self._used)
        return [
            f"An [[allow]] entry matched nothing, so it may be out of date: {rule} in {path}"
            for rule, path, _value in stale
        ]


def _scan_artifact(
    artifact: Artifact, context: ScanContext, allowlist: _Allowlist
) -> list[Finding]:
    detections = _run_file_scanner(PATH_SCANNER, artifact, context)
    scanners = [scanner for scanner in CONTENT_SCANNERS if scanner.supports(artifact)]
    if not scanners:
        context.report_skip(
            artifact.relpath,
            SkipReason.UNSUPPORTED_BINARY,
            f"{artifact.kind.value.lower()} files are not inspected by this version",
        )
    for scanner in scanners:
        detections.extend(_run_file_scanner(scanner, artifact, context))
    findings = allowlist.keep(
        _build_findings(
            detections,
            context.target,
            git_packaged=context.inventory.git_packaged,
            tracked=artifact.tracked,
        )
    )
    return _within_limit(findings, artifact.relpath, context)


def _within_limit(findings: list[Finding], path: str, context: ScanContext) -> list[Finding]:
    """Keep the most severe findings. Passing the limit is reported, so nothing hides silently."""
    findings.sort(key=_sort_key)
    if len(findings) > MAX_FINDINGS_PER_ARTIFACT:
        context.report_skip(
            path,
            SkipReason.TOO_MANY_MATCHES,
            f"only the {MAX_FINDINGS_PER_ARTIFACT} most severe of {len(findings)} are listed",
        )
    return findings[:MAX_FINDINGS_PER_ARTIFACT]


def _relative_config_path(root: Path, config_path: Path | None) -> str | None:
    if config_path is None:
        return None
    try:
        return os.path.relpath(os.path.realpath(config_path), os.path.realpath(root)).replace(
            os.sep, "/"
        )
    except ValueError:  # another drive on Windows
        return None


def _deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    """Merge identical findings, such as a directory name seen from each file inside it."""
    unique = {(item.rule_id, item.artifact, item.location, item.matched): item for item in findings}
    return list(unique.values())


def _deduplicate_suppressed(items: Iterable[SuppressedFinding]) -> list[SuppressedFinding]:
    unique = {
        (
            item.finding.rule_id,
            item.finding.artifact,
            item.finding.location,
            item.finding.matched,
        ): item
        for item in items
    }
    return sorted(unique.values(), key=lambda item: _sort_key(item.finding))


def run_scan(
    root: Path,
    config: Config,
    target: Target,
    config_path: Path | None = None,
    max_commits: int = DEFAULT_MAX_COMMITS,
) -> ScanReport:
    """Scan a directory. Failures in one artifact are recorded, never raised."""
    identities = config.identity.identities()
    inventory = build_inventory(root, target, config.scan)
    context = ScanContext(
        root=root,
        config=config,
        target=target,
        matcher=IdentityMatcher(identities),
        signals=SignalMatcher(identities),
        inventory=inventory,
        max_commits=max_commits,
    )
    config_relpath = _relative_config_path(root, config_path)
    allowlist = _Allowlist(config.allow)

    findings: list[Finding] = []
    for artifact in inventory.artifacts:
        if artifact.relpath == config_relpath:
            # Whatever it is called, the active config lists every identity by design.
            artifact = replace(artifact, kind=ArtifactKind.REVIEWBLIND)
        findings.extend(_scan_artifact(artifact, context, allowlist))
    for scanner in REPOSITORY_SCANNERS:
        findings.extend(
            _within_limit(
                allowlist.keep(
                    _build_findings(
                        _run_repository_scanner(scanner, context),
                        target,
                        git_packaged=inventory.git_packaged,
                        tracked=None,
                    )
                ),
                ".git",
                context,
            )
        )

    skipped = sorted(
        {*inventory.skipped, *context.skipped},
        key=lambda item: (item.path, item.reason.value, item.detail or ""),
    )
    skipped_paths = {item.path for item in skipped}
    result = ScanResult(
        findings=sorted(_deduplicate(findings), key=_sort_key),
        suppressed=_deduplicate_suppressed(allowlist.suppressed),
        inspected=sum(1 for item in inventory.artifacts if item.relpath not in skipped_paths),
        excluded=inventory.excluded,
        skipped=list(skipped),
        notes=[*inventory.notes, *allowlist.stale_notes()],
        incomplete=bool(skipped),
    )
    return ScanReport(
        result=result,
        target=target,
        root=root,
        config_path=config_path,
        identities=identities,
        version=__version__,
    )


def compute_verdict(result: ScanResult) -> Verdict:
    """What the findings mean for a person. Independent of `--fail-on`."""
    severities = {finding.severity for finding in result.findings}
    if Severity.BLOCKER in severities:
        return Verdict.NOT_READY
    if severities & {Severity.WARNING, Severity.REVIEW}:
        return Verdict.REVIEW_REQUIRED
    return Verdict.NO_KNOWN_LEAKS_INCOMPLETE if result.incomplete else Verdict.NO_KNOWN_LEAKS


def compute_exit_code(result: ScanResult, fail_on: Severity, *, strict: bool) -> int:
    """Codes 0 and 1 describe a completed scan, so `--strict` puts incompleteness first."""
    if strict and result.incomplete:
        return 3
    return 1 if any(finding.severity >= fail_on for finding in result.findings) else 0
