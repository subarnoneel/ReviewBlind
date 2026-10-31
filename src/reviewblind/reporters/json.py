"""The JSON report, the stable contract that `export` reads. See docs/REPORT_SCHEMA.md."""

from __future__ import annotations

import json
from typing import Any

from reviewblind.engine import compute_verdict
from reviewblind.models import Finding, ScanReport, Severity
from reviewblind.reporters import display_config_path, display_root
from reviewblind.rules.registry import get_rule
from reviewblind.utils.text import sanitize_text

SCHEMA_VERSION = 1


def _text(value: str | None) -> str | None:
    # Paths can hold undecodable bytes and control characters. JSON must stay writable as UTF-8.
    return None if value is None else sanitize_text(value)


def _finding(finding: Finding) -> dict[str, Any]:
    location = finding.location
    return {
        "rule_id": finding.rule_id,
        "title": get_rule(finding.rule_id).title,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "artifact": _text(finding.artifact),
        "location": {
            "path": _text(location.path),
            "line": location.line,
            "column": location.column,
            "field": _text(location.field),
            "git_commit": _text(location.git_commit),
        },
        "matched": finding.matched,
        "evidence": finding.evidence,
        "message": finding.message,
        "reason": finding.reason,
        "remediation": finding.remediation,
        "identity": finding.identity,
        "targets": sorted(target.value for target in finding.targets),
        "fingerprint": finding.fingerprint,
    }


def render_json(report: ScanReport) -> str:
    """Render the report. Key order is fixed and there is no timestamp, so runs are identical."""
    result = report.result
    summary: dict[str, int] = {
        severity.value.lower(): sum(1 for item in result.findings if item.severity is severity)
        for severity in Severity
    }
    summary["suppressed"] = len(result.suppressed)
    document = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "reviewblind", "version": report.version},
        "target": report.target.value.lower(),
        "root": _text(display_root(report.root)),
        "config_path": _text(display_config_path(report)),
        "verdict": compute_verdict(result).value,
        "summary": summary,
        "scan": {
            "complete": not result.incomplete,
            "inspected": result.inspected,
            "excluded": result.excluded,
            "skipped": [
                {
                    "path": _text(item.path),
                    "reason": item.reason.value,
                    "detail": _text(item.detail),
                }
                for item in result.skipped
            ],
            "notes": [_text(note) for note in result.notes],
        },
        "identities": [
            {
                "value": identity.value,
                "kind": identity.kind.value,
                "source": identity.source,
                "confidence": identity.confidence.value,
                "confirmed": identity.confirmed,
            }
            for identity in report.identities
        ],
        "findings": [_finding(finding) for finding in result.findings],
        "suppressed": [
            {"finding": _finding(item.finding), "reason": item.reason} for item in result.suppressed
        ],
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
