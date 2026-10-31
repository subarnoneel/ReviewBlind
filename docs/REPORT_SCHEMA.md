# Report Formats

JSON is the stable, machine-readable contract, and `export` depends on it. Terminal and
Markdown are for people, and their exact layout may change between releases.

> **Reports contain your identities in plain text.** Keep them out of the artifact you share.

## JSON

`schema_version` increases on any breaking change. `export` refuses a version it does not
support.

```json
{
  "schema_version": 1,
  "tool": { "name": "reviewblind", "version": "0.1.0" },
  "target": "mirror",
  "root": "~/research/my-paper",
  "config_path": ".reviewblind.toml",
  "verdict": "NOT_READY",
  "summary": {
    "blocker": 1,
    "warning": 1,
    "review": 1,
    "info": 0,
    "suppressed": 1
  },
  "scan": {
    "complete": false,
    "inspected": 137,
    "excluded": 12,
    "skipped": [
      {
        "path": "results/model-output.bin",
        "reason": "UNSUPPORTED_BINARY",
        "detail": null
      }
    ],
    "notes": ["Results reflect the working tree; 1 tracked file differs from the index."]
  },
  "identities": [
    {
      "value": "Alice Example",
      "kind": "NAME",
      "source": "config",
      "confidence": "HIGH",
      "confirmed": true
    }
  ],
  "findings": [
    {
      "rule_id": "RB101",
      "title": "Confirmed name in reviewer-visible text",
      "severity": "BLOCKER",
      "confidence": "HIGH",
      "artifact": "README.md",
      "location": {
        "path": "README.md",
        "line": 42,
        "column": 12,
        "field": null,
        "git_commit": null
      },
      "matched": "Alice Example",
      "evidence": "Maintained by Alice Example at the lab",
      "message": "Found confirmed author name",
      "reason": "Direct author identity is visible in reviewer-facing text.",
      "remediation": "Remove this name from the review artifact or configure your anonymous mirror to replace it.",
      "identity": "Alice Example",
      "targets": ["ARCHIVE", "MIRROR", "REPOSITORY"],
      "fingerprint": "rb1:64-hex-characters"
    }
  ],
  "suppressed": [
    {
      "finding": { "rule_id": "RB101", "...": "same shape as a finding" },
      "reason": "Legitimate bibliographic reference; neutral self-citation"
    }
  ]
}
```

### Fields

| Field | Type | Notes |
|---|---|---|
| `schema_version` | integer | `1` |
| `tool.name` | string | Always `reviewblind`. RB805 recognizes a saved report by `schema_version` followed by this |
| `target` | enum | `mirror`, `archive`, `repository` |
| `root` | string | Scan root; shown as `~/...` when under the home directory |
| `config_path` | string | Config used. Relative to the root when inside it |
| `verdict` | enum | See below |
| `summary` | object | Counts by severity, excluding suppressed findings |
| `scan.complete` | boolean | `false` if anything required was not inspected |
| `scan.inspected` | integer | Files inspected |
| `scan.excluded` | integer | Files removed by `scan.exclude` |
| `scan.skipped` | array | See skip reasons below |
| `scan.notes` | array of strings | Caveats that do not affect completeness |
| `identities` | array | The confirmed identities used for this scan |
| `findings` | array | Sorted by severity (highest first), artifact, line, column, rule ID, fingerprint |
| `suppressed` | array | Findings hidden by `[[allow]]`, with the reason given |

`location.line` and `location.column` are 1-based and may be `null`. `location.field` holds a
structured location, such as `output[7].traceback[3]` or `PDF metadata: Author`.
`location.git_commit` is the first commit in which the Git finding was seen.

`matched` is the exact matched value, and `[[allow]]` compares against it. `evidence` is a
display excerpt of at most 160 characters, with control characters removed.

Arrays of enums, such as `targets`, are sorted. Keys are written in the order shown, using
UTF-8, with non-ASCII text left unescaped. With no timestamps, two runs on the same input are
byte-identical.

### Verdict values

| Value | Verdict line |
|---|---|
| `NOT_READY` | `NOT READY FOR ANONYMOUS REVIEW` |
| `REVIEW_REQUIRED` | `MANUAL REVIEW REQUIRED` |
| `NO_KNOWN_LEAKS` | `NO KNOWN LEAKS DETECTED` |
| `NO_KNOWN_LEAKS_INCOMPLETE` | `NO KNOWN LEAKS DETECTED - SCAN INCOMPLETE` |

### Skip reasons

| Value | Meaning |
|---|---|
| `TOO_LARGE` | Over a configured size cap |
| `UNREADABLE` | Permission or I/O error |
| `CORRUPT` | The parser rejected the file |
| `ENCRYPTED` | A password-protected PDF |
| `UNSUPPORTED_BINARY` | A binary format with no scanner |
| `ARCHIVE_NOT_INSPECTED` | An archive, which 0.1.0 does not unpack |
| `SYMLINK_NOT_FOLLOWED` | A symlink, by default or because it leaves the root |
| `GIT_UNAVAILABLE` | Git is not installed, or refused the repository. `path` is `.git` |
| `GIT_TRUNCATED` | History exceeded `--max-commits`. `path` is `.git` |
| `SUBMODULE_NOT_INSPECTED` | A submodule or nested Git repository. Only its path is known |
| `TOO_MANY_MATCHES` | More matches in one file than are examined or listed |
| `SCANNER_ERROR` | A scanner failed on this artifact |

Any entry in `skipped` makes `scan.complete` false.

## Markdown

The first line is a marker that RB805 recognizes:

```markdown
<!-- reviewblind-report schema=1 -->
```

Sections, in order: title and metadata table; verdict; summary table; findings grouped by
severity; skipped artifacts; notes. Suppressed findings appear only as a count.

Repository-controlled text (evidence, paths, field names) is always written as an inline code
span with a fence longer than any backtick run inside it. Line breaks are removed. Raw
HTML, links and images from a repository can therefore never render.

See [examples/sample-report.md](../examples/sample-report.md).

## Terminal

The layout is shown in [CLI.md](CLI.md#reviewblind-scan-path). Rich markup is disabled for
repository-controlled text. RB805 recognizes a saved terminal report by its first two lines, including one
saved as UTF-16 by Windows PowerShell's `>` operator.
