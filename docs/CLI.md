# CLI Reference

> Status: `scan` and `rules` work, except for `--max-commits`, which needs the Git scanner.
> The other commands and flags here are the planned 0.1.0 interface.

Examples use the fictional researcher **Dr. Alice Example** of Example University.

## Conventions

- Reports go to stdout, or to `--output`. Prompts and diagnostics go to stderr, so
  stdout can always be redirected.
- `NO_COLOR` is honoured. Color is disabled when stdout is not a terminal.
- `PATH` defaults to the current directory.
- `reviewblind --version` and `--help` work everywhere.

## `reviewblind init [PATH]`

The normal starting point. Runs discovery, asks you to confirm candidates, and writes
`.reviewblind.toml`.

| Flag | Default | Meaning |
|---|---|---|
| `--config FILE` | `PATH/.reviewblind.toml` | Where to write the config. Keeping it outside the repository is the safest choice |
| `--force` | off | Overwrite an existing config |
| `--yes` | off | Non-interactive: accept HIGH-confidence candidates only |
| `--include-env` | off | Also inspect `USER` and the home directory |
| `--max-commits N` | `5000` | Git history limit for discovery |
| `--no-exclude` | off | Do not add entries to `.git/info/exclude` |

```text
ReviewBlind identity discovery

HIGH CONFIDENCE

[1] ✓ Alice Example
    Sources:
      Git author (5 commits)
      pyproject.toml author
      CITATION.cff

[2] ✓ alice@example.edu
    Sources:
      Git commit email

[3] ✓ aliceexample
    Sources:
      GitHub remote
      pyproject.toml repository URL

MEDIUM CONFIDENCE

[4] ? Example University
    Source:
      CITATION.cff affiliation

LOW CONFIDENCE

[5] ? EU
    Source:
      derived alias of "Example University"

Accept selected identities? [Y/n]
```

`✓` is selected and `?` is not. Answering `n` opens a prompt that takes numbers to
toggle, then shows the list again. Nothing is written until you accept.

```text
Created .reviewblind.toml
Added .reviewblind.toml and reviewblind-report.* to .git/info/exclude

This file lists your identities. Do not include it in the artifact you share.
```

**Writes:** the config file and, in a Git repository, `.git/info/exclude`. Nothing else.

## `reviewblind discover [PATH]`

Non-destructive discovery. Writes nothing.

| Flag | Default | Meaning |
|---|---|---|
| `--json` | off | Machine-readable output |
| `--include-env` | off | Also inspect `USER` and the home directory |
| `--max-commits N` | `5000` | Git history limit |

Sources: Git author names, committer names, email addresses and remotes;
`pyproject.toml`; `package.json`; `setup.py` and `setup.cfg`; `CITATION.cff`; selected
LaTeX author macros; repository URLs; and, with `--include-env`, local user information.

| Confidence | Basis |
|---|---|
| HIGH | Direct structured author field, or repeated Git identity (2+ commits) |
| MEDIUM | Repository owner, affiliation, structured URL, or single-commit Git identity |
| LOW | Derived alias, email local part alone, or environment username |

Agreement between two independent source classes raises confidence by one level.
LOW candidates are never activated automatically.

`--json` output:

```json
{
  "schema_version": 1,
  "candidates": [
    {
      "value": "Alice Example",
      "kind": "NAME",
      "confidence": "HIGH",
      "sources": ["Git author (5 commits)", "pyproject.toml author"]
    }
  ],
  "notes": []
}
```

## `reviewblind scan [PATH]`

| Flag | Default | Meaning |
|---|---|---|
| `--target` | `mirror` | `mirror`, `archive` or `repository` |
| `--config FILE` | `PATH/.reviewblind.toml` | Config to use |
| `--format` | `terminal` | `terminal`, `json` or `markdown` |
| `-o`, `--output FILE` | stdout | Write the report to a file |
| `--fail-on` | `blocker` | Lowest severity that causes exit code 1: `blocker`, `warning`, `review` or `info` |
| `--strict` | off | An incomplete scan causes exit code 3 |
| `--max-commits N` | `5000` | Git history limit |

```bash
reviewblind scan . --target mirror
reviewblind scan . --target archive --format json --output ../reviewblind-report.json
reviewblind scan . --target repository --fail-on warning
reviewblind scan . --format markdown -o ../REPORT.md
```

Example terminal report:

```text
ReviewBlind 0.1.0
Target: anonymous mirror
Root: ~/research/my-paper

Identities: 5 confirmed
Files inspected: 137
Files excluded: 12
Files skipped: 2
Scan complete: NO

BLOCKER  RB101  HIGH
README.md:42:12

Found confirmed author name:
Maintained by Alice Example at the lab

Reason:
Direct author identity is visible in reviewer-facing text.

Suggested action:
Remove this name from the review artifact or configure your
anonymous mirror to replace it.


WARNING  RB502  HIGH
notebooks/error_analysis.ipynb
output[7].traceback[3]

Found a personal home path:
/home/aliceexample/miniconda3/envs/nlp/...

Reason:
Notebook execution output exposes a personal workstation username.


REVIEW  RB703  HIGH
figures/team-photo.png

Visual content was not inspected.

Reason:
ReviewBlind checks image metadata but does not perform OCR or
visual identity recognition.


Skipped:
results/model-output.bin
Reason:
unsupported binary format

Use --strict to treat incomplete scanning as CI failure.

------------------------------------

BLOCKERS    1
WARNINGS    1
REVIEW      1
INFO        0

RESULT: NOT READY FOR ANONYMOUS REVIEW
```

## `reviewblind export REPORT`

Reads a JSON scan report and writes a term list.

| Flag | Default | Meaning |
|---|---|---|
| `--format` | `anonymous-github` | `anonymous-github`, `hido` or `plain` |
| `-o`, `--output FILE` | stdout | Write the term list to a file |

```bash
reviewblind export ../reviewblind-report.json --format anonymous-github
```

**Terms** are all confirmed identities from the report, plus the matched URL of any
RB105, RB203 or RB204 finding on a confirmed namespace. They are de-duplicated by
casefolded value and ordered longest first, so that a shorter term cannot break a
longer one.

| Format | Output |
|---|---|
| `plain` | One literal term per line |
| `anonymous-github` | One term per line, with regular-expression syntax escaped |
| `hido` | Currently identical to `plain`, because Hido does not document its term format ([D-22](DECISIONS.md#d-22-export-format-details)) |

```text
github\.com/aliceexample
Example University
alice@example\.edu
Alice Example
aliceexample
```

Anonymous GitHub compiles each term as a regular expression when it can, so an
unescaped `.` or `(` would change what a term matches.

`export` does not refuse a report that still has blockers, because a mirror-based
workflow may rely on term replacement. It warns on stderr if the report came from an
incomplete scan.

Binary files pass through a mirror unchanged. Term replacement does not fix PDF
metadata, image metadata or embedded images.

## `reviewblind rules [RULE_ID]`

```text
$ reviewblind rules RB502

RB502 - Identity in notebook output/traceback

Severity:
  mirror      BLOCKER
  archive     BLOCKER
  repository  BLOCKER
  Indirect evidence such as a home path: WARNING

Detects:
Author names, usernames, emails or personal paths retained
inside Jupyter stream, error or text outputs.

Why:
Outputs remain stored in the .ipynb JSON even when the source
cell itself is clean.

Fix:
Clear or re-run the affected output before preparing the anonymous artifact.
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no findings at or above the failure threshold |
| `1` | Scan completed; findings at or above the threshold |
| `2` | CLI, configuration or user error |
| `3` | Scan incomplete and `--strict` was passed |
| `4` | Unexpected internal ReviewBlind failure |

**Precedence:** codes 0 and 1 describe a completed scan, so with `--strict` an incomplete
scan returns `3` even if findings also exceed the threshold. Without `--strict`, an
incomplete scan returns `0` or `1` by threshold and states `Scan complete: NO`.

## Verdicts

The verdict describes the findings, regardless of `--fail-on`. Exit codes are for
automation; the verdict is for people.

| Condition | Verdict line |
|---|---|
| Any BLOCKER | `RESULT: NOT READY FOR ANONYMOUS REVIEW` |
| No BLOCKER; any WARNING or REVIEW | `RESULT: MANUAL REVIEW REQUIRED` |
| Only INFO or nothing; scan complete | `RESULT: NO KNOWN LEAKS DETECTED` |
| Only INFO or nothing; scan incomplete | `RESULT: NO KNOWN LEAKS DETECTED - SCAN INCOMPLETE` |

ReviewBlind never prints "clean", "anonymous" or "compliant".

## Running in CI

Reports and terminal output contain your identities in plain text, and so do the logs
and uploaded artifacts of a public repository.

- Use CI only on a private repository, or locally through a pre-submission script.
- Do not commit `.reviewblind.toml`. Write it from a CI secret to a path outside the
  checkout and pass `--config`.

```bash
reviewblind scan . --config "$RUNNER_TEMP/reviewblind.toml" --fail-on blocker --strict
```
