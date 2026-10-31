# Architecture

> Status: this is the design for 0.1.0. Implementation has not started.

## 1. Overview

ReviewBlind is one Python process that reads a directory, runs scanners over what it
finds, and writes a report. It has no services, no database and no network access.

```text
                     ┌───────────────────┐
                     │       CLI         │
                     └─────────┬─────────┘
                               │
                     ┌─────────▼─────────┐
                     │    ScanConfig     │
                     └─────────┬─────────┘
                               │
                     ┌─────────▼─────────┐
                     │  Identity Store   │
                     └─────────┬─────────┘
                               │
                     ┌─────────▼─────────┐
                     │ Inventory Engine  │
                     └─────────┬─────────┘
                               │
       ┌───────────────────────┼────────────────────────┐
       │                       │                        │
┌──────▼───────┐       ┌───────▼────────┐       ┌──────▼──────┐
│ Repo Scanner │       │ File Scanners  │       │ Git Scanner │
└──────┬───────┘       └───────┬────────┘       └──────┬──────┘
       │                       │                        │
       │                 Detections                     │
       └───────────────────────┼────────────────────────┘
                               │
                     ┌─────────▼─────────┐
                     │ Finding Pipeline  │
                     │ - normalize       │
                     │ - resolve overlap │
                     │ - severity        │
                     │ - fingerprint     │
                     │ - allowlist       │
                     │ - sort            │
                     └─────────┬─────────┘
                               │
                     ┌─────────▼─────────┐
                     │    ScanResult     │
                     └─────────┬─────────┘
                               │
              ┌────────────────┼─────────────────┐
              │                │                 │
          Terminal       JSON/Markdown      Export terms
```

### Dependency direction

```text
cli → engine → scanners → matching → models
         ↓        ↓
      profiles  rules/catalog → models
         ↓
      reporters, exporters → models
```

- `models.py` imports nothing else from the package.
- Scanners never import each other, reporters or the CLI.
- Only `cli.py` knows about Typer. Only `reporters/terminal.py` and `cli.py` know about Rich.
- Only `scanners/pdf.py` imports PyMuPDF. Only `scanners/image.py` imports Pillow.
- Only `utils/git.py` starts a subprocess.

## 2. Repository layout

```text
reviewblind/
├── src/reviewblind/
│   ├── __init__.py
│   ├── __main__.py
│   ├── py.typed
│   ├── cli.py              Typer commands; exit-code mapping
│   ├── config.py           .reviewblind.toml parsing, validation and writing
│   ├── engine.py           Orchestrates one scan
│   ├── inventory.py        Decides what is inspected, for each target
│   ├── models.py           Dataclasses and enums
│   ├── profiles.py         Severity resolution for rule + target + evidence
│   ├── fingerprints.py     Stable finding fingerprints
│   ├── matching.py         Normalization, identity and structural matching
│   ├── discovery/          git.py, manifests.py, latex.py
│   ├── scanners/           base.py, text.py, paths.py, manifests.py, git.py,
│   │                       notebook.py, pdf.py, image.py, packaging.py
│   ├── rules/              catalog.py (the rules), registry.py (lookup)
│   ├── reporters/          terminal.py, json.py, markdown.py
│   ├── exporters/          terms.py
│   └── utils/              files.py, git.py (hardened runner), text.py
├── tests/                  See TEST_PLAN.md
├── docs/
├── examples/
└── .github/
```

## 3. Data model

Everything is a frozen dataclass except `ScanResult`, which the engine builds up.
Enums use uppercase string values, which appear directly in JSON.

```python
class Severity(Enum):       # ordered: BLOCKER > WARNING > REVIEW > INFO
class Confidence(Enum):     # ordered: HIGH > MEDIUM > LOW
class Target(Enum):         # MIRROR, ARCHIVE, REPOSITORY
class IdentityKind(Enum):   # NAME, EMAIL, USERNAME, AFFILIATION, URL, ALIAS
class ArtifactKind(Enum):   # TEXT, MANIFEST, NOTEBOOK, PDF, IMAGE, ARCHIVE, BINARY
class EvidenceClass(Enum):  # DIRECT, INDIRECT, ACRONYM, AMBIGUOUS
class SkipReason(Enum):     # see REPORT_SCHEMA.md

@dataclass(frozen=True)
class Identity:
    value: str
    kind: IdentityKind
    source: str
    confidence: Confidence
    confirmed: bool

@dataclass(frozen=True)
class Artifact:
    path: Path              # absolute, inside the scan root
    relpath: str            # POSIX, relative to the root
    kind: ArtifactKind
    size: int
    tracked: bool | None    # None when the root is not a Git repository

@dataclass(frozen=True)
class Location:
    path: str
    line: int | None = None
    column: int | None = None
    field: str | None = None
    git_commit: str | None = None

@dataclass(frozen=True)
class Detection:
    """What a scanner saw. Contains no policy."""
    rule_id: str
    artifact: str
    location: Location
    matched: str            # the exact matched value
    evidence: str           # short display excerpt
    message: str
    identity: str | None    # the confirmed identity, if there is one
    evidence_class: EvidenceClass
    span: tuple[int, int] | None = None  # character offsets, for overlap resolution

@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    confidence: Confidence
    artifact: str
    location: Location
    matched: str
    evidence: str
    message: str
    reason: str
    remediation: str
    identity: str | None
    targets: frozenset[Target]
    fingerprint: str

@dataclass(frozen=True)
class SkippedArtifact:
    path: str
    reason: SkipReason
    detail: str | None = None

@dataclass(frozen=True)
class SuppressedFinding:
    finding: Finding
    reason: str             # the [[allow]] reason

@dataclass
class ScanResult:
    findings: list[Finding]
    suppressed: list[SuppressedFinding]
    inspected: int
    excluded: int
    skipped: list[SkippedArtifact]
    notes: list[str]
    incomplete: bool
```

### Rules

```python
@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    default_severity: Severity
    description: str
    reason: str
    remediation: str
    severity_by_target: Mapping[Target, Severity]  # overrides of the default
    confidence: Confidence
    container: bool  # a ◆ rule: INDIRECT evidence is capped at WARNING
    identity_based: bool  # False for a fact about a file, shown as "n/a" in RULES.md
    unconfirmed: UnconfirmedPolicy | None  # None: no finding when unconfirmed
    blocker_if_git_packaged: bool  # the † rules in RULES.md
    blocker_if_tracked: bool  # the ‡ rule in RULES.md
    applicable_targets: frozenset[Target]
```

Scanners emit `Detection`s. `profiles.py` turns each one into a `Finding` by combining the
catalog with the target. This is the only place severity and confidence are decided.

## 4. Scanner interfaces

```python
class FileScanner(Protocol):
    name: str

    def supports(self, artifact: Artifact) -> bool: ...
    def scan(self, artifact: Artifact, context: ScanContext) -> Iterable[Detection]: ...


class RepositoryScanner(Protocol):
    name: str

    def scan(self, context: ScanContext) -> Iterable[Detection]: ...
```

`ScanContext` is read-only. It holds the config, the target, the compiled identity
matcher, the inventory, and a `report_skip()` callback for recording incompleteness.

| Scanner | Type | Handles | Rules |
|---|---|---|---|
| `TextScanner` | File | TEXT, MANIFEST | RB101–105, RB201–205 |
| `PathScanner` | File | Every artifact | RB106 |
| `ManifestScanner` | File | MANIFEST | RB301–304 |
| `NotebookScanner` | File | NOTEBOOK | RB501–504 |
| `PdfScanner` | File | PDF | RB601–602 |
| `ImageScanner` | File | IMAGE | RB701–703 |
| `PackagingScanner` | File and repository | Every artifact; root | RB801–805 |
| `GitScanner` | Repository | The root | RB401–404 |

The engine wraps every scanner call. A `RecursionError`, `MemoryError` or any other
`Exception` from a scanner becomes a skipped entry for that artifact, and the scan
continues. Anything escaping the engine itself is an internal failure, exit code 4.

Scanning runs sequentially in 0.1.0. Determinism matters more than speed here, and
results are sorted regardless.

### Classifying artifacts

The checks run in this order, and the first match wins.

1. Filename: `pyproject.toml`, `package.json`, `setup.py`, `setup.cfg`, `CITATION.cff`,
   `LICENSE*`, `NOTICE*`, `COPYING*`, `AUTHORS*` → MANIFEST
2. Extension: `.ipynb` → NOTEBOOK; `.pdf` → PDF; `.png`, `.jpg`, `.jpeg`, `.tif`, `.tiff`,
   `.webp`, `.gif`, `.bmp` → IMAGE; `.zip`, `.tar`, `.gz`, `.tgz`, `.bz2`, `.xz`, `.7z`,
   `.rar` → ARCHIVE
3. Content sniff of the first 8 KiB: a NUL byte, or bytes that do not decode as UTF-8 (a
   BOM is honoured) → BINARY; otherwise → TEXT

The extension list in the SRS is informative. Content sniffing is what makes "plus
UTF-8-like unknown text files" work, so a `.py` file containing binary data is treated as
binary.

## 5. Inventory

What counts as reviewer-visible depends on the target.

| Target | In a Git repository | Not in a Git repository |
|---|---|---|
| `mirror` | Tracked files, plus untracked files that are not ignored | Every file under the root, with a note |
| `repository` | Same as `mirror` | Same as `mirror` |
| `archive` | Every file under the root. `.gitignore` is **not** applied, because zipping a folder does not honour it | Every file under the root |

- Untracked, non-ignored files are included because they are one `git add` from being
  published. A false positive here is cheaper than a leak.
- `.git` is never descended into, whatever the target.
- `scan.exclude` applies last, in every case.

### Uncommitted changes

For `mirror` and `repository`, a scan reads the working tree, but a reviewer sees what was
pushed. If a tracked file differs from the index, the report carries a note saying results
reflect the working tree.

This check **does not use `git status`**, because of the problem described in
[§8](#8-running-git-safely). ReviewBlind hashes the file itself and compares the result to
the blob ID from `git ls-files -s`. Line-ending conversion or Git LFS can make a file look
changed when it is not. The only consequence is an unnecessary note.

### Symlinks

A symlink is never followed by default. It is recorded as skipped, which marks the scan
incomplete. With `follow_symlinks = true`, a link is followed only when its resolved path
stays inside the root; a link that leaves the root is always skipped.

## 6. Matching

Text and needles are both normalized with **NFC + casefold**. Offsets are mapped back to the
original text, since casefolding can change length (`ß` → `ss`). Line and column always
refer to the original file.

**Boundaries.** A match must not be directly preceded or followed by a word character,
meaning Unicode categories `L*`, `M*` or `N*`.

- Combining marks count as word characters, so Bangla, Devanagari and similar scripts
  are not split mid-syllable.
- `_`, `-`, `.` and `/` are boundaries, so `aliceexample` matches in `aliceexample_data.csv`.
- The boundary check is skipped on an edge whose character is CJK, Hiragana, Katakana, Hangul
  or Thai, since these scripts do not separate words with spaces.

**Whitespace.** A run of whitespace in a configured identity matches any run of whitespace in
the text, including line breaks. This catches `\author{Alice\nExample}`.

**Not done:** fuzzy matching, edit distance, diacritic folding, name reordering and initials.
These need aliases. See [LIMITATIONS.md](LIMITATIONS.md).

**Overlaps.** When one span lies inside another at the same location, one finding survives. The
order is: longest span, then higher severity, then lower rule ID. Spans that only partly overlap
both survive, because each may be a separate leak.

| Text | Candidates | Reported |
|---|---|---|
| `alice@example.edu` | RB102, RB202 | RB102 (longest) |
| `/home/aliceexample/data` | RB201, RB103 | RB201 (longest), so WARNING and not BLOCKER |
| `wandb.ai/aliceexample/run` | RB203, RB103 | RB203 (longest) |
| `--mail-user=alice@example.edu` | RB205, RB102 (same span: the value) | RB102 (higher severity) |

Manifest files are read by both `TextScanner` and `ManifestScanner`. On the same line and
value, the RB3xx finding wins, as it is more specific.

**Performance and safety.** Each identity is searched for separately, as escaped literals joined by
`\s+`, so a longer identity failing its boundary check cannot hide a shorter one at the same
position. Structural detectors must be linear-time: no nested quantifiers, and they run
per line with a line-length cap.

## 7. Fingerprints

```text
fingerprint = "rb1:" + hex(SHA256(rule_id + 0x00 + path + 0x00 + evidence))
```

| Input | Normalization |
|---|---|
| `rule_id` | As is |
| `path` | Repository-relative, POSIX separators, NFC. Case is preserved because paths are case-sensitive on many systems |
| `evidence` | `Finding.matched`, after NFC, casefold and whitespace collapse |

The fingerprint omits the line number, because lines move during edits, and the target, so
one leak has one identity across targets.

It also uses the matched value rather than the display excerpt, so editing other text on the
line does not change it. Two occurrences of a name in one file therefore share a fingerprint.
**A fingerprint identifies a leak, not a row.** 0.1.0 uses it only for reporting. It exists so
that 1.1 baselines do not need a model redesign.

## 8. Running Git safely

A repository's `.git/config` is attacker-controlled input, and some of its keys run commands.
All Git access goes through one function in `utils/git.py`.

```text
git --no-pager --no-optional-locks --no-replace-objects
    -c core.fsmonitor=false
    -c core.hooksPath=<null device>
    -c protocol.allow=never
    -c safe.bareRepository=explicit
    <allowlisted subcommand>
```

The child environment has every inherited `GIT_*` variable removed, then sets
`GIT_TERMINAL_PROMPT=0` and `GIT_OPTIONAL_LOCKS=0`. Stdin is closed, and each command has a
timeout. Calls never use a shell.

**Allowlisted subcommands:** `rev-parse`, `ls-files --cached --others --exclude-standard`,
`ls-files -s`, `log`, `rev-list`, `remote -v`.

**Banned, verified by test:** `status`, `diff`, `ls-files --modified`, `fetch`, `pull`,
`ls-remote`, `submodule`, `checkout`.

The ban exists because the flags above do not remove every execution path. During the design of
this project, we confirmed on Git 2.55 that `git status` and `git ls-files --modified` run a
repo-local `filter.<name>.clean` command when a file changes without changing size, even with
all the flags above. Filter names are chosen by the repository, so they cannot be disabled
with `-c`. `ls-files -s`, inventory-mode `ls-files` and `log` did not run it.

The user's own global config still applies, so their `safe.directory` choices keep working.
ReviewBlind never adds a `safe.directory` entry. If Git refuses a repository, the Git scan is
skipped and the scan is marked incomplete, with the message from Git.

**Reading history.** Records are read from `git log --all --no-mailmap` with NUL-separated fields
using raw `%an`, `%ae`, `%cn`, `%ce` and `%B`, so `.mailmap` cannot hide an identity. Output is
decoded as UTF-8 with replacement. `git rev-list --all --count` is compared to `--max-commits`
to detect truncation.

## 9. Reports

A reporter is a pure function from `ScanResult` to text. Each one also receives the report
metadata (`target`, `root`, tool version, identities). Findings are sorted by severity (highest
first), then artifact, line, column, rule ID and fingerprint.

The `root` is shown as `~/...` when under the home directory, and no timestamp is ever included.

JSON and Markdown formats are defined in [REPORT_SCHEMA.md](REPORT_SCHEMA.md).

## 10. Extension points

| To add | Change |
|---|---|
| A file format | A new `FileScanner`, registered in `scanners/__init__.py` |
| A rule | `rules/catalog.py`, `docs/RULES.md`, a test and a benchmark entry |
| A report format | A new reporter, plus a `--format` value |
| An export format | A new function in `exporters/terms.py`, plus a `--format` value |

No engine changes are needed for any of these.

## 11. Why not…

| Alternative | Reason not chosen |
|---|---|
| GitPython | Adds a dependency and hides which Git commands run, which is the thing we must control |
| YAML config | TOML needs no extra dependency for reading config. PyYAML is used only to read `CITATION.cff` |
| Regex allowlists | A broad pattern can silently hide a different leak |
| Fuzzy matching | False positives erode trust, and results become hard to explain |
| One combined risk score | It hides whether something is dangerous or just uncertain |
| Rewriting files or history | Destructive changes to research artifacts are out of scope |
