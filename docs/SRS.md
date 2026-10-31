# Software Requirements Specification — ReviewBlind 0.1.0

## 1. Purpose and how to read this

This document lists what ReviewBlind 0.1.0 must do, in testable statements. Each
requirement has a stable ID so that code, tests and reviews can refer to it.

**MUST** and **MUST NOT** are binding for 0.1.0. **SHOULD** is expected unless there
is a recorded reason not to.

Details live in one place and are referenced from here:

| Topic | Source of truth |
|---|---|
| Why the product exists; non-goals | [PRODUCT.md](PRODUCT.md) |
| Commands, flags, exit codes, verdicts | [CLI.md](CLI.md) |
| `.reviewblind.toml` | [CONFIG.md](CONFIG.md) |
| Rules and severity per target | [RULES.md](RULES.md) |
| JSON and Markdown report format | [REPORT_SCHEMA.md](REPORT_SCHEMA.md) |
| Internal design | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Attacks and mitigations | [THREAT_MODEL.md](THREAT_MODEL.md) |
| How requirements are verified | [TEST_PLAN.md](TEST_PLAN.md) |
| Why ambiguous points were resolved as they were | [DECISIONS.md](DECISIONS.md) |

## 2. Definitions

| Term | Meaning |
|---|---|
| **Artifact** | One file or path inside the scan root |
| **Identity** | A name, email, username, affiliation, URL or alias belonging to an author |
| **Confirmed identity** | An identity listed in the active configuration. Listing it there is the confirmation. |
| **Target** | The sharing scenario: `mirror`, `archive` or `repository` |
| **Finding** | A rule match at a location, with severity, confidence and evidence |
| **Severity** | How dangerous the leak is: `BLOCKER` > `WARNING` > `REVIEW` > `INFO` |
| **Confidence** | How certain ReviewBlind is: `HIGH` > `MEDIUM` > `LOW` |
| **Incomplete scan** | A scan in which some required inspection did not happen |

## 3. Constraints

| ID | Constraint |
|---|---|
| CON-1 | Python 3.11 or newer |
| CON-2 | Runtime dependencies are limited to Typer, Rich, PyMuPDF, Pillow, PyYAML and pathspec, plus the standard library |
| CON-3 | Packaged with hatchling; `uv` is the recommended development tool |
| CON-4 | No database, no API, no Docker requirement, no web frontend |
| CON-5 | Linux, macOS and Windows are all supported |
| CON-6 | Git features use the `git` executable; GitPython is not used |

## 4. Functional requirements

### 4.1 Identity discovery (`discover`)

| ID | Requirement |
|---|---|
| FR-DISC-1 | MUST inspect Git author names, committer names, email addresses and remotes |
| FR-DISC-2 | MUST inspect `pyproject.toml`, `package.json`, `setup.py`, `setup.cfg` and `CITATION.cff` |
| FR-DISC-3 | MUST inspect selected LaTeX author macros and repository URLs |
| FR-DISC-4 | MUST read local environment identity (`USER`, home directory) only when `--include-env` is passed |
| FR-DISC-5 | MUST assign confidence: **HIGH** for a direct structured author field or a repeated Git identity; **MEDIUM** for a repository owner, affiliation or structured URL; **LOW** for a derived alias or environment username |
| FR-DISC-6 | MUST raise confidence by one level, up to HIGH, when two independent source classes agree |
| FR-DISC-7 | MUST filter bots and map GitHub noreply addresses to the username they contain |
| FR-DISC-8 | MUST report every source of each candidate |
| FR-DISC-9 | MUST honour `--max-commits`, default 5000, and say so when history was truncated |
| FR-DISC-10 | MUST write nothing to disk |
| FR-DISC-11 | MUST support `--json` output |

### 4.2 Initialization (`init`)

| ID | Requirement |
|---|---|
| FR-INIT-1 | MUST run discovery and show candidates grouped by confidence, with sources |
| FR-INIT-2 | MUST preselect HIGH candidates and leave MEDIUM and LOW unselected |
| FR-INIT-3 | MUST let the user toggle candidates before writing |
| FR-INIT-4 | MUST NOT activate a LOW candidate or derived alias without an explicit user action |
| FR-INIT-5 | MUST refuse to overwrite an existing config unless `--force` is passed |
| FR-INIT-6 | MUST exit with code 2 when stdin is not interactive and `--yes` was not passed. `--yes` accepts HIGH candidates only |
| FR-INIT-7 | MUST write TOML that `tomllib` parses back to the same values, including values containing quotes, backslashes and non-ASCII text |
| FR-INIT-8 | MUST add the config and default report names to `.git/info/exclude`, unless `--no-exclude` is passed, and MUST NOT edit `.gitignore` |
| FR-INIT-9 | MUST warn when the config path is inside the scan root and already tracked by Git |
| FR-INIT-10 | MUST refuse to write through a symbolic link |

### 4.3 Scanning (`scan`)

| ID | Requirement |
|---|---|
| FR-SCAN-1 | MUST support `--target mirror`, `archive` and `repository`, defaulting to `mirror` |
| FR-SCAN-2 | MUST exit with code 2 when no config is found or the config has no identities |
| FR-SCAN-3 | MUST apply the inventory scope defined for the target ([ARCHITECTURE.md §5](ARCHITECTURE.md#5-inventory)) |
| FR-SCAN-4 | MUST run every scanner that supports an artifact, and contain any scanner failure to that artifact |
| FR-SCAN-5 | MUST produce the exit codes in [CLI.md](CLI.md#exit-codes) |
| FR-SCAN-6 | MUST honour `--fail-on`, default `blocker`, and `--strict` |
| FR-SCAN-7 | MUST report the verdict in [CLI.md](CLI.md#verdicts), and MUST NOT state that an artifact is anonymous, clean or compliant |
| FR-SCAN-8 | MUST warn on stderr when `--output` is inside the scan root |

### 4.4 Matching

| ID | Requirement |
|---|---|
| FR-MATCH-1 | MUST compare using Unicode NFC normalization and casefolding |
| FR-MATCH-2 | MUST apply boundary-aware matching, as defined in [ARCHITECTURE.md §6](ARCHITECTURE.md#6-matching) |
| FR-MATCH-3 | MUST match a multi-word identity across any run of whitespace, including line breaks |
| FR-MATCH-4 | MUST report line and column positions from the original, unnormalized text |
| FR-MATCH-5 | MUST NOT use fuzzy or edit-distance matching |
| FR-MATCH-6 | MUST resolve a match contained in another to one finding: longest span first, then higher severity, then lower rule ID. Spans that only partly overlap MUST both be reported |
| FR-MATCH-7 | MUST treat a short all-caps affiliation or alias as an acronym, with severity and confidence per [RULES.md](RULES.md#evidence-classes) |

### 4.5 Scanners

Rule assignments are in [RULES.md](RULES.md).

| ID | Requirement |
|---|---|
| FR-TEXT-1 | `TextScanner` MUST inspect the listed source and data extensions, plus unknown files that decode as text |
| FR-TEXT-2 | MUST detect confirmed names, aliases, emails, usernames and affiliations |
| FR-TEXT-3 | MUST structurally detect `/home/<u>/`, `/Users/<u>/`, `C:\Users\<u>\`; `github.com`, `gitlab.com`, `huggingface.co` and `wandb.ai` namespaces; `s3://` and `gs://` URIs; institutional domains; SLURM identifiers |
| FR-TEXT-4 | MUST NOT flag a generic URL or a placeholder home path unless its namespace corresponds to a confirmed identity or a rule explicitly covers the unconfirmed case |
| FR-PATH-1 | `PathScanner` MUST check every path segment of every inventoried artifact |
| FR-MAN-1 | `ManifestScanner` MUST parse author, maintainer, email, repository, homepage and organization fields in the manifest files |
| FR-MAN-2 | MUST inspect `setup.py` only through static text or AST analysis, and MUST NOT execute or import it |
| FR-MAN-3 | MUST flag structured author fields even when the value is not a confirmed identity, excluding placeholders |
| FR-MAN-4 | MUST inspect `LICENSE*`, `NOTICE*`, `COPYING*` and `AUTHORS*` for author identity |
| FR-GIT-1 | `GitScanner` MUST inspect authors, committers, emails, remotes and commit messages using raw (non-mailmapped) values |
| FR-GIT-2 | MUST limit history to `--max-commits`, default 5000, and mark the scan incomplete when the limit is exceeded |
| FR-GIT-3 | MUST report each unique Git identity once, and mark the scan incomplete when Git is unavailable or refuses the repository |
| FR-GIT-4 | MUST run Git only through the hardened runner in [ARCHITECTURE.md §8](ARCHITECTURE.md#8-running-git-safely) |
| FR-NB-1 | `NotebookScanner` MUST parse `.ipynb` as JSON and inspect separately: Markdown cells, code cells, stream outputs, error tracebacks, `text/plain` outputs, notebook and kernel metadata, and VS Code and Colab metadata |
| FR-NB-2 | MUST report the location as a JSON-style field, such as `output[7].traceback[3]` |
| FR-NB-3 | MUST report base64 binary output as REVIEW and MUST NOT OCR it |
| FR-PDF-1 | `PdfScanner` MUST inspect Author, Creator, Producer, Subject, Keywords, XMP metadata, extractable page text and exposed URLs |
| FR-PDF-2 | MUST NOT modify PDFs |
| FR-PDF-3 | MUST mark encrypted or corrupt PDFs as skipped |
| FR-IMG-1 | `ImageScanner` MUST inspect EXIF Artist, Copyright, ImageDescription, UserComment, GPS, camera owner fields, PNG text and iTXt, and software metadata |
| FR-IMG-2 | MUST add a REVIEW finding for visual content on every image |
| FR-IMG-3 | MUST NOT decode pixel data |
| FR-PKG-1 | `PackagingScanner` MUST detect `.DS_Store`, `__MACOSX/`, `Thumbs.db`, `.git`, archive files and unknown binaries |
| FR-PKG-2 | MUST NOT unpack archives |
| FR-PKG-3 | MUST detect a ReviewBlind config or report inside the artifact, and MUST NOT scan its contents as ordinary text |

### 4.6 Finding pipeline

| ID | Requirement |
|---|---|
| FR-PIPE-1 | MUST resolve severity from rule, target and evidence, per [RULES.md](RULES.md). Scanners MUST NOT set severity |
| FR-PIPE-2 | MUST apply exact `[[allow]]` suppressions matching rule, path and value, and MUST keep suppressed findings visible in the JSON report |
| FR-PIPE-3 | MUST attach the stable fingerprint in [ARCHITECTURE.md §7](ARCHITECTURE.md#7-fingerprints) to every finding |
| FR-PIPE-4 | MUST sort findings deterministically |
| FR-PIPE-5 | MUST strip control characters from evidence before it reaches any reporter |

### 4.7 Scan completeness

| ID | Requirement |
|---|---|
| FR-COMP-1 | MUST record every artifact that could not be fully inspected, with a reason |
| FR-COMP-2 | MUST mark the scan incomplete for: an unreadable, corrupt or encrypted file; a file over a size cap; an unsupported binary; an uninspected archive; a symlink that was not followed; a submodule or nested repository; more matches in one file than the limit; truncated Git history; or unavailable Git |
| FR-COMP-3 | MUST NOT mark the scan incomplete solely because image pixels or embedded notebook images were not inspected. These are REVIEW findings |
| FR-COMP-4 | MUST always show the completeness state in every report format |

### 4.8 Reports

| ID | Requirement |
|---|---|
| FR-REP-1 | MUST support `terminal`, `json` and `markdown` formats |
| FR-REP-2 | MUST write the report to stdout, or to `--output`, and diagnostics to stderr |
| FR-REP-3 | JSON output MUST conform to [REPORT_SCHEMA.md](REPORT_SCHEMA.md) and carry `schema_version` |
| FR-REP-4 | Report contents MUST be byte-identical across repeated runs on the same input |
| FR-REP-5 | Markdown output MUST escape repository-controlled text so that it cannot inject links, images or HTML |

### 4.9 Export (`export`)

| ID | Requirement |
|---|---|
| FR-EXP-1 | MUST consume a JSON scan report and produce a term list |
| FR-EXP-2 | MUST support `anonymous-github`, `hido` and `plain` |
| FR-EXP-3 | MUST order terms longest first, breaking ties lexicographically |
| FR-EXP-4 | The `anonymous-github` format MUST escape regular-expression syntax so that each term matches literally |
| FR-EXP-5 | MUST NOT generate Git rewrite rules |
| FR-EXP-6 | MUST exit with code 2 for an unreadable report or unsupported `schema_version` |
| FR-EXP-7 | MUST warn on stderr when the report is from an incomplete scan |

### 4.10 Rule documentation (`rules`)

| ID | Requirement |
|---|---|
| FR-RULE-1 | `reviewblind rules` MUST list all rules; `reviewblind rules <ID>` MUST show one rule's severity per target, what it detects, why it matters and how to fix it |
| FR-RULE-2 | MUST exit with code 2 for an unknown rule ID |
| FR-RULE-3 | Rule text MUST come from the catalog used by the scan pipeline, not from separate strings |

### 4.11 Configuration

| ID | Requirement |
|---|---|
| FR-CFG-1 | MUST parse `.reviewblind.toml` with `tomllib`, per [CONFIG.md](CONFIG.md) |
| FR-CFG-2 | MUST exit with code 2 for malformed TOML, an unknown key, an unsupported `version`, an unknown rule ID or an `[[allow]]` entry without `reason` |
| FR-CFG-3 | MUST support an alternative location through `--config` |
| FR-CFG-4 | MUST NOT support regex allowlists |

## 5. Non-functional requirements

### 5.1 Safety

ReviewBlind inspects files that may be hostile. See [THREAT_MODEL.md](THREAT_MODEL.md).

| ID | Requirement |
|---|---|
| NFR-SAFE-1 | MUST NOT execute repository code or import repository modules |
| NFR-SAFE-2 | MUST NOT trigger code execution through Git configuration, hooks, filters or fsmonitor |
| NFR-SAFE-3 | MUST NOT follow a symlink that resolves outside the scan root |
| NFR-SAFE-4 | MUST NOT upload files or open a network connection during a scan |
| NFR-SAFE-5 | MUST NOT modify scanned files or rewrite Git. The only writes are the requested report, the config and `.git/info/exclude` during `init` |
| NFR-SAFE-6 | MUST NOT unpack archives |
| NFR-SAFE-7 | MUST enforce size caps before parsing |
| NFR-SAFE-8 | MUST handle malformed files without crashing the scan |

### 5.2 Reliability and determinism

| ID | Requirement |
|---|---|
| NFR-REL-1 | A malformed artifact MUST result in a skipped entry, never an uncaught exception |
| NFR-REL-2 | An unexpected internal failure MUST exit with code 4 and MUST NOT report a passing verdict |
| NFR-DET-1 | Reports MUST NOT contain timestamps or other run-dependent values |
| NFR-DET-2 | Results MUST NOT depend on file-system enumeration order |
| NFR-DET-3 | Rule severity MUST NOT depend on the operating system |

### 5.3 Usability

| ID | Requirement |
|---|---|
| NFR-USE-1 | Every finding MUST state the reason it matters and a suggested action |
| NFR-USE-2 | Terminal output MUST honour `NO_COLOR` and remain readable without color |
| NFR-USE-3 | Evidence MUST be shown at most once per finding and truncated to 160 characters |

### 5.4 Performance

| ID | Requirement |
|---|---|
| NFR-PERF-1 | SHOULD scan a 1,000-file text repository in under 30 seconds on a typical laptop. This is a provisional target, to be checked during dogfooding |

### 5.5 Maintainability

| ID | Requirement |
|---|---|
| NFR-MNT-1 | Code MUST pass `ruff check`, `ruff format --check` and `mypy --strict` |
| NFR-MNT-2 | At least 70 meaningful automated tests by 0.1.0 |
| NFR-MNT-3 | CI MUST run on Linux, macOS and Windows |
| NFR-MNT-4 | Adding a scanner or rule MUST NOT require changes to the engine |

## 6. Acceptance

0.1.0 is accepted when every MUST above is verified as described in
[TEST_PLAN.md](TEST_PLAN.md) and the checklist in
[ROADMAP.md](ROADMAP.md#definition-of-done-for-010) is complete.
