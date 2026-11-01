# Rule Catalogue

This is the normative list of the 33 rules in 0.1.0. `rules/catalog.py` implements it,
and a test keeps the two in step.

Scanners detect evidence. Rules describe policy. A scanner never decides severity.

## Severity and confidence

These are independent, and are never combined into a score.

| Severity | Meaning |
|---|---|
| `BLOCKER` | Direct, high-confidence identity disclosure |
| `WARNING` | Probable deanonymization vector |
| `REVIEW` | Needs human inspection |
| `INFO` | Useful context, not necessarily a problem |

| Confidence | Meaning |
|---|---|
| `HIGH` | Exact match of a confirmed identity, or a structural fact such as a file being present |
| `MEDIUM` | A structural signal that is not tied to a confirmed identity, or an exact-case acronym |
| `LOW` | A weak signal, such as an acronym in the wrong case or an unconfirmed storage bucket |

Examples:

| Finding | Severity | Confidence |
|---|---|---|
| `Alice Example` in `pyproject.toml` | BLOCKER | HIGH |
| `EU`, confirmed as an acronym, in a config comment | WARNING | MEDIUM |
| `eu` in a variable name, possibly that same acronym | REVIEW | LOW |

## How severity is resolved

The pipeline applies these steps in order. Each may replace the result of the one before.

1. **Base:** the rule's severity for the current target, from the table below.
2. **Packaged Git:** RB401–RB404 become BLOCKER when the target is `archive` and a `.git`
   directory will be packaged.
3. **Evidence class:** container rules are capped according to the evidence, as below.
4. **Unconfirmed:** when the evidence is not tied to a confirmed identity, the rule's
   *Unconfirmed* column applies. `—` means no finding is raised.

### Evidence classes

Container rules (marked ◆) describe *where* something was found, so their severity
also depends on *what* was found.

| Class | Evidence | Severity for ◆ rules |
|---|---|---|
| `DIRECT` | Confirmed name, alias, email, username, profile URL or Git-hosting namespace | The rule's base severity |
| `INDIRECT` | Affiliation, institutional domain, home path, research-service namespace or HPC identifier | WARNING |

**Acronyms.** A confirmed affiliation or alias of at most five characters, all uppercase
letters, is treated as an acronym. Unlike the classes above, this applies to **every** rule,
not just ◆ rules:

| Class | Evidence | Severity | Confidence |
|---|---|---|---|
| `ACRONYM` | An acronym matched in its exact case | WARNING | MEDIUM |
| `AMBIGUOUS` | An acronym matched in a different case | REVIEW | LOW |

Evidence classes only ever lower severity. An INFO finding stays INFO.

## Catalogue

Table columns: **Mir** = `mirror`, **Arc** = `archive`, **Repo** = `repository`. **Conf.** is
the confidence for confirmed evidence. **Unconfirmed** gives severity and confidence when
the evidence is not tied to a confirmed identity.

Severities: **B** = BLOCKER, **W** = WARNING, **R** = REVIEW, **I** = INFO.

### Identity

| ID | Title | Mir | Arc | Repo | Conf. | Unconfirmed |
|---|---|---|---|---|---|---|
| RB101 | Confirmed name in reviewer-visible text | B | B | B | HIGH | — |
| RB102 | Confirmed email | B | B | B | HIGH | — |
| RB103 | Confirmed username/handle | B | B | B | HIGH | — |
| RB104 | Confirmed affiliation | W | W | W | HIGH | — |
| RB105 | Personal/profile URL | B | B | B | HIGH | — |
| RB106 ◆ | Identity exposed through filename/path | B | B | B | HIGH | — |

### Workstation and service

| ID | Title | Mir | Arc | Repo | Conf. | Unconfirmed |
|---|---|---|---|---|---|---|
| RB201 | Personal absolute home path | W | W | W | HIGH | R + MEDIUM (placeholders ignored) |
| RB202 | Institution-associated hostname/domain | W | W | W | HIGH | — |
| RB203 | Research-service account namespace | W | W | W | HIGH | R + LOW for `wandb.ai`, `s3://` and `gs://`; — for `huggingface.co` |
| RB204 | Personal Git hosting namespace | B | B | B | HIGH | — |
| RB205 | SLURM/HPC user or mail identifier | W | W | W | HIGH | W + MEDIUM |

### Manifests

| ID | Title | Mir | Arc | Repo | Conf. | Unconfirmed |
|---|---|---|---|---|---|---|
| RB301 | Author/maintainer metadata | B | B | B | HIGH | B + MEDIUM (placeholders ignored) |
| RB302 | Identifying repository/homepage metadata | B | B | B | HIGH | W + MEDIUM |
| RB303 | CITATION author identity | B | B | B | HIGH | B + MEDIUM (placeholders ignored) |
| RB304 | LICENSE/NOTICE author identity | B | B | B | HIGH | W + MEDIUM |

### Git

| ID | Title | Mir | Arc | Repo | Conf. | Unconfirmed |
|---|---|---|---|---|---|---|
| RB401 | Identifying Git remote | I | I† | B | HIGH | — |
| RB402 | Identifying Git author/committer | I | I† | B | HIGH | `repository` only: W + MEDIUM |
| RB403 | Identifying Git email | I | I† | B | HIGH | `repository` only: W + MEDIUM |
| RB404 ◆ | Identity in commit message | I | I† | B | HIGH | — |

† BLOCKER when a `.git` directory will be packaged.

### Notebooks

| ID | Title | Mir | Arc | Repo | Conf. | Unconfirmed |
|---|---|---|---|---|---|---|
| RB501 ◆ | Identity in notebook source/Markdown | B | B | B | HIGH | — |
| RB502 ◆ | Identity in notebook output/traceback | B | B | B | HIGH | R + MEDIUM for a home path |
| RB503 ◆ | Identity/path in notebook metadata | B | B | B | HIGH | R + MEDIUM for a home path |
| RB504 | Embedded binary notebook output requires review | R | R | R | HIGH | n/a |

### PDF

| ID | Title | Mir | Arc | Repo | Conf. | Unconfirmed |
|---|---|---|---|---|---|---|
| RB601 ◆ | Identity in PDF metadata | B | B | B | HIGH | W + MEDIUM for the `Author` field (placeholders ignored) |
| RB602 ◆ | Identity in extractable PDF text | B | B | B | HIGH | — |

### Image

| ID | Title | Mir | Arc | Repo | Conf. | Unconfirmed |
|---|---|---|---|---|---|---|
| RB701 ◆ | Identity in image metadata | B | B | B | HIGH | W + MEDIUM for owner fields such as `Artist` |
| RB702 | GPS metadata | W | W | W | HIGH | n/a |
| RB703 | Visual content requires manual review | R | R | R | HIGH | n/a |

### Packaging

| ID | Title | Mir | Arc | Repo | Conf. | Unconfirmed |
|---|---|---|---|---|---|---|
| RB801 | `.git` present for archive target | I | B | I | HIGH | n/a |
| RB802 | OS metadata files present | W | W | W | HIGH | n/a |
| RB803 | Unsupported binary requires review | R | R | R | HIGH | n/a |
| RB804 | Archive requires manual/deep inspection | R | R | R | HIGH | n/a |
| RB805 | ReviewBlind config or report in artifact | I‡ | B | I‡ | HIGH | n/a |

‡ BLOCKER when the file is tracked by Git, or when tracking cannot be determined.

## Rule details

These are the source text for `rules/catalog.py` and `reviewblind rules`. **Fix** is the
suggested action shown with a finding.

### Identity rules

**RB101 — Confirmed name in reviewer-visible text**
- *Detects:* a configured name or alias in any inspected text file.
- *Why:* direct author identity is visible in reviewer-facing text.
- *Fix:* remove this name from the review artifact or configure your anonymous mirror to replace it.

**RB102 — Confirmed email**
- *Detects:* a configured email address.
- *Why:* an email address identifies a person and often an institution.
- *Fix:* remove the address, or replace it with a placeholder.

**RB103 — Confirmed username/handle**
- *Detects:* a configured username outside a more specific URL or path.
- *Why:* usernames resolve to public profiles with a simple search.
- *Fix:* remove the handle, or replace it with a neutral value.

**RB104 — Confirmed affiliation**
- *Detects:* a configured institution, lab or department.
- *Why:* affiliation narrows the author set, sometimes to one group.
- *Fix:* remove the affiliation, or add an `[[allow]]` entry if it refers to third-party work.

**RB105 — Personal/profile URL**
- *Detects:* a URL from `identity.urls`, or a hosting profile such as `github.com/<username>`.
- *Why:* the link leads directly to the author.
- *Fix:* remove the link.

**RB106 — Identity exposed through filename/path** ◆
- *Detects:* a confirmed identity in a directory or file name.
- *Why:* file names are visible in every listing, and many tools do not rewrite them.
- *Fix:* rename the file or directory.

### Workstation and service rules

**RB201 — Personal absolute home path**
- *Detects:* `/home/<user>/`, `/Users/<user>/` and `C:\Users\<user>\`. Placeholders such as `user`, `ubuntu`, `runner`, `root`, `jovyan` and `vscode` are ignored.
- *Why:* the path exposes a workstation username, even when the author's name is absent.
- *Fix:* use relative paths or environment variables.

**RB202 — Institution-associated hostname/domain**
- *Detects:* a domain from a confirmed email, or a subdomain of it. Public mail providers are excluded.
- *Why:* an institutional hostname reveals where the work was done.
- *Fix:* replace it with a generic hostname, or read it from configuration.

**RB203 — Research-service account namespace**
- *Detects:* a confirmed namespace on `huggingface.co` or `wandb.ai`. Unconfirmed `wandb.ai` namespaces and `s3://` or `gs://` URIs are raised for review.
- *Why:* experiment-tracking and model-hosting accounts usually map to one person or lab.
- *Fix:* remove the URL, or move the asset to a neutral account.

**RB204 — Personal Git hosting namespace**
- *Detects:* `github.com/<username>/<repo>` and `gitlab.com/<username>/<repo>` for a confirmed username.
- *Why:* a repository URL reveals its owner.
- *Fix:* remove the URL, or point to the anonymized location.

**RB205 — SLURM/HPC user or mail identifier**
- *Detects:* `#SBATCH --mail-user`, `#SBATCH --account`, and similar scheduler directives.
- *Why:* scheduler scripts often hold a personal address or cluster account.
- *Fix:* remove the directive, or read the value from the environment.

### Manifest rules

**RB301 — Author/maintainer metadata**
- *Detects:* author and maintainer fields in `pyproject.toml`, `package.json`, `setup.py` and `setup.cfg`. Unconfirmed values are reported too, because a co-author may be missing from your config.
- *Why:* package metadata remains reviewer-visible and may disclose authorship.
- *Fix:* replace it with a neutral value such as `Anonymous Authors`.

**RB302 — Identifying repository/homepage metadata**
- *Detects:* repository, homepage and organization fields in a manifest.
- *Why:* project URLs commonly point to the author's account or institution.
- *Fix:* remove the field for the review copy.

**RB303 — CITATION author identity**
- *Detects:* author entries in `CITATION.cff`.
- *Why:* a citation file exists to name its authors.
- *Fix:* remove the file from the review copy, or anonymize its authors.

**RB304 — LICENSE/NOTICE author identity**
- *Detects:* copyright holders in `LICENSE*`, `NOTICE*`, `COPYING*` and `AUTHORS*`.
- *Why:* a copyright line names its holder.
- *Fix:* use a neutral holder for the review copy, and restore it afterwards.

### Git rules

**RB401 — Identifying Git remote**
- *Detects:* a remote URL under a confirmed namespace.
- *Why:* a publication URL reveals its owner. An anonymizing mirror hides this; a public repository does not.
- *Fix:* publish from an anonymous account, or use a mirror.

**RB402 — Identifying Git author/committer**
- *Detects:* author and committer names in history. Each unique identity is reported once.
- *Why:* full history is public on a repository and is packaged with `.git`.
- *Fix:* publish a fresh history under a neutral identity. ReviewBlind does not rewrite history.

**RB403 — Identifying Git email**
- *Detects:* author and committer emails in history. Each unique address is reported once.
- *Why:* full history is public on a repository and is packaged with `.git`.
- *Fix:* publish a fresh history under a neutral identity. ReviewBlind does not rewrite history.

**RB404 — Identity in commit message** ◆
- *Detects:* a confirmed identity in a commit message, including `Signed-off-by` and `Co-authored-by` trailers.
- *Why:* commit messages travel with the history.
- *Fix:* publish a fresh history under a neutral identity. ReviewBlind does not rewrite history.

### Notebook rules

**RB501 — Identity in notebook source/Markdown** ◆
- *Detects:* a confirmed identity or structural signal in Markdown or code cells.
- *Why:* cell source is shown directly when the notebook is rendered.
- *Fix:* edit the cell.

**RB502 — Identity in notebook output/traceback** ◆
- *Detects:* author names, usernames, emails or personal paths retained inside Jupyter stream, error or text outputs.
- *Why:* outputs remain stored in the `.ipynb` JSON even when the source cell itself is clean.
- *Fix:* clear or re-run the affected output before preparing the anonymous artifact.

**RB503 — Identity/path in notebook metadata** ◆
- *Detects:* a confirmed identity or path in notebook, kernel, VS Code or Colab metadata.
- *Why:* metadata is hidden from the rendered view but remains in the file.
- *Fix:* clear the metadata, for example with `nbstripout`.

**RB504 — Embedded binary notebook output requires review**
- *Detects:* base64 image or binary output.
- *Why:* ReviewBlind does not perform OCR, so a plot title or screenshot could contain identity.
- *Fix:* look at the output, or clear it.

### PDF rules

**RB601 — Identity in PDF metadata** ◆
- *Detects:* a confirmed identity in Author, Title, Creator, Producer, Subject, Keywords or XMP metadata. A non-placeholder `Author` is reported even when unconfirmed.
- *Why:* metadata is hidden from the page, and a mirror cannot rewrite binary files.
- *Fix:* re-export the PDF with metadata removed.

**RB602 — Identity in extractable PDF text** ◆
- *Detects:* a confirmed identity in page text or exposed URLs.
- *Why:* a mirror cannot rewrite binary files, so visible text in a PDF stays visible.
- *Fix:* regenerate the document. If this is a legitimate citation, add an `[[allow]]` entry.

### Image rules

**RB701 — Identity in image metadata** ◆
- *Detects:* a confirmed identity in EXIF, PNG text or software metadata. A non-placeholder owner field such as `Artist` is reported even when unconfirmed.
- *Why:* image metadata is invisible when viewing and survives copying.
- *Fix:* strip the metadata and re-export.

**RB702 — GPS metadata**
- *Detects:* EXIF GPS tags.
- *Why:* coordinates can identify a home or an institution.
- *Fix:* strip the metadata and re-export.

**RB703 — Visual content requires manual review**
- *Detects:* every reviewer-visible image.
- *Why:* ReviewBlind checks image metadata but does not perform OCR or visual identity recognition.
- *Fix:* look at the image.

### Packaging rules

**RB801 — `.git` present for archive target**
- *Detects:* a `.git` directory or file, unless the config excludes `.git/**`.
- *Why:* packaging `.git` ships the entire history, with its authors and remotes.
- *Fix:* build the archive with `git archive`, or from a clean export. If you will not package `.git`, add `.git/**` to `exclude`.

**RB802 — OS metadata files present**
- *Detects:* `.DS_Store`, `__MACOSX/` and `Thumbs.db`.
- *Why:* these files can hold folder listings, paths and thumbnails.
- *Fix:* delete them and exclude them from the artifact.

**RB803 — Unsupported binary requires review**
- *Detects:* a binary file ReviewBlind cannot parse, such as model weights or a video.
- *Why:* its contents could not be inspected.
- *Fix:* inspect or remove the file. The scan is marked incomplete.

**RB804 — Archive requires manual/deep inspection**
- *Detects:* ZIP, TAR, GZIP and similar files.
- *Why:* archive contents were not recursively inspected in V1.
- *Fix:* extract the archive and scan the result. The scan is marked incomplete.

**RB805 — ReviewBlind config or report in artifact**
- *Detects:* `.reviewblind.toml`, or a file carrying the ReviewBlind report marker.
- *Why:* these files list your identities in plain text. ReviewBlind itself would be the leak.
- *Fix:* remove the file from the artifact, and keep it outside the repository or untracked.

## Adding a rule

See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-or-changing-a-rule). Rule IDs are permanent.
A retired ID is never reused.
