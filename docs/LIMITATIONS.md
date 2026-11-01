# Limitations

A report with no findings means ReviewBlind found nothing **it knows how to look for**. It
does not mean your artifact is anonymous. Please read this before relying on a result.

## You are responsible for

- **Listing identities.** Discovery suggests candidates, and you confirm them. A co-author
  you do not list is only caught through structural signals, such as a manifest author field.
- **Your venue's rules.** ReviewBlind does not know any conference's policy. Check it yourself.
- **Looking at flagged files.** A `REVIEW` finding means a person has to look.

## Discovery only suggests

`reviewblind init` proposes identities, and you decide. In particular:

- A fork or imported history lists upstream authors. Anyone with two or more commits counts as HIGH
  confidence, so `--yes` would accept them. Review the list rather than using `--yes` on such a repository.
- A co-author with one commit is only MEDIUM, so it is not selected for you.
- Only manifests at the top of the directory are read, to avoid suggesting the authors of vendored code.

## Not detected

### Name variations

Matching is exact after Unicode normalization and casefolding. There is no fuzzy matching. Add
each form you use as an alias.

| Configured | Not matched without an alias |
|---|---|
| `Alice Example` | `Example, Alice` |
| `Alice Example` | `A. Example` |
| `José García` | `Jose Garcia` |
| `Alice Example` | `Alice B. Example` |

### Visual and embedded content

- Text, logos or faces in images, including embedded notebook images. Each one gets a `REVIEW` finding.
- Scanned PDFs, or text rendered as images inside a PDF.
- Video and audio.
- Text in figures that only appears after rendering.

### Git

For `repository` and `archive` with `.git`, these are **not** inspected in 0.1.0:

- **File contents in past commits.** A name removed from the README last year is still in
  history. `GitScanner` reads commit metadata and messages only. For a public anonymous
  repository, **publish a fresh history**.
- Annotated tag authors and messages.
- Git notes, reflogs, stashes and unreachable objects.
- Submodule contents and history.

Forks and repositories with imported history show upstream authors as candidates and
as unconfirmed findings at the `repository` target.

### Manifests

- `setup.py` is parsed and never run, so a computed value such as `author=get_author()` is not read as
  metadata. Ordinary text matching still covers the rest of the file.
- Copyright holders are recognized from common forms, such as `Copyright (c) 2026 Name`. Unusual wording is
  only caught when it contains a confirmed identity.

### Formats

- Contents of ZIP, TAR and other archives. They are reported, and mark the scan incomplete.
- DOCX, PPTX and XLSX contents. They are treated as unsupported binaries and also mark the
  scan incomplete. DOCX support is planned for 1.1.
- Model weights, pickle files, HDF5 and other binary data formats. Metadata inside them can
  name the author.
- PDF named destinations and hyperref citation keys, planned for 1.1.
- PDF annotations, bookmarks and embedded file attachments.
- Notebooks older than format version 4. They are reported as unreadable, and mark the scan incomplete.
- Image metadata outside the fields listed in the requirements, such as camera maker notes.
- Text in encodings other than UTF-8, which are treated as binary and reported.

### Beyond the repository

- Stylometry, writing style or code style.
- Your public pre-print, talks, social media or a search for your paper's title.
- Self-citations in the paper itself.
- Dataset, topic or domain clues that only a few groups could match.
- Whether a remote repository matches your local one. ReviewBlind reads the working tree and
  never contacts the remote. Fixing a leak locally does not fix what was pushed.

## Known noise

- `RB703` fires on every image by design. Repositories with many images will list many of them.
- Files containing a real name for legitimate reasons, such as bibliographies, need an
  `[[allow]]` entry.
- Short usernames and acronyms produce more false positives. Acronyms are handled specially
  (see [RULES.md](RULES.md#evidence-classes)), but a username such as `max` will match the word `max`.
- Any binary file, including ordinary model weights, marks the scan incomplete. That is
  intentional: `--strict` will fail until those files are removed from the artifact, or
  excluded because they will not ship.

## Mirror workflows

- Term replacement only rewrites text. Mirrors pass binary files through unchanged, so PDF
  and image findings remain BLOCKER or WARNING under `--target mirror`.
- If you rely on the mirror to replace a term in text, the finding stays in the report on
  every re-scan, because ReviewBlind inspects the source and not the mirror's output. Record
  that decision with an `[[allow]]` entry. Baselines, planned for 1.1, will make this easier.
- `--target mirror` assumes the mirror hides your Git history, so Git findings are only INFO. ReviewBlind
  cannot verify that. Hido, for example, lets reviewers `git clone`, and its documentation does not say what
  a clone contains. Clone your own anonymized link and run `git log` on it.
- Mirrors may not rewrite everything. Hido, for example, does not recurse into submodules.
- An exported term list leaves out institutional hostnames, scheduler values and unconfirmed usernames in home
  paths, and it cannot match a name split across fields or lines. See [CLI.md](CLI.md#reviewblind-export-report).
- `--format hido` has not been tried against a real Hido dry-run, and Hido does not document its term format.
- Always open the anonymized URL and check it yourself before submitting.

## Security limitations

- Malformed PDFs and images are parsed in-process by C libraries (MuPDF and Pillow). There is
  no sandbox in 0.1.0. Be careful when scanning repositories from people you do not trust.
- ReviewBlind's own report and config contain your identities in plain text. Treat them as
  private. See [THREAT_MODEL.md](THREAT_MODEL.md#threats-from-reviewblinds-own-output).
