# Decision Log

Writing the specifications exposed contradictions and gaps in the original product
definition. This log records how each one was resolved, so that nobody has to work it out again.

"Spec §N" refers to a numbered section of the original product definition. The other documents
in `docs/` supersede it wherever they differ.

To change a decision, edit the affected documents and add a note to its entry here.

## Open questions

None at the moment. The project owner has settled the earlier ones: the licence stays AGPL-3.0-or-later
(D-01), Hido is <https://hido.fim.ai/> (D-22), and spec sections 1–6 and 42–43 are not needed.

## Contradictions in the spec

### D-01: Licence is AGPL-3.0-or-later

**Issue:** the spec requires a `LICENSE` file and PyMuPDF (§38), but names no licence. PyMuPDF is
dual-licensed: AGPL-3.0 or a paid commercial licence from Artifex. PyPI metadata confirms this.

**Decision:** AGPL-3.0-or-later, confirmed by the project owner. The stack is frozen, and this is the
licence that is clearly compatible with it. The other dependencies are all compatible.

**Alternative, if this is ever revisited:** using MIT or Apache-2.0 would mean replacing PyMuPDF with a
permissively licensed library such as `pypdf`, which changes the frozen stack.

### D-02: There are 33 rules, not 28

**Issue:** spec §29 says "28 rules is enough", but its catalogue lists 32.

**Decision:** the list is authoritative. With RB805 (D-10), the total is 33.

### D-03: Mislabelled rules in the example output

**Issue:** the example in spec §11 uses RB302 for a `pyproject.toml` authors field, and RB503 for
a notebook traceback. The catalogue in §29 assigns these to RB301 and RB502.

**Decision:** the catalogue wins. Examples in these docs use RB301 and RB502.

### D-04: RB502 severity and the evidence-class model

**Issue:** spec §33 gives RB502 severity BLOCKER, including for personal paths. §11 shows a
traceback home path as WARNING, and §12 lists `/home/<user>/` as WARNING. Spec §13 also
requires `IUT` to be WARNING + MEDIUM in one example and REVIEW + LOW in another.

**Decision:** severity also depends on the kind of evidence. Container rules are capped by
evidence class: DIRECT uses the base severity, INDIRECT is WARNING, and AMBIGUOUS is REVIEW. An
acronym in exact case is WARNING + MEDIUM, and in another case is REVIEW + LOW. See
[RULES.md](RULES.md#evidence-classes).

### D-05: Derived aliases are LOW confidence

**Issue:** spec §8 shows a derived alias under MEDIUM confidence. §9 says derived aliases are LOW.
§8 also shows a username at HIGH, sourced from a remote (MEDIUM) and an email local part (LOW).

**Decision:** §9 is the rule. Two independent source classes raise confidence by one level, which
also explains the username in §8. A derived alias on its own stays LOW.

### D-06: Scanners emit `Detection`, not `Finding`

**Issue:** spec §19 has scanners return `Finding`, which includes severity. §30 says "scanners
detect evidence, rules describe policy", and §18 places severity in the pipeline.

**Decision:** scanners yield a policy-free `Detection`, and the pipeline creates the `Finding`.
This is the only way to keep the separation that §30 calls important.

### D-07: "No YAML dependency" is limited to config

**Issue:** spec §15 prefers TOML because it needs no YAML dependency, but §38 includes PyYAML.

**Decision:** there is no real conflict. Config uses `tomllib`, and PyYAML reads only `CITATION.cff`,
always through `safe_load`.

### D-08: Who decides on RB801 when `.git` exists

**Issue:** spec §31 makes `.git` a BLOCKER for `archive`. Every repository has `.git`, so a user
scanning their working copy could never get past this finding, even if they intended to zip
only the source.

**Decision:** RB801 fires unless `scan.exclude` contains `.git/**`, which states that it will not
be packaged. The RB40x escalation to BLOCKER follows the same condition. The recommended path
is to scan an extracted copy of what will ship.

## Gaps in the spec

### D-10: The config and report can leak identity (RB805)

**Issue:** `init` writes all author identities to `.reviewblind.toml` at the repository root, the
very thing being shared. Reports do the same. The spec does not address this, and the product
would itself cause the leak.

**Decision:**
- New rule **RB805**. BLOCKER if the file is tracked, or the target is `archive`.
- `init` adds the config and `reviewblind-report.*` to `.git/info/exclude`. This keeps the
  promise never to modify source files, as it is local and untracked. `--no-exclude` opts out.
- `--config` allows keeping the file outside the repository.
- `scan --output` inside the root prints a warning.

### D-11: `tomllib` cannot write TOML

**Issue:** `init` must write TOML, but `tomllib` only reads it, and the stack is frozen.

**Decision:** a small writer in `config.py`, for this one fixed schema. Strings are escaped per the
TOML specification, and a test confirms each value parses back identically. `init --force` replaces
the whole file, so user comments are not preserved.

### D-12: Git commands can execute repository code

**Issue:** spec §24 lists `git` commands, and §36 forbids executing repository code. These conflict,
because `.git/config` can define commands.

**Decision:** a hardened runner with an allowlist of subcommands. See
[ARCHITECTURE.md §8](ARCHITECTURE.md#8-running-git-safely).

**Evidence:** a probe on Git 2.55 showed that a plain `git status` ran `core.fsmonitor`. With
hardening flags, `fsmonitor` no longer ran, but `git status` and `git ls-files --modified` still ran
a repo-local clean filter. Inventory-mode `ls-files`, `ls-files -s`, `log`, `rev-list` and `remote -v`
ran nothing. Hence `status` is banned, and uncommitted changes are found by hashing blobs directly.

### D-13: What each target inspects

**Issue:** the spec defines targets by severity only, and never says which files are in scope.

**Decision:** see [ARCHITECTURE.md §5](ARCHITECTURE.md#5-inventory). `mirror` and `repository` use tracked
plus untracked non-ignored files. `archive` uses everything, because zipping a folder ignores
`.gitignore`.

### D-14: What makes a scan incomplete

**Issue:** spec §35 shows an unsupported binary as incomplete. §27 and §25 report images and embedded
outputs as REVIEW, without saying if that is incomplete. If it were, every repository with a
PNG would be incomplete, and `--strict` would be useless.

**Decision:** incomplete means an inspection ReviewBlind *should* perform did not happen, or a
whole file was opaque: unreadable, corrupt, encrypted, oversized, an unsupported binary, an archive,
an unfollowed symlink, or truncated or unavailable Git. Image pixels and embedded notebook images
are a documented limit, and are REVIEW findings only.

### D-15: Exit code precedence

**Issue:** spec §14 does not say which code wins when `--strict` is on, the scan is incomplete, and
blockers exist.

**Decision:** 3 wins, as §14 defines 0 and 1 as "scan completed".

### D-16: Missing or empty config

**Issue:** undefined in the spec.

**Decision:** exit code 2. Running without identities would produce a misleading pass.

### D-17: Verdict wording

**Issue:** spec §11 shows only `NOT READY FOR ANONYMOUS REVIEW`. The non-goals rule out any guarantee of
compliance.

**Decision:** four verdicts, none claiming the artifact is anonymous. See
[CLI.md](CLI.md#verdicts). The verdict depends on the findings only, and `--fail-on` affects only
the exit code.

### D-18: Unconfirmed signals

**Issue:** spec §22 says a generic URL is not automatically dangerous. But a manifest author who
isn't in the config, such as a forgotten co-author, is exactly what a preflight must catch.

**Decision:** structured author fields are flagged regardless of the config, excluding placeholders.
Generic hosting URLs are not. See the *Unconfirmed* column in [RULES.md](RULES.md#catalogue).

### D-19: Overlap resolution

**Issue:** `/home/aliceexample/` contains a username, which is a BLOCKER, but spec §12 makes the path
a WARNING. Ranking by severity alone would contradict the spec.

**Decision:** longest span, then higher severity, then lower rule ID.

### D-20: Fingerprint details

**Issue:** spec §17 gives a formula, but concatenating fields without a separator is ambiguous. And
if "evidence" were a line excerpt, an unrelated edit on that line would change it.

**Decision:** fields are separated by a NUL byte. A new `Finding.matched` field holds the exact
value, and is used for fingerprints and `[[allow]]`, while `evidence` remains for display. The
same value twice in one file therefore shares a fingerprint. Full detail is in
[ARCHITECTURE.md §7](ARCHITECTURE.md#7-fingerprints).

### D-21: `identity.urls`

**Issue:** `IdentityKind` includes `URL`, and the export example in §32 includes one, but the config in
§15 has no key for URLs.

**Decision:** add `identity.urls`.

### D-22: Export format details

**Issue:** spec §32 shows a plain list. The spec does not cover ordering or escaping.

**Evidence:** Anonymous GitHub's `src/core/anonymize-utils.ts` (checked October 2026) compiles each term as a
case-insensitive, word-bounded regular expression when it can, applies terms in list order, and
passes binary files through unchanged.

**Decision:** terms go longest first, so a short term cannot break a longer one. `anonymous-github`
escapes only regex syntax characters, and `plain` stays literal. Because binary files pass through
unchanged, PDF and image rules stay at their severity under `mirror`, as §31 specifies.

**Hido:** [Hido](https://hido.fim.ai/) is a hosted service from FIM Labs that "only replaces strings you
list". Its public page and FAQ (checked October 2026) do not document the term format, matching behaviour
or binary handling. `--format hido` therefore emits one literal term per line with no regex escaping, which
is the same as `plain` and is what the spec expects. Milestone M7 checks this against a real Hido dry-run.

### D-23: Text findings under `mirror`

**Issue:** spec §11 suggests fixing a name by configuring the mirror to replace it. But re-scanning
inspects the source, so the finding remains, and §44 expects a clean re-scan before export.

**Decision:** RB101 stays BLOCKER under `mirror`. Authors can fix the source, or record the decision with
`[[allow]]`. `export` does not refuse a report with blockers. Baselines in 1.1 will make this smoother.

### D-24: Matching details

**Issue:** spec §21 says "boundary-aware" without defining it.

**Decision:** see [ARCHITECTURE.md §6](ARCHITECTURE.md#6-matching). A word character is any Unicode letter, mark or
number. This keeps combining marks in scripts such as Bangla from splitting a match, and `_`, `-` and `.`
remain boundaries. Edges in unspaced scripts such as CJK skip the check.

### D-25: Deduplicating Git findings

**Issue:** a name in 5,000 commits should not produce 5,000 findings.

**Decision:** RB402 and RB403 report each unique identity once, with the first commit seen. RB404 reports each
matching commit.

### D-26: Reports have no timestamps

**Issue:** "deterministic" conflicts with the usual report timestamp.

**Decision:** no timestamp. Determinism is testable and useful, and file metadata already records when a
report was made.

## Project setup

### D-30: A fictional persona in all documentation

**Issue:** the spec's examples use what appears to be a real person's name, email and institution. The
repository will be public, and this is a tool for protecting exactly that information.

**Decision:** all docs, examples and fixtures use Dr. Alice Example of Example University, as in spec §39.
`example.edu` is a reserved domain. `pyproject.toml` lists "ReviewBlind contributors" as its author.

### D-31: Extra test files

**Issue:** spec §37 lists no tests for packaging, reporters, exporters, rules, the CLI or safety. §36 requires
safety properties to be tested.

**Decision:** these test files are added. See [TEST_PLAN.md](TEST_PLAN.md#test-allocation).

### D-32: The benchmark has 33 planted leaks

**Issue:** spec §39 asks for 20.

**Decision:** one per rule, so that each rule is proven to fire. This satisfies the original minimum.

### D-33: Binary and Git fixtures are built at test time

**Issue:** spec §37 shows fixture directories, but a nested `.git` cannot be committed, and committed
binaries are opaque.

**Decision:** `conftest.py` generates Git repositories, PDFs, images and symlinks in `tmp_path`.

### D-34: Notebooks use the binary size cap

**Issue:** spec §15 has two size caps, and doesn't say where notebooks fall. A notebook with plots can exceed
the 8 MiB text cap, which would make ordinary notebooks skip inspection.

**Decision:** notebooks use `max_binary_bytes`.

### D-35: Dependency lower bounds

**Decision:** minimums are the versions current in October 2026, which are the ones tested. Loosen them
only with a CI job that tests the lower versions.

### D-36: The CLI entry point is enabled at M2

**Decision:** `[project.scripts]` stays commented out until `cli.py` exists, so that the package never
installs a broken `reviewblind` command.

### D-37: PyMuPDF stays on 1.x

**Issue:** PyMuPDF 2.0 is a meta-package. It requires `pymupdf4llm`, `pymupdf-layout`, `onnxruntime`,
`numpy`, `networkx`, `psutil`, `tabulate` and `pyyaml`, which adds about 100 MB, including an ML
runtime. PyMuPDF 1.28.2 has no dependencies at all. ReviewBlind only needs metadata, XMP, page text and
links, and promises a small stack with no LLM involvement.

**Decision:** `pymupdf>=1.28,<2`, with Dependabot told to ignore major updates.

**Revisit:** at each release, check that 1.x still receives MuPDF security fixes, since parser bugs are
a known risk (T-09). If it stops, re-evaluate 2.x, or a lighter way of installing it.

### D-38: Git severity under `mirror` assumes the mirror hides history

**Issue:** spec §31 makes RB401–RB404 INFO under `mirror`, on the basis that the mirror hides Git history.
Hido lets reviewers `git clone`, and its public documentation does not say what a clone contains.

**Decision:** keep INFO, as specified. This is an assumption about third-party services that ReviewBlind
cannot check, so [LIMITATIONS.md](LIMITATIONS.md#mirror-workflows) tells authors to verify it themselves.
Milestone M7 checks what a Hido clone contains. If it includes author history, this decision is reopened.

### D-39: PyMuPDF crashes on macOS when warnings are errors

**Issue:** on macOS, importing PyMuPDF raises three SWIG `DeprecationWarning`s from native code while its
extension module loads. When warnings are errors, the process segfaults instead of raising an exception, so
it cannot be caught. CI diagnostics on October 31, 2026 showed that `python -W error -c "import pymupdf"`
crashes on Python 3.11 and 3.14, that pytest passes once warnings are not errors, and that pytest on PyMuPDF
1.27.2.3 crashes too, so the 1.x pin is not the cause. The warnings do not appear on Windows.

**Decision:**
- Pytest keeps treating warnings as errors, but ignores exactly these three messages.
- `scanners/pdf.py` must import PyMuPDF with `DeprecationWarning` ignored. A user who sets
  `PYTHONWARNINGS=error` must not get a crash that the engine cannot contain. A Phase 6 test covers this.

## Decisions made during implementation

### D-40: Acronyms apply to every rule, and RB404 is a container rule

**Issue:** the spec requires an acronym to be WARNING + MEDIUM or REVIEW + LOW, but `EU` listed under `aliases`
raises RB101, which is not a container rule, so the three evidence classes could not express it. RB404 also
describes where something was found, like the other container rules, yet an affiliation in a commit message
would have been a BLOCKER while the same text in a README is a WARNING.

**Decision:** a fourth class, `ACRONYM`, and both acronym classes apply to every rule. RB404 is marked ◆.

### D-41: Only contained spans are dropped

**Issue:** spec-derived D-19 said one finding survives an overlap. In `Alice Example University`, the name and
the affiliation overlap on `Example`, and the longer affiliation (a WARNING) would have hidden the name (a
BLOCKER).

**Decision:** a span is dropped only when it lies entirely inside another. All the examples in D-19 still hold.

### D-42: Scanners do not set confidence

**Issue:** `Detection` had an optional confidence override for acronyms and weak signals, but `EvidenceClass` and
each rule's unconfirmed policy already determine both cases.

**Decision:** the field is removed, so `profiles.py` alone decides severity and confidence, as D-06 intends.
`Rule` gains the flags needed to express the catalogue as data.

### D-43: The hardened Git runner moved from M4 to M2

**Issue:** the `mirror` target needs Git's list of tracked files, which the first scan requires, but the runner
was planned for M4, and running Git any other way is forbidden.

**Decision:** the runner and its attack tests are part of M2. M4 adds only the commands the Git scanner needs.

### D-44: Git is found without searching the current directory

**Issue:** `subprocess` and `shutil.which` on Windows look in the current directory first. Running `reviewblind
scan .` in a hostile repository could run the repository's own `git.exe`, breaking the promise never to execute
repository code.

**Decision:** only absolute `PATH` entries outside the scan root are searched. See threat T-15.

### D-45: Per-file limits on matches

**Issue:** a file repeating a name 100,000 times gains nothing from 100,000 report entries, and a hostile file
could exhaust memory. But silently dropping findings could hide a BLOCKER.

**Decision:** at most 5,000 matches are examined and the 1,000 most severe findings are listed per file. Passing
either limit adds a `TOO_MANY_MATCHES` skip, which marks the scan incomplete.

### D-46: Files without a scanner yet are reported as skipped

**Issue:** notebooks, PDFs and images get scanners in M6, and packaging rules arrive in M3. Until then, a scan that
ignored them would claim more than it inspected.

**Decision:** each is recorded as skipped, which marks the scan incomplete. Their names are still checked.

### D-47: A directory name is reported once

**Issue:** a directory named after an author would raise RB106 once for every file inside it.

**Decision:** RB106 is reported against the path up to the matched component, and identical findings are merged.

### D-48: `--strict` arrived early

**Issue:** M3 was to add `--strict`, but incomplete scans already exist in M2, and the flag is one line.

**Decision:** added in M2, with exit code 3.

### D-49: Tool output uses ASCII punctuation

**Issue:** box-drawing characters and em dashes in the tool's own text become escape sequences on consoles using
a legacy code page, such as Windows cp1252.

**Decision:** the tool's own text is ASCII. Repository text keeps its real characters, and characters the console
cannot show are escaped rather than crashing the report.

### D-50: Nested `.git` directories are reported too

**Issue:** RB801 described "a `.git` directory", and the inventory skipped every `.git` it met. An archive of a
folder holding a vendored repository would ship that repository's history without any finding.

**Decision:** every `.git` in the tree raises RB801, unless excluded. Only the one at the root affects RB401-RB404,
because that is the history the Git scanner reads.

### D-51: ReviewBlind's own files are a kind of artifact

**Issue:** FR-PKG-3 requires a config or report to be reported rather than scanned as text. Spec section 16 lists seven
artifact kinds, and an ordinary text scan of a saved report would produce one finding per identity it mentions.

**Decision:** an eighth kind, `REVIEWBLIND`, set by file name or by a report's first bytes. All three report formats are
recognized, including terminal output saved as UTF-16 by Windows PowerShell's `>` operator, since that is the easiest
way to end up with a report in the repository.

### D-52: Operating-system files are not also unread binaries

**Issue:** `.DS_Store` and `Thumbs.db` are binary, so they would raise both RB802 and RB803, and mark the scan incomplete.

**Decision:** RB802 only, and the scan stays complete. Its only meaning is that the file should not ship, and the fix is
to delete it, not to inspect it.

### D-53: Report files are written like configs

**Issue:** `--output` could be pointed at a symlink planted in the repository, and a report lists author identities.

**Decision:** writing through a symlink is refused, with exit code 2. Files are created through a temporary file readable
only by the owner, then moved into place.

### D-54: JSON and Markdown on stdout are always UTF-8

**Issue:** on a legacy Windows code page, characters would become `\xNN` escapes, which are not valid JSON.

**Decision:** those formats switch stdout to UTF-8 with LF line endings. Only the terminal format adapts to the console.

### D-55: `--fail-on info` fails in every Git repository

**Issue:** spec section 31 makes RB801 INFO under `mirror`, so every Git repository has at least one INFO finding, and
`--fail-on info` always fails there.

**Decision:** kept as specified. INFO is context, and `--fail-on info` is unusual. The verdict does not change.
