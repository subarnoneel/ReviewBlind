# Roadmap

Each milestone ends with something that runs and passes CI. Later milestones build on earlier
ones, so they should be done in order.

## M0 — Foundation

**Status: done.** Specifications, repository scaffolding, CI passing on Linux, macOS and Windows, and a
package that builds with one smoke test.

## M1 — Core model

**Tests:** +27, for 27 in total.

**Deliver:** `models.py`, `rules/catalog.py`, `rules/registry.py`, `profiles.py`,
`fingerprints.py`, `matching.py`, `config.py`, and `utils/text.py`.

**Exit criteria:**
- The catalog has all 33 rules, and a test confirms it matches `docs/RULES.md`.
- Severity resolves correctly for every rule and target.
- All matching cases in the test plan pass.
- Config reads, validates and writes, with round-trip tests.

## M2 — First working scan

**Tests:** +22, for 49 in total.

**Deliver:** `utils/git.py` with its attack tests, `utils/files.py`, `inventory.py`, `signals.py`, `engine.py`,
`scanners/base.py`, `scanners/text.py`, `scanners/paths.py`, `reporters/terminal.py`, `cli.py` with `scan` and
`rules`, and `__main__.py`. Enable `[project.scripts]` in `pyproject.toml`.

**Exit criteria:**
- `reviewblind scan .` works on a text-only repository.
- Exit codes 0, 1, 2, 3 and 4 work.
- `inventory` applies each target's scope.
- No attack test can make Git run repository-defined code.
- Files no scanner can read yet are reported as skipped, never as inspected.

## M3 — Reports and completeness

**Tests:** +14, for 63 in total.

**Deliver:** `reporters/json.py`, `reporters/markdown.py`, `scanners/packaging.py`,
allowlist handling, and the incomplete-scan state.

**Exit criteria:**
- JSON conforms to `docs/REPORT_SCHEMA.md`, and two runs are byte-identical.
- RB801–RB805 fire. The output-injection tests pass.
- A saved report is recognized in every format, so re-scanning does not flood.

## M4 — Git and manifests

**Tests:** +20, for 83 in total. This passes the 70-test floor.

**Deliver:** `scanners/git.py` and `scanners/manifests.py`.

**Exit criteria:**
- `log`, `rev-list` and `remote -v` join the Git runner's allowlist only with an attack test for each.
- RB301–RB304 and RB401–RB404 fire, with correct severity per target.

## M5 — Discovery and init

**Tests:** +13, for 96 in total.

**Deliver:** `discovery/`, and the `discover` and `init` commands.

**Exit criteria:**
- `init` then `scan` works end to end on a fresh repository.
- `.git/info/exclude` is updated, and no tracked file is changed.
- `--yes` accepts HIGH candidates only. A non-interactive run without `--yes` exits with code 2.

## M6 — Rich formats

**Tests:** +20, for 116 in total.

**Deliver:** `scanners/notebook.py`, `scanners/pdf.py`, and `scanners/image.py`.

**Exit criteria:**
- RB501–RB504, RB601, RB602 and RB701–RB703 fire.
- The `malformed_repo` fixture completes without a crash.
- Pixels are never decoded; size caps are enforced before parsing.
- `python -W error` can import `scanners/pdf.py` without crashing, on macOS too
  ([D-39](DECISIONS.md#d-39-pymupdf-crashes-on-macos-when-warnings-are-errors)).

## M7 — Export and benchmark

**Tests:** +11, for 127 in total.

**Deliver:** `exporters/terms.py`, the `export` command, the full `leaking_repo` and
`clean_repo` fixtures, and `test_integration.py`.

**Exit criteria:**
- All 33 planted leaks are detected, with correct severity on all three targets.
- `clean_repo` has no findings at WARNING or above.
- The complete safety test suite passes on all operating systems.
- A real Hido dry-run accepts an exported term list, and a clone of the resulting link has been checked
  for author history ([D-38](DECISIONS.md#d-38-git-severity-under-mirror-assumes-the-mirror-hides-history)).
  This needs the project owner's account.

## M8 — Dogfood and release

**Needs from the project owner:** at least 3 real research repositories to scan. Their reports stay
outside this repository.

**Deliver:** runs on those repositories; regression tests for what they
reveal; a real `examples/sample-report.md`; and an updated `CHANGELOG.md`.

**Exit criteria:** every item below is checked.

## Definition of done for 0.1.0

- [ ] `pip` and `uv` install both work
- [ ] `reviewblind init` works
- [ ] `reviewblind discover` works
- [ ] `reviewblind scan` works
- [ ] `reviewblind export` works
- [ ] `reviewblind rules` works
- [ ] `mirror`, `archive` and `repository` target profiles work
- [ ] Text scanner
- [ ] Path scanner
- [ ] Manifest scanner
- [ ] Git scanner
- [ ] Notebook scanner
- [ ] PDF scanner
- [ ] Image scanner
- [ ] Packaging scanner
- [ ] Stable fingerprints
- [ ] Terminal report
- [ ] JSON report
- [ ] Markdown report
- [ ] Explicit incomplete-scan state
- [ ] 70+ tests
- [ ] CI passing
- [ ] Zero execution of inspected code, verified by tests
- [ ] Threat model documented, and updated to match the implementation
- [ ] Limitations documented, and updated to match the implementation
- [ ] Dogfooded against at least 3 research repositories

## Not part of 0.1.0

`bundle`, `adjudicate`, baselines, SARIF, HTML reports, DOCX, recursive archives, hyperref
internals, venue profiles, MCP, LLMs, stylometry.

## After 0.1.0

### 1.1 (only after using 0.1.0 on real repositories)

- Baselines and adjudication, built on existing fingerprints
- SARIF output
- DOCX metadata
- Safe ZIP and TAR inspection
- A hyperref named-destination scanner

### Candidates to evaluate

- `reviewblind bundle`. Not committed until scanning itself works extremely well.
- Annotated tag authors, and file contents in Git history.
- Process isolation for PDF and image parsing.
- A reduced-output mode that is safe for public CI logs.
