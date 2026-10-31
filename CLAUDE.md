# ReviewBlind

Deterministic, local-first CLI that preflights research repositories for identity leaks before
double-anonymous review. Python 3.11+, src layout.

**Status:** foundation only. Follow the milestones in `docs/ROADMAP.md`, in order.

## Where things are decided

`docs/` is the specification, so read the relevant file before implementing:

- `SRS.md`: requirements (FR-*, NFR-*). Reference these IDs in tests.
- `RULES.md`: rules and severity. `rules/catalog.py` must match it.
- `ARCHITECTURE.md`: data model, matching, fingerprints, inventory, the Git runner.
- `CLI.md`, `CONFIG.md`, `REPORT_SCHEMA.md`: external interfaces.
- `THREAT_MODEL.md`, `TEST_PLAN.md`: what must be proven.
- `DECISIONS.md`: why. Check it before "fixing" something that looks odd. Record new decisions there.

If code and docs disagree, resolve it deliberately and update both.

## Commands

```bash
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

## Invariants

These are product guarantees, not style preferences:

- Never execute or import scanned code. `setup.py` gets static analysis only.
- Subprocesses only in `utils/git.py`, only allowlisted subcommands. `git status`, `git diff` and
  `git ls-files --modified` are banned: they run repo-defined filters even with hardening flags.
- No network. No writes except the requested report, and the config and `.git/info/exclude`
  during `init`.
- Scanners emit `Detection`. Only `profiles.py` decides severity.
- Anything uninspected is recorded as skipped. Malformed input never crashes a scan.
- Reports are byte-deterministic: no timestamps, sorted output.
- Never output "clean", "anonymous" or "compliant" as a result.
- Stack is frozen (`SRS.md` CON-2). Ask before adding a dependency.

## Git

Show the project owner what will be committed and get confirmation before every commit and push.
Commit messages are one line, with no `Co-Authored-By` or other attribution.

## Fixtures and examples

Use only the fictional persona: Alice Example, Example University, `alice@example.edu`,
`aliceexample`. Never put a real person's details in this repository.

Build Git repositories, PDFs, images and symlinks at test time in `tests/conftest.py`.
