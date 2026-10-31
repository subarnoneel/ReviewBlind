# Contributing to ReviewBlind

## Protect your own anonymity

ReviewBlind's users are often preparing work under anonymous review, and issues here are public.

**Never post a real report, a real `.reviewblind.toml`, or real names, paths or URLs from your
project.** Reproduce the problem with the fictional persona below.

| Field | Value |
|---|---|
| Name | Alice Example |
| Affiliation | Example University |
| Email | `alice@example.edu` |
| Username | `aliceexample` |

Everything committed to this repository, including test fixtures, must use only this persona.

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

## Before opening a pull request

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

CI runs these on Linux, macOS and Windows.

## Rules that do not bend

These are product guarantees, listed in [the threat model](docs/THREAT_MODEL.md#security-properties).
A pull request that weakens any of them will not be accepted.

- Never execute or import anything from a scanned repository.
- Never start a subprocess outside `utils/git.py`, and never add a Git subcommand to its
  allowlist without a test showing it cannot run repository-defined commands. In particular,
  `git status` and `git diff` stay banned.
- Never open a network connection.
- Never modify scanned files.
- Never use `yaml.load`. Always use `yaml.safe_load`.
- Never decode image pixels, and never unpack an archive.
- A scanner never decides severity. It emits a `Detection`.
- Anything not inspected must be recorded as skipped. Never fail silently.
- Never print "clean", "anonymous" or "compliant" as a result.

## Code conventions

- Fully typed; `mypy --strict` must pass.
- Data structures are frozen dataclasses where possible.
- Dependencies point the way [the architecture](docs/ARCHITECTURE.md#dependency-direction) shows.
- New runtime dependencies need a discussion first, because the stack is deliberately small.
- Regular expressions over file content must be linear-time, with no nested quantifiers.

## Adding or changing a rule

1. Add or update it in `src/reviewblind/rules/catalog.py`.
2. Update [docs/RULES.md](docs/RULES.md). A test keeps these two in step.
3. Add a detection test, and a false-positive test.
4. Add a planted leak to the benchmark in `tests/fixtures/leaking_repo/` and to the table in
   [docs/TEST_PLAN.md](docs/TEST_PLAN.md).
5. Update `CHANGELOG.md`.

Rule IDs are permanent. A retired ID is never reused.

## Reporting a false positive or a missed leak

These are the most valuable reports. Please use the issue template, and reproduce the problem
with the fictional persona. Each confirmed case becomes a regression test.

## Pull requests

- Keep each pull request focused on one change.
- Include tests for any behaviour change.
- Update the relevant documents in `docs/`. If behaviour changes a decision, note it in
  [docs/DECISIONS.md](docs/DECISIONS.md).
- Use short, imperative commit subjects, such as `Add RB502 traceback detection`.

## Security issues

Please do not open a public issue. See [SECURITY.md](SECURITY.md).
