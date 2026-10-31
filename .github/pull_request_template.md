## What and why

<!-- What does this change, and why? Link the issue, or the SRS requirement ID. -->

## Checklist

- [ ] `ruff check`, `ruff format --check`, `mypy` and `pytest` all pass
- [ ] Tests cover the change
- [ ] Relevant files in `docs/` are updated, and `CHANGELOG.md` if users will notice
- [ ] New rule: catalog, `docs/RULES.md`, detection and false-positive tests, and a benchmark entry
- [ ] Reads untrusted input: considered size caps and malformed files, and failures are recorded as skipped
- [ ] Committed data uses only the fictional persona, with no real names, emails or paths
