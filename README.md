# ReviewBlind

**A deterministic, local-first CLI that preflights research repositories for accidental
identity disclosure before double-anonymous peer review.**

> **Status: pre-alpha, and not ready for real submissions.** `reviewblind scan` and `reviewblind rules` work on
> text files, file names, manifests, Git metadata and packaging. Notebooks, PDFs and images are reported as skipped.
> The other commands below are planned. Progress is tracked in the [roadmap](docs/ROADMAP.md).

## Why

You removed your name from the README. But is it still in:

- a traceback saved inside a notebook, as `/home/yourname/miniconda3/...`?
- the `Author` metadata of a figure exported to PDF?
- `pyproject.toml`, `CITATION.cff` or `LICENSE`?
- a `wandb.ai/yourname/` link in a config file?
- the `.git` directory inside your supplementary ZIP?

ReviewBlind finds these before a reviewer does, and tells you exactly where each one is and
why it matters.

## How it will work

```bash
# Find likely identities, confirm them, and write .reviewblind.toml
reviewblind init .

# Scan for how you plan to share the artifact
reviewblind scan . --target mirror       # through an anonymizing proxy
reviewblind scan . --target archive      # as a supplementary ZIP
reviewblind scan . --target repository   # as a public anonymous repository

# Create a term list for Anonymous GitHub or Hido
reviewblind scan . --format json -o ../report.json
reviewblind export ../report.json --format anonymous-github
```

Example finding:

```text
WARNING  RB502  HIGH
notebooks/error_analysis.ipynb
output[7].traceback[3]

/home/aliceexample/miniconda3/envs/nlp/...

Reason:
Notebook execution output exposes a personal workstation username.
```

## What it inspects

| Area | Examples |
|---|---|
| Text and code | Names, emails, usernames, affiliations, profile URLs |
| Paths and services | Home directories, institutional hostnames, W&B and Hugging Face namespaces, SLURM directives |
| Manifests | `pyproject.toml`, `package.json`, `setup.py`, `setup.cfg`, `CITATION.cff`, `LICENSE` |
| Git | Remotes, authors, committers, emails, commit messages |
| Notebooks | Cells, outputs, tracebacks, kernel and editor metadata |
| PDFs | Metadata, XMP, extractable text, exposed URLs |
| Images | EXIF, GPS, PNG text metadata |
| Packaging | `.git`, `.DS_Store`, archives, unknown binaries |

See the [33 rules](docs/RULES.md).

## Design commitments

- **Read-only.** It never edits your files or rewrites Git history.
- **Local and inert.** No network access, no LLM, and repository code is never executed.
- **Deterministic.** The same input gives a byte-identical report.
- **Honest.** "Nothing found" and "could not inspect everything" are separate results.

## What it does not do

ReviewBlind does not guarantee conference-policy compliance, anonymize the public internet,
perform stylometric analysis, or recognize faces. It does not replace anonymization proxies
such as [Anonymous GitHub](https://github.com/tdurieux/anonymous_github) or
[Hido](https://hido.fim.ai/); it helps you use them well.

A report with no findings does **not** mean your artifact is anonymous. Please read the
[limitations](docs/LIMITATIONS.md).

> **Privacy note:** `.reviewblind.toml` and scan reports contain your identities in plain text.
> Keep them out of the artifact you share.

## Documentation

| Document | Contents |
|---|---|
| [PRODUCT](docs/PRODUCT.md) | What this is, who it is for, and what it refuses to do |
| [SRS](docs/SRS.md) | Testable requirements |
| [CLI](docs/CLI.md) | Commands, flags, exit codes |
| [CONFIG](docs/CONFIG.md) | `.reviewblind.toml` reference |
| [RULES](docs/RULES.md) | Every rule, with severity for each target |
| [REPORT_SCHEMA](docs/REPORT_SCHEMA.md) | JSON and Markdown report formats |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Internal design |
| [THREAT_MODEL](docs/THREAT_MODEL.md) | Deanonymization vectors, and attacks on the tool itself |
| [LIMITATIONS](docs/LIMITATIONS.md) | What ReviewBlind cannot see |
| [TEST_PLAN](docs/TEST_PLAN.md) | How requirements are verified |
| [ROADMAP](docs/ROADMAP.md) | Milestones and the definition of done |
| [DECISIONS](docs/DECISIONS.md) | Why ambiguous points were resolved as they were |

## Development

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```

See [CONTRIBUTING](CONTRIBUTING.md).

## License

[GNU AGPL-3.0-or-later](LICENSE). ReviewBlind depends on PyMuPDF, which is available under the
AGPL or a commercial licence. See [the decision log](docs/DECISIONS.md#d-01-licence-is-agpl-30-or-later).
