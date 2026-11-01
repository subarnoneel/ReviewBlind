# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Product, requirements, architecture, threat-model, rule, CLI, config, report, test-plan and
  roadmap documentation.
- Project scaffolding: packaging, lint, type-check and test configuration; CI; and GitHub templates.
- Core model: data types, the 33-rule catalogue, severity resolution, identity matching, stable
  fingerprints, and config reading, validation and writing.
- `reviewblind scan` for text files and file names, with `--target`, `--config`, `--fail-on` and `--strict`, and
  `reviewblind rules`. Notebooks, PDFs, images and Git history are not inspected yet, and are reported as skipped.
- A hardened Git runner that cannot be made to run repository-defined code.
- JSON and Markdown reports with `--format` and `--output`, byte-identical across runs.
- Exact `[[allow]]` suppressions, which stay visible in the JSON report.
- Packaging checks: `.git`, operating-system files, unknown binaries, archives, and ReviewBlind's own config and reports.
- Git history checks: remotes, authors, committers, emails and commit messages, with `--max-commits`.
- Manifest checks: `pyproject.toml`, `package.json`, `setup.cfg`, `setup.py`, `CITATION.cff`, and license and authors files.
- `reviewblind discover`, which finds likely identities from Git, manifests and LaTeX, and writes nothing.
- `reviewblind init`, which lets you confirm them, writes `.reviewblind.toml` and adds it to `.git/info/exclude`.
- Notebook checks: cells, saved outputs, tracebacks and metadata, located by field.
- PDF checks: metadata, XMP, page text and links.
- Image checks: EXIF, GPS and PNG text, without decoding pixels, plus a manual-review finding for every image.
