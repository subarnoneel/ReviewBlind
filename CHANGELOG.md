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
