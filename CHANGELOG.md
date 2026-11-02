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
  `reviewblind rules`.
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
- `reviewblind export`, which turns a JSON report into a term list for Anonymous GitHub, Hido or a plain file.
- A benchmark of 33 planted leaks, one for each rule, and a corpus of lookalikes that must stay quiet.

### Fixed

- A Git history under a neutral identity such as `Anonymous Authors` is no longer a warning on `repository`.
- A config saved with a byte order mark, as PowerShell's `Out-File` writes it, can now be read.
- Progress bars and other JSON notebook outputs are read as text, rather than reported as embedded binary output.
- Default account names such as `C:\Users\hp` are no longer reported as personal home paths, and ImgBot is treated as a bot.
- Default excludes such as `__pycache__` now apply anywhere in the tree.
- Tracking is treated as unknown when a repository's Git index is missing, which keeps RB805 a blocker.
- `discover` lists each person in a license that names several.

### Changed

- The name of a Colab account that ran a cell is reported by RB503 even when it is not in the config.
- Kaggle input paths such as `/kaggle/input/datasets/<user>/` are reported by RB203, and in notebooks by RB501 to RB503.
- A home path in a notebook cell is reported for review when its user is not in the config, as it is in other text files.
