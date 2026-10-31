# Test Plan

## Goals

At least 70 meaningful automated tests for 0.1.0. The count is a floor, not the objective.
The objective is to prove three things:

1. ReviewBlind finds the leaks it claims to find.
2. It stays quiet on ordinary research code.
3. It keeps its safety properties on hostile input.

## Tools

`pytest`, `pytest-cov`, `ruff`, `mypy --strict`. CI runs on Linux, macOS and Windows.

## Test allocation

| File | Area | Planned |
|---|---|---|
| `test_discovery.py` | Identity discovery | 10 |
| `test_matching.py` | Matching | 10 |
| `test_text_scanner.py` | Text and path scanners | 10 |
| `test_manifest_scanner.py` | Manifests | 7 |
| `test_git_scanner.py` | Git | 8 |
| `test_notebook_scanner.py` | Notebooks | 8 |
| `test_pdf_scanner.py` | PDF | 6 |
| `test_image_scanner.py` | Images | 5 |
| `test_profiles.py` | Severity for each target | 4 |
| `test_integration.py` | End to end, including the benchmark | 5 |
| **Subtotal** | | **73** |
| `test_config.py` | Config parsing, validation and writing | 6 |
| `test_inventory.py` | Scope for each target, symlinks, excludes | 6 |
| `test_fingerprints.py` | Fingerprint stability | 4 |
| `test_packaging_scanner.py` | Packaging, including RB805 | 5 |
| `test_rules.py` | Catalogue integrity | 3 |
| `test_reporters.py` | Terminal, JSON, Markdown | 6 |
| `test_exporters.py` | Term lists | 4 |
| `test_cli.py` | Commands, flags, exit codes | 8 |
| `test_safety.py` | Security properties | 12 |
| **Total** | | **127** |

## Key cases

### Matching

- NFC and NFD forms of `José` match each other.
- Casefolding: `STRASSE` matches `Straße`, with correct columns in the original text.
- `Alice Example` does not match inside `MalicE Examples`.
- `aliceexample` matches in `aliceexample_data.csv` and `aliceexample-v2`.
- `Alice Example` matches across a line break.
- A Bangla name is not matched when a following combining mark would split a syllable.
- A CJK name matches when followed directly by another CJK character.
- Overlaps resolve as listed in [ARCHITECTURE.md §6](ARCHITECTURE.md#6-matching).
- An acronym in exact case gives WARNING + MEDIUM, and in another case gives REVIEW + LOW.
- Needles containing regex metacharacters, such as `A. Example (PhD)`, match literally.

### Severity

- Every rule resolves correctly on every target (parametrized from the catalog).
- RB402 is INFO for `mirror`, INFO for `archive`, and BLOCKER for `repository`.
- RB402 is BLOCKER for `archive` when `.git` is packaged.
- RB601 is BLOCKER on every target. RB801 is BLOCKER for `archive` only.
- RB502 with a home path gives WARNING; with a name it gives BLOCKER.

### Catalogue integrity (`test_rules.py`)

- The catalog has exactly the IDs in `docs/RULES.md`, parsed from that file.
- Every rule has non-empty text and valid severities for every target.
- Every rule ID emitted by a scanner exists in the catalog.

### Exit codes (`test_cli.py`)

- Each of codes 0, 1, 2 and 3 is reached, and `--fail-on` shifts the threshold.
- Code 4 is reached by injecting a failure into the engine.
- With `--strict`, an incomplete scan with blockers returns 3.
- Without `--strict`, an incomplete scan returns 0 or 1 by threshold.
- A missing config, and a config with no identities, return 2.
- The verdict never contains "clean", "anonymous" (other than in the verdict line "NOT READY
  FOR ANONYMOUS REVIEW") or "compliant".

### Determinism

- Two runs on the same input produce byte-identical JSON.
- Shuffling file-system enumeration does not change the output.

## Safety tests

`test_safety.py` covers these, and each maps to [THREAT_MODEL.md](THREAT_MODEL.md).

| Property | Test |
|---|---|
| No code execution (T-01) | `setup.py` and `conftest.py` that write a marker on import; scan; no marker |
| Git config (T-02) | `core.fsmonitor`, `core.hooksPath`, `core.pager` and `core.sshCommand` each set to write a marker; no marker |
| Git filters (T-03) | Same-size edit under a hostile `filter.<x>.clean`; no marker |
| Git subcommand allowlist (T-03) | The runner rejects `status`, `diff`, `fetch` and others |
| Nested bare repository (T-04) | Hostile bare repository in the tree; no marker |
| Symlink escape (T-05) | A link to a file outside the root; its contents are absent from the report |
| Writes through links (T-06) | `init` refuses a symlinked config target |
| No network (T-13) | `socket.socket` patched to raise; the scan still passes |
| No modification (NFR-SAFE-5) | A hash of every file and of `.git` before and after a scan is unchanged |
| Size caps (T-07) | A file over the cap is not opened by a parser, and is recorded as skipped |
| Malformed input (T-07, T-09) | The `malformed_repo` fixture completes without an exception |
| Output injection (T-10, T-11) | ANSI, Rich markup and Markdown payloads are neutralized |

Symlink tests are skipped on Windows when the process lacks the privilege to create links.

## Benchmark: the planted-leak repository

ReviewBlind's own benchmark is a synthetic repository for a fictional researcher:

```text
Dr. Alice Example
Example University
alice@example.edu
aliceexample
```

It plants **one leak per rule, 33 in total**, exceeding the original minimum of 20.
`test_integration.py` requires every expected finding, with the severity from
[RULES.md](RULES.md), on all three targets. A missed leak fails the build.

| ID | Rule | File | Planted leak |
|---|---|---|---|
| L01 | RB101 | `README.md` | `Dr. Alice Example` |
| L02 | RB102 | `README.md` | `alice@example.edu` |
| L03 | RB103 | `scripts/train.py` | `# maintained by aliceexample` |
| L04 | RB104 | `docs/setup.md` | `Example University` |
| L05 | RB105 | `README.md` | `https://github.com/aliceexample` |
| L06 | RB106 | `data/aliceexample_results.csv` | The file name |
| L07 | RB201 | `configs/paths.yaml` | `/home/aliceexample/data` |
| L08 | RB202 | `scripts/fetch.sh` | `cluster.cs.example.edu` |
| L09 | RB203 | `configs/tracking.yaml` | `https://wandb.ai/aliceexample/proj` |
| L10 | RB204 | `scripts/clone.sh` | `github.com/aliceexample/private-tools.git` |
| L11 | RB205 | `slurm/train.sbatch` | `#SBATCH --mail-user=a.example@cs.example.edu` |
| L12 | RB301 | `pyproject.toml` | `authors` field |
| L13 | RB302 | `package.json` | `homepage` on `aliceexample.github.io` |
| L14 | RB303 | `CITATION.cff` | Author entry |
| L15 | RB304 | `LICENSE` | `Copyright (c) 2026 Alice Example` |
| L16 | RB401 | Git remote | `git@github.com:aliceexample/paper.git` |
| L17 | RB402 | Git history | Author `Alice Example` |
| L18 | RB403 | Git history | Email `alice@example.edu` |
| L19 | RB404 | Git history | `Signed-off-by: Alice Example` |
| L20 | RB501 | `notebooks/analysis.ipynb` | Markdown cell with the name |
| L21 | RB502 | `notebooks/analysis.ipynb` | Traceback through `/home/aliceexample/` |
| L22 | RB503 | `notebooks/analysis.ipynb` | Metadata path |
| L23 | RB504 | `notebooks/analysis.ipynb` | Embedded PNG output |
| L24 | RB601 | `figures/architecture.pdf` | `Author` metadata |
| L25 | RB602 | `figures/poster.pdf` | Name in page text |
| L26 | RB701 | `figures/plot.jpg` | EXIF `Artist` |
| L27 | RB702 | `figures/field-site.jpg` | EXIF GPS |
| L28 | RB703 | `figures/team-photo.png` | Any image |
| L29 | RB801 | `.git` | The directory itself |
| L30 | RB802 | `.DS_Store` | The file itself |
| L31 | RB803 | `results/model-output.bin` | The file itself |
| L32 | RB804 | `data/raw.zip` | The file itself |
| L33 | RB805 | `.reviewblind.toml` | Tracked config |

A manifest in `tests/fixtures/leaking_repo/expected.toml` holds this table in machine-readable form.

## Fixtures

| Fixture | Purpose | Expected result |
|---|---|---|
| `clean_repo/` | False-positive corpus | No findings at WARNING or above |
| `leaking_repo/` | The benchmark above | Every expected finding |
| `malformed_repo/` | Robustness | No crash; skipped entries; exit 3 with `--strict` |

**`clean_repo` must contain lookalikes**, so it proves something:

- `Alicia Examples`, `malice example` and `example` on its own
- `github.com/pytorch/pytorch` and `huggingface.co/bert-base-uncased`
- `/home/user/` and `C:\Users\runner\`
- `Author: Anonymous Authors` in a manifest

**`malformed_repo` contains:** a truncated notebook, broken TOML, invalid YAML in
`CITATION.cff`, a `setup.py` with a syntax error, very deeply nested JSON, a corrupt PDF, an
encrypted PDF, a corrupt PNG, a binary file named `.py`, and a non-UTF-8 text file.

### Fixtures built at test time

Some fixtures cannot or should not be committed. `tests/conftest.py` builds them in `tmp_path`:

- **Git history:** a repository cannot contain a nested `.git`.
- **PDFs and images:** created with PyMuPDF and Pillow, so the repository holds no opaque binaries.
- **Symlinks:** these do not survive checkout on all platforms.

Every committed fixture file uses only the Alice Example persona and `example.edu`, which is a
reserved domain. Real names must never appear.

## Dogfooding

Before release, run against at least 3 real research repositories. Record, for each one, its
findings, false positives, missed leaks and any crash, in a private note. Publish only
aggregate results, because the raw reports contain identities.

Each false positive or missed leak becomes a regression test, using the fictional persona.
