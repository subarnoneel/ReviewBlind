# Threat Model

ReviewBlind faces two different threats, which are easy to confuse:

- **Part A — Deanonymization.** A reviewer works out who the authors are. This is the
  problem the product addresses.
- **Part B — ReviewBlind as an attack surface.** A hostile repository attacks the person
  running the tool, or the tool itself causes a leak. This is the problem the product must
  not create.

## Part A: Deanonymization

### Assets

The link between an artifact and its authors, their institution and their funding.

### Adversary

A reviewer who is curious, or who stumbles on a clue, using ordinary tools: a text editor,
PDF properties, `git log`, a web search. Motivated forensic analysis is out of scope.

### Vectors

| Vector | Example | Rules | Residual risk |
|---|---|---|---|
| Direct text | Name in README | RB101–RB105 | Name forms not configured as aliases |
| File and directory names | `aliceexample_results.csv` | RB106 | |
| Workstation traces | `/home/aliceexample/` | RB201 | |
| Infrastructure | `cluster.cs.example.edu` | RB202 | Hostnames unrelated to a confirmed email domain |
| Service accounts | `wandb.ai/aliceexample` | RB203, RB204 | Accounts under an unconfigured name |
| HPC scripts | `#SBATCH --mail-user=` | RB205 | |
| Package metadata | `pyproject.toml` authors | RB301, RB302 | |
| Citation and legal files | `CITATION.cff`, `LICENSE` | RB303, RB304 | |
| Git metadata | Remotes, authors, messages | RB401–RB404 | Tag authors and old file contents (see below) |
| Notebook residue | Traceback paths | RB501–RB504 | Text inside embedded images |
| PDF metadata and text | `Author` field | RB601, RB602 | Text inside figures; hyperref destinations (1.1) |
| Image metadata | EXIF `Artist`, GPS | RB701, RB702 | Visible content: logos, faces, lab photos |
| Packaging residue | `.git`, `.DS_Store` | RB801, RB802 | |
| Opaque files | Weights, videos, archives | RB803, RB804 | All content, which is reported honestly as uninspected |

### Out of scope

These are not detected. [LIMITATIONS.md](LIMITATIONS.md) lists them in full.

- Writing style, code style, and research topic
- Public pre-prints, talks, or searching for the title online
- Self-citations in the paper itself
- Domain knowledge such as "only one lab has this dataset"
- Face or logo recognition

### The central risk: false assurance

A tool that says "all good" when it did not look is worse than no tool. It is the most
important risk in Part A, and it shapes the product:

- Verdicts never say "clean", "anonymous" or "compliant".
- Anything not inspected is recorded, and `Scan complete: NO` is always visible.
- `--strict` turns incompleteness into a CI failure.
- No config, or a config without identities, is an error rather than an empty pass.
- A misspelled config key is an error rather than being ignored.

## Part B: ReviewBlind as an attack surface

### Assets

The user's machine; their files; and their identity, which ReviewBlind itself writes down.

### Trust boundaries

| Input | Trust |
|---|---|
| The CLI arguments and the user's global Git config | Trusted |
| `.reviewblind.toml` | Trusted when the user wrote it, but still validated. A cloned repository could ship one |
| Everything else in the scan root, including `.git/config` | **Untrusted** |
| A JSON report passed to `export` | Untrusted. Validated, and never evaluated |

Assume a researcher may scan a repository they cloned from someone else.

### Threats and mitigations

| ID | Threat | Mitigation | Verified by |
|---|---|---|---|
| T-01 | **Code execution through `setup.py` or imports.** | Static AST or text analysis only. Repository paths are never added to `sys.path`. Nothing is imported or `exec`'d. | A `setup.py` that writes a marker file; assert no marker |
| T-02 | **Code execution through Git config.** `core.fsmonitor`, hooks and pagers in `.git/config` run commands. | One hardened runner, with overrides on the command line ([ARCHITECTURE §8](ARCHITECTURE.md#8-running-git-safely)). | Hostile config sets each key to write a marker; assert no marker |
| T-03 | **Code execution through Git filters.** `git status` and `ls-files --modified` run repo-local clean filters even when hardened. | These commands are banned. Changes are detected by hashing blobs directly. | Same-size edit under a hostile filter; assert no marker. A test checks the subcommand allowlist |
| T-04 | **Nested bare repository.** A bare repository in the tree carries executable config and is picked up by discovery. | `safe.bareRepository=explicit`. Git commands run only at the scan root. | A fixture with a nested bare repository and a marker |
| T-05 | **Symlink escape.** `data -> ~/.ssh` makes the scanner read secrets into a report. | Links are not followed by default, and a link leaving the root is never followed. | A symlink to a file outside the root; its contents never appear in the report |
| T-06 | **Writing through a symlink.** A hostile `.reviewblind.toml`, report path or `.git/info/exclude` symlink redirects a write. | `init` and `scan --output` refuse to write through a symlink. | A symlinked target; assert refusal and no change |
| T-07 | **Resource exhaustion.** Huge files, deep JSON, YAML alias expansion, a decompression bomb. | Size caps before parsing. Pixels are never decoded. Tree walks have a node cap. Recursion and memory errors are contained. Per-command Git timeouts. Named pipes are never opened. Matches per file are capped, and passing the cap marks the scan incomplete. | Fixtures for each; the scan finishes and records a skip |
| T-08 | **Pathological regex input.** A crafted line stalls matching. | Linear-time patterns with a line-length cap; identity needles are escaped. | A very long line finishes inside a time limit |
| T-09 | **Parser vulnerabilities.** Memory-safety bugs in MuPDF or Pillow's C code. | Keep dependencies patched through Dependabot and a lock file. Size caps. **There is no process isolation in 0.1.0**, so this risk is reduced but not removed. | Corrupt-file fixtures; documented residual risk |
| T-10 | **Terminal injection.** Escape sequences in evidence spoof output or manipulate the terminal. | Control characters are stripped in the pipeline, and Rich markup is disabled for repository text. | Evidence containing ANSI codes and `[red]` markup |
| T-11 | **Markdown or HTML injection.** Repository text in a Markdown report adds a tracking image or a misleading link. | Evidence is rendered in escaped code spans, and paths are escaped. | Evidence containing `![](http://...)` and HTML |
| T-12 | **Hiding from the scan.** A repository's own config suppresses findings. | Using `--config` from outside the tree avoids this. A report always shows the config path used, the suppressed count and the excluded count. | Assertions on report content |
| T-13 | **Network access or exfiltration.** | No network code. `protocol.allow=never` covers Git. | A test blocks sockets and asserts that none are attempted |
| T-15 | **Planted Git executable.** Windows searches the current directory first, so a repository's own `git.exe` could run as soon as it is scanned. | Git is found only through absolute `PATH` entries outside the scan root, and is run by absolute path. | A planted `git` and `git.exe`, with the root on `PATH` |
| T-14 | **Malformed report passed to `export`.** | The JSON is schema-checked, and terms are treated as data. | Malformed and wrong-version reports exit with code 2 |

### Threats from ReviewBlind's own output

These matter most, because they would make the tool cause the harm it exists to prevent.

| ID | Threat | Mitigation |
|---|---|---|
| T-20 | **The config is the leak.** `.reviewblind.toml` lists every author identity at the root of the very repository being shared. | `init` adds it to `.git/info/exclude` without touching tracked files. RB805 fires as BLOCKER if it is tracked or the target is `archive`. `--config` allows keeping it elsewhere. |
| T-21 | **The report is the leak.** A report inside the repository gets committed or zipped. | Every report format is recognized by RB805, including a saved terminal report. Report files are readable only by their owner. `--output` inside the root warns on stderr. `init` excludes `reviewblind-report.*`. |
| T-22 | **Public CI logs.** Terminal output in a public workflow publishes the names it found. | Documented in [CLI.md](CLI.md#running-in-ci), with a recommended private-only setup. There is no technical control in 0.1.0. |
| T-23 | **Fingerprints reveal values.** An unsalted hash of a name can be confirmed by guessing. | Reports are already sensitive and must not be shared. Fingerprints add no new exposure. |
| T-24 | **Environment disclosure.** A local username ends up in reports without being requested. | The environment is read only with `--include-env`. |
| T-25 | **Bug reports.** A user pastes a real report into a public issue. | Issue templates warn against this and ask for synthetic reproductions. |

## Security properties

Each property has at least one test. See [TEST_PLAN.md](TEST_PLAN.md#safety-tests).

ReviewBlind:

1. never executes repository code
2. never imports repository modules
3. never follows symlinks outside the root
4. never uploads files
5. never connects to the internet during a scan
6. never modifies source files
7. never rewrites Git
8. never unpacks untrusted archives in V1
9. caps file sizes
10. handles malformed files safely

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
