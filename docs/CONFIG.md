# Configuration — `.reviewblind.toml`

`reviewblind init` generates this file. An annotated example is in
[examples/.reviewblind.example.toml](../examples/.reviewblind.example.toml).

> **This file lists your identities in plain text.** Do not include it in the artifact
> you share. `init` adds it to `.git/info/exclude`, and a scan reports RB805 if it is
> tracked or would be packaged. You can also keep it outside the repository and pass
> `--config`.

## Example

```toml
version = 1

[identity]
names = ["Alice Example"]
emails = ["alice@example.edu"]
usernames = ["aliceexample"]
affiliations = ["Example University"]
aliases = ["A. Example"]
urls = ["https://alice.example.edu"]

[scan]
max_text_bytes = 8388608
max_binary_bytes = 52428800
follow_symlinks = false
exclude = [
  ".venv/**",
  "node_modules/**",
  "__pycache__/**",
  ".pytest_cache/**",
  ".mypy_cache/**",
]

[[allow]]
rule = "RB101"
path = "references.bib"
value = "Alice Example"
reason = "Legitimate bibliographic reference; neutral self-citation"
```

## Schema

### Top level

| Key | Type | Required | Meaning |
|---|---|---|---|
| `version` | integer | Yes | Must be `1` |

### `[identity]`

Every value listed here is a **confirmed** identity. At least one value is required
across all keys. Every key is optional and defaults to an empty list.

| Key | Scanned as | Rule |
|---|---|---|
| `names` | Full names | RB101 |
| `emails` | Email addresses. Their domain also feeds institutional-domain detection, unless it is a public mail provider | RB102, RB202 |
| `usernames` | Handles and account names. Also used to recognize namespaces and home paths | RB103, and the RB2xx rules |
| `affiliations` | Institutions, labs and departments | RB104 |
| `aliases` | Other forms of a name, such as `A. Example` | RB101 |
| `urls` | Personal or profile URLs, such as a homepage or ORCID record | RB105 |

ReviewBlind performs no fuzzy matching. If a name also appears as `Example, Alice` or
without its diacritics, list that form under `aliases`.

### `[scan]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `max_text_bytes` | integer | `8388608` (8 MiB) | Size cap for text and manifest files. Larger files are skipped and the scan is marked incomplete |
| `max_binary_bytes` | integer | `52428800` (50 MiB) | Size cap for notebooks, PDFs and images. Notebooks use this cap because embedded base64 outputs make them large |
| `follow_symlinks` | boolean | `false` | Follow symlinks that stay inside the scan root. A symlink that leaves the root is never followed, whatever this says |
| `exclude` | list of strings | See the example | Gitignore-style patterns, relative to the scan root. Setting this key **replaces** the default list |

Excluded paths are not inspected, and the report states how many were excluded.

**Target `archive` and `.git`:** add `.git/**` to `exclude` only if you will not package
the `.git` directory. This is how you tell ReviewBlind so; RB801 then no longer fires.
A safer alternative is to scan an extracted copy of what you intend to ship.

### `[[allow]]`

Suppresses one specific finding. All four keys are required.

| Key | Meaning |
|---|---|
| `rule` | A rule ID from the catalog |
| `path` | Exact repository-relative path with forward slashes. No wildcards |
| `value` | The matched value. Compared after NFC normalization and casefolding |
| `reason` | Why this is acceptable. Shown in JSON reports |

Regex allowlists are deliberately unsupported. Exact suppressions cannot accidentally
hide a different leak. Suppressed findings do not count toward the verdict or exit code,
and they remain listed in the JSON report's `suppressed` array.

An entry that matched nothing produces a note in the report, so stale suppressions are
visible.

## Validation

Each of these exits with code 2 and a message naming the problem:

- malformed TOML
- `version` missing or unsupported
- an unknown key, such as a misspelled `emials`
- a value of the wrong type
- no identities at all (for `scan`)
- an unknown rule ID in `[[allow]]`
- an `[[allow]]` entry missing a key, or with an empty `reason`
- a non-positive size cap

Unknown keys are errors because a silently ignored `emials` would look like a passing
scan.

## Lookup order

1. `--config FILE`, if passed. A missing file is an error.
2. `PATH/.reviewblind.toml`.
3. Otherwise exit with code 2 and suggest `reviewblind init`.

Config files are never searched for in parent directories. A scan's behaviour should not
depend on where a repository happens to be checked out.
