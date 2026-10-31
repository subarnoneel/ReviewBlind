<!-- reviewblind-report schema=1 -->
# ReviewBlind report

> Hand-written example of the planned format, using a fictional researcher. It will be replaced
> by real tool output at milestone M8.

| | |
|---|---|
| **Version** | 0.1.0 |
| **Target** | mirror |
| **Root** | `~/research/my-paper` |
| **Config** | `.reviewblind.toml` |
| **Identities** | 5 confirmed |
| **Files inspected** | 137 |
| **Files excluded** | 12 |
| **Files skipped** | 1 |
| **Scan complete** | NO |

## Result: NOT READY FOR ANONYMOUS REVIEW

| Severity | Count |
|---|---|
| Blocker | 3 |
| Warning | 1 |
| Review | 1 |
| Info | 1 |
| Suppressed | 1 |

## Blockers

### RB101 - Confirmed name in reviewer-visible text

- **Location:** `README.md:42:12`
- **Confidence:** HIGH
- **Evidence:** `Maintained by Alice Example at the lab`
- **Reason:** Direct author identity is visible in reviewer-facing text.
- **Suggested action:** Remove this name from the review artifact or configure your anonymous mirror to replace it.
- **Fingerprint:** `rb1:0000000000000000000000000000000000000000000000000000000000000001`

### RB301 - Author/maintainer metadata

- **Location:** `pyproject.toml:8`
- **Confidence:** HIGH
- **Evidence:** `authors = [{ name = "Alice Example" }]`
- **Reason:** Package metadata remains reviewer-visible and may disclose authorship.
- **Suggested action:** Replace it with a neutral value such as `Anonymous Authors`.
- **Fingerprint:** `rb1:0000000000000000000000000000000000000000000000000000000000000002`

### RB601 - Identity in PDF metadata

- **Location:** `figures/architecture.pdf`, `PDF metadata: Author`
- **Confidence:** HIGH
- **Evidence:** `Alice Example`
- **Reason:** Metadata is hidden from the page, and a mirror cannot rewrite binary files.
- **Suggested action:** Re-export the PDF with metadata removed.
- **Fingerprint:** `rb1:0000000000000000000000000000000000000000000000000000000000000003`

## Warnings

### RB502 - Identity in notebook output/traceback

- **Location:** `notebooks/error_analysis.ipynb`, `output[7].traceback[3]`
- **Confidence:** HIGH
- **Evidence:** `/home/aliceexample/miniconda3/envs/nlp/...`
- **Reason:** Outputs remain stored in the `.ipynb` JSON even when the source cell itself is clean.
- **Suggested action:** Clear or re-run the affected output before preparing the anonymous artifact.
- **Fingerprint:** `rb1:0000000000000000000000000000000000000000000000000000000000000004`

## Review

### RB703 - Visual content requires manual review

- **Location:** `figures/team-photo.png`
- **Confidence:** HIGH
- **Evidence:** `Visual content was not inspected.`
- **Reason:** ReviewBlind checks image metadata but does not perform OCR or visual identity recognition.
- **Suggested action:** Look at the image.
- **Fingerprint:** `rb1:0000000000000000000000000000000000000000000000000000000000000005`

## Info

### RB402 - Identifying Git author/committer

- **Location:** Git history, commit `a1b2c3d`
- **Confidence:** HIGH
- **Evidence:** `Alice Example`
- **Reason:** Full history is public on a repository and is packaged with `.git`. An anonymizing mirror hides it.
- **Suggested action:** No action needed for this target.
- **Fingerprint:** `rb1:0000000000000000000000000000000000000000000000000000000000000006`

## Skipped

| Path | Reason |
|---|---|
| `results/model-output.bin` | Unsupported binary format |

Use `--strict` to treat incomplete scanning as CI failure.
