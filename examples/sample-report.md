<!-- reviewblind-report schema=1 -->
# ReviewBlind report

| | |
|---|---|
| **Version** | `0.1.0` |
| **Target** | mirror |
| **Root** | `~/research/my-paper` |
| **Config** | `.reviewblind.toml` |
| **Identities** | 4 confirmed |
| **Files inspected** | 21 |
| **Files excluded** | 0 |
| **Files skipped** | 2 |
| **Scan complete** | NO |

## Result: NOT READY FOR ANONYMOUS REVIEW

| Severity | Count |
|---|---|
| Blockers | 15 |
| Warnings | 9 |
| Review | 6 |
| Info | 6 |
| Suppressed | 0 |

## Blockers

### RB805 - ReviewBlind config or report in artifact

- **Location:** `.reviewblind.toml`
- **Confidence:** HIGH
- **Evidence:** `This file lists author identities in plain text.`
- **Reason:** These files list your identities in plain text. ReviewBlind itself would be the leak.
- **Suggested action:** Remove the file from the artifact, and keep it outside the repository or untracked.
- **Fingerprint:** `rb1:46ff987ae0918afac758695984620ea78982cc5563d41c6f2a57416d0eafd2ee`

### RB303 - CITATION author identity

- **Location:** `CITATION.cff`, `authors[0].name`
- **Confidence:** HIGH
- **Evidence:** `Alice Example`
- **Reason:** A citation file exists to name its authors.
- **Suggested action:** Remove the file from the review copy, or anonymize its authors.
- **Fingerprint:** `rb1:04db07b47a2907fdfeb98ba1192e357934064247a174db1a508b049cf0317f18`

### RB304 - LICENSE/NOTICE author identity

- **Location:** `LICENSE:3:20`
- **Confidence:** HIGH
- **Evidence:** `Copyright (c) 2026 Alice Example`
- **Reason:** A copyright line names its holder.
- **Suggested action:** Use a neutral holder for the review copy, and restore it afterwards.
- **Fingerprint:** `rb1:7fdd4584a7d713fb91d2034ae786981683fbbc556ff03a1e4d8e92d1c7754174`

### RB101 - Confirmed name in reviewer-visible text

- **Location:** `README.md:5:19`
- **Confidence:** HIGH
- **Evidence:** `Maintained by Dr. Alice Example.`
- **Reason:** Direct author identity is visible in reviewer-facing text.
- **Suggested action:** Remove this name from the review artifact or configure your anonymous mirror to replace it.
- **Fingerprint:** `rb1:9605501c75821186b3e952d3e23c118070e2d0f5e3f9e088b4b37ea38542923b`

### RB102 - Confirmed email

- **Location:** `README.md:7:26`
- **Confidence:** HIGH
- **Evidence:** `Questions can be sent to alice@example.edu.`
- **Reason:** An email address identifies a person and often an institution.
- **Suggested action:** Remove the address, or replace it with a placeholder.
- **Fingerprint:** `rb1:b366331f8894e0a4f4f1dc026a3ba3ace5c18637522bc91a662b289aa87bc2d9`

### RB105 - Personal/profile URL

- **Location:** `README.md:9:31`
- **Confidence:** HIGH
- **Evidence:** `More of my work is at https://github.com/aliceexample`
- **Reason:** The link leads directly to the author.
- **Suggested action:** Remove the link.
- **Fingerprint:** `rb1:7bd586200fc1cfde889a0d031220144d474623867a81334a80a3a912d3b97b9f`

### RB106 - Identity exposed through filename/path

- **Location:** `data/aliceexample_results.csv`
- **Confidence:** HIGH
- **Evidence:** `data/aliceexample_results.csv`
- **Reason:** File names are visible in every listing, and many tools do not rewrite them.
- **Suggested action:** Rename the file or directory.
- **Fingerprint:** `rb1:bd3415bb74eb401815f8d205f471a58a5606beb9f1cb4862542dc20708ddb551`

### RB601 - Identity in PDF metadata

- **Location:** `figures/architecture.pdf`, `PDF metadata: Author`
- **Confidence:** HIGH
- **Evidence:** `Alice Example`
- **Reason:** Metadata is hidden from the page, and not every mirror removes it.
- **Suggested action:** Re-export the PDF with metadata removed.
- **Fingerprint:** `rb1:c3ef993fab4ed2dc81e8d047cfa1be528ea313bff74fd6b43902a62e68b2e447`

### RB701 - Identity in image metadata

- **Location:** `figures/plot.jpg`, `EXIF Artist`
- **Confidence:** HIGH
- **Evidence:** `Alice Example`
- **Reason:** Image metadata is invisible when viewing and survives copying.
- **Suggested action:** Strip the metadata and re-export.
- **Fingerprint:** `rb1:b65ed8712aa4d943aeeb4fa829190e095b727e0eb4cf37e46c8f2b81747e5b8f`

### RB602 - Identity in extractable PDF text

- **Location:** `figures/poster.pdf`, `page 1`
- **Confidence:** HIGH
- **Evidence:** `Poster by Alice Example`
- **Reason:** Term replacement does not reach PDF pages, so visible text stays visible.
- **Suggested action:** Regenerate the document. If this is a legitimate citation, add an \[\[allow\]\] entry.
- **Fingerprint:** `rb1:d78698c636229a262ce627623ce32674f268f56580a98be82b8734654cb3159a`

### RB501 - Identity in notebook source/Markdown

- **Location:** `notebooks/analysis.ipynb`, `cell[0].source`
- **Confidence:** HIGH
- **Evidence:** `# Analysis by Alice Example`
- **Reason:** Cell source is shown directly when the notebook is rendered.
- **Suggested action:** Edit the cell.
- **Fingerprint:** `rb1:0bb34727b4005bd54de08555e1508e3e39eedc930f8ee8a5db34c02b179e9b24`

### RB302 - Identifying repository/homepage metadata

- **Location:** `package.json:4:16`
- **Confidence:** HIGH
- **Evidence:** `"homepage": "https://aliceexample.github.io/graph-contrast"`
- **Reason:** Project URLs commonly point to the author's account or institution.
- **Suggested action:** Remove the field for the review copy.
- **Fingerprint:** `rb1:0a7a97a398fcccf8ba8da53c2fb17cf58dccbc0f5a163adbb2f04347fb29b1ac`

### RB301 - Author/maintainer metadata

- **Location:** `pyproject.toml:4:22`
- **Confidence:** HIGH
- **Evidence:** `authors = [{ name = "Alice Example" }]`
- **Reason:** Package metadata remains reviewer-visible and may disclose authorship.
- **Suggested action:** Replace it with a neutral value such as Anonymous Authors.
- **Fingerprint:** `rb1:7813ae918f31f0ae91d8561814ac42fb491a62b9d5a70cd2712f02c4268c152f`

### RB204 - Personal Git hosting namespace

- **Location:** `scripts/clone.sh:2:19`
- **Confidence:** HIGH
- **Evidence:** `git clone https://github.com/aliceexample/private-tools.git`
- **Reason:** A repository URL reveals its owner.
- **Suggested action:** Remove the URL, or point to the anonymized location.
- **Fingerprint:** `rb1:fc85a68bc961e5fe9c74a7ae129c1357aaf7e7a83a2ebbdfcfed20744df3eaee`

### RB103 - Confirmed username/handle

- **Location:** `scripts/train.py:1:17`
- **Confidence:** HIGH
- **Evidence:** `# maintained by aliceexample`
- **Reason:** Usernames resolve to public profiles with a simple search.
- **Suggested action:** Remove the handle, or replace it with a neutral value.
- **Fingerprint:** `rb1:e424ee0af8bb96d43a97261009e881eab1ea33561a9af1a1ac7838ebd5769654`

## Warnings

### RB802 - OS metadata files present

- **Location:** `.DS_Store`
- **Confidence:** HIGH
- **Evidence:** `.DS_Store`
- **Reason:** These files can hold folder listings, paths and thumbnails.
- **Suggested action:** Delete them and exclude them from the artifact.
- **Fingerprint:** `rb1:106a2b495538115ebb631385bab9c74e388107cc17c6ab6f499dbe40464c1b1c`

### RB201 - Personal absolute home path

- **Location:** `configs/paths.yaml:1:12`
- **Confidence:** HIGH
- **Evidence:** `data_root: /home/aliceexample/data`
- **Reason:** The path exposes a workstation username, even when the author's name is absent.
- **Suggested action:** Use relative paths or environment variables.
- **Fingerprint:** `rb1:985673450d2aefd49dded74db67f207b0eca88d70601016c2c8c4974f264430c`

### RB203 - Research-service account namespace

- **Location:** `configs/tracking.yaml:1:18`
- **Confidence:** HIGH
- **Evidence:** `tracker: https://wandb.ai/aliceexample/proj`
- **Reason:** Experiment-tracking and model-hosting accounts usually map to one person or lab.
- **Suggested action:** Remove the URL, or move the asset to a neutral account.
- **Fingerprint:** `rb1:c57f0655cf47de72552ab6c9b81ed382b98542d26cab75bbe08fa7ade28fc77e`

### RB104 - Confirmed affiliation

- **Location:** `docs/setup.md:3:46`
- **Confidence:** HIGH
- **Evidence:** `The experiments ran on the shared cluster at Example University.`
- **Reason:** Affiliation narrows the author set, sometimes to one group.
- **Suggested action:** Remove the affiliation, or add an \[\[allow\]\] entry if it refers to third-party work.
- **Fingerprint:** `rb1:64f075c1437c3a0f9bf2c9db2209926b566d500735161947f74dca2f5c5b87df`

### RB702 - GPS metadata

- **Location:** `figures/field-site.jpg`, `EXIF GPS`
- **Confidence:** HIGH
- **Evidence:** `This image contains GPS coordinates.`
- **Reason:** Coordinates can identify a home or an institution.
- **Suggested action:** Strip the metadata and re-export.
- **Fingerprint:** `rb1:3aa13258e201bd5e86a2ff234327a7faa4c749d8ed4dca02bbadc2bfeecbdc03`

### RB502 - Identity in notebook output/traceback

- **Location:** `notebooks/analysis.ipynb`, `cell[1].output[0].traceback[0]`
- **Confidence:** HIGH
- **Evidence:** `File /home/aliceexample/project/run.py, line 3`
- **Reason:** Outputs remain stored in the .ipynb JSON even when the source cell itself is clean.
- **Suggested action:** Clear or re-run the affected output before preparing the anonymous artifact.
- **Fingerprint:** `rb1:035f01a930cc62aaa51971291f28e3e1f3dfcf3c3a374190e2414725523c044f`

### RB503 - Identity/path in notebook metadata

- **Location:** `notebooks/analysis.ipynb`, `metadata.vscode.interpreter.path`
- **Confidence:** HIGH
- **Evidence:** `/home/aliceexample/miniconda3/bin/python`
- **Reason:** Metadata is hidden from the rendered view but remains in the file.
- **Suggested action:** Clear the metadata, for example with nbstripout.
- **Fingerprint:** `rb1:906a72019ab3f7fbb42d0de39d24e82166c36f049e8477c9c3746ead911d6c61`

### RB202 - Institution-associated hostname/domain

- **Location:** `scripts/fetch.sh:2:5`
- **Confidence:** HIGH
- **Evidence:** `scp cluster.cs.example.edu:/scratch/graphs.tar .`
- **Reason:** An institutional hostname reveals where the work was done.
- **Suggested action:** Replace it with a generic hostname, or read it from configuration.
- **Fingerprint:** `rb1:6f5ddf1b95d3136d792397976661b4de524ff6ecee47bb32e4d8760db5433334`

### RB205 - SLURM/HPC user or mail identifier

- **Location:** `slurm/train.sbatch:3:21`
- **Confidence:** MEDIUM
- **Evidence:** `#SBATCH --mail-user=a.example@cs.example.edu`
- **Reason:** Scheduler scripts often hold a personal address or cluster account.
- **Suggested action:** Remove the directive, or read the value from the environment.
- **Fingerprint:** `rb1:1d926ee740361ee471e4d7d4fe058ca610cebd0b17b7e94872b645ee57b093e0`

## Review

### RB804 - Archive requires manual/deep inspection

- **Location:** `data/raw.zip`
- **Confidence:** HIGH
- **Evidence:** `Archive contents were not inspected.`
- **Reason:** Archive contents were not recursively inspected in V1.
- **Suggested action:** Extract the archive and scan the result. The scan is marked incomplete.
- **Fingerprint:** `rb1:034be09cc277f485499c06d84da1dae12fecb2322d2e66156abe92d8f74a8e3f`

### RB703 - Visual content requires manual review

- **Location:** `figures/field-site.jpg`
- **Confidence:** HIGH
- **Evidence:** `Visual content was not inspected.`
- **Reason:** ReviewBlind checks image metadata but does not perform OCR or visual identity recognition.
- **Suggested action:** Look at the image.
- **Fingerprint:** `rb1:2f93b439c3a7eb4bcd173274beb43abaff5a3c1145054d2e0c23e442cc46447a`

### RB703 - Visual content requires manual review

- **Location:** `figures/plot.jpg`
- **Confidence:** HIGH
- **Evidence:** `Visual content was not inspected.`
- **Reason:** ReviewBlind checks image metadata but does not perform OCR or visual identity recognition.
- **Suggested action:** Look at the image.
- **Fingerprint:** `rb1:8395c7d71a4c52ef707a447e607ef8a100714bf1ac416c2da0b9df0ec1619b7e`

### RB703 - Visual content requires manual review

- **Location:** `figures/team-photo.png`
- **Confidence:** HIGH
- **Evidence:** `Visual content was not inspected.`
- **Reason:** ReviewBlind checks image metadata but does not perform OCR or visual identity recognition.
- **Suggested action:** Look at the image.
- **Fingerprint:** `rb1:55408511f53a814d601aca5b9e26ae715c53faad46e23183697c370272ec689c`

### RB504 - Embedded binary notebook output requires review

- **Location:** `notebooks/analysis.ipynb`, `cell[1].output[1].data`
- **Confidence:** HIGH
- **Evidence:** `Binary notebook output was not inspected.`
- **Reason:** ReviewBlind does not perform OCR, so a plot title or screenshot could contain identity.
- **Suggested action:** Look at the output, or clear it.
- **Fingerprint:** `rb1:ecd9225600df75e5795017c79f76783398628882efa31f154d49d93ccdadcf9b`

### RB803 - Unsupported binary requires review

- **Location:** `results/model-output.bin`
- **Confidence:** HIGH
- **Evidence:** `Binary contents were not inspected.`
- **Reason:** Its contents could not be inspected.
- **Suggested action:** Inspect or remove the file. The scan is marked incomplete.
- **Fingerprint:** `rb1:34b0526ff001c5ad511dba78cf42590b283811edb479efe823d703a4df5b5949`

## Info

### RB401 - Identifying Git remote

- **Location:** `.git`, `remote origin`
- **Confidence:** HIGH
- **Evidence:** `git@github.com:aliceexample/paper.git`
- **Reason:** A publication URL reveals its owner. An anonymizing mirror hides this; a public repository does not.
- **Suggested action:** Publish from an anonymous account, or use a mirror.
- **Fingerprint:** `rb1:eaaaa280085f1927efc7abf28c4a0e9497cd8f34eddc790f78530e14e74e65b4`

### RB402 - Identifying Git author/committer

- **Location:** `.git`, commit `0521134d8068`
- **Confidence:** HIGH
- **Evidence:** `Alice Example`
- **Reason:** Full history is public on a repository and is packaged with .git.
- **Suggested action:** Publish a fresh history under a neutral identity. ReviewBlind does not rewrite history.
- **Fingerprint:** `rb1:f34cc3ad95cc753b82a148e3f50d4d48088ab4b57c3244ef3785f02bb330c888`

### RB403 - Identifying Git email

- **Location:** `.git`, commit `0521134d8068`
- **Confidence:** HIGH
- **Evidence:** `alice@example.edu`
- **Reason:** Full history is public on a repository and is packaged with .git.
- **Suggested action:** Publish a fresh history under a neutral identity. ReviewBlind does not rewrite history.
- **Fingerprint:** `rb1:8515f4c18dcc280fb8078f26a88b67d6943d933576b49d03b7b452f0cc8b278e`

### RB404 - Identity in commit message

- **Location:** `.git`, commit `0521134d8068`
- **Confidence:** HIGH
- **Evidence:** `Signed-off-by: Alice Example <alice@example.edu>`
- **Reason:** Commit messages travel with the history.
- **Suggested action:** Publish a fresh history under a neutral identity. ReviewBlind does not rewrite history.
- **Fingerprint:** `rb1:239b4d6940ecbd08d313e8fafb578fd5f9af1fe9e96c059021c1958493bb131e`

### RB404 - Identity in commit message

- **Location:** `.git`, commit `0521134d8068`
- **Confidence:** HIGH
- **Evidence:** `Signed-off-by: Alice Example <alice@example.edu>`
- **Reason:** Commit messages travel with the history.
- **Suggested action:** Publish a fresh history under a neutral identity. ReviewBlind does not rewrite history.
- **Fingerprint:** `rb1:8d7d0230dab5ec0de776e05a805cf8c5fcd3739b09b5608f5d8e4e371127e238`

### RB801 - .git present for archive target

- **Location:** `.git`
- **Confidence:** HIGH
- **Evidence:** `.git`
- **Reason:** Packaging .git ships the entire history, with its authors and remotes.
- **Suggested action:** Build the archive with git archive, or from a clean export. If you will not package .git, add .git/\*\* to exclude.
- **Fingerprint:** `rb1:af65de629692404f7d8399b6d3f694d9b5f6b97b61eeb6250a6c8e943c1c83f0`

## Skipped

| Path | Reason |
|---|---|
| `data/raw.zip` | archive not inspected: archives are not unpacked |
| `results/model-output.bin` | unsupported binary: unsupported binary format |

Use `--strict` to treat incomplete scanning as CI failure.
