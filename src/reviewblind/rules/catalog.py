"""Every rule ReviewBlind can raise. tests/test_rules.py keeps this in step with docs/RULES.md."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from reviewblind.models import Confidence, Rule, Severity, Target, UnconfirmedPolicy

_B = Severity.BLOCKER
_W = Severity.WARNING
_R = Severity.REVIEW
_I = Severity.INFO

_FRESH_HISTORY = (
    "Publish a fresh history under a neutral identity. ReviewBlind does not rewrite history."
)
_GIT_ONLY_ON_REPOSITORY: Mapping[Target, Severity] = {
    Target.MIRROR: _I,
    Target.ARCHIVE: _I,
    Target.REPOSITORY: _B,
}


def _rule(
    rule_id: str,
    title: str,
    severity: Severity,
    *,
    detects: str,
    why: str,
    fix: str,
    by_target: Mapping[Target, Severity] | None = None,
    container: bool = False,
    identity_based: bool = True,
    unconfirmed: UnconfirmedPolicy | None = None,
    git_packaged: bool = False,
    tracked: bool = False,
) -> Rule:
    return Rule(
        id=rule_id,
        title=title,
        default_severity=severity,
        description=detects,
        reason=why,
        remediation=fix,
        severity_by_target=MappingProxyType(dict(by_target or {})),
        container=container,
        identity_based=identity_based,
        unconfirmed=unconfirmed,
        blocker_if_git_packaged=git_packaged,
        blocker_if_tracked=tracked,
    )


CATALOG: tuple[Rule, ...] = (
    # Identity
    _rule(
        "RB101",
        "Confirmed name in reviewer-visible text",
        _B,
        detects="A configured name or alias in any inspected text file.",
        why="Direct author identity is visible in reviewer-facing text.",
        fix="Remove this name from the review artifact or configure your anonymous mirror to "
        "replace it.",
    ),
    _rule(
        "RB102",
        "Confirmed email",
        _B,
        detects="A configured email address.",
        why="An email address identifies a person and often an institution.",
        fix="Remove the address, or replace it with a placeholder.",
    ),
    _rule(
        "RB103",
        "Confirmed username/handle",
        _B,
        detects="A configured username outside a more specific URL or path.",
        why="Usernames resolve to public profiles with a simple search.",
        fix="Remove the handle, or replace it with a neutral value.",
    ),
    _rule(
        "RB104",
        "Confirmed affiliation",
        _W,
        detects="A configured institution, lab or department.",
        why="Affiliation narrows the author set, sometimes to one group.",
        fix="Remove the affiliation, or add an [[allow]] entry if it refers to third-party work.",
    ),
    _rule(
        "RB105",
        "Personal/profile URL",
        _B,
        detects="A URL from identity.urls, or a hosting profile such as github.com/<username>.",
        why="The link leads directly to the author.",
        fix="Remove the link.",
    ),
    _rule(
        "RB106",
        "Identity exposed through filename/path",
        _B,
        detects="A confirmed identity in a directory or file name.",
        why="File names are visible in every listing, and many tools do not rewrite them.",
        fix="Rename the file or directory.",
        container=True,
    ),
    # Workstation and service
    _rule(
        "RB201",
        "Personal absolute home path",
        _W,
        detects="/home/<user>/, /Users/<user>/ and C:\\Users\\<user>\\. Placeholders such as "
        "user, ubuntu, runner, root, jovyan and vscode are ignored.",
        why="The path exposes a workstation username, even when the author's name is absent.",
        fix="Use relative paths or environment variables.",
        unconfirmed=UnconfirmedPolicy(_R, Confidence.MEDIUM),
    ),
    _rule(
        "RB202",
        "Institution-associated hostname/domain",
        _W,
        detects="A domain from a confirmed email, or a subdomain of it. Public mail providers "
        "are excluded.",
        why="An institutional hostname reveals where the work was done.",
        fix="Replace it with a generic hostname, or read it from configuration.",
    ),
    _rule(
        "RB203",
        "Research-service account namespace",
        _W,
        detects="A confirmed namespace on huggingface.co or wandb.ai. Unconfirmed wandb.ai "
        "namespaces and s3:// or gs:// URIs are raised for review.",
        why="Experiment-tracking and model-hosting accounts usually map to one person or lab.",
        fix="Remove the URL, or move the asset to a neutral account.",
        unconfirmed=UnconfirmedPolicy(_R, Confidence.LOW),
    ),
    _rule(
        "RB204",
        "Personal Git hosting namespace",
        _B,
        detects="github.com/<username>/<repo> and gitlab.com/<username>/<repo> for a confirmed "
        "username.",
        why="A repository URL reveals its owner.",
        fix="Remove the URL, or point to the anonymized location.",
    ),
    _rule(
        "RB205",
        "SLURM/HPC user or mail identifier",
        _W,
        detects="#SBATCH --mail-user, #SBATCH --account, and similar scheduler directives.",
        why="Scheduler scripts often hold a personal address or cluster account.",
        fix="Remove the directive, or read the value from the environment.",
        unconfirmed=UnconfirmedPolicy(_W, Confidence.MEDIUM),
    ),
    # Manifests
    _rule(
        "RB301",
        "Author/maintainer metadata",
        _B,
        detects="Author and maintainer fields in pyproject.toml, package.json, setup.py and "
        "setup.cfg. Unconfirmed values are reported too, because a co-author may be missing "
        "from your config.",
        why="Package metadata remains reviewer-visible and may disclose authorship.",
        fix="Replace it with a neutral value such as Anonymous Authors.",
        unconfirmed=UnconfirmedPolicy(_B, Confidence.MEDIUM),
    ),
    _rule(
        "RB302",
        "Identifying repository/homepage metadata",
        _B,
        detects="Repository, homepage and organization fields in a manifest.",
        why="Project URLs commonly point to the author's account or institution.",
        fix="Remove the field for the review copy.",
        unconfirmed=UnconfirmedPolicy(_W, Confidence.MEDIUM),
    ),
    _rule(
        "RB303",
        "CITATION author identity",
        _B,
        detects="Author entries in CITATION.cff.",
        why="A citation file exists to name its authors.",
        fix="Remove the file from the review copy, or anonymize its authors.",
        unconfirmed=UnconfirmedPolicy(_B, Confidence.MEDIUM),
    ),
    _rule(
        "RB304",
        "LICENSE/NOTICE author identity",
        _B,
        detects="Copyright holders in LICENSE*, NOTICE*, COPYING* and AUTHORS*.",
        why="A copyright line names its holder.",
        fix="Use a neutral holder for the review copy, and restore it afterwards.",
        unconfirmed=UnconfirmedPolicy(_W, Confidence.MEDIUM),
    ),
    # Git
    _rule(
        "RB401",
        "Identifying Git remote",
        _I,
        detects="A remote URL under a confirmed namespace.",
        why="A publication URL reveals its owner. An anonymizing mirror hides this; a public "
        "repository does not.",
        fix="Publish from an anonymous account, or use a mirror.",
        by_target=_GIT_ONLY_ON_REPOSITORY,
        git_packaged=True,
    ),
    _rule(
        "RB402",
        "Identifying Git author/committer",
        _I,
        detects="Author and committer names in history. Each unique identity is reported once.",
        why="Full history is public on a repository and is packaged with .git.",
        fix=_FRESH_HISTORY,
        by_target=_GIT_ONLY_ON_REPOSITORY,
        git_packaged=True,
        unconfirmed=UnconfirmedPolicy(_W, Confidence.MEDIUM, frozenset({Target.REPOSITORY})),
    ),
    _rule(
        "RB403",
        "Identifying Git email",
        _I,
        detects="Author and committer emails in history. Each unique address is reported once.",
        why="Full history is public on a repository and is packaged with .git.",
        fix=_FRESH_HISTORY,
        by_target=_GIT_ONLY_ON_REPOSITORY,
        git_packaged=True,
        unconfirmed=UnconfirmedPolicy(_W, Confidence.MEDIUM, frozenset({Target.REPOSITORY})),
    ),
    _rule(
        "RB404",
        "Identity in commit message",
        _I,
        detects="A confirmed identity in a commit message, including Signed-off-by and "
        "Co-authored-by trailers.",
        why="Commit messages travel with the history.",
        fix=_FRESH_HISTORY,
        by_target=_GIT_ONLY_ON_REPOSITORY,
        container=True,
        git_packaged=True,
    ),
    # Notebooks
    _rule(
        "RB501",
        "Identity in notebook source/Markdown",
        _B,
        detects="A confirmed identity or structural signal in Markdown or code cells.",
        why="Cell source is shown directly when the notebook is rendered.",
        fix="Edit the cell.",
        container=True,
    ),
    _rule(
        "RB502",
        "Identity in notebook output/traceback",
        _B,
        detects="Author names, usernames, emails or personal paths retained inside Jupyter "
        "stream, error or text outputs.",
        why="Outputs remain stored in the .ipynb JSON even when the source cell itself is clean.",
        fix="Clear or re-run the affected output before preparing the anonymous artifact.",
        container=True,
        unconfirmed=UnconfirmedPolicy(_R, Confidence.MEDIUM),
    ),
    _rule(
        "RB503",
        "Identity/path in notebook metadata",
        _B,
        detects="A confirmed identity or path in notebook, kernel, VS Code or Colab metadata.",
        why="Metadata is hidden from the rendered view but remains in the file.",
        fix="Clear the metadata, for example with nbstripout.",
        container=True,
        unconfirmed=UnconfirmedPolicy(_R, Confidence.MEDIUM),
    ),
    _rule(
        "RB504",
        "Embedded binary notebook output requires review",
        _R,
        detects="Base64 image or binary output.",
        why="ReviewBlind does not perform OCR, so a plot title or screenshot could contain "
        "identity.",
        fix="Look at the output, or clear it.",
        identity_based=False,
    ),
    # PDF
    _rule(
        "RB601",
        "Identity in PDF metadata",
        _B,
        detects="A confirmed identity in Author, Creator, Producer, Subject, Keywords or XMP "
        "metadata. A non-placeholder Author is reported even when unconfirmed.",
        why="Metadata is hidden from the page, and a mirror cannot rewrite binary files.",
        fix="Re-export the PDF with metadata removed.",
        container=True,
        unconfirmed=UnconfirmedPolicy(_W, Confidence.MEDIUM),
    ),
    _rule(
        "RB602",
        "Identity in extractable PDF text",
        _B,
        detects="A confirmed identity in page text or exposed URLs.",
        why="A mirror cannot rewrite binary files, so visible text in a PDF stays visible.",
        fix="Regenerate the document. If this is a legitimate citation, add an [[allow]] entry.",
        container=True,
    ),
    # Image
    _rule(
        "RB701",
        "Identity in image metadata",
        _B,
        detects="A confirmed identity in EXIF, PNG text or software metadata. A non-placeholder "
        "owner field such as Artist is reported even when unconfirmed.",
        why="Image metadata is invisible when viewing and survives copying.",
        fix="Strip the metadata and re-export.",
        container=True,
        unconfirmed=UnconfirmedPolicy(_W, Confidence.MEDIUM),
    ),
    _rule(
        "RB702",
        "GPS metadata",
        _W,
        detects="EXIF GPS tags.",
        why="Coordinates can identify a home or an institution.",
        fix="Strip the metadata and re-export.",
        identity_based=False,
    ),
    _rule(
        "RB703",
        "Visual content requires manual review",
        _R,
        detects="Every reviewer-visible image.",
        why="ReviewBlind checks image metadata but does not perform OCR or visual identity "
        "recognition.",
        fix="Look at the image.",
        identity_based=False,
    ),
    # Packaging
    _rule(
        "RB801",
        ".git present for archive target",
        _I,
        detects="A .git directory or file, unless the config excludes .git/**.",
        why="Packaging .git ships the entire history, with its authors and remotes.",
        fix="Build the archive with git archive, or from a clean export. If you will not "
        "package .git, add .git/** to exclude.",
        by_target={Target.ARCHIVE: _B},
        identity_based=False,
    ),
    _rule(
        "RB802",
        "OS metadata files present",
        _W,
        detects=".DS_Store, __MACOSX/ and Thumbs.db.",
        why="These files can hold folder listings, paths and thumbnails.",
        fix="Delete them and exclude them from the artifact.",
        identity_based=False,
    ),
    _rule(
        "RB803",
        "Unsupported binary requires review",
        _R,
        detects="A binary file ReviewBlind cannot parse, such as model weights or a video.",
        why="Its contents could not be inspected.",
        fix="Inspect or remove the file. The scan is marked incomplete.",
        identity_based=False,
    ),
    _rule(
        "RB804",
        "Archive requires manual/deep inspection",
        _R,
        detects="ZIP, TAR, GZIP and similar files.",
        why="Archive contents were not recursively inspected in V1.",
        fix="Extract the archive and scan the result. The scan is marked incomplete.",
        identity_based=False,
    ),
    _rule(
        "RB805",
        "ReviewBlind config or report in artifact",
        _I,
        detects=".reviewblind.toml, or a file carrying the ReviewBlind report marker.",
        why="These files list your identities in plain text. ReviewBlind itself would be the leak.",
        fix="Remove the file from the artifact, and keep it outside the repository or untracked.",
        by_target={Target.ARCHIVE: _B},
        identity_based=False,
        tracked=True,
    ),
)
