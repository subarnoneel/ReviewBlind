"""Identities in Git metadata: remotes, authors, committers, emails and commit messages.

File contents in past commits, tags and notes are not read. See docs/LIMITATIONS.md.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from reviewblind.matching import resolve_overlaps
from reviewblind.models import Detection, EvidenceClass, Location, Severity, SkipReason
from reviewblind.scanners.base import ScanContext, confirmed_url_identity
from reviewblind.scanners.manifests import FieldKind, ManifestField, is_placeholder
from reviewblind.utils.git import Commit, GitError, GitRepository
from reviewblind.utils.text import comparison_key, excerpt

GIT_PATH = ".git"
SHORT_COMMIT_LENGTH = 12

_BOT_NAMES = frozenset(
    {
        "dependabot",
        "github",
        "github action",
        "github actions",
        "github-actions",
        "gitlab",
        "pre-commit-ci",
        "renovate",
        "semantic-release-bot",
        "web-flow",
    }
)
_BOT_EMAILS = frozenset({"action@github.com", "noreply@github.com"})
# A token in a remote URL must not be copied into a report. `git@` is the normal SSH user.
_URL_CREDENTIALS = re.compile(r"(?<=://)(?!git@)[^/@\s]+@")


def is_bot_name(name: str) -> bool:
    key = comparison_key(name)
    return key.endswith("[bot]") or key in _BOT_NAMES


def is_bot_email(email: str) -> bool:
    key = comparison_key(email)
    return key in _BOT_EMAILS or key.endswith("[bot]@users.noreply.github.com")


def redact_url(url: str) -> str:
    return _URL_CREDENTIALS.sub("***@", url)


@dataclass
class _Seen:
    """A value seen in history. The first time seen is the newest, since Git lists newest first."""

    value: str
    commit: str
    count: int = 1


def _note(seen: dict[str, _Seen], values: Iterable[str], commit: str) -> None:
    """Count each value once per commit, however many of its fields hold it."""
    keys = {comparison_key(value): value for value in values}
    for key, value in keys.items():
        if not key:
            continue
        if key in seen:
            seen[key].count += 1
        else:
            seen[key] = _Seen(value, commit[:SHORT_COMMIT_LENGTH])


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


class GitScanner:
    name = "git"

    def scan(self, context: ScanContext) -> Iterable[Detection]:
        repository = context.inventory.repository
        if repository is None:
            return []  # the inventory has already reported a repository it could not read
        try:
            return [
                *self._remotes(repository, context),
                *self._history(repository, context),
            ]
        except GitError as error:
            context.report_skip(GIT_PATH, SkipReason.GIT_UNAVAILABLE, str(error))
            return []

    @staticmethod
    def _remotes(repository: GitRepository, context: ScanContext) -> Iterator[Detection]:
        for name, url in repository.remotes():
            identity = confirmed_url_identity(url, context)
            if identity is None:
                continue
            shown = redact_url(url)
            yield Detection(
                rule_id="RB401",
                artifact=GIT_PATH,
                location=Location(GIT_PATH, field=f"remote {name}"),
                matched=shown,
                evidence=shown,
                message="Found an identifying Git remote",
                identity=identity,
                evidence_class=EvidenceClass.DIRECT,
            )

    def _history(self, repository: GitRepository, context: ScanContext) -> Iterator[Detection]:
        total = repository.commit_count()
        if total > context.max_commits:
            context.report_skip(
                GIT_PATH,
                SkipReason.GIT_TRUNCATED,
                f"only the newest {context.max_commits} of {total} commits were inspected",
            )
        if total == 0:
            return
        commits = repository.commits(context.max_commits)
        names: dict[str, _Seen] = {}
        emails: dict[str, _Seen] = {}
        for commit in commits:
            _note(
                names,
                [
                    name
                    for name in (commit.author_name, commit.committer_name)
                    if not is_bot_name(name)
                ],
                commit.sha,
            )
            _note(
                emails,
                [
                    email
                    for email in (commit.author_email, commit.committer_email)
                    if not is_bot_email(email)
                ],
                commit.sha,
            )
        yield from self._people(
            names, "RB402", FieldKind.PERSON, "Found an author or committer", context
        )
        yield from self._people(
            emails, "RB403", FieldKind.EMAIL, "Found an author or committer email", context
        )
        yield from self._messages(commits, context)

    @staticmethod
    def _people(
        seen: dict[str, _Seen], rule_id: str, kind: FieldKind, label: str, context: ScanContext
    ) -> Iterator[Detection]:
        for item in seen.values():
            matches = context.matcher.find(item.value)
            longest = max(matches, key=lambda match: match.end - match.start, default=None)
            # A neutral identity is the fix these rules ask for, so it must be able to pass.
            if longest is None and is_placeholder(ManifestField(kind, item.value, GIT_PATH)):
                continue
            yield Detection(
                rule_id=rule_id,
                artifact=GIT_PATH,
                location=Location(GIT_PATH, git_commit=item.commit),
                matched=item.value,
                evidence=item.value,
                message=f"{label} in {_plural(item.count, 'commit')}",
                identity=None if longest is None else longest.identity.value,
                evidence_class=EvidenceClass.DIRECT,
            )

    @staticmethod
    def _messages(commits: list[Commit], context: ScanContext) -> Iterator[Detection]:
        """Each identity is reported once, however many messages mention it (D-57)."""
        seen: dict[str, _Seen] = {}
        first: dict[str, Detection] = {}
        for commit in commits:
            matches = resolve_overlaps(
                context.matcher.find(commit.message),
                span=lambda match: (match.start, match.end),
                severity=lambda _match: Severity.BLOCKER,
                rule_id=lambda match: match.identity.value,
            )
            _note(seen, [match.matched for match in matches], commit.sha)
            for match in matches:
                key = comparison_key(match.matched)
                first.setdefault(
                    key,
                    Detection(
                        rule_id="RB404",
                        artifact=GIT_PATH,
                        location=Location(GIT_PATH, git_commit=commit.sha[:SHORT_COMMIT_LENGTH]),
                        matched=match.matched,
                        evidence=excerpt(commit.message, match.start, match.end),
                        message="",
                        identity=match.identity.value,
                        evidence_class=match.evidence_class,
                    ),
                )
        for key, detection in first.items():
            count = _plural(seen[key].count, "commit message")
            yield Detection(
                rule_id=detection.rule_id,
                artifact=detection.artifact,
                location=detection.location,
                matched=detection.matched,
                evidence=detection.evidence,
                message=f"Found a confirmed identity in {count}",
                identity=detection.identity,
                evidence_class=detection.evidence_class,
            )
