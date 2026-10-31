"""Identity candidates from Git history and remotes, through the hardened runner only."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator

from reviewblind.discovery.candidates import Observation, SourceClass, person_kind
from reviewblind.models import Confidence, IdentityKind
from reviewblind.scanners.git import is_bot_email, is_bot_name
from reviewblind.signals import namespace_owner
from reviewblind.utils.git import Commit, GitRepository
from reviewblind.utils.text import comparison_key

_NOREPLY = re.compile(
    r"(?:\d+\+)?(?P<username>[\w.-]+)@users\.noreply\.(?:github\.com|gitlab\.com)", re.IGNORECASE
)
_HOST_LABELS = {"github": "GitHub", "gitlab": "GitLab", "huggingface": "Hugging Face"}


def _plural(count: int) -> str:
    return f"{count} commit" if count == 1 else f"{count} commits"


def _strength(count: int) -> Confidence:
    return Confidence.HIGH if count >= 2 else Confidence.MEDIUM


def email_local_part(email: str, source_class: SourceClass) -> Observation | None:
    """The part before `@` might be a username, but that is only a guess.

    It keeps the class of the email it came from, since it is not independent evidence of it.
    """
    local, separator, _domain = email.partition("@")
    if not separator or not local:
        return None
    return Observation(
        local,
        IdentityKind.USERNAME,
        Confidence.LOW,
        "email local part",
        source_class,
        guess=True,
    )


def _count(values: list[list[str]]) -> tuple[Counter[str], dict[str, str]]:
    """How many commits hold each value, once per commit, and how it was first written."""
    counts: Counter[str] = Counter()
    first: dict[str, str] = {}
    for commit_values in values:
        keys = {comparison_key(value): value for value in commit_values if value.strip()}
        counts.update(keys.keys())
        for key, value in keys.items():
            first.setdefault(key, value)
    return counts, first


def _names(commits: list[Commit], role: str, attribute: str) -> Iterator[Observation]:
    values = [[getattr(commit, attribute)] for commit in commits]
    counts, first = _count(values)
    for key, count in counts.items():
        value = first[key]
        if not is_bot_name(value):
            yield Observation(
                value,
                person_kind(value),
                _strength(count),
                f"Git {role} ({_plural(count)})",
                SourceClass.GIT_HISTORY,
            )


def _emails(commits: list[Commit]) -> Iterator[Observation]:
    counts, first = _count([[commit.author_email, commit.committer_email] for commit in commits])
    for key, count in counts.items():
        value = first[key]
        if is_bot_email(value):
            continue
        noreply = _NOREPLY.fullmatch(value)
        if noreply is not None:
            # This address exists to hide the real one, and it still names the account.
            yield Observation(
                noreply["username"],
                IdentityKind.USERNAME,
                _strength(count),
                f"Git noreply address ({_plural(count)})",
                SourceClass.GIT_HISTORY,
            )
            continue
        yield Observation(
            value,
            IdentityKind.EMAIL,
            _strength(count),
            f"Git commit email ({_plural(count)})",
            SourceClass.GIT_HISTORY,
        )
        local = email_local_part(value, SourceClass.GIT_HISTORY)
        if local is not None:
            yield local


def _remotes(repository: GitRepository) -> Iterator[Observation]:
    for _name, url in repository.remotes():
        owner = namespace_owner(url)
        if owner is None:
            continue
        host = next((label for key, label in _HOST_LABELS.items() if key in url.lower()), "Git")
        yield Observation(
            owner,
            IdentityKind.USERNAME,
            Confidence.MEDIUM,
            f"{host} remote",
            SourceClass.GIT_REMOTE,
        )


def from_git(repository: GitRepository, max_commits: int) -> tuple[list[Observation], list[str]]:
    """Observations from one repository, and notes about anything left unread."""
    notes = []
    total = repository.commit_count()
    if total > max_commits:
        notes.append(f"Only the newest {max_commits} of {total} commits were read.")
    commits = repository.commits(max_commits) if total else []
    observations = [
        *_names(commits, "author", "author_name"),
        *_names(commits, "committer", "committer_name"),
        *_emails(commits),
        *_remotes(repository),
    ]
    return observations, notes
