"""Structural signals: home paths, service namespaces, institutional hosts, scheduler directives.

Every pattern begins with a literal or a fixed-width check and has no nested quantifiers, so it runs
in linear time on hostile input (threat T-08). A generic URL is not a finding by itself: it becomes
one when its namespace corresponds to a confirmed identity, or a rule covers the unconfirmed case.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import Enum
from itertools import islice

from reviewblind.matching import IdentityMatcher
from reviewblind.models import EvidenceClass, Identity, IdentityKind
from reviewblind.utils.text import normalize_text

MAX_HOSTNAME_LENGTH = 253

_NAME = r"[\w.-]+"
_NOT_IN_A_PATH = r"(?:(?<![\w/.:-])|(?<=file://))"
_HOME_PATH = re.compile(
    rf"{_NOT_IN_A_PATH}(?:/home/|/Users/)(?P<posix>{_NAME})"
    rf"|(?<![\w:])[A-Za-z]:[\\/]{{1,2}}[Uu][Ss][Ee][Rr][Ss][\\/]{{1,2}}(?P<windows>{_NAME})"
)
_SERVICE_URL = re.compile(
    r"(?<![\w.-])(?:www\.)?(?P<host>github\.com|gitlab\.com|huggingface\.co|wandb\.ai)"
    rf"[/:](?P<first>{_NAME})(?:/(?P<second>{_NAME}))?(?:/(?P<third>{_NAME}))?",
    re.IGNORECASE,
)
_PAGES_HOST = re.compile(r"(?<![\w.-])(?P<owner>[\w-]+)\.(?:github|gitlab)\.io", re.IGNORECASE)
_BUCKET = re.compile(rf"(?<![\w.-])(?:s3|gs)://(?P<bucket>{_NAME})", re.IGNORECASE)
_SCHEDULER = re.compile(
    r"^[ \t]*#(?:SBATCH[ \t]+(?:--mail-user|--account|--uid|-A)(?:=|[ \t]+)"
    r"|(?:PBS|\$)[ \t]+-[MAu][ \t]+"
    r"|BSUB[ \t]+-[uG][ \t]+)"
    r"(?P<value>[\w.@+-]+)",
    re.MULTILINE,
)

_PLACEHOLDER_USERS = frozenset(
    {
        "admin",
        "administrator",
        "default",
        "ec2-user",
        "guest",
        "jovyan",
        "me",
        "name",
        "public",
        "root",
        "runner",
        "runneradmin",
        "shared",
        "test",
        "ubuntu",
        "user",
        "username",
        "vscode",
        "your_name",
        "your_username",
        "yourname",
        "yourusername",
    }
)
_PUBLIC_MAIL_DOMAINS = frozenset(
    {
        "163.com",
        "aol.com",
        "fastmail.com",
        "gmail.com",
        "gmx.com",
        "gmx.de",
        "googlemail.com",
        "hey.com",
        "hotmail.com",
        "icloud.com",
        "live.com",
        "mail.com",
        "me.com",
        "msn.com",
        "outlook.com",
        "pm.me",
        "proton.me",
        "protonmail.com",
        "qq.com",
        "tutanota.com",
        "users.noreply.github.com",
        "yahoo.com",
        "yandex.com",
        "yandex.ru",
        "zoho.com",
    }
)
_HUGGING_FACE_SECTIONS = frozenset({"datasets", "models", "spaces"})
_WANDB_PAGES = frozenset(
    {"authorize", "fully-connected", "home", "login", "pricing", "settings", "site"}
)


_SITE_PAGES = frozenset({"features", "marketplace", "orgs", "settings", "topics", "users"})


class SignalKind(Enum):
    HOME_PATH = "HOME_PATH"
    INSTITUTION_DOMAIN = "INSTITUTION_DOMAIN"
    SERVICE_NAMESPACE = "SERVICE_NAMESPACE"
    GIT_NAMESPACE = "GIT_NAMESPACE"
    PROFILE_URL = "PROFILE_URL"
    SCHEDULER_ID = "SCHEDULER_ID"


_EVIDENCE_CLASS = {
    SignalKind.HOME_PATH: EvidenceClass.INDIRECT,
    SignalKind.INSTITUTION_DOMAIN: EvidenceClass.INDIRECT,
    SignalKind.SERVICE_NAMESPACE: EvidenceClass.INDIRECT,
    SignalKind.GIT_NAMESPACE: EvidenceClass.DIRECT,
    SignalKind.PROFILE_URL: EvidenceClass.DIRECT,
    SignalKind.SCHEDULER_ID: EvidenceClass.INDIRECT,
}


@dataclass(frozen=True)
class Signal:
    kind: SignalKind
    start: int
    end: int
    matched: str
    identity: str | None  # the confirmed identity, if the signal corresponds to one

    @property
    def evidence_class(self) -> EvidenceClass:
        return _EVIDENCE_CLASS[self.kind]


def is_placeholder_user(name: str) -> bool:
    """A generic account name, such as `runner` or `ubuntu`, which identifies nobody."""
    return name.casefold() in _PLACEHOLDER_USERS


def namespace_owner(url: str) -> str | None:
    """The account a hosting or research-service URL belongs to, if it has one."""
    match = _SERVICE_URL.search(url)
    if match is not None:
        host = match["host"].lower()
        owner = match["first"].rstrip(".")
        section = owner.lower()
        if host == "huggingface.co" and section in _HUGGING_FACE_SECTIONS:
            owner = (match["second"] or "").rstrip(".")
        elif (host == "wandb.ai" and section in _WANDB_PAGES) or section in _SITE_PAGES:
            return None
        return owner or None
    pages = _PAGES_HOST.search(url)
    return pages["owner"] if pages is not None else None


def email_domain(email: str) -> str | None:
    """The institutional domain of an email address, or `None` for a public mail provider."""
    domain = normalize_text(email.rpartition("@")[2])
    return domain if domain and domain not in _PUBLIC_MAIL_DOMAINS else None


class SignalMatcher:
    """Finds structural signals in text, given the confirmed identities."""

    def __init__(self, identities: Iterable[Identity]) -> None:
        identities = tuple(identities)
        usernames = tuple(item for item in identities if item.kind is IdentityKind.USERNAME)
        emails = tuple(item for item in identities if item.kind is IdentityKind.EMAIL)
        self._usernames = {normalize_text(item.value): item.value for item in usernames}
        self._emails = {normalize_text(item.value): item.value for item in emails}
        self._username_matcher = IdentityMatcher(usernames)
        domains = {email_domain(item.value) for item in emails} - {None}
        self._domain_pattern = (
            re.compile(
                r"(?<![\w-])(?:"
                + "|".join(sorted(re.escape(str(d)) for d in domains))
                + r")(?![\w-])",
                re.IGNORECASE,
            )
            if domains
            else None
        )

    def _confirmed_owner(self, name: str) -> str | None:
        """The confirmed username a namespace corresponds to, such as in `aliceexample-lab`."""
        exact = self._usernames.get(normalize_text(name))
        if exact is not None:
            return exact
        matches = self._username_matcher.find(name)
        return matches[0].identity.value if matches else None

    def find(self, text: str, limit: int) -> list[Signal]:
        """Signals in order of position. `limit` bounds the work done per kind on hostile input."""
        finders = (
            self._home_paths(text),
            self._service_urls(text),
            self._pages_hosts(text),
            self._buckets(text),
            self._domains(text),
            self._scheduler_ids(text),
        )
        signals = [signal for finder in finders for signal in islice(finder, limit)]
        signals.sort(key=lambda signal: (signal.start, -signal.end, signal.kind.value))
        return signals

    def _home_paths(self, text: str) -> Iterator[Signal]:
        for match in _HOME_PATH.finditer(text):
            user = (match["posix"] or match["windows"]).rstrip(".")
            if user.casefold() in _PLACEHOLDER_USERS:
                continue
            group = "posix" if match["posix"] else "windows"
            end = match.start(group) + len(user)
            yield Signal(
                SignalKind.HOME_PATH,
                match.start(),
                end,
                text[match.start() : end],
                self._confirmed_owner(user),
            )

    def _service_urls(self, text: str) -> Iterator[Signal]:
        for match in _SERVICE_URL.finditer(text):
            host = match["host"].lower()
            owner = match["first"].rstrip(".")
            project = (match["second"] or "").rstrip(".")
            third = (match["third"] or "").rstrip(".")
            if host == "huggingface.co" and owner.lower() in _HUGGING_FACE_SECTIONS and project:
                owner = project
                group = "third" if third else "second"
            elif project:
                group = "second"
            else:
                group = "first"
            end = match.start(group) + len((match[group] or "").rstrip("."))
            identity = self._confirmed_owner(owner)
            matched = text[match.start() : end]
            if host in {"github.com", "gitlab.com"}:
                if identity is not None:
                    kind = SignalKind.GIT_NAMESPACE if project else SignalKind.PROFILE_URL
                    yield Signal(kind, match.start(), end, matched, identity)
            elif identity is not None or (host == "wandb.ai" and owner.lower() not in _WANDB_PAGES):
                yield Signal(SignalKind.SERVICE_NAMESPACE, match.start(), end, matched, identity)

    def _pages_hosts(self, text: str) -> Iterator[Signal]:
        for match in _PAGES_HOST.finditer(text):
            identity = self._confirmed_owner(match["owner"])
            if identity is not None:
                yield Signal(SignalKind.PROFILE_URL, match.start(), match.end(), match[0], identity)

    def _buckets(self, text: str) -> Iterator[Signal]:
        for match in _BUCKET.finditer(text):
            end = match.start("bucket") + len(match["bucket"].rstrip("."))
            yield Signal(
                SignalKind.SERVICE_NAMESPACE,
                match.start(),
                end,
                text[match.start() : end],
                self._confirmed_owner(match["bucket"]),
            )

    def _domains(self, text: str) -> Iterator[Signal]:
        if self._domain_pattern is None:
            return
        for match in self._domain_pattern.finditer(text):
            # Extended by hand, because a pattern for subdomains would need nested quantifiers.
            start = match.start()
            floor = max(0, match.end() - MAX_HOSTNAME_LENGTH)
            while start > floor and (text[start - 1].isalnum() or text[start - 1] in "-._"):
                start -= 1
            yield Signal(
                SignalKind.INSTITUTION_DOMAIN,
                start,
                match.end(),
                text[start : match.end()],
                match[0].lower(),
            )

    def _scheduler_ids(self, text: str) -> Iterator[Signal]:
        for match in _SCHEDULER.finditer(text):
            value = match["value"]
            key = normalize_text(value)
            identity = self._emails.get(key) or self._usernames.get(key)
            yield Signal(
                SignalKind.SCHEDULER_ID, match.start("value"), match.end(), value, identity
            )
