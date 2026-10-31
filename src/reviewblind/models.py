"""Core data model. This module imports nothing else from the package."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class _RankedEnum(Enum):
    """An enum whose members are declared from highest to lowest."""

    @property
    def rank(self) -> int:
        """Position in declaration order: 0 is the highest member."""
        return list(type(self)).index(self)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank < other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.rank <= other.rank


class Severity(_RankedEnum):
    """How dangerous a leak is."""

    BLOCKER = "BLOCKER"
    WARNING = "WARNING"
    REVIEW = "REVIEW"
    INFO = "INFO"


class Confidence(_RankedEnum):
    """How certain ReviewBlind is."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Target(Enum):
    """The sharing scenario being checked."""

    MIRROR = "MIRROR"
    ARCHIVE = "ARCHIVE"
    REPOSITORY = "REPOSITORY"


ALL_TARGETS = frozenset(Target)


class IdentityKind(Enum):
    NAME = "NAME"
    EMAIL = "EMAIL"
    USERNAME = "USERNAME"
    AFFILIATION = "AFFILIATION"
    URL = "URL"
    ALIAS = "ALIAS"


class ArtifactKind(Enum):
    TEXT = "TEXT"
    MANIFEST = "MANIFEST"
    NOTEBOOK = "NOTEBOOK"
    PDF = "PDF"
    IMAGE = "IMAGE"
    ARCHIVE = "ARCHIVE"
    BINARY = "BINARY"
    REVIEWBLIND = "REVIEWBLIND"  # our own config or report: it is reported, never scanned as text


class EvidenceClass(Enum):
    """What kind of thing was found. See "Evidence classes" in docs/RULES.md."""

    DIRECT = "DIRECT"
    INDIRECT = "INDIRECT"
    ACRONYM = "ACRONYM"
    AMBIGUOUS = "AMBIGUOUS"


class SkipReason(Enum):
    """Why an artifact could not be fully inspected. See docs/REPORT_SCHEMA.md."""

    TOO_LARGE = "TOO_LARGE"
    UNREADABLE = "UNREADABLE"
    CORRUPT = "CORRUPT"
    ENCRYPTED = "ENCRYPTED"
    UNSUPPORTED_BINARY = "UNSUPPORTED_BINARY"
    ARCHIVE_NOT_INSPECTED = "ARCHIVE_NOT_INSPECTED"
    SYMLINK_NOT_FOLLOWED = "SYMLINK_NOT_FOLLOWED"
    GIT_UNAVAILABLE = "GIT_UNAVAILABLE"
    GIT_TRUNCATED = "GIT_TRUNCATED"
    SUBMODULE_NOT_INSPECTED = "SUBMODULE_NOT_INSPECTED"
    TOO_MANY_MATCHES = "TOO_MANY_MATCHES"
    SCANNER_ERROR = "SCANNER_ERROR"


class Verdict(Enum):
    """What the findings mean for a person. Never claims an artifact is anonymous."""

    NOT_READY = "NOT_READY"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    NO_KNOWN_LEAKS = "NO_KNOWN_LEAKS"
    NO_KNOWN_LEAKS_INCOMPLETE = "NO_KNOWN_LEAKS_INCOMPLETE"

    @property
    def line(self) -> str:
        return _VERDICT_LINES[self]


_VERDICT_LINES = {
    Verdict.NOT_READY: "NOT READY FOR ANONYMOUS REVIEW",
    Verdict.REVIEW_REQUIRED: "MANUAL REVIEW REQUIRED",
    Verdict.NO_KNOWN_LEAKS: "NO KNOWN LEAKS DETECTED",
    Verdict.NO_KNOWN_LEAKS_INCOMPLETE: "NO KNOWN LEAKS DETECTED - SCAN INCOMPLETE",
}


@dataclass(frozen=True)
class Identity:
    value: str
    kind: IdentityKind
    source: str
    confidence: Confidence
    confirmed: bool


@dataclass(frozen=True)
class Artifact:
    path: Path  # absolute, inside the scan root
    relpath: str  # POSIX, relative to the root
    kind: ArtifactKind
    size: int
    tracked: bool | None  # None when the root is not a Git repository


@dataclass(frozen=True)
class Location:
    path: str
    line: int | None = None
    column: int | None = None
    field: str | None = None
    git_commit: str | None = None


@dataclass(frozen=True)
class Detection:
    """What a scanner saw. Contains no policy."""

    rule_id: str
    artifact: str
    location: Location
    matched: str  # the exact matched value
    evidence: str  # short display excerpt
    message: str
    identity: str | None  # the confirmed identity, if there is one
    evidence_class: EvidenceClass
    span: tuple[int, int] | None = None  # character offsets, for overlap resolution


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    confidence: Confidence
    artifact: str
    location: Location
    matched: str
    evidence: str
    message: str
    reason: str
    remediation: str
    identity: str | None
    targets: frozenset[Target]
    fingerprint: str


@dataclass(frozen=True)
class SkippedArtifact:
    path: str
    reason: SkipReason
    detail: str | None = None


@dataclass(frozen=True)
class SuppressedFinding:
    finding: Finding
    reason: str  # the [[allow]] reason


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[SuppressedFinding] = field(default_factory=list)
    inspected: int = 0
    excluded: int = 0
    skipped: list[SkippedArtifact] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    incomplete: bool = False


@dataclass(frozen=True)
class ScanReport:
    """A finished scan, with the context a reporter needs."""

    result: ScanResult
    target: Target
    root: Path
    config_path: Path | None
    identities: tuple[Identity, ...]
    version: str


@dataclass(frozen=True)
class UnconfirmedPolicy:
    """What a rule does when its evidence is not tied to a confirmed identity."""

    severity: Severity
    confidence: Confidence
    targets: frozenset[Target] = ALL_TARGETS


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    default_severity: Severity
    description: str
    reason: str
    remediation: str
    severity_by_target: Mapping[Target, Severity] = field(default_factory=dict, hash=False)
    confidence: Confidence = Confidence.HIGH
    container: bool = False  # a ◆ rule: INDIRECT evidence is capped at WARNING
    identity_based: bool = True  # False for a fact about a file, shown as "n/a" in RULES.md
    unconfirmed: UnconfirmedPolicy | None = None  # None: no finding when unconfirmed
    blocker_if_git_packaged: bool = False  # the † rules in RULES.md
    blocker_if_tracked: bool = False  # the ‡ rule in RULES.md
    applicable_targets: frozenset[Target] = ALL_TARGETS

    def severity_for(self, target: Target) -> Severity:
        return self.severity_by_target.get(target, self.default_severity)
