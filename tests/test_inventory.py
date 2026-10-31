"""What each target inspects (FR-SCAN-3, ARCHITECTURE section 5)."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path

import pytest

from _helpers import git, init_repo, symlink_or_skip, write_tree
from reviewblind import inventory as inventory_module
from reviewblind.config import ConfigError, ScanSettings
from reviewblind.inventory import Inventory, build_inventory
from reviewblind.models import ArtifactKind, SkipReason, Target
from reviewblind.utils.files import SNIFF_BYTES, classify, decode_text, looks_like_text
from reviewblind.utils.git import GitError

NO_EXCLUDES = ScanSettings(exclude=())


def build(
    root: Path, target: Target = Target.MIRROR, settings: ScanSettings = NO_EXCLUDES
) -> Inventory:
    return build_inventory(root, target, settings)


def paths(inventory: Inventory) -> list[str]:
    return [artifact.relpath for artifact in inventory.artifacts]


def skip_reasons(inventory: Inventory) -> dict[str, SkipReason]:
    return {item.path: item.reason for item in inventory.skipped}


# Scope for each target


def test_outside_git_every_file_is_listed_with_a_note(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.txt": "a", "sub/b.txt": "b"})
    inventory = build(tmp_path)
    assert paths(inventory) == ["a.txt", "sub/b.txt"]
    assert all(artifact.tracked is None for artifact in inventory.artifacts)
    assert any("Not a Git repository" in note for note in inventory.notes)
    assert not inventory.skipped


@pytest.mark.parametrize("target", [Target.MIRROR, Target.REPOSITORY])
def test_published_targets_cover_tracked_and_untracked_but_not_ignored(
    tmp_path: Path, target: Target
) -> None:
    init_repo(tmp_path, {"tracked.txt": "t", ".gitignore": "ignored.txt\n"})
    write_tree(tmp_path, {"ignored.txt": "i", "untracked.txt": "u"})
    inventory = build(tmp_path, target)
    assert paths(inventory) == [".gitignore", "tracked.txt", "untracked.txt"]
    tracked = {artifact.relpath: artifact.tracked for artifact in inventory.artifacts}
    assert tracked["tracked.txt"] is True
    assert tracked["untracked.txt"] is False


def test_an_archive_covers_ignored_files_too(tmp_path: Path) -> None:
    # Zipping a folder does not honour .gitignore.
    init_repo(tmp_path, {"tracked.txt": "t", ".gitignore": "ignored.txt\n"})
    write_tree(tmp_path, {"ignored.txt": "i"})
    inventory = build(tmp_path, Target.ARCHIVE)
    assert paths(inventory) == [".gitignore", "ignored.txt", "tracked.txt"]
    tracked = {artifact.relpath: artifact.tracked for artifact in inventory.artifacts}
    assert tracked["tracked.txt"] is True
    assert tracked["ignored.txt"] is False


@pytest.mark.parametrize("target", list(Target))
def test_dot_git_is_never_listed(tmp_path: Path, target: Target) -> None:
    init_repo(tmp_path)
    assert not any(path.startswith(".git/") for path in paths(build(tmp_path, target)))


def test_a_subdirectory_of_a_repository_can_be_scanned(tmp_path: Path) -> None:
    init_repo(tmp_path, {"inside/a.txt": "a", "outside.txt": "o"})
    inventory = build(tmp_path / "inside")
    assert paths(inventory) == ["a.txt"]
    assert inventory.artifacts[0].tracked is True


def test_results_do_not_depend_on_listing_order(tmp_path: Path) -> None:
    write_tree(tmp_path, {name: "x" for name in ["z.txt", "a.txt", "m/b.txt", "m/a.txt"]})
    assert paths(build(tmp_path)) == sorted(paths(build(tmp_path)))


# Excludes


def test_excludes_remove_and_count_files(tmp_path: Path) -> None:
    write_tree(tmp_path, {"keep.txt": "k", ".venv/a.py": "a", ".venv/lib/b.py": "b", "x.log": "x"})
    settings = ScanSettings(exclude=(".venv/**", "*.log"))
    inventory = build(tmp_path, settings=settings)
    assert paths(inventory) == ["keep.txt"]
    assert inventory.excluded == 3


def test_excludes_apply_to_files_listed_by_git(tmp_path: Path) -> None:
    init_repo(tmp_path, {"keep.txt": "k", "data/big.csv": "b"})
    inventory = build(tmp_path, settings=ScanSettings(exclude=("data/**",)))
    assert paths(inventory) == ["keep.txt"]
    assert inventory.excluded == 1


def test_an_invalid_exclude_pattern_is_a_config_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="invalid pattern"):
        build(tmp_path, settings=ScanSettings(exclude=("\\",)))


# Whether .git will be packaged


def test_git_counts_as_packaged_only_for_an_archive(tmp_path: Path) -> None:
    init_repo(tmp_path)
    assert build(tmp_path, Target.ARCHIVE).git_packaged
    assert not build(tmp_path, Target.MIRROR).git_packaged
    assert build(tmp_path, Target.MIRROR).git_present


def test_excluding_git_states_it_will_not_be_packaged(tmp_path: Path) -> None:
    # D-08
    init_repo(tmp_path)
    settings = ScanSettings(exclude=(".git/**",))
    inventory = build(tmp_path, Target.ARCHIVE, settings)
    assert inventory.git_present
    assert not inventory.git_packaged


def test_no_git_means_nothing_to_package(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.txt": "a"})
    assert not build(tmp_path, Target.ARCHIVE).git_packaged


# Things that cannot be inspected


def test_a_tracked_file_that_was_deleted_is_reported(tmp_path: Path) -> None:
    init_repo(tmp_path, {"gone.txt": "g", "kept.txt": "k"})
    (tmp_path / "gone.txt").unlink()
    inventory = build(tmp_path)
    assert paths(inventory) == ["kept.txt"]
    assert skip_reasons(inventory) == {"gone.txt": SkipReason.UNREADABLE}


def test_a_nested_repository_is_reported_rather_than_inspected(tmp_path: Path) -> None:
    init_repo(tmp_path)
    init_repo(tmp_path / "vendor")
    inventory = build(tmp_path)
    assert skip_reasons(inventory) == {"vendor": SkipReason.SUBMODULE_NOT_INSPECTED}
    assert not any(path.startswith("vendor") for path in paths(inventory))


def test_when_git_refuses_every_file_is_listed_and_the_scan_is_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # FR-GIT-3
    init_repo(tmp_path, {"a.txt": "a", ".gitignore": "b.txt\n"})
    write_tree(tmp_path, {"b.txt": "b"})

    def refuse(_root: Path) -> None:
        raise GitError("detected dubious ownership")

    monkeypatch.setattr(inventory_module, "open_repository", refuse)
    inventory = build(tmp_path)
    assert "b.txt" in paths(inventory)
    assert skip_reasons(inventory) == {".git": SkipReason.GIT_UNAVAILABLE}


def test_a_missing_git_executable_is_reported_when_a_repository_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    init_repo(tmp_path)
    monkeypatch.setenv("PATH", "")
    assert skip_reasons(build(tmp_path)) == {".git": SkipReason.GIT_UNAVAILABLE}


def test_a_missing_git_executable_does_not_matter_without_a_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_tree(tmp_path, {"a.txt": "a"})
    monkeypatch.setenv("PATH", "")
    inventory = build(tmp_path)
    assert paths(inventory) == ["a.txt"]
    assert not inventory.skipped


def test_a_named_pipe_is_skipped_rather_than_opened(tmp_path: Path) -> None:
    # Opening a FIFO for reading would hang the scan forever.
    make_pipe = getattr(os, "mkfifo", None)
    if make_pipe is None:
        pytest.skip("this platform has no named pipes")
    make_pipe(tmp_path / "pipe")
    assert skip_reasons(build(tmp_path)) == {"pipe": SkipReason.UNREADABLE}


# Symlinks


def test_a_symlink_is_not_followed_by_default(tmp_path: Path) -> None:
    write_tree(tmp_path, {"real.txt": "r"})
    symlink_or_skip(tmp_path / "link.txt", tmp_path / "real.txt")
    inventory = build(tmp_path)
    assert paths(inventory) == ["real.txt"]
    assert skip_reasons(inventory) == {"link.txt": SkipReason.SYMLINK_NOT_FOLLOWED}


def test_a_symlink_inside_the_root_is_followed_when_enabled(tmp_path: Path) -> None:
    write_tree(tmp_path, {"real.txt": "r"})
    symlink_or_skip(tmp_path / "link.txt", tmp_path / "real.txt")
    settings = replace(NO_EXCLUDES, follow_symlinks=True)
    assert paths(build(tmp_path, settings=settings)) == ["link.txt", "real.txt"]


@pytest.mark.parametrize("follow", [False, True])
def test_a_symlink_out_of_the_root_is_never_followed(tmp_path: Path, follow: bool) -> None:
    # NFR-SAFE-3
    root = tmp_path / "root"
    write_tree(root, {"a.txt": "a"})
    write_tree(tmp_path, {"secret.txt": "s", "secrets/key.txt": "k"})
    symlink_or_skip(root / "file-link", tmp_path / "secret.txt")
    symlink_or_skip(root / "dir-link", tmp_path / "secrets", directory=True)
    inventory = build(root, settings=replace(NO_EXCLUDES, follow_symlinks=follow))
    assert paths(inventory) == ["a.txt"]
    assert skip_reasons(inventory) == {
        "dir-link": SkipReason.SYMLINK_NOT_FOLLOWED,
        "file-link": SkipReason.SYMLINK_NOT_FOLLOWED,
    }


def test_a_symlink_listed_by_git_is_not_followed_out_of_the_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    write_tree(tmp_path, {"secret.txt": "s"})
    init_repo(root)
    symlink_or_skip(root / "link.txt", tmp_path / "secret.txt")
    git(root, "add", "-A")
    assert skip_reasons(build(root))["link.txt"] is SkipReason.SYMLINK_NOT_FOLLOWED


def test_a_symlink_loop_terminates(tmp_path: Path) -> None:
    write_tree(tmp_path, {"dir/a.txt": "a"})
    symlink_or_skip(tmp_path / "dir" / "loop", tmp_path, directory=True)
    settings = replace(NO_EXCLUDES, follow_symlinks=True)
    assert paths(build(tmp_path, settings=settings)) == ["dir/a.txt"]


def test_a_broken_symlink_is_reported(tmp_path: Path) -> None:
    write_tree(tmp_path, {"a.txt": "a"})
    symlink_or_skip(tmp_path / "broken", tmp_path / "missing.txt")
    settings = replace(NO_EXCLUDES, follow_symlinks=True)
    assert skip_reasons(build(tmp_path, settings=settings)) == {
        "broken": SkipReason.SYMLINK_NOT_FOLLOWED
    }


# Uncommitted changes


def has_uncommitted_note(inventory: Inventory) -> bool:
    return any("differ from the index" in note for note in inventory.notes)


def test_a_changed_tracked_file_adds_a_note(tmp_path: Path) -> None:
    init_repo(tmp_path, {"a.txt": "before\n"})
    assert not has_uncommitted_note(build(tmp_path))
    write_tree(tmp_path, {"a.txt": "after!\n"})
    assert has_uncommitted_note(build(tmp_path))


def test_line_endings_alone_do_not_add_a_note(tmp_path: Path) -> None:
    init_repo(tmp_path, {"a.txt": "one\ntwo\n"})
    write_tree(tmp_path, {"a.txt": b"one\r\ntwo\r\n"})
    assert not has_uncommitted_note(build(tmp_path))


def test_archives_do_not_get_the_note(tmp_path: Path) -> None:
    init_repo(tmp_path, {"a.txt": "before\n"})
    write_tree(tmp_path, {"a.txt": "after!\n"})
    assert not has_uncommitted_note(build(tmp_path, Target.ARCHIVE))


# Classification


@pytest.mark.parametrize(
    ("relpath", "head", "kind"),
    [
        ("pyproject.toml", b"", ArtifactKind.MANIFEST),
        ("sub/package.json", b"", ArtifactKind.MANIFEST),
        ("setup.py", b"", ArtifactKind.MANIFEST),
        ("setup.cfg", b"", ArtifactKind.MANIFEST),
        ("CITATION.cff", b"", ArtifactKind.MANIFEST),
        ("LICENSE", b"", ArtifactKind.MANIFEST),
        ("license.txt", b"", ArtifactKind.MANIFEST),
        ("LICENCE-MIT", b"", ArtifactKind.MANIFEST),
        ("NOTICE", b"", ArtifactKind.MANIFEST),
        ("COPYING.md", b"", ArtifactKind.MANIFEST),
        ("AUTHORS", b"", ArtifactKind.MANIFEST),
        ("notebook.ipynb", b"{}", ArtifactKind.NOTEBOOK),
        ("FIGURE.PDF", b"%PDF", ArtifactKind.PDF),
        ("plot.png", b"\x89PNG", ArtifactKind.IMAGE),
        ("photo.jpeg", b"\xff\xd8", ArtifactKind.IMAGE),
        ("data.tar.gz", b"\x1f\x8b", ArtifactKind.ARCHIVE),
        ("data.zip", b"PK", ArtifactKind.ARCHIVE),
        ("train.py", b"import os\n", ArtifactKind.TEXT),
        ("no_extension", b"plain words\n", ArtifactKind.TEXT),
        ("weights.bin", b"\x00\x01\x02", ArtifactKind.BINARY),
        ("binary_named.py", b"MZ\x00\x00", ArtifactKind.BINARY),
        ("latin1.txt", b"caf\xe9 au lait\n", ArtifactKind.BINARY),
        ("empty.dat", b"", ArtifactKind.TEXT),
    ],
)
def test_classification(relpath: str, head: bytes, kind: ArtifactKind) -> None:
    assert classify(relpath, head) is kind


@pytest.mark.parametrize("relpath", ["licenseplates.csv", "noticeboard.txt", "authorship.md"])
def test_names_that_only_start_like_a_legal_file_are_not_manifests(relpath: str) -> None:
    assert classify(relpath, b"text\n") is ArtifactKind.TEXT


def test_a_multibyte_character_cut_at_the_sample_edge_is_still_text() -> None:
    head = ("a" * (SNIFF_BYTES - 1) + "\u00e9").encode("utf-8")[:SNIFF_BYTES]
    assert looks_like_text(head)


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-32"])
def test_files_with_a_byte_order_mark_are_read_correctly(encoding: str) -> None:
    content = "Alice Example".encode(encoding)
    assert looks_like_text(content)
    assert decode_text(content) == "Alice Example"
