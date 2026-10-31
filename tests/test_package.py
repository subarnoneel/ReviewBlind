"""Smoke test: the package installs and every runtime dependency imports."""

import importlib

import pytest

import reviewblind


def test_version_is_set() -> None:
    assert reviewblind.__version__


@pytest.mark.parametrize("module", ["typer", "rich", "pymupdf", "PIL", "yaml", "pathspec"])
def test_runtime_dependency_imports(module: str) -> None:
    importlib.import_module(module)
