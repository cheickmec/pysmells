"""Enforce version parity across all version sources.

All of these must agree:
  - pyproject.toml          [project] version
  - .release-please-manifest.json  "."
  - .claude-plugin/marketplace.json  metadata.version + plugins[0].version
  - smellcheck.__version__  (importlib.metadata, derived from pyproject.toml)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# Repo root is one level up from tests/
REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]


def _read_json(rel: str) -> dict:
    return json.loads((REPO_ROOT / rel).read_text(encoding="utf-8"))


def _pyproject_version() -> str:
    path = REPO_ROOT / "pyproject.toml"
    if tomllib is not None:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        return data["project"]["version"]
    # Fallback: regex for environments without tomllib/tomli
    import re
    text = path.read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert m, "Could not find version in pyproject.toml"
    return m.group(1)


# ---------------------------------------------------------------------------
# The single source of truth
# ---------------------------------------------------------------------------

CANONICAL_VERSION = _pyproject_version()

VERSION_SOURCES: list[tuple[str, str]] = []


def _collect() -> list[tuple[str, str]]:
    """Gather (label, version) pairs from every file that declares a version."""
    sources: list[tuple[str, str]] = []

    # 1. pyproject.toml
    sources.append(("pyproject.toml [project].version", CANONICAL_VERSION))

    # 2. .release-please-manifest.json
    manifest = _read_json(".release-please-manifest.json")
    sources.append((".release-please-manifest.json", manifest["."]))

    # 3. marketplace.json — metadata.version
    mp = _read_json(".claude-plugin/marketplace.json")
    sources.append(("marketplace.json metadata.version", mp["metadata"]["version"]))

    # 4. marketplace.json — plugins[0].version
    sources.append(("marketplace.json plugins[0].version", mp["plugins"][0]["version"]))

    # 5. Runtime __version__
    from smellcheck import __version__
    sources.append(("smellcheck.__version__", __version__))

    return sources


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def version_sources() -> list[tuple[str, str]]:
    return _collect()


def test_all_versions_match(version_sources):
    """Every version source must equal the canonical version in pyproject.toml."""
    mismatches = [
        (label, ver)
        for label, ver in version_sources
        if ver != CANONICAL_VERSION
    ]
    assert not mismatches, (
        f"Version drift detected! Canonical version is {CANONICAL_VERSION}.\n"
        + "\n".join(f"  {label}: {ver}" for label, ver in mismatches)
    )


def test_at_least_four_sources_checked(version_sources):
    """Sanity check: we should be checking at least 4 distinct sources."""
    assert len(version_sources) >= 4, (
        f"Expected >= 4 version sources, got {len(version_sources)}: "
        + ", ".join(label for label, _ in version_sources)
    )


# ---------------------------------------------------------------------------
# Vendored bundle sync tests
# ---------------------------------------------------------------------------

VENDORED_DIR = (
    REPO_ROOT
    / "plugins"
    / "python-refactoring"
    / "skills"
    / "python-refactoring"
    / "scripts"
    / "smellcheck"
)


def test_vendored_detector_matches_source():
    """Vendored detector.py must be identical to source."""
    source = REPO_ROOT / "src" / "smellcheck" / "detector.py"
    vendored = VENDORED_DIR / "detector.py"
    assert vendored.exists(), (
        "Vendored detector.py not found — run scripts/vendor-smellcheck.sh"
    )
    assert source.read_text() == vendored.read_text(), (
        "Vendored detector.py out of sync — run scripts/vendor-smellcheck.sh"
    )


def test_vendored_init_version_matches():
    """Vendored __init__.py version must match canonical version."""
    vendored_init = VENDORED_DIR / "__init__.py"
    assert vendored_init.exists(), (
        "Vendored __init__.py not found — run scripts/vendor-smellcheck.sh"
    )
    content = vendored_init.read_text()
    assert f'__version__ = "{CANONICAL_VERSION}"' in content, (
        f"Vendored __init__.py version doesn't match {CANONICAL_VERSION}"
    )
