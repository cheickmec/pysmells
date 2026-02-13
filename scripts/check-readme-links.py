#!/usr/bin/env python3
"""Check README.md for relative links and verify repo file paths.

Relative links break on PyPI — all links in README.md must be absolute.
For absolute GitHub links pointing to this repo, verify the target file exists.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# Matches markdown links: [text](url)
# Excludes images: ![alt](src) handled separately
LINK_RE = re.compile(
    r"(?<!!)"           # negative lookbehind for ! (skip images)
    r"\[([^\]]*)\]"     # [link text]
    r"\(([^)]+)\)",     # (url)
)

# Also check image links
IMAGE_RE = re.compile(
    r"!\[([^\]]*)\]"    # ![alt text]
    r"\(([^)]+)\)",     # (url)
)

# HTML href and src attributes
HTML_RE = re.compile(
    r'(?:href|src)="([^"]+)"',
)

REPO_SLUG = "cheickmec/smellcheck"
GITHUB_PREFIX = f"https://github.com/{REPO_SLUG}/blob/main/"
RAW_PREFIX = f"https://raw.githubusercontent.com/{REPO_SLUG}/main/"


def _repo_root() -> Path:
    """Find the git repo root."""
    try:
        root = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        return Path(root)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return Path(__file__).resolve().parent.parent


def _is_absolute(url: str) -> bool:
    return url.startswith(("http://", "https://", "#", "mailto:"))


def _is_badge_image(url: str) -> bool:
    """Badge images (shields.io, img.shields.io, etc.) are external."""
    return "shields.io" in url or "badge" in url.lower()


def _local_path_from_github_url(url: str) -> str | None:
    """Extract the repo-relative path from an absolute GitHub URL."""
    for prefix in (GITHUB_PREFIX, RAW_PREFIX):
        if url.startswith(prefix):
            path = url[len(prefix):]
            # Strip fragment (#section)
            path = path.split("#")[0]
            # Strip query (?foo=bar)
            path = path.split("?")[0]
            return path
    return None


def check_readme(readme_path: Path, repo_root: Path) -> list[str]:
    """Return list of error messages."""
    text = readme_path.read_text(encoding="utf-8")
    lines = text.splitlines()
    errors: list[str] = []

    for lineno, line in enumerate(lines, 1):
        # Check markdown links and images
        for pattern in (LINK_RE, IMAGE_RE):
            for match in pattern.finditer(line):
                url = match.group(2).strip()

                # Skip anchors (same-page links)
                if url.startswith("#"):
                    continue

                # Flag relative links
                if not _is_absolute(url):
                    errors.append(
                        f"README.md:{lineno}: relative link '{url}' — "
                        f"use absolute URL for PyPI compatibility"
                    )
                    continue

                # Verify GitHub links point to existing files
                local_path = _local_path_from_github_url(url)
                if local_path and not (repo_root / local_path).exists():
                    errors.append(
                        f"README.md:{lineno}: broken repo link '{url}' — "
                        f"file '{local_path}' does not exist"
                    )

        # Check HTML href/src attributes
        for match in HTML_RE.finditer(line):
            url = match.group(1).strip()

            if url.startswith("#"):
                continue

            if not _is_absolute(url):
                errors.append(
                    f"README.md:{lineno}: relative link '{url}' in HTML — "
                    f"use absolute URL for PyPI compatibility"
                )
                continue

            local_path = _local_path_from_github_url(url)
            if local_path and not (repo_root / local_path).exists():
                errors.append(
                    f"README.md:{lineno}: broken repo link '{url}' — "
                    f"file '{local_path}' does not exist"
                )

    return errors


def main() -> int:
    repo_root = _repo_root()
    readme = repo_root / "README.md"

    if not readme.exists():
        print("README.md not found", file=sys.stderr)
        return 1

    errors = check_readme(readme, repo_root)

    if errors:
        print(f"Found {len(errors)} link issue(s) in README.md:\n")
        for err in errors:
            print(f"  {err}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
