#!/usr/bin/env python3
"""smellcheck launcher for Agent Skills.

Works out of the box — no pip install required.
Uses the bundled copy shipped with this skill.
Falls back to a pip-installed version if the bundled copy is missing.
"""
from __future__ import annotations

import sys
from pathlib import Path


def _bundled_main():
    """Import main from the bundled smellcheck package next to this script."""
    scripts_dir = str(Path(__file__).resolve().parent)
    bundled = Path(scripts_dir) / "smellcheck" / "detector.py"
    if not bundled.is_file():
        return None
    # Prepend so bundled smellcheck shadows any installed version
    sys.path.insert(0, scripts_dir)
    try:
        from smellcheck.detector import main
        return main
    except ImportError:
        if scripts_dir in sys.path:
            sys.path.remove(scripts_dir)
        return None


def _installed_main():
    """Import main from a pip-installed smellcheck."""
    try:
        from smellcheck.detector import main
        return main
    except ModuleNotFoundError as exc:
        if exc.name != "smellcheck":
            raise
        return None


def _local_checkout_main():
    """Import main from a local repo checkout (development)."""
    here = Path(__file__).resolve().parent
    for parent in [here, *here.parents]:
        if (parent / "src" / "smellcheck" / "detector.py").is_file():
            src = str(parent / "src")
            if src not in sys.path:
                sys.path.insert(0, src)
            try:
                from smellcheck.detector import main
                return main
            except ImportError:
                sys.path.remove(src)
    return None


if __name__ == "__main__":
    main = _bundled_main() or _installed_main() or _local_checkout_main()

    if main is None:
        print(
            "smellcheck is not available.\n"
            "\n"
            "Install it (zero dependencies, Python 3.10+):\n"
            f"  {sys.executable} -m pip install smellcheck\n",
            file=sys.stderr,
        )
        raise SystemExit(1)

    main()
