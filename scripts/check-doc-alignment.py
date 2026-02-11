#!/usr/bin/env python3
"""Verify every SC code in _RULE_REGISTRY appears in the README pattern tables and vice versa."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sc_codes_from_registry() -> set[str]:
    """Import the registry and return the set of SC codes."""
    sys.path.insert(0, str(ROOT / "src"))
    from smellcheck.detector import _RULE_REGISTRY

    return {rd.rule_id for rd in _RULE_REGISTRY.values()}


def sc_codes_from_readme() -> set[str]:
    """Extract SC codes from README.md markdown tables."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    return set(re.findall(r"\|\s*(SC\d{3})\s*\|", text))


def main() -> int:
    registry = sc_codes_from_registry()
    readme = sc_codes_from_readme()

    missing_from_readme = sorted(registry - readme)
    extra_in_readme = sorted(readme - registry)

    ok = True
    if missing_from_readme:
        print(f"SC codes in registry but missing from README: {', '.join(missing_from_readme)}", file=sys.stderr)
        ok = False
    if extra_in_readme:
        print(f"SC codes in README but missing from registry: {', '.join(extra_in_readme)}", file=sys.stderr)
        ok = False

    if ok:
        print(f"Doc alignment OK: {len(registry)} SC codes match between registry and README.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
