"""smellcheck -- Python code smell detector."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from smellcheck.detector import (
    Finding,
    RuleDef,
    SmellDetector,
    load_config,
    print_findings,
    scan_path,
    scan_paths,
)

try:
    __version__ = version("smellcheck")
except PackageNotFoundError:
    __version__ = "0.2.6"

__all__ = [
    "Finding",
    "RuleDef",
    "SmellDetector",
    "load_config",
    "print_findings",
    "scan_path",
    "scan_paths",
    "__version__",
]
