"""smellcheck -- Python code smell detector."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from smellcheck.detector import Finding, SmellDetector, print_findings, scan_path

try:
    __version__ = version("smellcheck")
except PackageNotFoundError:
    __version__ = "0.2.3"

__all__ = ["Finding", "SmellDetector", "scan_path", "print_findings", "__version__"]
