#!/usr/bin/env bash
set -euo pipefail

SRC="src/smellcheck/detector.py"
VENDORED="plugins/python-refactoring/skills/python-refactoring/scripts/smellcheck/detector.py"

if [ ! -f "$VENDORED" ]; then
    echo "ERROR: Vendored detector.py not found. Run: scripts/vendor-smellcheck.sh"
    exit 1
fi

if ! diff -q "$SRC" "$VENDORED" > /dev/null 2>&1; then
    echo "ERROR: Vendored detector.py is out of sync with source."
    echo "Run: scripts/vendor-smellcheck.sh"
    exit 1
fi
