#!/usr/bin/env bash
set -euo pipefail

SRC="src/smellcheck/detector.py"
VENDORED="plugins/python-refactoring/skills/python-refactoring/scripts/smellcheck/detector.py"

if [ ! -f "$VENDORED" ] || ! diff -q "$SRC" "$VENDORED" > /dev/null 2>&1; then
    echo "Auto-vendoring: detector.py changed, syncing vendored copy..."
    scripts/vendor-smellcheck.sh
    git add "$VENDORED" \
        "plugins/python-refactoring/skills/python-refactoring/scripts/smellcheck/__init__.py"
    echo "Vendored copy updated and staged. Please re-run your commit."
    exit 1
fi
