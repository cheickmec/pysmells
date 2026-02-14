#!/usr/bin/env bash
set -euo pipefail

SRC="src/smellcheck/detector.py"
VENDOR_DIR="plugins/python-refactoring/skills/python-refactoring/scripts/smellcheck"
VENDORED="$VENDOR_DIR/detector.py"

if [ ! -f "$VENDORED" ] || ! diff -q "$SRC" "$VENDORED" > /dev/null 2>&1; then
    # CI: check-only mode (no auto-fix)
    if [ "${CI:-}" = "true" ]; then
        echo "ERROR: Vendored detector.py is out of sync. Run: scripts/vendor-smellcheck.sh"
        exit 1
    fi

    echo "Auto-vendoring: detector.py changed, syncing vendored copy..."
    if ! scripts/vendor-smellcheck.sh; then
        echo "ERROR: vendor-smellcheck.sh failed. Fix the issue above and retry."
        exit 1
    fi
    git add "$VENDOR_DIR/"
    echo "Vendored copy updated and staged. Commit was aborted — re-run 'git commit' to include the changes."
    exit 1
fi
