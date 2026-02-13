#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SRC="$REPO_ROOT/src/smellcheck"
DEST="$REPO_ROOT/plugins/python-refactoring/skills/python-refactoring/scripts/smellcheck"

VERSION=$(sed -n 's/^version *= *"\([^"]*\)"/\1/p' "$REPO_ROOT/pyproject.toml")

mkdir -p "$DEST"
cp "$SRC/detector.py" "$DEST/detector.py"

cat > "$DEST/__init__.py" << EOF
"""smellcheck -- vendored for Agent Skills (do not edit, run scripts/vendor-smellcheck.sh)."""
# x-release-please-start-version
__version__ = "$VERSION"
# x-release-please-end
EOF

echo "Vendored smellcheck $VERSION into skill bundle."
