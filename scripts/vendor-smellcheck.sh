#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SRC="$REPO_ROOT/src/smellcheck"
DEST="$REPO_ROOT/plugins/python-refactoring/skills/python-refactoring/scripts/smellcheck"

VERSION=$(python3 -c "
import tomllib, pathlib
data = tomllib.loads(pathlib.Path('$REPO_ROOT/pyproject.toml').read_text())
print(data['project']['version'])
")

mkdir -p "$DEST"
cp "$SRC/detector.py" "$DEST/detector.py"

cat > "$DEST/__init__.py" << EOF
"""smellcheck -- vendored for Agent Skills (do not edit, run scripts/vendor-smellcheck.sh)."""
__version__ = "$VERSION"
EOF

echo "Vendored smellcheck $VERSION into skill bundle."
