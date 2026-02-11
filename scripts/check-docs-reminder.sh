#!/usr/bin/env bash
# Warn-only reminder: did you update docs after a code change?
# Always exits 0 — never blocks commits.

# Color only when stderr is a terminal
if [ -t 2 ]; then
  YELLOW='\033[0;33m'
  RESET='\033[0m'
else
  YELLOW=''
  RESET=''
fi

# Doc files that are manually maintained and can go stale
DOC_PATTERNS=(
  "README.md"
  "CONTRIBUTING.md"
  "plugins/python-refactoring/skills/python-refactoring/SKILL.md"
  "plugins/python-refactoring/skills/python-refactoring/references/"
)

# Capture staged files once
STAGED=$(git diff --cached --name-only)

# Check if any doc file is in the staged changeset
for pattern in "${DOC_PATTERNS[@]}"; do
  if echo "$STAGED" | grep -qF "$pattern"; then
    # At least one doc file is staged — no reminder needed
    exit 0
  fi
done

# Code changed but no docs staged — print reminder
echo -e "${YELLOW}╭──────────────────────────────────────────────────────────╮${RESET}" >&2
echo -e "${YELLOW}│  Reminder: You're committing code without doc updates.  │${RESET}" >&2
echo -e "${YELLOW}│                                                         │${RESET}" >&2
echo -e "${YELLOW}│  If your change affects any of these, update them too:  │${RESET}" >&2
echo -e "${YELLOW}│    • README.md          (features, CLI options, usage)  │${RESET}" >&2
echo -e "${YELLOW}│    • CONTRIBUTING.md    (architecture, adding checks)   │${RESET}" >&2
echo -e "${YELLOW}│    • SKILL.md + refs/   (pattern catalog & families)    │${RESET}" >&2
echo -e "${YELLOW}│                                                         │${RESET}" >&2
echo -e "${YELLOW}│  CHANGELOG.md is auto-generated — no action needed.    │${RESET}" >&2
echo -e "${YELLOW}╰──────────────────────────────────────────────────────────╯${RESET}" >&2

exit 0
