#!/usr/bin/env bash
# Warn-only reminder: did you consider whether this is a breaking change?
# Always exits 0 — never blocks commits.

# Color only when stderr is a terminal
if [ -t 2 ]; then
  YELLOW='\033[0;33m'
  RESET='\033[0m'
else
  YELLOW=''
  RESET=''
fi

commit_msg_file="$1"
if [ -z "$commit_msg_file" ] || [ ! -f "$commit_msg_file" ]; then
  exit 0
fi

message=$(cat "$commit_msg_file")

# If message already signals a breaking change, no reminder needed
if echo "$message" | grep -qE '!:|BREAKING CHANGE:'; then
  exit 0
fi

# Check if staged files include src/ changes
STAGED=$(git diff --cached --name-only 2>/dev/null)
if ! echo "$STAGED" | grep -q '^src/'; then
  # No source changes — no reminder needed
  exit 0
fi

# Source changed but no breaking-change signal — print reminder
echo -e "${YELLOW}╭──────────────────────────────────────────────────────────╮${RESET}" >&2
echo -e "${YELLOW}│  Reminder: Does this commit introduce a breaking change? │${RESET}" >&2
echo -e "${YELLOW}│                                                          │${RESET}" >&2
echo -e "${YELLOW}│  If yes, signal it in the commit message:                │${RESET}" >&2
echo -e "${YELLOW}│    • Add ! after the type:  feat!: description           │${RESET}" >&2
echo -e "${YELLOW}│    • Or add a footer:       BREAKING CHANGE: details     │${RESET}" >&2
echo -e "${YELLOW}│                                                          │${RESET}" >&2
echo -e "${YELLOW}│  Breaking changes bump the minor version (0.x -> 0.y).  │${RESET}" >&2
echo -e "${YELLOW}│                                                          │${RESET}" >&2
echo -e "${YELLOW}│  Examples of breaking changes:                           │${RESET}" >&2
echo -e "${YELLOW}│    • Removing/renaming public API (Finding fields, etc.) │${RESET}" >&2
echo -e "${YELLOW}│    • Changing CLI flag behavior or output format         │${RESET}" >&2
echo -e "${YELLOW}│    • Removing or renaming SC codes                       │${RESET}" >&2
echo -e "${YELLOW}╰──────────────────────────────────────────────────────────╯${RESET}" >&2

exit 0
