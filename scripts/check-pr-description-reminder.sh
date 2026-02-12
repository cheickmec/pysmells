#!/usr/bin/env bash
# Warn-only reminder: does your PR description need updating?
# Fires on pre-push when the current branch has an open PR.
# Always exits 0 — never blocks pushes.

# Color only when stderr is a terminal
if [ -t 2 ]; then
  YELLOW='\033[0;33m'
  DIM='\033[2m'
  RESET='\033[0m'
else
  YELLOW=''
  DIM=''
  RESET=''
fi

# Bail if gh CLI is not installed
if ! command -v gh &>/dev/null; then
  exit 0
fi

# Check for an open PR on the current branch (suppress errors)
pr_json=$(gh pr view --json number,title,body,url 2>/dev/null)
if [ $? -ne 0 ] || [ -z "$pr_json" ]; then
  # No open PR for this branch — nothing to remind
  exit 0
fi

pr_number=$(echo "$pr_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('number',''))" 2>/dev/null)
pr_title=$(echo "$pr_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('title',''))" 2>/dev/null)
pr_url=$(echo "$pr_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('url',''))" 2>/dev/null)
pr_body=$(echo "$pr_json" | python3 -c "import sys,json; print(json.load(sys.stdin).get('body','') or '(empty)')" 2>/dev/null)

# Truncate body for display (first 15 lines, max 800 chars)
pr_body_preview=$(echo "$pr_body" | head -15)
if [ ${#pr_body_preview} -gt 800 ]; then
  pr_body_preview="${pr_body_preview:0:800}..."
fi
body_lines=$(echo "$pr_body" | wc -l | tr -d ' ')
if [ "$body_lines" -gt 15 ]; then
  pr_body_preview="${pr_body_preview}
  ... (${body_lines} lines total)"
fi

echo -e "${YELLOW}╭──────────────────────────────────────────────────────────╮${RESET}" >&2
echo -e "${YELLOW}│  Reminder: You have an open PR for this branch.         │${RESET}" >&2
echo -e "${YELLOW}│  Does the PR description still reflect your changes?    │${RESET}" >&2
echo -e "${YELLOW}│                                                         │${RESET}" >&2
pr_label="PR #${pr_number} -- ${pr_title}"
printf  "${YELLOW}│  %-55.55s│${RESET}\n" "$pr_label" >&2
printf  "${YELLOW}│  %-55.55s│${RESET}\n" "$pr_url" >&2
echo -e "${YELLOW}╰──────────────────────────────────────────────────────────╯${RESET}" >&2
echo -e "${DIM}Current PR description:${RESET}" >&2
echo -e "${DIM}─────────────────────────${RESET}" >&2
echo "$pr_body_preview" | while IFS= read -r line; do
  echo -e "${DIM}  ${line}${RESET}" >&2
done
echo -e "${DIM}─────────────────────────${RESET}" >&2
echo "" >&2

exit 0
