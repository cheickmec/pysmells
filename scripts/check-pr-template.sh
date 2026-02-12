#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# PR template validator — ensures the PR body contains a marker from at
# least one of the repo's PR templates.
#
# Each template in .github/PULL_REQUEST_TEMPLATE/ must include a unique
# HTML comment marker:  <!-- template:NAME -->
#
# The script scans the template directory for markers, then checks if the
# PR body (passed via $PR_BODY env var) contains at least one.
#
# Adapted from nowNick/pr-template-validator (MIT).
# ---------------------------------------------------------------------------
set -euo pipefail

template_dir=".github/PULL_REQUEST_TEMPLATE"

if [ -z "${PR_BODY:-}" ]; then
    echo "::error::PR_BODY environment variable is empty or not set."
    exit 1
fi

if [ ! -d "$template_dir" ]; then
    echo "::error::Template directory $template_dir not found."
    exit 1
fi

# Collect all markers from template files
markers=()
while IFS= read -r marker; do
    markers+=("$marker")
done < <(grep -roh '<!-- template:[a-z-]* -->' "$template_dir" | sort -u)

if [ ${#markers[@]} -eq 0 ]; then
    echo "::error::No template markers found in $template_dir."
    echo "Each template must contain a marker like: <!-- template:feature -->"
    exit 1
fi

# Check if PR body contains at least one marker
for marker in "${markers[@]}"; do
    if echo "$PR_BODY" | grep -qF "$marker"; then
        name="${marker#*:}"
        name="${name%% *}"
        echo "PR uses template: $name"
        exit 0
    fi
done

# None matched
echo "::error::PR body does not match any PR template."
echo "Available templates:"
for marker in "${markers[@]}"; do
    name="${marker#*:}"
    name="${name%% *}"
    echo "  - $name  ($template_dir/)"
done
echo ""
echo "When creating a PR, select a template from the dropdown or add the"
echo "template URL parameter: ?template=feature.md"
exit 1
