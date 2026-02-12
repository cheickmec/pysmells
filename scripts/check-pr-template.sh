#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# PR template validator — ensures the PR body uses at least one of the
# repo's PR templates and that all required headings are present.
#
# Two-layer validation:
#   1. Marker check — each template has a unique HTML comment marker
#      (<!-- template:NAME -->). The PR body must contain at least one.
#   2. Header check — the matched template's ## headings must all appear
#      in the PR body. Reports which headings are missing.
#
# Environment variables (set by the workflow):
#   PR_BODY       — the pull request body text (required)
#   PR_NUMBER     — the pull request number (optional, for commenting)
#   GH_TOKEN      — GitHub token (optional, for commenting)
#   GITHUB_REPO   — owner/repo (optional, for commenting)
#
# If PR_NUMBER, GH_TOKEN, and GITHUB_REPO are set, the script posts a
# comment on the PR with validation results (adapted from ranemihir's
# template-validator).
#
# Adapted from nowNick/pr-template-validator (MIT) and
# ranemihir/template-validator.
# ---------------------------------------------------------------------------
set -euo pipefail

template_dir=".github/PULL_REQUEST_TEMPLATE"

# --- Input validation ------------------------------------------------------

if [ -z "${PR_BODY:-}" ]; then
    echo "::error::PR body is empty. Please use a PR template."
    exit 1
fi

if [ ! -d "$template_dir" ]; then
    echo "::error::Template directory $template_dir not found."
    exit 1
fi

# --- Discover templates and markers ----------------------------------------

# Build parallel arrays: template files, markers, and names
template_files=()
template_markers=()
template_names=()

for file in "$template_dir"/*.md; do
    [ -f "$file" ] || continue
    marker=$(grep -o '<!-- template:[a-z-]* -->' "$file" 2>/dev/null || true)
    if [ -n "$marker" ]; then
        template_files+=("$file")
        template_markers+=("$marker")
        name="${marker#*:}"
        name="${name%% *}"
        template_names+=("$name")
    fi
done

if [ ${#template_markers[@]} -eq 0 ]; then
    echo "::error::No template markers found in $template_dir."
    echo "Each template must contain a marker like: <!-- template:feature -->"
    exit 1
fi

# --- Phase 1: Marker check ------------------------------------------------
# Find which template the PR body matches (first match wins).

matched_index=-1
for i in "${!template_markers[@]}"; do
    if echo "$PR_BODY" | grep -qF "${template_markers[$i]}"; then
        matched_index=$i
        break
    fi
done

if [ "$matched_index" -eq -1 ]; then
    msg="PR body does not match any PR template.\n\n"
    msg+="Available templates:\n"
    for name in "${template_names[@]}"; do
        msg+="  - \`$name\` — use \`?template=$name.md\` when creating the PR\n"
    done
    echo -e "::error::$msg"

    # Post comment if configured
    if [ -n "${PR_NUMBER:-}" ] && [ -n "${GH_TOKEN:-}" ] && [ -n "${GITHUB_REPO:-}" ]; then
        comment_body=$(printf "### :x: PR Template Validation Failed\n\n")
        comment_body+=$(printf "No template marker found in the PR body.\n\n")
        comment_body+=$(printf "Please use one of the available templates when creating your PR:\n")
        for name in "${template_names[@]}"; do
            comment_body+=$(printf "\n- \`%s\`" "$name")
        done
        comment_body+=$(printf "\n\n**Tip:** Add \`?template=%s.md\` to the PR creation URL, or select a template from the dropdown." "${template_names[0]}")
        gh api "repos/$GITHUB_REPO/issues/$PR_NUMBER/comments" \
            --method POST --field body="$comment_body" --silent 2>/dev/null || true
    fi

    exit 1
fi

matched_name="${template_names[$matched_index]}"
matched_file="${template_files[$matched_index]}"
echo "PR uses template: $matched_name"

# --- Phase 2: Header check ------------------------------------------------
# Extract ## headings from the template and verify they appear in the PR body.

template_headers=()
while IFS= read -r header; do
    template_headers+=("$header")
done < <(grep '^## ' "$matched_file" | sed 's/^ *//')

if [ ${#template_headers[@]} -eq 0 ]; then
    echo "Template '$matched_name' has no ## headings to validate — skipping header check."
    exit 0
fi

missing_headers=()
for header in "${template_headers[@]}"; do
    if ! echo "$PR_BODY" | grep -qF "$header"; then
        missing_headers+=("$header")
    fi
done

if [ ${#missing_headers[@]} -eq 0 ]; then
    echo "All ${#template_headers[@]} required headings present."
    exit 0
fi

# Some headings are missing
msg="PR is missing ${#missing_headers[@]} required heading(s) from the '$matched_name' template:\n"
for header in "${missing_headers[@]}"; do
    msg+="  - $header\n"
done
echo -e "::error::$msg"

# Post comment if configured
if [ -n "${PR_NUMBER:-}" ] && [ -n "${GH_TOKEN:-}" ] && [ -n "${GITHUB_REPO:-}" ]; then
    comment_body=$(printf "### :warning: PR Template Validation Failed\n\n")
    comment_body+=$(printf "Using template: **%s**\n\n" "$matched_name")
    comment_body+=$(printf "The following required sections are missing from the PR body:\n")
    for header in "${missing_headers[@]}"; do
        comment_body+=$(printf "\n- \`%s\`" "$header")
    done
    comment_body+=$(printf "\n\nPlease add the missing sections to your PR description.")
    gh api "repos/$GITHUB_REPO/issues/$PR_NUMBER/comments" \
        --method POST --field body="$comment_body" --silent 2>/dev/null || true
fi

exit 1
