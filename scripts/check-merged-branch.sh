#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Pre-commit hook: block commits on branches already merged into main.
#
# Problem:  After a PR merges, the local branch still exists. If you
#           accidentally keep working on it, commits land on a stale branch
#           instead of a fresh feature branch.
#
# Strategy: Two checks cover both merge styles GitHub supports:
#
#   1. Regular merge — every commit on this branch is reachable from
#      origin/main, so HEAD is an ancestor of origin/main.
#      Detected with: git merge-base --is-ancestor HEAD origin/main
#      Guards:
#        a) HEAD != origin/main — a brand-new branch (whose HEAD equals
#           origin/main) is allowed through.
#        b) The branch has unique commits that are not in origin/main
#           (log origin/main..HEAD is non-empty). A stale branch created
#           from an older main that was never committed to also passes.
#
#   2. Squash merge — the original commits are NOT in origin/main (different
#      SHAs), but the resulting tree is identical.
#      Detected with: git diff origin/main..HEAD  (empty = same tree)
#      Guards:
#        a) origin/main is NOT an ancestor of HEAD — if it is, the branch
#           is just based on current main and may have no-op commits
#           (e.g. change + revert), which should be allowed.
#        b) The branch has unique commits (log is non-empty), so a
#           brand-new branch with no commits is allowed through.
#
# Neither check depends on the branch's remote tracking ref, so they
# work even after the remote branch is deleted post-merge and pruned.
#
# Uses origin/main (not local main) so it works without fetching — the
# remote-tracking ref is updated automatically by push/pull/fetch.
# ---------------------------------------------------------------------------
set -euo pipefail

branch=$(git rev-parse --abbrev-ref HEAD)

# Skip main/master (handled by the no-commit-to-main hook)
if [ "$branch" = "main" ] || [ "$branch" = "master" ]; then
    exit 0
fi

# Skip when origin/main is not available (shallow clone, no remote, etc.)
if ! git rev-parse --verify origin/main >/dev/null 2>&1; then
    exit 0
fi

head_sha=$(git rev-parse HEAD)
main_sha=$(git rev-parse origin/main)

# Check 1: regular merge — HEAD is an ancestor of origin/main.
# Guards:
#   a) HEAD != origin/main — a brand-new branch at main passes through.
#   b) The branch has unique commits (log origin/main..HEAD is non-empty).
#      A stale branch created from an older main without commits passes.
unique_commits_for_check1=$(git log origin/main..HEAD --oneline 2>/dev/null || true)
if [ "$head_sha" != "$main_sha" ] \
    && [ -n "$unique_commits_for_check1" ] \
    && git merge-base --is-ancestor HEAD origin/main 2>/dev/null; then
    echo "ERROR: Branch '$branch' is already merged into main." >&2
    echo "       Create a new feature branch:  git checkout -b feat/my-change main" >&2
    exit 1
fi

# Check 2: squash merge — commits differ but tree is identical.
# Guards:
#   a) origin/main is NOT an ancestor of HEAD. If it is, the branch is
#      based on current main and may just have no-op commits (change +
#      revert), which should be allowed.
#   b) The branch has unique commits (log origin/main..HEAD is non-empty).
#      A brand-new branch with no commits has an empty log, so it passes.
if ! git merge-base --is-ancestor origin/main HEAD 2>/dev/null; then
    unique_commits=$(git log origin/main..HEAD --oneline 2>/dev/null)
    if [ -n "$unique_commits" ] && [ -z "$(git diff origin/main..HEAD 2>/dev/null)" ]; then
        echo "ERROR: Branch '$branch' appears squash-merged into main (identical tree)." >&2
        echo "       Create a new feature branch:  git checkout -b feat/my-change main" >&2
        exit 1
    fi
fi
