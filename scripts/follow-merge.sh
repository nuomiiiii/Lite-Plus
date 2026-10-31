#!/bin/sh
# Merge an upstream Lite tag into a Plus checkout. B-class conflicts keep Plus.
# C-class JSON keeps Plus keys and Lite additions. Other C-class files 3-way merge:
# Plus deletions win, Lite-only functions/imports stay. Leftovers exit 2 for a PR.
set -eu

REPO="${1:?repo dir}"
UPSTREAM_URL="${2:?upstream url}"
TAG="${3:?tag}"
OURS_FILE="${4:?ours list}"
C_FILE="${5:?c-class list}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

cd "$REPO"
git remote add lite-upstream "$UPSTREAM_URL" 2>/dev/null || git remote set-url lite-upstream "$UPSTREAM_URL"
git fetch --force --no-tags lite-upstream "refs/tags/${TAG}:refs/tags/${TAG}"

set +e
git merge --no-ff --no-edit "refs/tags/$TAG"
STATUS=$?
set -e

if [ "$STATUS" -eq 0 ]; then
  exit 0
fi

RESULT=$(python3 "$SCRIPT_DIR/plus_follow.py" apply-ours "$REPO" "$OURS_FILE" "$C_FILE") || true
if [ "$RESULT" = "ok" ] && [ -z "$(git diff --name-only --diff-filter=U)" ]; then
  git commit --no-edit
  exit 0
fi
exit 2
