#!/usr/bin/env bash
# B-536 (2026-09-22): the reconciler's `.export-sync` marker advance goes through a branch
# and a pull request, never a push to `main`. Until this file, two steps of
# `reconcile-public.yml` committed the marker on `main` and pushed it with the workflow's
# `contents: write` — `main` carries no branch protection, so a bot wrote the private
# default branch with nobody reading. A marker PR appears only when public gained
# commits private did not record (a promotion records its own marker), which is exactly
# the case that needs eyes. Usage: marker-pr.sh "<commit message>"; expects `.export-sync`
# modified in the working tree and GH_TOKEN in the environment.
set -euo pipefail
msg="${1:?commit message}"
branch="export/marker-${GITHUB_RUN_ID:-local}"
git config user.name  "tracelane-export"
git config user.email "export@tracelane.dev"
git checkout -q -b "$branch"
git add .export-sync
git commit -q -m "$msg"
git push -q origin "$branch"
body=$(printf '%s\n\n%s\n' \
  "The public mirror moved and this tree's absorption marker (\`.export-sync\`) has to follow it. Only the marker changes here — one line." \
  "Merging advances the marker; \`promote-staging-to-public.sh\` reads it. Opened as a PR rather than pushed to \`main\` (B-536).")
existing=$(gh pr list --state open --search 'in:title "Advance the public-mirror absorption marker"' --json number --jq '.[0].number' || true)
if [ -n "$existing" ]; then
  gh pr comment "$existing" --body "$body"
  echo "commented on existing PR #$existing (branch $branch pushed)"
  exit 0
fi
if gh pr create --base main --head "$branch" --title "Advance the public-mirror absorption marker" --body "$body" 2>/tmp/marker-pr.txt; then
  echo "PR opened for $branch"
else
  cat /tmp/marker-pr.txt
  repo="${GITHUB_REPOSITORY:-}"
  gh issue create --title "Advance the public-mirror absorption marker" --body "$(printf '%s\n\n%s\n' "$body" "Branch \`$branch\` is pushed. Actions may not open PRs here — open it in one click: https://github.com/$repo/compare/main...$branch?expand=1")"
  echo "::warning::Actions cannot open PRs here; filed an issue with the branch + compare link instead."
fi
