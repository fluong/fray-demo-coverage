#!/usr/bin/env bash
# Point this clone at .githooks so pre-push runs gitleaks and the internal-
# identifier denylist (same checks as the secrets-and-denylist job in fray.yml).
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "not a git repository: $root" >&2
  exit 1
fi

git config core.hooksPath .githooks
echo "Installed: core.hooksPath=.githooks"
echo "pre-push will refuse the push on gitleaks or denylist hits."
echo "Requires gitleaks on PATH (brew install gitleaks)."
echo "Denylist: FRAY_DENYLIST env, or ~/.config/fray/denylist (fail closed if missing)."
