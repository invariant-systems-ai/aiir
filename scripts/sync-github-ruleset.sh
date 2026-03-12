#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="${1:-$(gh repo view --json nameWithOwner --jq '.nameWithOwner')}"
RULESET_FILE="${RULESET_FILE:-$ROOT_DIR/.github/rulesets/main-production-gate.json}"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

if [[ ! -f "$RULESET_FILE" ]]; then
  echo "Ruleset file not found: $RULESET_FILE" >&2
  exit 1
fi

ruleset_name="$(jq -r '.name' "$RULESET_FILE")"
ruleset_id="$(gh api "repos/$REPO/rulesets" --paginate --jq ".[] | select(.name == \"$ruleset_name\" and .target == \"branch\") | .id" | head -n1)"

if [[ -n "$ruleset_id" ]]; then
  echo "Updating ruleset '$ruleset_name' on $REPO (id: $ruleset_id)"
  gh api --method PUT "repos/$REPO/rulesets/$ruleset_id" --input "$RULESET_FILE" >/dev/null
else
  echo "Creating ruleset '$ruleset_name' on $REPO"
  gh api --method POST "repos/$REPO/rulesets" --input "$RULESET_FILE" >/dev/null
fi

echo "Applied $RULESET_FILE to $REPO"
